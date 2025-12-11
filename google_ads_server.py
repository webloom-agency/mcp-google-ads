from typing import Any, Dict, List, Optional
from pydantic import Field
import os
import json
import requests
import re
import time
import difflib
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

# MCP
from mcp.server.fastmcp import FastMCP

# ----------------------------- LOGGING -----------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('google_ads_server')

# ----------------------------- MCP APP -----------------------------
mcp = FastMCP(
    "google-ads-server",
    dependencies=[
        "google-auth-oauthlib",
        "google-auth",
        "requests",
        "python-dotenv"
    ]
)

# ----------------------------- CONSTANTS -----------------------------
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v19"  # keep aligned with your Google Ads API

# Load environment variables (optional)
try:
    from dotenv import load_dotenv
    load_dotenv()
    logger.info("Environment variables loaded from .env file")
except ImportError:
    logger.warning("python-dotenv not installed, skipping .env file loading")

# Core env
GOOGLE_ADS_CREDENTIALS_PATH = os.environ.get("GOOGLE_ADS_CREDENTIALS_PATH")
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
GOOGLE_ADS_AUTH_TYPE = os.environ.get("GOOGLE_ADS_AUTH_TYPE", "oauth")  # 'oauth' or 'service_account'
DEFAULT_GOOGLE_ADS_CUSTOMER_ID = os.environ.get("DEFAULT_GOOGLE_ADS_CUSTOMER_ID")  # optional default
GOOGLE_ADS_READ_ONLY = os.environ.get("GOOGLE_ADS_READ_ONLY", "1") not in ("0", "false", "False")

# Caches
ACCOUNTS_CACHE_TTL_SECONDS = int(os.getenv("ACCOUNTS_CACHE_TTL_SECONDS", "900"))
HIER_CACHE_TTL_SECONDS = int(os.getenv("HIER_CACHE_TTL_SECONDS", "900"))

# Prefer hierarchy-based lookups for name → ID (recommended for big MCCs)
USE_HIERARCHY_LOOKUP = os.getenv("USE_HIERARCHY_LOOKUP", "1") not in ("0", "false", "False")

_accounts_cache: Dict[str, Any] = {"at": 0, "items": []}     # listAccessibleCustomers-based (fallback)
_hierarchy_cache: Dict[str, Any] = {"at": 0, "items": []}    # customer_client-based (full subtree)

# ----------------------------- HELPERS -----------------------------
def _now_s() -> int:
    return int(time.time())

def _is_google_ads_api_url(url: str) -> bool:
    try:
        return "googleads.googleapis.com" in str(url)
    except Exception:
        return False

def _is_readonly_allowed(url: str, method: str) -> bool:
    """
    Whitelist Google Ads API endpoints that are considered read-only.
    Currently allowed:
      - POST .../customers/{cid}/googleAds:search (GAQL search)
      - GET  .../customers:listAccessibleCustomers
    """
    if not _is_google_ads_api_url(url):
        return True
    method_u = (method or "").upper()
    try:
        path = str(url).split("googleads.googleapis.com/", 1)[-1]
    except Exception:
        path = str(url)

    if method_u == "POST" and path.endswith("/googleAds:search"):
        return True
    if method_u == "GET" and path.endswith("/customers:listAccessibleCustomers"):
        return True
    return False

def _google_ads_request(method: str, url: str, headers: Dict[str, str], *, json: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None):
    """
    Centralized HTTP wrapper for Google Ads API calls.
    Enforces read-only mode by blocking non-whitelisted endpoints/methods.
    """
    if GOOGLE_ADS_READ_ONLY and _is_google_ads_api_url(url):
        if not _is_readonly_allowed(url, method):
            raise PermissionError("Write operations are disabled (GOOGLE_ADS_READ_ONLY=1).")
    return requests.request(method, url, headers=headers, json=json, params=params)

def normalize_customer_id(value: Optional[str]) -> str:
    """
    Accepts '123-456-7890' or '1234567890' and returns digits-only (10 chars).
    Raises ValueError on missing/malformed.
    """
    if value is None or str(value).strip() == "":
        if DEFAULT_GOOGLE_ADS_CUSTOMER_ID:
            value = DEFAULT_GOOGLE_ADS_CUSTOMER_ID
        else:
            raise ValueError("customer_id is required (e.g., '123-456-7890').")
    digits = re.sub(r"\D", "", str(value))
    if not re.fullmatch(r"\d{10}", digits):
        raise ValueError(f"Invalid customer_id: {value!r}. Expected 10 digits.")
    return digits

def normalize_login_customer_id(value: Optional[str]) -> Optional[str]:
    """Normalize optional MCC/login ID. Returns digits-only or None if not provided."""
    if not value:
        return None
    digits = re.sub(r"\D", "", str(value))
    if not re.fullmatch(r"\d{10}", digits):
        raise ValueError(f"Invalid login_customer_id: {value!r}. Expected 10 digits.")
    return digits

def get_credentials():
    """
    Get credentials based on GOOGLE_ADS_AUTH_TYPE.
    - service_account: requires GOOGLE_ADS_CREDENTIALS_PATH (SA JSON)
    - oauth: prefer env-based refresh-token; else token file; else interactive (local only)
    """
    auth_type = GOOGLE_ADS_AUTH_TYPE.lower()
    logger.info(f"Using authentication type: {auth_type}")

    if auth_type == "service_account":
        if not GOOGLE_ADS_CREDENTIALS_PATH:
            raise ValueError("GOOGLE_ADS_CREDENTIALS_PATH must point to your service account JSON when using service_account auth.")
        return get_service_account_credentials()

    # OAuth by default
    return get_oauth_credentials()

def get_service_account_credentials():
    """Get credentials using a service account key file."""
    logger.info(f"Loading service account credentials from {GOOGLE_ADS_CREDENTIALS_PATH}")

    if not os.path.exists(GOOGLE_ADS_CREDENTIALS_PATH):
        raise FileNotFoundError(f"Service account key file not found at {GOOGLE_ADS_CREDENTIALS_PATH}")

    try:
        credentials = service_account.Credentials.from_service_account_file(
            GOOGLE_ADS_CREDENTIALS_PATH,
            scopes=SCOPES
        )
        impersonation_email = os.environ.get("GOOGLE_ADS_IMPERSONATION_EMAIL")
        if impersonation_email:
            logger.info(f"Impersonating user: {impersonation_email}")
            credentials = credentials.with_subject(impersonation_email)
        return credentials
    except Exception as e:
        logger.error(f"Error loading service account credentials: {str(e)}")
        raise

def get_oauth_credentials():
    """
    Headless-friendly OAuth:
    1) If REFRESH TOKEN + CLIENT_ID + CLIENT_SECRET exist in env, build creds directly.
    2) Else, try token file at GOOGLE_ADS_CREDENTIALS_PATH (if set).
    3) Else, fall back to interactive InstalledAppFlow (local dev only).
    """
    env_client_id = os.environ.get("GOOGLE_ADS_CLIENT_ID")
    env_client_secret = os.environ.get("GOOGLE_ADS_CLIENT_SECRET")
    env_refresh_token = os.environ.get("GOOGLE_ADS_REFRESH_TOKEN")

    if env_client_id and env_client_secret and env_refresh_token:
        logger.info("Building OAuth credentials from environment (refresh token).")
        creds = Credentials(
            token=None,
            refresh_token=env_refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=env_client_id,
            client_secret=env_client_secret,
            scopes=SCOPES,
        )
        try:
            creds.refresh(Request())
        except Exception as e:
            logger.error(f"Failed to refresh OAuth token from env: {e}")
            raise
        return creds

    # Fallback: token file
    token_path = None
    if GOOGLE_ADS_CREDENTIALS_PATH:
        token_path = GOOGLE_ADS_CREDENTIALS_PATH
        if os.path.exists(token_path) and not os.path.basename(token_path).endswith('.json'):
            token_dir = os.path.dirname(token_path)
            token_path = os.path.join(token_dir, 'google_ads_token.json')

    client_config = None
    if token_path and os.path.exists(token_path):
        try:
            logger.info(f"Loading OAuth credentials from file: {token_path}")
            with open(token_path, 'r') as f:
                creds_data = json.load(f)
                if "refresh_token" in creds_data or "access_token" in creds_data:
                    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
                    if not creds.valid:
                        creds.refresh(Request())
                    return creds
                else:
                    client_config = creds_data
        except Exception as e:
            logger.warning(f"Could not load token from file: {e}")

    # Interactive (local only)
    logger.info("Falling back to interactive OAuth flow (local dev).")
    if not client_config:
        if not env_client_id or not env_client_secret:
            raise ValueError(
                "For OAuth you must either provide CLIENT_ID/CLIENT_SECRET/REFRESH_TOKEN in env, "
                "or set GOOGLE_ADS_CREDENTIALS_PATH to a token JSON, "
                "or run the interactive flow locally with CLIENT_ID/SECRET."
            )
        client_config = {
            "installed": {
                "client_id": env_client_id,
                "client_secret": env_client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
            }
        }

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
    creds = flow.run_local_server(port=0)

    try:
        if GOOGLE_ADS_CREDENTIALS_PATH:
            out_path = GOOGLE_ADS_CREDENTIALS_PATH
            if os.path.isdir(out_path):
                out_path = os.path.join(out_path, "google_ads_token.json")
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as f:
                f.write(creds.to_json())
            logger.info(f"Saved OAuth token to {out_path}")
    except Exception as e:
        logger.warning(f"Could not save OAuth token to file: {e}")

    return creds

def get_headers(creds, *, login_customer_id: Optional[str] = None):
    """
    Build request headers. You may override login_customer_id per call if needed.
    """
    if not GOOGLE_ADS_DEVELOPER_TOKEN:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")

    # Get/refresh bearer
    if isinstance(creds, service_account.Credentials):
        auth_req = Request()
        creds.refresh(auth_req)
        token = creds.token
    else:
        if not creds.valid:
            if getattr(creds, "expired", False) and getattr(creds, "refresh_token", None):
                try:
                    logger.info("Refreshing expired OAuth token in get_headers")
                    creds.refresh(Request())
                except RefreshError as e:
                    raise ValueError(f"Failed to refresh OAuth token: {str(e)}")
            else:
                raise ValueError("OAuth credentials are invalid and cannot be refreshed")
        token = creds.token

    headers = {
        'Authorization': f'Bearer {token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json'
    }

    login_id = normalize_login_customer_id(login_customer_id) or normalize_login_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID)
    if login_id:
        headers['login-customer-id'] = login_id

    return headers

# ----------------------------- GAQL SEARCH (pagination helper) -----------------------------
def _gaql_search_all(cid: str, query: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Fetch all rows for a GAQL query using googleAds:search pagination.
    Note: For Google Ads API v19, page size is fixed by the API (10,000).
    Setting pageSize triggers PAGE_SIZE_NOT_SUPPORTED, so we do NOT send it.
    """
    url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"
    results: List[Dict[str, Any]] = []
    page_token: Optional[str] = None

    while True:
        payload: Dict[str, Any] = {"query": query}
        if page_token:
            payload["pageToken"] = page_token

        r = _google_ads_request("POST", url, headers, json=payload)
        if r.status_code != 200:
            raise RuntimeError(f"GAQL search error [{r.status_code}]: {r.text}")

        data = r.json()
        results.extend(data.get("results", []))
        page_token = data.get("nextPageToken")
        if not page_token:
            break

    return results

# ----------------------------- ACCOUNT INDEXES -----------------------------
def get_full_hierarchy_index(
    force: bool = False,
    include_managers: bool = True,
    include_hidden: bool = False,
    max_level: int = 10,
) -> List[Dict[str, Any]]:
    """
    Returns the FULL subtree under the umbrella MCC in env (GOOGLE_ADS_LOGIN_CUSTOMER_ID),
    using customer_client. Much more complete than listAccessibleCustomers.
    """
    if (
        not force
        and _hierarchy_cache["items"]
        and _now_s() - _hierarchy_cache["at"] < HIER_CACHE_TTL_SECONDS
    ):
        return _hierarchy_cache["items"]

    root_id = normalize_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID)
    creds = get_credentials()
    headers = get_headers(creds, login_customer_id=root_id)

    where_status = "" if include_hidden else " AND customer_client.status = 'ENABLED'"
    query = f"""
        SELECT
          customer_client.id,
          customer_client.descriptive_name,
          customer_client.manager,
          customer_client.level,
          customer_client.status,
          customer_client.currency_code
        FROM customer_client
        WHERE customer_client.level <= {int(max_level)}
        {where_status}
        ORDER BY customer_client.level, customer_client.descriptive_name
    """.strip()

    try:
        rows = _gaql_search_all(root_id, query, headers)
    except Exception as e:
        # Fallback: return empty (caller can fallback to listAccessibleCustomers)
        logger.error(f"Hierarchy GAQL failed: {e}")
        rows = []

    items: List[Dict[str, Any]] = []
    for row in rows:
        cc = row.get("customerClient", {})
        cid = normalize_customer_id(cc.get("id", ""))
        name = cc.get("descriptiveName", "") or ""
        manager = bool(cc.get("manager", False))
        level = cc.get("level", 0)
        status = cc.get("status", "")
        currency = cc.get("currencyCode", "")
        if (not include_managers) and manager:
            continue
        items.append({
            "id": cid,
            "name": name,
            "manager": manager,
            "status": status,
            "currency": currency,
            "level": level
        })

    _hierarchy_cache["items"] = items
    _hierarchy_cache["at"] = _now_s()
    return items

def get_accounts_index(force: bool = False) -> List[Dict[str, Any]]:
    """
    Fallback (listAccessibleCustomers + per-customer name fetch).
    Kept for completeness if you disable hierarchy lookup.
    """
    if (
        not force
        and _accounts_cache["items"]
        and _now_s() - _accounts_cache["at"] < ACCOUNTS_CACHE_TTL_SECONDS
    ):
        return _accounts_cache["items"]

    creds_root = get_credentials()
    headers_root = get_headers(creds_root)
    url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
    r = _google_ads_request("GET", url, headers_root)
    if r.status_code != 200:
        raise RuntimeError(f"listAccessibleCustomers error [{r.status_code}]: {r.text}")

    ids = [rn.split("/")[-1] for rn in r.json().get("resourceNames", [])]
    items: List[Dict[str, Any]] = []

    q = """
        SELECT
          customer.id,
          customer.descriptive_name,
          customer.manager,
          customer.status,
          customer.currency_code
        FROM customer
        LIMIT 1
    """.strip()

    for raw in ids:
        cid = normalize_customer_id(raw)
        u = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        # Attempt 1: login_customer_id = cid
        try:
            headers_1 = get_headers(get_credentials(), login_customer_id=cid)
            rr = _google_ads_request("POST", u, headers_1, json={"query": q})
        except Exception:
            rr = None

        # Attempt 2: fallback to env MCC
        if not rr or rr.status_code != 200 or not rr.json().get("results"):
            try:
                headers_2 = get_headers(get_credentials())  # uses env MCC
                rr2 = _google_ads_request("POST", u, headers_2, json={"query": q})
            except Exception:
                rr2 = None
        else:
            rr2 = None

        use_resp = None
        if rr and rr.status_code == 200 and rr.json().get("results"):
            use_resp = rr
        elif rr2 and rr2.status_code == 200 and rr2.json().get("results"):
            use_resp = rr2

        if use_resp:
            c = use_resp.json()["results"][0].get("customer", {})
            items.append({
                "id": normalize_customer_id(c.get("id", cid)),
                "name": c.get("descriptiveName", "") or "",
                "manager": bool(c.get("manager", False)),
                "status": c.get("status", ""),
                "currency": c.get("currencyCode", ""),
            })
        else:
            err_txt = ""
            try:
                if rr and rr.text:
                    err_txt = rr.text
                elif rr2 and rr2.text:
                    err_txt = rr2.text
            except Exception:
                pass
            items.append({
                "id": cid,
                "name": "",
                "manager": None,
                "status": "",
                "currency": "",
                "error": err_txt
            })

    _accounts_cache["items"] = items
    _accounts_cache["at"] = _now_s()
    return items

def _active_index(force: bool = False) -> List[Dict[str, Any]]:
    """
    Choose which index to use (hierarchy preferred).
    """
    if USE_HIERARCHY_LOOKUP:
        items = get_full_hierarchy_index(force=force, include_managers=True, include_hidden=False, max_level=10)
        if items:
            return items
    return get_accounts_index(force=force)

# ----------------------------- NAME/ID RESOLUTION -----------------------------
def coerce_customer_id(identifier: str, prefer_non_manager: bool = True) -> str:
    """
    Accepts ID (with/without dashes) or account name (approximate).
    Returns 10-digit customer ID. Prefers non-MCC accounts on ties.
    Matching order:
      1) Already-an-ID → normalize & return
      2) Exact name (case-insensitive)
      3) Substring name match (case-insensitive)
      4) Fuzzy name match with low cutoff (0.3)
      5) Best SequenceMatcher score (no cutoff)
    """
    # 1) Already an ID?
    try:
        return normalize_customer_id(identifier)
    except Exception:
        pass

    def _extract_name_candidates(text: str) -> List[str]:
        raw = (text or "").strip().lower()
        out: List[str] = []

        # Primary candidate: the raw input lowered
        if raw:
            out.append(raw)

        # Try URL parsing to extract hostname
        try:
            parsed = urlparse(raw if re.match(r"^[a-z]+://", raw) else f"http://{raw}")
            host = (parsed.hostname or "").lower()
        except Exception:
            host = ""

        # If not parsed, try regex domain extraction
        if not host:
            m = re.search(r"([a-z0-9][a-z0-9-]*\.)+[a-z]{2,}", raw)
            if m:
                host = m.group(0)

        if host:
            out.append(host)
            # Drop www.
            if host.startswith("www."):
                out.append(host[4:])
            # Base label (left-most without www)
            base = host.split(".")[0]
            if base == "www" and len(host.split(".")) > 1:
                base = host.split(".")[1]
            if base:
                out.append(base)
                # Split hyphen/underscore variants
                for token in re.split(r"[-_]+", base):
                    if token and token not in out:
                        out.append(token)

        # De-duplicate while preserving order
        seen = set()
        uniq: List[str] = []
        for s in out:
            if s not in seen:
                uniq.append(s)
                seen.add(s)
        return uniq

    q = (identifier or "").strip().lower()
    if not q:
        raise ValueError("Empty account identifier.")

    accounts = _active_index(force=False)
    candidates = _extract_name_candidates(q)

    # 2) Exact name match
    for cand in candidates:
        exact = [a for a in accounts if (a.get("name") or "").lower() == cand]
        if exact:
            if prefer_non_manager:
                for a in exact:
                    if not a.get("manager"):
                        return a["id"]
            return exact[0]["id"]

    # 3) Substring match
    for cand in candidates:
        contains = [a for a in accounts if cand in (a.get("name") or "").lower()]
        if contains:
            if prefer_non_manager:
                for a in contains:
                    if not a.get("manager"):
                        return a["id"]
            return contains[0]["id"]

    # 4) Fuzzy (lower cutoff)
    names = [a["name"] for a in accounts if a.get("name")]
    close_any: List[str] = []
    for cand in candidates:
        for hit in difflib.get_close_matches(cand, names, n=5, cutoff=0.3):
            if hit not in close_any:
                close_any.append(hit)
    if close_any:
        cand_rows = [a for a in accounts if a.get("name") in close_any]
        if prefer_non_manager:
            for a in cand_rows:
                if not a.get("manager"):
                    return a["id"]
        return cand_rows[0]["id"]

    # 5) Best score across all names
    best_row = None
    best_score = -1.0
    for a in accounts:
        nm = a.get("name") or ""
        # Consider the best score among all candidate tokens
        score = 0.0
        for cand in candidates:
            score = max(score, difflib.SequenceMatcher(None, cand, nm.lower()).ratio())
        if (score > best_score) or (abs(score - best_score) < 1e-9 and best_row and best_row.get("manager") and not a.get("manager")):
            best_score = score
            best_row = a
    if best_row:
        return best_row["id"]

    raise ValueError(f"No account found matching name or ID: {identifier!r}")

# ----------------------------- TOOLS -----------------------------
@mcp.tool()
async def list_accounts(
    force_refresh: bool = Field(default=False, description="Refresh the cache"),
    use_hierarchy: bool = Field(default=True, description="If true, list from the full hierarchy under the umbrella MCC")
) -> str:
    """
    Lists accessible accounts with name, ID, MCC flag, and currency.
    """
    try:
        items = get_full_hierarchy_index(force=force_refresh, include_managers=True, include_hidden=False, max_level=10) \
            if use_hierarchy else get_accounts_index(force=force_refresh)
        if not items:
            return "No accessible accounts found."

        # Some indexes may not include 'level' (fallback path)
        for it in items:
            it.setdefault("level", 0)

        lines = ["Accessible Google Ads Accounts:", "-" * 80]
        items_sorted = sorted(items, key=lambda x: (x.get("level", 0), (x["manager"] is True), (x.get("name") or "").lower(), x["id"]))
        for a in items_sorted:
            tag = "MCC" if a["manager"] else "Client"
            nm = a["name"] or "(no name)"
            cur = f" · {a['currency']}" if a.get("currency") else ""
            lvl = f" · L{a.get('level', 0)}"
            lines.append(f"{nm} — {a['id']} [{tag}{lvl}]{cur}")
        return "\n".join(lines)
    except Exception as e:
        return f"Error listing accounts: {str(e)}"

@mcp.tool()
async def find_account(
    query: str = Field(description="Account name (partial) or ID"),
    top_k: int = Field(default=5, ge=1, le=20, description="Max results to return")
) -> str:
    """
    Fuzzy-search accounts by name or normalize an ID (using full hierarchy index).
    """
    try:
        rows = []
        try:
            cid = normalize_customer_id(query)
            rows = [a for a in _active_index() if a["id"] == cid]
        except Exception:
            all_rows = _active_index()
            scored = []
            for a in all_rows:
                nm = a.get("name") or ""
                score = difflib.SequenceMatcher(None, query.lower(), nm.lower()).ratio()
                scored.append((score, a))
            scored.sort(key=lambda x: x[0], reverse=True)
            rows = [a for _, a in scored[:top_k]]

        if not rows:
            return "No matches."
        out = []
        for a in rows[:top_k]:
            tag = "MCC" if a["manager"] else "Client"
            nm = a["name"] or "(no name)"
            lvl = f" · L{a.get('level', 0)}" if a.get("level") is not None else ""
            out.append(f"{nm} — {a['id']} [{tag}{lvl}]")
        return "\n".join(out)
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
async def list_accounts_hierarchy(
    root: str = Field(default="", description="MCC name or ID to start from. Empty = env GOOGLE_ADS_LOGIN_CUSTOMER_ID"),
    max_level: int = Field(default=10, ge=1, le=10, description="Depth to traverse (1..10)"),
    include_managers: bool = Field(default=True, description="Include MCCs in the output"),
    include_hidden: bool = Field(default=False, description="Include CANCELLED/UNSPECIFIED statuses")
) -> str:
    """
    Lists the account hierarchy from a manager (MCC) using customer_client.
    """
    try:
        root_id = coerce_customer_id(root, prefer_non_manager=False) if root else normalize_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID)
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=root_id)

        status_filter = "" if include_hidden else " AND customer_client.status = 'ENABLED'"
        query = f"""
            SELECT
              customer_client.id,
              customer_client.descriptive_name,
              customer_client.manager,
              customer_client.level,
              customer_client.status,
              customer_client.currency_code
            FROM customer_client
            WHERE customer_client.level <= {int(max_level)}
            {status_filter}
            ORDER BY customer_client.level, customer_client.manager DESC, customer_client.descriptive_name
        """

        rows = _gaql_search_all(root_id, query, headers)
        if not rows:
            return f"No accounts found under MCC {root_id}."

        lines = [f"Hierarchy under {root_id} (level ≤ {max_level}):", "-" * 90]
        count_total = 0
        count_clients = 0
        count_mcc = 0

        for row in rows:
            cc = row.get("customerClient", {})
            cid = normalize_customer_id(cc.get("id", ""))
            name = cc.get("descriptiveName", "") or "(no name)"
            manager = bool(cc.get("manager", False))
            level = cc.get("level", 0)
            status = cc.get("status", "")
            currency = cc.get("currencyCode", "")
            if (not include_managers) and manager:
                continue
            tag = "MCC" if manager else "Client"
            indent = "  " * int(level)
            cur = f" · {currency}" if currency else ""
            lines.append(f"{indent}{name} — {cid} [{tag} · {status} · L{level}]{cur}")
            count_total += 1
            if manager:
                count_mcc += 1
            else:
                count_clients += 1

        lines.append("-" * 90)
        lines.append(f"Total: {count_total} (Clients: {count_clients}, MCCs: {count_mcc})")
        return "\n".join(lines)

    except Exception as e:
        return f"Error listing hierarchy: {str(e)}"

@mcp.tool()
async def list_manager_clients(
    manager_id: str = Field(description="MCC ID or name (e.g., 879-804-8996)"),
    level: int = Field(default=1, ge=0, le=10, description="Depth to include (0=self only, 1=direct children, ... )"),
    enabled_only: bool = Field(default=True, description="Only include ENABLED accounts")
) -> str:
    """
    Lists client accounts under the given MCC using customer_client.
    """
    try:
        root_id = coerce_customer_id(manager_id, prefer_non_manager=False)
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=root_id)

        where_status = "" if not enabled_only else " AND customer_client.status = 'ENABLED'"
        query = f"""
            SELECT
              customer_client.id,
              customer_client.descriptive_name,
              customer_client.manager,
              customer_client.level,
              customer_client.status,
              customer_client.currency_code
            FROM customer_client
            WHERE customer_client.level <= {int(level)}
            {where_status}
            ORDER BY customer_client.level, customer_client.descriptive_name
        """

        rows = _gaql_search_all(root_id, query, headers)
        if not rows:
            return f"No clients found under MCC {root_id}."

        out = [f"Accounts under {root_id} (level ≤ {level}):", "-"*90]
        for row in rows:
            cc = row.get("customerClient", {})
            cid = normalize_customer_id(cc.get("id", ""))
            name = cc.get("descriptiveName", "") or "(no name)"
            manager = bool(cc.get("manager", False))
            lvl = cc.get("level", 0)
            status = cc.get("status", "")
            cur = cc.get("currencyCode", "")
            tag = "MCC" if manager else "Client"
            indent = "  " * int(lvl)
            cur_s = f" · {cur}" if cur else ""
            out.append(f"{indent}{name} — {cid} [{tag} · {status} · L{lvl}]{cur_s}")
        return "\n".join(out)

    except Exception as e:
        return f"Error: {str(e)}"

# ------- Query tools (all accept name or ID; prefer non-MCC automatically) -------
def _adjust_change_event_query(query: str) -> str:
    """
    Adjusts change_event queries to comply with Google Ads API restrictions:
    - Replaces LAST_30_DAYS/LAST_MONTH with explicit date range (29 days max)
    - Ensures LIMIT is present (max 10000)
    """
    # Only adjust if query contains 'change_event'
    if 'change_event' not in query.lower():
        return query
    
    adjusted = query
    
    # Replace LAST_30_DAYS or LAST_MONTH with explicit date >= (today - 29 days)
    if re.search(r'DURING\s+(LAST_30_DAYS|LAST_MONTH)', adjusted, re.IGNORECASE):
        start_date = (datetime.now() - timedelta(days=29)).strftime('%Y-%m-%d')
        adjusted = re.sub(
            r'(\w+\.\w+)\s+DURING\s+(LAST_30_DAYS|LAST_MONTH)',
            rf"\1 >= '{start_date}'",
            adjusted,
            flags=re.IGNORECASE
        )
    
    # Ensure LIMIT is present (add if missing, cap if > 10000)
    limit_match = re.search(r'LIMIT\s+(\d+)', adjusted, re.IGNORECASE)
    if limit_match:
        limit_val = int(limit_match.group(1))
        if limit_val > 10000:
            adjusted = re.sub(r'LIMIT\s+\d+', 'LIMIT 10000', adjusted, flags=re.IGNORECASE)
    else:
        # Append LIMIT if not present
        adjusted = adjusted.rstrip() + ' LIMIT 10000'
    
    return adjusted

@mcp.tool()
async def execute_gaql_query(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID to use as login-customer-id override")
) -> str:
    """
    Execute a custom GAQL query against the specified customer (name or ID).
    Fetches all pages (no artificial caps; only API limitations apply).
    """
    try:
        creds = get_credentials()
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)
        headers = get_headers(creds, login_customer_id=login_customer_id)

        # Auto-adjust change_event queries for API restrictions
        adjusted_query = _adjust_change_event_query(query)

        # Fetch all rows via pagination helper (no page size parameter sent)
        rows = _gaql_search_all(cid, adjusted_query, headers)
        if not rows:
            return "No results found for the query."

        first = rows[0]
        fields: List[str] = []
        for k, v in first.items():
            if isinstance(v, dict):
                for sk in v:
                    fields.append(f"{k}.{sk}")
            else:
                fields.append(k)

        lines = [f"Query Results for Account {cid}:", "-" * 80]
        lines.append(" | ".join(fields))
        lines.append("-" * 80)
        for row in rows:
            row_vals = []
            for field in fields:
                if "." in field:
                    p, c = field.split(".")
                    val = str(row.get(p, {}).get(c, ""))
                else:
                    val = str(row.get(field, ""))
                row_vals.append(val)
            lines.append(" | ".join(row_vals))
        return "\n".join(lines)

    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_campaign_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    days: int = Field(default=30, description="Number of days to look back (7, 14, 30, 60, 90, 180)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    query = f"""
        SELECT
            campaign.id,
            campaign.name,
            campaign.status,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions,
            metrics.average_cpc
        FROM campaign
        WHERE segments.date DURING {date_range}
        ORDER BY metrics.cost_micros DESC
    """
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def get_ad_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    days: int = Field(default=30, description="Number of days to look back (7, 14, 30, 60, 90, 180)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    query = f"""
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.status,
            campaign.name,
            ad_group.name,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions
        FROM ad_group_ad
        WHERE segments.date DURING {date_range}
        ORDER BY metrics.impressions DESC
    """
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def run_gaql(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    format: str = Field(default="table", description="Output format: 'table', 'json', or 'csv'"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    try:
        creds = get_credentials()
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)
        headers = get_headers(creds, login_customer_id=login_customer_id)

        # Auto-adjust change_event queries for API restrictions
        adjusted_query = _adjust_change_event_query(query)

        # Fetch all rows with pagination (no artificial caps)
        rows = _gaql_search_all(cid, adjusted_query, headers)
        if not rows:
            return "No results found for the query."

        if format.lower() == "json":
            return json.dumps({"results": rows}, indent=2)

        first = rows[0]
        fields: List[str] = []
        for k, v in first.items():
            if isinstance(v, dict):
                for sk in v:
                    fields.append(f"{k}.{sk}")
            else:
                fields.append(k)

        if format.lower() == "csv":
            csv_lines = [",".join(fields)]
            for row in rows:
                row_vals = []
                for f in fields:
                    if "." in f:
                        p, c = f.split(".")
                        val = str(row.get(p, {}).get(c, "")).replace(",", ";")
                    else:
                        val = str(row.get(f, "")).replace(",", ";")
                    row_vals.append(val)
                csv_lines.append(",".join(row_vals))
            return "\n".join(csv_lines)

        # table
        lines = [f"Query Results for Account {cid}:", "-" * 100]
        widths = {f: len(f) for f in fields}
        for row in rows:
            for f in fields:
                if "." in f:
                    p, c = f.split(".")
                    v = str(row.get(p, {}).get(c, ""))
                else:
                    v = str(row.get(f, ""))
                widths[f] = max(widths[f], len(v))

        header = " | ".join(f"{f:{widths[f]}}" for f in fields)
        lines.append(header)
        lines.append("-" * len(header))
        for row in rows:
            vals = []
            for f in fields:
                if "." in f:
                    p, c = f.split(".")
                    v = str(row.get(p, {}).get(c, ""))
                else:
                    v = str(row.get(f, ""))
                vals.append(f"{v:{widths[f]}}")
            lines.append(" | ".join(vals))
        return "\n".join(lines)

    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_ad_creatives(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    query = """
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.ad.type,
            ad_group_ad.ad.final_urls,
            ad_group_ad.status,
            ad_group_ad.ad.responsive_search_ad.headlines,
            ad_group_ad.ad.responsive_search_ad.descriptions,
            ad_group.name,
            campaign.name
        FROM ad_group_ad
        WHERE ad_group_ad.status != 'REMOVED'
        ORDER BY campaign.name, ad_group.name
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)

        rows = _gaql_search_all(cid, query, headers)
        if not rows:
            return "No ad creatives found for this customer."

        out = [f"Ad Creatives for Customer {cid}:", "=" * 80]
        for i, res in enumerate(rows, 1):
            ad = res.get('adGroupAd', {}).get('ad', {})
            ad_group = res.get('adGroup', {})
            campaign = res.get('campaign', {})

            out.append(f"\n{i}. Campaign: {campaign.get('name', 'N/A')}")
            out.append(f"   Ad Group: {ad_group.get('name', 'N/A')}")
            out.append(f"   Ad ID: {ad.get('id', 'N/A')}")
            out.append(f"   Ad Name: {ad.get('name', 'N/A')}")
            out.append(f"   Status: {res.get('adGroupAd', {}).get('status', 'N/A')}")
            out.append(f"   Type: {ad.get('type', 'N/A')}")

            rsa = ad.get('responsiveSearchAd', {})
            if rsa:
                if 'headlines' in rsa:
                    out.append("   Headlines:")
                    for h in rsa['headlines']:
                        out.append(f"     - {h.get('text', 'N/A')}")
                if 'descriptions' in rsa:
                    out.append("   Descriptions:")
                    for d in rsa['descriptions']:
                        out.append(f"     - {d.get('text', 'N/A')}")

            final_urls = ad.get('finalUrls', [])
            if final_urls:
                out.append(f"   Final URLs: {', '.join(final_urls)}")

            out.append("-" * 80)
        return "\n".join(out)

    except Exception as e:
        return f"Error retrieving ad creatives: {str(e)}"

@mcp.tool()
async def get_account_currency(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    query = """
        SELECT
            customer.id,
            customer.currency_code
        FROM customer
        LIMIT 1
    """
    try:
        creds = get_credentials()
        if not creds.valid:
            if getattr(creds, 'refresh_token', None):
                creds.refresh(Request())
            else:
                raise ValueError("Invalid credentials and no refresh token available")

        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        response = _google_ads_request("POST", url, headers, json={"query": query})
        if response.status_code != 200:
            return f"Error retrieving account currency [{response.status_code}]: {response.text}"

        results = response.json()
        if not results.get('results'):
            return "No account information found for this customer."

        customer = results['results'][0].get('customer', {})
        currency_code = customer.get('currencyCode', 'Not specified')
        return f"Account {cid} uses currency: {currency_code}"

    except Exception as e:
        logger.error(f"Error retrieving account currency: {str(e)}")
        return f"Error retrieving account currency: {str(e)}"

@mcp.tool()
async def get_image_assets(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    limit: int = Field(default=0, description="Maximum number of image assets to return (0 = no limit)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.height_pixels,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.file_size
        FROM asset
        WHERE asset.type = 'IMAGE'
        {f"LIMIT {limit}" if isinstance(limit, int) and limit > 0 else ''}
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        # If limit > 0, rely on server-side LIMIT; else fetch all pages
        if isinstance(limit, int) and limit > 0:
            response = _google_ads_request("POST", url, headers, json={"query": query})
            if response.status_code != 200:
                return f"Error retrieving image assets [{response.status_code}]: {response.text}"
            rows = response.json().get('results', [])
        else:
            # Remove any trailing whitespace-only LIMIT fragment before sending
            q_no_limit = "\n".join([ln for ln in query.splitlines() if not ln.strip().startswith("LIMIT ")])
            rows = _gaql_search_all(cid, q_no_limit, headers)

        if not rows:
            return "No image assets found for this customer."

        out = [f"Image Assets for Customer {cid}:", "=" * 80]
        for i, res in enumerate(rows, 1):
            asset = res.get('asset', {})
            img = asset.get('imageAsset', {})
            full = img.get('fullSize', {})

            out.append(f"\n{i}. Asset ID: {asset.get('id', 'N/A')}")
            out.append(f"   Name: {asset.get('name', 'N/A')}")
            if full:
                out.append(f"   Image URL: {full.get('url', 'N/A')}")
                out.append(f"   Dimensions: {full.get('widthPixels', 'N/A')} x {full.get('heightPixels', 'N/A')} px")
            file_size = img.get('fileSize')
            if file_size is not None:
                out.append(f"   File Size: {int(file_size)/1024:.2f} KB")
            out.append("-" * 80)
        return "\n".join(out)

    except Exception as e:
        return f"Error retrieving image assets: {str(e)}"

@mcp.tool()
async def download_image_asset(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    asset_id: str = Field(description="The ID of the image asset to download"),
    output_dir: str = Field(default="./ad_images", description="Directory to save the downloaded image"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url
        FROM asset
        WHERE asset.type = 'IMAGE'
          AND asset.id = {asset_id}
        LIMIT 1
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        resp = _google_ads_request("POST", url, headers, json={"query": query})
        if resp.status_code != 200:
            return f"Error retrieving image asset [{resp.status_code}]: {resp.text}"

        results = resp.json()
        if not results.get('results'):
            return f"No image asset found with ID {asset_id}"

        asset = results['results'][0].get('asset', {})
        image_url = asset.get('imageAsset', {}).get('fullSize', {}).get('url')
        asset_name = asset.get('name', f"image_{asset_id}")

        if not image_url:
            return f"No download URL found for image asset ID {asset_id}"

        os.makedirs(output_dir, exist_ok=True)
        img_resp = requests.get(image_url)
        if img_resp.status_code != 200:
            return f"Failed to download image: HTTP {img_resp.status_code}"

        safe = ''.join(c for c in asset_name if c.isalnum() or c in ' ._-')
        filename = f"{asset_id}_{safe}.jpg"
        path = os.path.join(output_dir, filename)
        with open(path, 'wb') as f:
            f.write(img_resp.content)

        return f"Successfully downloaded image asset {asset_id} to {path}"

    except Exception as e:
        return f"Error downloading image asset: {str(e)}"

@mcp.tool()
async def get_asset_usage(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    asset_id: str = Field(default=None, description="Optional: specific asset ID to look up"),
    asset_type: str = Field(default="IMAGE", description="Asset type to search for ('IMAGE', 'TEXT', 'VIDEO', etc.)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    where_clause = f"asset.type = '{asset_type}'"
    if asset_id:
        where_clause += f" AND asset.id = {asset_id}"

    assets_query = f"""
        SELECT asset.id, asset.name, asset.type
        FROM asset
        WHERE {where_clause}
    """

    associations_query = f"""
        SELECT campaign.id, campaign.name, asset.id, asset.name, asset.type
        FROM campaign_asset
        WHERE {where_clause}
    """

    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)

        assets_rows = _gaql_search_all(cid, assets_query, headers)
        if not assets_rows:
            return f"No {asset_type} assets found for this customer."

        assoc_rows = _gaql_search_all(cid, associations_query, headers)

        out = [f"Asset Usage for Customer {cid}:", "=" * 80]
        asset_usage: Dict[str, Dict[str, Any]] = {}

        for r in assets_rows:
            a = r.get('asset', {})
            aid = a.get('id')
            if aid:
                asset_usage[aid] = {
                    "name": a.get('name', 'Unnamed asset'),
                    "type": a.get('type', 'Unknown'),
                    "usage": []
                }

        for r in assoc_rows:
            a = r.get('asset', {})
            aid = a.get('id')
            if aid and aid in asset_usage:
                campaign = r.get('campaign', {})
                usage = {
                    'campaign_id': campaign.get('id', 'N/A'),
                    'campaign_name': campaign.get('name', 'N/A'),
                }
                asset_usage[aid]['usage'].append(usage)

        for aid, info in asset_usage.items():
            out.append(f"\nAsset ID: {aid}")
            out.append(f"Name: {info['name']}")
            out.append(f"Type: {info['type']}")
            if info['usage']:
                out.append("\nUsed in:")
                out.append("-" * 60)
                out.append(f"{'Campaign':<30}")
                out.append("-" * 60)
                for u in info['usage']:
                    out.append(f"{(u['campaign_name'] + ' (' + str(u['campaign_id']) + ')')[:60]}")
            out.append("=" * 80)
        return "\n".join(out)

    except Exception as e:
        return f"Error retrieving asset usage: {str(e)}"

@mcp.tool()
async def analyze_image_assets(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    days: int = Field(default=30, description="Number of days to look back (7, 14, 30, 60, 90, 180)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.full_size.height_pixels,
            campaign.name,
            metrics.impressions,
            metrics.clicks,
            metrics.conversions,
            metrics.cost_micros
        FROM campaign_asset
        WHERE asset.type = 'IMAGE'
          AND segments.date DURING {date_range}
        ORDER BY metrics.impressions DESC
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)

        rows = _gaql_search_all(cid, query, headers)
        if not rows:
            return "No image asset performance data found for this customer and time period."

        assets_data: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            a = r.get('asset', {})
            aid = a.get('id')
            if aid not in assets_data:
                assets_data[aid] = {
                    'name': a.get('name', f"Asset {aid}"),
                    'url': a.get('imageAsset', {}).get('fullSize', {}).get('url', 'N/A'),
                    'dimensions': f"{a.get('imageAsset', {}).get('fullSize', {}).get('widthPixels', 'N/A')} x {a.get('imageAsset', {}).get('fullSize', {}).get('heightPixels', 'N/A')}",
                    'impressions': 0,
                    'clicks': 0,
                    'conversions': 0.0,
                    'cost_micros': 0,
                    'campaigns': set()
                }
            m = r.get('metrics', {})
            assets_data[aid]['impressions'] += int(m.get('impressions', 0))
            assets_data[aid]['clicks'] += int(m.get('clicks', 0))
            assets_data[aid]['conversions'] += float(m.get('conversions', 0))
            assets_data[aid]['cost_micros'] += int(m.get('costMicros', 0))

            c = r.get('campaign', {})
            if c.get('name'):
                assets_data[aid]['campaigns'].add(c.get('name'))

        out = [f"Image Asset Performance Analysis for Customer {cid} ({date_range.replace('_', ' ').title()}):",
               "=" * 100]

        sorted_assets = sorted(assets_data.items(), key=lambda x: x[1]['impressions'], reverse=True)
        for aid, data in sorted_assets:
            ctr = (data['clicks'] / data['impressions'] * 100) if data['impressions'] > 0 else 0
            out.append(f"\nAsset ID: {aid}")
            out.append(f"Name: {data['name']}")
            out.append(f"Dimensions: {data['dimensions']}")
            out.append("\nPerformance Metrics:")
            out.append(f"  Impressions: {data['impressions']:,}")
            out.append(f"  Clicks: {data['clicks']:,}")
            out.append(f"  CTR: {ctr:.2f}%")
            out.append(f"  Conversions: {data['conversions']:.2f}")
            out.append(f"  Cost (micros): {data['cost_micros']:,}")
            out.append(f"\nUsed in {len(data['campaigns'])} campaigns:")
            for c in list(data['campaigns'])[:5]:
                out.append(f"  - {c}")
            if len(data['campaigns']) > 5:
                out.append(f"  - ... and {len(data['campaigns']) - 5} more")
            if data['url'] != 'N/A':
                out.append(f"\nImage URL: {data['url']}")
            out.append("-" * 100)

        return "\n".join(out)

    except Exception as e:
        return f"Error analyzing image assets: {str(e)}"

# ----------------------------- MCP RESOURCES & PROMPTS -----------------------------
@mcp.resource("gaql://reference")
def gaql_reference() -> str:
    return """
    # Google Ads Query Language (GAQL) Reference (short)
    SELECT field1, field2 FROM resource WHERE condition ORDER BY field LIMIT n
    Common resources: campaign, ad_group, ad_group_ad, asset, customer, keyword_view, customer_client, etc.
    Date ranges: LAST_7_DAYS, LAST_14_DAYS, LAST_30_DAYS, LAST_90_DAYS, ...
    """

@mcp.prompt("google_ads_workflow")
def google_ads_workflow() -> str:
    return """
    1) list_accounts(use_hierarchy=true)
    2) get_account_currency(customer_id="name or ID")
    3) get_campaign_performance / get_ad_performance / get_ad_creatives
    4) run_gaql(customer_id="name or ID", query="...")
    5) list_accounts_hierarchy(root="", max_level=10) for full tree
    """

@mcp.prompt("gaql_help")
def gaql_help() -> str:
    return """
    Examples:
    SELECT campaign.name, metrics.clicks FROM campaign WHERE segments.date DURING LAST_30_DAYS LIMIT 10
    """

# ----------------------------- HTTP (ASGI) APP FOR RENDER -----------------------------
MCP_HTTP_PATH = os.getenv("MCP_HTTP_PATH", "/mcp")

# Configure FastMCP settings for Render deployment
try:
    # On newer fastmcp versions
    mcp.settings.streamable_http_path = MCP_HTTP_PATH  # type: ignore[attr-defined]
    # Disable Host header validation for Render - use None instead of ["*"]
    mcp.settings.allowed_hosts = None  # type: ignore[attr-defined]
except Exception as e:
    logger.info(f"Could not set mcp.settings (older version?): {e}")

class BearerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Allow CORS preflight to pass through
        if getattr(request, "method", "").upper() == "OPTIONS":
            return await call_next(request)

        token_expected = os.getenv("MCP_BEARER_TOKEN")
        # If no token configured, do not enforce auth
        if not token_expected:
            return await call_next(request)

        try:
            path = request.url.path
        except Exception:
            path = ""

        base_path = MCP_HTTP_PATH.rstrip("/")
        # Protect only the MCP endpoints (e.g., /mcp, /mcp/sse, /mcp/messages)
        if path == base_path or path.startswith(base_path + "/"):
            auth_header = request.headers.get("authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return PlainTextResponse("Unauthorized", status_code=401)
            token = auth_header.split(" ", 1)[1]
            if token != token_expected:
                return PlainTextResponse("Forbidden", status_code=403)

        return await call_next(request)

# Create app and disable host validation after creation
app = mcp.streamable_http_app()

# Monkey-patch to disable Host header validation
try:
    if hasattr(app, 'state') and hasattr(app.state, '_mcp_transport_manager'):
        manager = app.state._mcp_transport_manager
        if hasattr(manager, '_transport_security'):
            manager._transport_security.allowed_hosts = None
            logger.info("Disabled Host header validation for Render deployment")
except Exception as e:
    logger.warning(f"Could not disable Host header validation: {e}")

# Add Bearer auth enforcement if MCP_BEARER_TOKEN is set
app.add_middleware(BearerAuthMiddleware)

# --- CORS for browser-based MCP clients (e.g., bolt.new / webcontainer) ---
# Allow exact origins and a regex for ephemeral *.webcontainer-api.io subdomains.
# You can also widen to ["*"] while testing.
ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "MCP_CORS_ORIGINS",
    "https://bolt.new"
).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


if __name__ == "__main__":
    # Local dev convenience (Render should run uvicorn externally)
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("google_ads_server:app", host="0.0.0.0", port=port, reload=False)
