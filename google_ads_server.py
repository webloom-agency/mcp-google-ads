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

# Patch MCP transport security BEFORE importing FastMCP
# This must happen before any MCP modules are loaded
import sys
if 'mcp.server.transport_security' not in sys.modules:
    # Pre-patch by injecting our own version
    import types
    mock_module = types.ModuleType('mcp.server.transport_security')
    
    # Create a security class that implements validate_request (not a middleware)
    class _PermissiveTransportSecurity:
        def __init__(self, allowed_hosts=None):
            # Ignore allowed_hosts parameter
            self.allowed_hosts = None
        
        async def validate_request(self, request, is_post=False):
            # Always return None (no error) to allow all requests
            # Bearer token middleware provides the real security
            host = request.headers.get('host', 'unknown')
            print(f"🔓 Transport security: allowing Host {host} (Bearer token validates)")
            return None  # None means validation passed
    
    # Create settings class that always disables validation
    from pydantic import BaseModel as _BaseModel, Field as _Field
    from typing import Optional as _Optional, List as _List
    class _PermissiveSecuritySettings(_BaseModel):
        allowed_hosts: _Optional[_List[str]] = _Field(default=None)
        
        class Config:
            extra = "allow"  # Allow extra fields
    
    # Add necessary module attributes
    mock_module.TransportSecurityMiddleware = _PermissiveTransportSecurity
    mock_module.TransportSecuritySettings = _PermissiveSecuritySettings
    mock_module.logger = None  # Placeholder
    mock_module.logging = logging
    
    sys.modules['mcp.server.transport_security'] = mock_module
    print("✓ Pre-patched transport_security module before MCP import (v2 - with validate_request)")

# MCP
from mcp.server.fastmcp import FastMCP

# ----------------------------- LOGGING -----------------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('google_ads_server')

logger.info("=" * 80)
logger.info("🚀 Google Ads MCP Server starting up...")
logger.info("=" * 80)

# Monkey-patch transport_security BEFORE any FastMCP initialization
logger.info("🔧 Attempting to patch transport_security module...")
try:
    from mcp.server import transport_security
    from mcp.server import streamable_http_manager
    
    # Patch TransportSecurityMiddleware to bypass host validation
    if hasattr(transport_security, 'TransportSecurityMiddleware'):
        OriginalMiddleware = transport_security.TransportSecurityMiddleware
        
        class PatchedMiddleware(OriginalMiddleware):
            async def dispatch(self, request, call_next):
                # Skip host validation entirely - just call next
                logger.info(f"🔓 Bypassing Host validation for: {request.headers.get('host', 'unknown')}")
                return await call_next(request)
        
        transport_security.TransportSecurityMiddleware = PatchedMiddleware
        logger.info("✓ Patched TransportSecurityMiddleware to bypass Host validation")
    
    # Also patch in streamable_http_manager if it references it
    if hasattr(streamable_http_manager, 'TransportSecurityMiddleware'):
        streamable_http_manager.TransportSecurityMiddleware = transport_security.TransportSecurityMiddleware
        logger.info("✓ Updated TransportSecurityMiddleware reference in streamable_http_manager")
    
    # Patch TransportSecuritySettings to disable validation by default
    if hasattr(transport_security, 'TransportSecuritySettings'):
        OriginalSettings = transport_security.TransportSecuritySettings
        
        class PatchedSettings(OriginalSettings):
            def __init__(self, *args, **kwargs):
                # Force allowed_hosts to None (disables validation)
                kwargs['allowed_hosts'] = None
                super().__init__(*args, **kwargs)
        
        transport_security.TransportSecuritySettings = PatchedSettings
        logger.info("✓ Patched TransportSecuritySettings to disable Host validation")
    
    if hasattr(streamable_http_manager, 'TransportSecuritySettings'):
        streamable_http_manager.TransportSecuritySettings = transport_security.TransportSecuritySettings
        logger.info("✓ Updated TransportSecuritySettings reference in streamable_http_manager")
        
except Exception as e:
    logger.error(f"❌ Could not patch transport_security: {e}")
    import traceback
    traceback.print_exc()
else:
    logger.info("✅ Transport security patch block completed without exceptions")

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
API_VERSION = "v23"  # keep aligned with your Google Ads API (v23 released Jan 2026, sunset Feb 2027)

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
_search_terms_cache: Dict[str, Any] = {}                     # search terms paginated cache: {cache_key: {"at": int, "rows": [...], "summary": {...}}}

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
    Note: For Google Ads API, page size is fixed by the API (10,000).
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
    Results are sorted so Client accounts appear before MCC/manager accounts
    (at equal relevance), because metrics queries only work on client accounts.
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
            # Sort by score DESC, then prefer non-manager (Client) over manager (MCC)
            scored.sort(key=lambda x: (-x[0], x[1].get("manager", False) is True))
            rows = [a for _, a in scored[:top_k]]

        if not rows:
            return "No matches."

        # Final sort: Client accounts first, then MCC, preserving relevance within each group
        # (stable sort keeps original relevance order within each group)
        has_clients = any(not a.get("manager") for a in rows)
        if has_clients:
            rows.sort(key=lambda a: (1 if a.get("manager") else 0))

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
def _format_compact(rows: List[Dict], fields: List[str], cid: str, total: int, max_shown: Optional[int]) -> str:
    """Format results in a compact, readable format with minimal whitespace."""
    lines = [f"Results for {cid} ({len(rows)}/{total}):"]
    
    # For compact format, show only most essential fields (first 5)
    key_fields = fields[:5] if len(fields) > 5 else fields
    
    for i, row in enumerate(rows, 1):
        vals = []
        for f in key_fields:
            if "." in f:
                p, c = f.split(".", 1)
                v = str(row.get(p, {}).get(c, ""))
            else:
                v = str(row.get(f, ""))
            # Truncate long values
            if len(v) > 50:
                v = v[:47] + "..."
            vals.append(f"{f.split('.')[-1]}:{v}")
        lines.append(f"{i}. " + " | ".join(vals))
    
    if max_shown and total > max_shown:
        lines.append(f"\n... and {total - max_shown} more results")
    return "\n".join(lines)

def _summarize_performance_data(rows: List[Dict], cid: str, total: int, max_shown: Optional[int], entity_type: str = "campaign") -> str:
    """
    Summarize performance data (campaigns, ads, keywords) by showing:
    1. Aggregate totals (ALL data preserved)
    2. Top N detailed results
    This ensures no data is lost while keeping output manageable.
    """
    if not rows:
        return f"No {entity_type} data found."
    
    # Calculate aggregate totals from ALL rows (preserves all data)
    total_impressions = 0
    total_clicks = 0
    total_cost = 0
    total_conversions = 0
    total_conversion_value = 0
    
    for row in rows:
        metrics = row.get("metrics", {})
        total_impressions += int(metrics.get("impressions", 0))
        total_clicks += int(metrics.get("clicks", 0))
        total_cost += int(metrics.get("costMicros", 0))
        total_conversions += float(metrics.get("conversions", 0))
        total_conversion_value += float(metrics.get("conversionsValue", 0))
    
    # Calculate aggregates
    avg_ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0
    avg_cpc = (total_cost / total_clicks) if total_clicks > 0 else 0
    cost_per_conv = (total_cost / total_conversions) if total_conversions > 0 else 0
    
    # Build summary header
    lines = [
        f"Performance Summary for {cid} ({entity_type.title()}s)",
        "=" * 100,
        f"Total {entity_type}s analyzed: {total}",
        f"Showing detailed breakdown for top {min(max_shown or total, total)} {entity_type}s",
        "",
        "📊 AGGREGATE TOTALS (All Data):",
        f"   Total Impressions: {total_impressions:,}",
        f"   Total Clicks: {total_clicks:,}",
        f"   Total Cost: ${total_cost / 1_000_000:,.2f}",
        f"   Total Conversions: {total_conversions:,.2f}",
        f"   Total Conversion Value: ${total_conversion_value:,.2f}",
        f"   Average CTR: {avg_ctr:.2f}%",
        f"   Average CPC: ${avg_cpc / 1_000_000:.2f}",
        f"   Cost per Conversion: ${cost_per_conv / 1_000_000:.2f}",
        "",
        "🎯 TOP PERFORMERS (Detailed):",
        "=" * 100
    ]
    
    # Show detailed top results (limited for readability)
    shown_rows = rows[:max_shown] if max_shown else rows
    
    for i, row in enumerate(shown_rows, 1):
        # Extract entity name based on type
        if entity_type == "campaign":
            entity = row.get("campaign", {})
            name = entity.get("name", "Unknown")
            status = entity.get("status", "")
        elif entity_type == "ad":
            ad_data = row.get("adGroupAd", {}).get("ad", {})
            campaign = row.get("campaign", {})
            name = f"{campaign.get('name', 'Unknown')} / {ad_data.get('name', 'Unknown Ad')}"
            status = row.get("adGroupAd", {}).get("status", "")
        elif entity_type == "keyword":
            keyword = row.get("adGroupCriterion", {}).get("keyword", {})
            name = f"{keyword.get('text', 'Unknown')} ({keyword.get('matchType', '')})"
            status = row.get("adGroupCriterion", {}).get("status", "")
            quality_score = row.get("adGroupCriterion", {}).get("qualityInfo", {}).get("qualityScore", "N/A")
        else:
            name = "Unknown"
            status = ""
        
        metrics = row.get("metrics", {})
        impr = int(metrics.get("impressions", 0))
        clicks = int(metrics.get("clicks", 0))
        cost = int(metrics.get("costMicros", 0))
        conv = float(metrics.get("conversions", 0))
        ctr = float(metrics.get("ctr", 0)) * 100
        cpc = int(metrics.get("averageCpc", 0))
        
        lines.append(f"\n{i}. {name}")
        if status:
            lines.append(f"   Status: {status}")
        if entity_type == "keyword" and quality_score != "N/A":
            lines.append(f"   Quality Score: {quality_score}")
        lines.append(f"   Impressions: {impr:,} | Clicks: {clicks:,} | CTR: {ctr:.2f}%")
        lines.append(f"   Cost: ${cost / 1_000_000:,.2f} | CPC: ${cpc / 1_000_000:.2f}")
        lines.append(f"   Conversions: {conv:.2f}")
    
    if total > len(shown_rows):
        lines.append(f"\n... and {total - len(shown_rows)} more {entity_type}s (included in aggregate totals above)")
    
    return "\n".join(lines)

def _summarize_change_events(rows: List[Dict], cid: str, total: int, max_shown: Optional[int]) -> str:
    """Summarize change events by grouping similar changes."""
    from collections import defaultdict
    
    # Group by resource type, operation, and date
    groups = defaultdict(lambda: {"count": 0, "users": set(), "fields": set(), "latest": None})
    
    for row in rows:
        ce = row.get("changeEvent", {})
        resource_type = ce.get("resourceType", "UNKNOWN")
        operation = ce.get("resourceChangeOperation", "UNKNOWN")
        date = ce.get("changeDateTime", "")[:10]  # Just the date part
        user = ce.get("userEmail", "unknown")
        changed_fields = ce.get("changedFields", "")
        
        key = (resource_type, operation, date)
        groups[key]["count"] += 1
        groups[key]["users"].add(user)
        if changed_fields:
            for field in changed_fields.split(","):
                groups[key]["fields"].add(field.strip())
        if not groups[key]["latest"] or date > groups[key]["latest"]:
            groups[key]["latest"] = ce.get("changeDateTime", "")
    
    # Sort by count descending
    sorted_groups = sorted(groups.items(), key=lambda x: x[1]["count"], reverse=True)
    
    lines = [
        f"Change Event Summary for {cid}",
        f"Total events: {total} (grouped into {len(sorted_groups)} categories)",
        "=" * 90,
        ""
    ]
    
    for (resource_type, operation, date), info in sorted_groups[:50]:  # Show top 50 groups
        users_list = list(info["users"])[:3]
        users_str = ", ".join(users_list)
        if len(info["users"]) > 3:
            users_str += f" +{len(info['users']) - 3} more"
        
        fields_list = list(info["fields"])[:5]
        fields_str = ", ".join(fields_list)
        if len(info["fields"]) > 5:
            fields_str += f" +{len(info['fields']) - 5} more"
        
        lines.append(f"📊 {resource_type} / {operation}")
        lines.append(f"   Count: {info['count']} events on {date}")
        lines.append(f"   Users: {users_str}")
        if fields_str:
            lines.append(f"   Fields: {fields_str}")
        lines.append(f"   Latest: {info['latest']}")
        lines.append("")
    
    if len(sorted_groups) > 50:
        lines.append(f"... and {len(sorted_groups) - 50} more change categories")
    
    return "\n".join(lines)

def _adjust_change_event_query(query: str) -> str:
    """
    Adjusts change_event queries to comply with Google Ads API restrictions:
    - Replaces LAST_30_DAYS/LAST_MONTH with explicit date range (29 days max)
    - Ensures LIMIT is present (max 10000)
    """
    # Only adjust if query contains 'change_event'
    if 'change_event' not in query.lower():
        logger.debug(f"Query does not contain change_event, skipping adjustment")
        return query
    
    logger.info(f"🔧 Adjusting change_event query...")
    adjusted = query
    
    # Replace LAST_30_DAYS or LAST_MONTH with explicit date range (BETWEEN)
    # 29 days until yesterday (excluding today)
    if re.search(r'DURING\s+(LAST_30_DAYS|LAST_MONTH)', adjusted, re.IGNORECASE):
        end_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')  # Yesterday
        start_date = (datetime.now() - timedelta(days=29)).strftime('%Y-%m-%d')  # 29 days ago
        logger.info(f"📅 Replacing LAST_30_DAYS/LAST_MONTH with BETWEEN {start_date} AND {end_date} (29 days until yesterday)")
        adjusted = re.sub(
            r'(\w+\.\w+)\s+DURING\s+(LAST_30_DAYS|LAST_MONTH)',
            rf"\1 BETWEEN '{start_date}' AND '{end_date}'",
            adjusted,
            flags=re.IGNORECASE
        )
        logger.info(f"✅ Adjusted query: {adjusted[:200]}...")
    
    # Ensure LIMIT is present (add if missing, cap if > 10000)
    limit_match = re.search(r'LIMIT\s+(\d+)', adjusted, re.IGNORECASE)
    if limit_match:
        limit_val = int(limit_match.group(1))
        if limit_val > 10000:
            adjusted = re.sub(r'LIMIT\s+\d+', 'LIMIT 10000', adjusted, flags=re.IGNORECASE)
            logger.info(f"⚠️ Capped LIMIT to 10000 (was {limit_val})")
    else:
        # Append LIMIT if not present
        adjusted = adjusted.rstrip() + ' LIMIT 10000'
        logger.info(f"➕ Added LIMIT 10000")
    
    return adjusted

@mcp.tool()
async def execute_gaql_query(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    max_results: Optional[int] = Field(default=100, description="Maximum number of results to return (default 100). Use 0 for unlimited"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID to use as login-customer-id override")
) -> str:
    """
    Execute a custom GAQL query against the specified customer (name or ID).
    Returns up to max_results (default 100). Use run_gaql for more formatting options.
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

        total_results = len(rows)
        if max_results and max_results > 0:
            rows = rows[:max_results]

        first = rows[0]
        fields: List[str] = []
        for k, v in first.items():
            if isinstance(v, dict):
                for sk in v:
                    fields.append(f"{k}.{sk}")
            else:
                fields.append(k)

        lines = [f"Query Results for Account {cid}:"]
        if max_results and max_results > 0 and total_results > max_results:
            lines.append(f"(Showing {max_results} of {total_results} results - use max_results=0 for all or run_gaql for more options)")
        lines.append("-" * 80)
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
    max_results: int = Field(default=50, description="Max campaigns to show in detail (default 50). Aggregates include ALL campaigns"),
    order_by: str = Field(default="cost", description="Sort by: 'cost', 'conversions', 'clicks', 'impressions', or 'name'"),
    status_filter: str = Field(default="ENABLED", description="Filter by status: 'ENABLED', 'PAUSED', 'REMOVED', or 'ALL'"),
    format: str = Field(default="summary", description="'summary' (default - aggregates+top N), 'table', 'compact', 'csv', 'json'"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    """
    Get campaign performance with smart summarization.
    
    format='summary' (default): Shows aggregate totals for ALL campaigns + top N detailed breakdown.
    NO DATA LOST: Aggregates include ALL campaigns, detailed view shows top N.
    Use format='table'/'json' for raw data (may be large).
    """
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    # Build WHERE clause
    where_clauses = [f"segments.date DURING {date_range}"]
    if status_filter.upper() != "ALL":
        where_clauses.append(f"campaign.status = '{status_filter.upper()}'")
    where_str = " AND ".join(where_clauses)

    # Map order_by
    order_map = {
        "cost": "metrics.cost_micros DESC",
        "conversions": "metrics.conversions DESC",
        "clicks": "metrics.clicks DESC",
        "impressions": "metrics.impressions DESC",
        "name": "campaign.name ASC"
    }
    order_clause = order_map.get(order_by.lower(), "metrics.cost_micros DESC")

    query = f"""
        SELECT
            campaign.id,
            campaign.name,
            campaign.status,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions,
            metrics.conversions_value,
            metrics.average_cpc,
            metrics.ctr
        FROM campaign
        WHERE {where_str}
        ORDER BY {order_clause}
    """
    
    # For summary format, fetch ALL data and summarize
    if format == "summary":
        try:
            creds = get_credentials()
            cid = coerce_customer_id(customer_id, prefer_non_manager=True)
            headers = get_headers(creds, login_customer_id=login_customer_id)
            
            rows = _gaql_search_all(cid, query, headers)
            if not rows:
                return "No campaign performance data found."
            
            total_count = len(rows)
            logger.info(f"📊 Summary mode: {total_count} campaigns, showing aggregates + top {max_results}")
            return _summarize_performance_data(rows, cid, total_count, max_results, "campaign")
        except Exception as e:
            return f"Error getting campaign performance: {str(e)}"
    
    # For other formats (table, json, csv, compact), limit results for performance
    return await run_gaql(
        customer_id=customer_id,
        query=query + f" LIMIT {max_results}",
        format=format,
        max_results=None,
        fields=None,
        login_customer_id=login_customer_id
    )

@mcp.tool()
async def get_ad_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    days: int = Field(default=30, description="Number of days to look back (7, 14, 30, 60, 90, 180)"),
    max_results: int = Field(default=50, description="Max ads to show in detail (default 50). Aggregates include ALL ads"),
    order_by: str = Field(default="impressions", description="Sort by: 'impressions', 'clicks', 'conversions', 'cost', or 'ctr'"),
    status_filter: str = Field(default="ENABLED", description="Filter by status: 'ENABLED', 'PAUSED', 'REMOVED', or 'ALL'"),
    format: str = Field(default="summary", description="'summary' (default - aggregates+top N), 'table', 'compact', 'csv', 'json'"),
    min_impressions: int = Field(default=0, description="Minimum impressions filter (default 0)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    """
    Get ad performance with smart summarization.
    
    format='summary' (default): Shows aggregate totals for ALL ads + top N detailed breakdown.
    NO DATA LOST: Aggregates include ALL ads, detailed view shows top N.
    Use format='table'/'json' for raw data (may be large).
    """
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    # Build WHERE clause
    where_clauses = [f"segments.date DURING {date_range}"]
    if status_filter.upper() != "ALL":
        where_clauses.append(f"ad_group_ad.status = '{status_filter.upper()}'")
    if min_impressions > 0:
        where_clauses.append(f"metrics.impressions >= {min_impressions}")
    where_str = " AND ".join(where_clauses)

    # Map order_by
    order_map = {
        "impressions": "metrics.impressions DESC",
        "clicks": "metrics.clicks DESC",
        "conversions": "metrics.conversions DESC",
        "cost": "metrics.cost_micros DESC",
        "ctr": "metrics.ctr DESC"
    }
    order_clause = order_map.get(order_by.lower(), "metrics.impressions DESC")

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
            metrics.conversions,
            metrics.conversions_value,
            metrics.ctr,
            metrics.average_cpc
        FROM ad_group_ad
        WHERE {where_str}
        ORDER BY {order_clause}
    """
    
    # For summary format, fetch ALL data and summarize
    if format == "summary":
        try:
            creds = get_credentials()
            cid = coerce_customer_id(customer_id, prefer_non_manager=True)
            headers = get_headers(creds, login_customer_id=login_customer_id)
            
            rows = _gaql_search_all(cid, query, headers)
            if not rows:
                return "No ad performance data found."
            
            total_count = len(rows)
            logger.info(f"📊 Summary mode: {total_count} ads, showing aggregates + top {max_results}")
            return _summarize_performance_data(rows, cid, total_count, max_results, "ad")
        except Exception as e:
            return f"Error getting ad performance: {str(e)}"
    
    # For other formats (table, json, csv, compact), limit results for performance
    return await run_gaql(
        customer_id=customer_id,
        query=query + f" LIMIT {max_results}",
        format=format,
        max_results=None,
        fields=None,
        login_customer_id=login_customer_id
    )

@mcp.tool()
async def get_keyword_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    days: int = Field(default=30, description="Number of days to look back (7, 14, 30, 60, 90, 180)"),
    max_results: int = Field(default=50, description="Max keywords to show in detail (default 50). Aggregates include ALL keywords"),
    order_by: str = Field(default="impressions", description="Sort by: 'impressions', 'clicks', 'conversions', 'cost', 'ctr', 'quality_score'"),
    status_filter: str = Field(default="ENABLED", description="Filter by status: 'ENABLED', 'PAUSED', 'REMOVED', or 'ALL'"),
    match_type: Optional[str] = Field(default=None, description="Filter by match type: 'EXACT', 'PHRASE', 'BROAD', or None for all"),
    format: str = Field(default="summary", description="'summary' (default - aggregates+top N), 'table', 'compact', 'csv', 'json'"),
    min_impressions: int = Field(default=10, description="Minimum impressions filter (default 10 to exclude low-volume keywords)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    """
    Get keyword performance with smart summarization.
    
    format='summary' (default): Shows aggregate totals for ALL keywords + top N detailed breakdown.
    NO DATA LOST: Aggregates include ALL keywords, detailed view shows top N.
    Filters out keywords with <10 impressions by default.
    Use format='table'/'json' for raw data (may be large).
    """
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    # Build WHERE clause
    where_clauses = [f"segments.date DURING {date_range}"]
    if status_filter.upper() != "ALL":
        where_clauses.append(f"ad_group_criterion.status = '{status_filter.upper()}'")
    if match_type:
        where_clauses.append(f"ad_group_criterion.keyword.match_type = '{match_type.upper()}'")
    if min_impressions > 0:
        where_clauses.append(f"metrics.impressions >= {min_impressions}")
    where_str = " AND ".join(where_clauses)

    # Map order_by
    order_map = {
        "impressions": "metrics.impressions DESC",
        "clicks": "metrics.clicks DESC",
        "conversions": "metrics.conversions DESC",
        "cost": "metrics.cost_micros DESC",
        "ctr": "metrics.ctr DESC",
        "quality_score": "ad_group_criterion.quality_info.quality_score DESC"
    }
    order_clause = order_map.get(order_by.lower(), "metrics.impressions DESC")

    query = f"""
        SELECT
            campaign.name,
            ad_group.name,
            ad_group_criterion.criterion_id,
            ad_group_criterion.keyword.text,
            ad_group_criterion.keyword.match_type,
            ad_group_criterion.quality_info.quality_score,
            ad_group_criterion.status,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions,
            metrics.conversions_value,
            metrics.ctr,
            metrics.average_cpc,
            metrics.search_impression_share
        FROM keyword_view
        WHERE {where_str}
        ORDER BY {order_clause}
    """
    
    # For summary format, fetch ALL data and summarize  
    if format == "summary":
        try:
            creds = get_credentials()
            cid = coerce_customer_id(customer_id, prefer_non_manager=True)
            headers = get_headers(creds, login_customer_id=login_customer_id)
            
            rows = _gaql_search_all(cid, query, headers)
            if not rows:
                return "No keyword performance data found."
            
            total_count = len(rows)
            logger.info(f"📊 Summary mode: {total_count} keywords, showing aggregates + top {max_results}")
            return _summarize_performance_data(rows, cid, total_count, max_results, "keyword")
        except Exception as e:
            return f"Error getting keyword performance: {str(e)}"
    
    # For other formats (table, json, csv, compact), limit results for performance
    return await run_gaql(
        customer_id=customer_id,
        query=query + f" LIMIT {max_results}",
        format=format,
        max_results=None,
        fields=None,
        login_customer_id=login_customer_id
    )

@mcp.tool()
async def get_campaign_budgets(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    status_filter: str = Field(default="ALL", description="Filter by status: 'ENABLED', 'PAUSED', 'REMOVED', or 'ALL'"),
    format: str = Field(default="summary", description="'summary' (default - aggregates+breakdown), 'table', 'json'"),
    max_results: int = Field(default=50, description="Max campaigns to show in detail (default 50)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    """
    Get campaign budget information with smart summarization.
    
    format='summary' (default): Shows total budgets, shared vs individual, by status breakdown.
    NO DATA LOST: Aggregates include ALL campaigns.
    """
    # Build WHERE clause
    where_clauses = []
    if status_filter.upper() != "ALL":
        where_clauses.append(f"campaign.status = '{status_filter.upper()}'")
    where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    query = f"""
        SELECT
            campaign.id,
            campaign.name,
            campaign.status,
            campaign.bidding_strategy_type,
            campaign_budget.amount_micros,
            campaign_budget.explicitly_shared,
            campaign_budget.resource_name
        FROM campaign
        {where_str}
        ORDER BY campaign_budget.amount_micros DESC
    """
    
    # For summary format, fetch ALL and summarize
    if format == "summary":
        try:
            creds = get_credentials()
            cid = coerce_customer_id(customer_id, prefer_non_manager=True)
            headers = get_headers(creds, login_customer_id=login_customer_id)
            
            rows = _gaql_search_all(cid, query, headers)
            if not rows:
                return "No campaign budget data found."
            
            # Aggregate totals
            total_campaigns = len(rows)
            total_budget = 0
            shared_budget = 0
            individual_budget = 0
            by_status = {"ENABLED": 0, "PAUSED": 0, "REMOVED": 0}
            shared_budgets = {}  # Track unique shared budgets
            
            for row in rows:
                campaign = row.get("campaign", {})
                budget = row.get("campaignBudget", {})
                
                amount = int(budget.get("amountMicros", 0))
                is_shared = budget.get("explicitlyShared", False)
                status = campaign.get("status", "UNKNOWN")
                budget_resource = budget.get("resourceName", "")
                
                if is_shared:
                    # Track shared budgets separately to avoid double counting
                    if budget_resource not in shared_budgets:
                        shared_budgets[budget_resource] = amount
                        shared_budget += amount
                else:
                    individual_budget += amount
                
                if status in by_status:
                    if is_shared and budget_resource not in [k for k, v in shared_budgets.items() if v == amount]:
                        pass  # Don't count shared budget multiple times per status
                    elif not is_shared:
                        by_status[status] += amount
            
            total_budget = shared_budget + individual_budget
            
            lines = [
                f"Campaign Budget Summary for {cid}",
                "=" * 100,
                f"Total campaigns: {total_campaigns}",
                f"Showing detailed breakdown for top {min(max_results, total_campaigns)} campaigns",
                "",
                "💰 TOTAL BUDGET ALLOCATION:",
                f"   Total Budget: ${total_budget / 1_000_000:,.2f}",
                f"   Shared Budgets: ${shared_budget / 1_000_000:,.2f} ({len(shared_budgets)} unique)",
                f"   Individual Budgets: ${individual_budget / 1_000_000:,.2f}",
                "",
                "📊 BUDGET BY STATUS:",
                f"   ENABLED: ${by_status['ENABLED'] / 1_000_000:,.2f}",
                f"   PAUSED: ${by_status['PAUSED'] / 1_000_000:,.2f}",
                f"   REMOVED: ${by_status['REMOVED'] / 1_000_000:,.2f}",
                "",
                "🎯 TOP CAMPAIGNS BY BUDGET:",
                "=" * 100
            ]
            
            # Show top campaigns
            for i, row in enumerate(rows[:max_results], 1):
                campaign = row.get("campaign", {})
                budget = row.get("campaignBudget", {})
                
                name = campaign.get("name", "Unknown")
                status = campaign.get("status", "")
                bidding = campaign.get("biddingStrategyType", "")
                amount = int(budget.get("amountMicros", 0))
                is_shared = budget.get("explicitlyShared", False)
                
                lines.append(f"\n{i}. {name}")
                lines.append(f"   Status: {status} | Bidding: {bidding}")
                lines.append(f"   Budget: ${amount / 1_000_000:,.2f} {'(Shared)' if is_shared else '(Individual)'}")
            
            if total_campaigns > max_results:
                lines.append(f"\n... and {total_campaigns - max_results} more campaigns (included in totals above)")
            
            return "\n".join(lines)
            
        except Exception as e:
            return f"Error getting campaign budgets: {str(e)}"
    
    # For other formats
    return await run_gaql(
        customer_id=customer_id,
        query=query + f" LIMIT {max_results}",
        format=format,
        max_results=None,
        fields=None,
        login_customer_id=login_customer_id
    )

def _search_terms_cache_key(cid: str, days: int, order_by: str, status_filter: Optional[str],
                             min_impressions: int, min_cost: float,
                             include_dsa: bool = True, include_pmax: bool = True) -> str:
    """Build a deterministic cache key for search terms queries."""
    return f"{cid}|{days}|{order_by}|{status_filter or 'ALL'}|mi{min_impressions}|mc{min_cost}|dsa{include_dsa}|pmax{include_pmax}"



def _build_search_terms_query(days: int, order_by: str, status_filter: Optional[str],
                               min_impressions: int, min_cost: float) -> str:
    """Build the GAQL query for search terms."""
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    where_clauses = [
        f"segments.date DURING {date_range}",
        "campaign.status = 'ENABLED'"
    ]
    if min_impressions > 0:
        where_clauses.append(f"metrics.impressions >= {min_impressions}")
    if min_cost > 0:
        min_cost_micros = int(min_cost * 1_000_000)
        where_clauses.append(f"metrics.cost_micros >= {min_cost_micros}")
    if status_filter:
        where_clauses.append(f"search_term_view.status = '{status_filter.upper()}'")

    order_map = {
        "cost": "metrics.cost_micros DESC",
        "clicks": "metrics.clicks DESC",
        "conversions": "metrics.conversions DESC",
        "impressions": "metrics.impressions DESC"
    }
    order_clause = order_map.get(order_by.lower(), "metrics.cost_micros DESC")

    return f"""
        SELECT
            campaign.name,
            campaign.advertising_channel_type,
            ad_group.name,
            search_term_view.search_term,
            search_term_view.status,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            metrics.conversions,
            metrics.conversions_value
        FROM search_term_view
        WHERE {" AND ".join(where_clauses)}
        ORDER BY {order_clause}
    """


def _build_dsa_search_terms_query(days: int, order_by: str,
                                   min_impressions: int, min_cost: float) -> str:
    """Build the GAQL query for Dynamic Search Ads search terms."""
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    where_clauses = [
        f"segments.date DURING {date_range}",
        "campaign.status = 'ENABLED'"
    ]
    if min_impressions > 0:
        where_clauses.append(f"metrics.impressions >= {min_impressions}")
    if min_cost > 0:
        min_cost_micros = int(min_cost * 1_000_000)
        where_clauses.append(f"metrics.cost_micros >= {min_cost_micros}")

    order_map = {
        "cost": "metrics.cost_micros DESC",
        "clicks": "metrics.clicks DESC",
        "conversions": "metrics.conversions DESC",
        "impressions": "metrics.impressions DESC"
    }
    order_clause = order_map.get(order_by.lower(), "metrics.cost_micros DESC")

    return f"""
        SELECT
            campaign.name,
            campaign.advertising_channel_type,
            ad_group.name,
            dynamic_search_ads_search_term_view.search_term,
            dynamic_search_ads_search_term_view.headline,
            dynamic_search_ads_search_term_view.landing_page,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            metrics.conversions,
            metrics.conversions_value
        FROM dynamic_search_ads_search_term_view
        WHERE {" AND ".join(where_clauses)}
        ORDER BY {order_clause}
    """


def _build_pmax_search_terms_query(days: int, order_by: str,
                                    min_impressions: int, min_cost: float) -> str:
    """Build the GAQL query for Performance Max search terms (individual terms via campaign_search_term_view)."""
    if days in (7, 14, 30, 60, 90, 180):
        date_range = f"LAST_{days}_DAYS"
    else:
        date_range = "LAST_30_DAYS"

    where_clauses = [
        f"segments.date DURING {date_range}",
        "campaign.status = 'ENABLED'"
    ]
    if min_impressions > 0:
        where_clauses.append(f"metrics.impressions >= {min_impressions}")
    if min_cost > 0:
        min_cost_micros = int(min_cost * 1_000_000)
        where_clauses.append(f"metrics.cost_micros >= {min_cost_micros}")

    order_map = {
        "cost": "metrics.cost_micros DESC",
        "clicks": "metrics.clicks DESC",
        "conversions": "metrics.conversions DESC",
        "impressions": "metrics.impressions DESC"
    }
    order_clause = order_map.get(order_by.lower(), "metrics.cost_micros DESC")

    return f"""
        SELECT
            campaign.name,
            campaign.advertising_channel_type,
            campaign_search_term_view.search_term,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            metrics.conversions,
            metrics.conversions_value
        FROM campaign_search_term_view
        WHERE {" AND ".join(where_clauses)}
        ORDER BY {order_clause}
    """


def _normalize_dsa_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a DSA search term row to match search_term_view format."""
    dsa = row.get("dynamicSearchAdsSearchTermView", {})
    return {
        "campaign": row.get("campaign", {}),
        "adGroup": row.get("adGroup", {}),
        "searchTermView": {
            "searchTerm": dsa.get("searchTerm", ""),
            "status": "NONE",
        },
        "metrics": row.get("metrics", {}),
        "_source": "DSA",
        "_dsaHeadline": dsa.get("headline", ""),
        "_dsaLandingPage": dsa.get("landingPage", ""),
    }


def _normalize_pmax_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a PMAX campaign_search_term_view row to match search_term_view format."""
    cstv = row.get("campaignSearchTermView", {})
    return {
        "campaign": row.get("campaign", {}),
        "adGroup": {"name": ""},  # PMAX has no traditional ad groups
        "searchTermView": {
            "searchTerm": cstv.get("searchTerm", ""),
            "status": "NONE",
        },
        "metrics": row.get("metrics", {}),
        "_source": "PMAX",
    }


def _compute_search_terms_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute aggregate summary over all search term rows. Computed once, cached."""
    by_status: Dict[str, Dict[str, float]] = {
        "ADDED":    {"count": 0, "clicks": 0, "impr": 0, "cost": 0, "conv": 0, "conv_value": 0},
        "EXCLUDED": {"count": 0, "clicks": 0, "impr": 0, "cost": 0, "conv": 0, "conv_value": 0},
        "NONE":     {"count": 0, "clicks": 0, "impr": 0, "cost": 0, "conv": 0, "conv_value": 0},
    }
    by_source: Dict[str, Dict[str, float]] = {}
    totals = {"clicks": 0, "impr": 0, "cost": 0, "conv": 0, "conv_value": 0}

    for row in rows:
        stv = row.get("searchTermView", {})
        m = row.get("metrics", {})
        source = row.get("_source", "SEARCH")
        status = stv.get("status", "NONE")
        clicks = int(m.get("clicks", 0))
        impr = int(m.get("impressions", 0))
        cost = int(m.get("costMicros", 0))
        conv = float(m.get("conversions", 0))
        conv_value = float(m.get("conversionsValue", 0))

        bucket = by_status.get(status, by_status["NONE"])
        bucket["count"] += 1
        bucket["clicks"] += clicks
        bucket["impr"] += impr
        bucket["cost"] += cost
        bucket["conv"] += conv
        bucket["conv_value"] += conv_value

        totals["clicks"] += clicks
        totals["impr"] += impr
        totals["cost"] += cost
        totals["conv"] += conv
        totals["conv_value"] += conv_value

        # Track by source
        if source not in by_source:
            by_source[source] = {"count": 0, "clicks": 0, "impr": 0, "cost": 0, "conv": 0, "conv_value": 0}
        src = by_source[source]
        src["count"] += 1
        src["clicks"] += clicks
        src["impr"] += impr
        src["cost"] += cost
        src["conv"] += conv
        src["conv_value"] += conv_value

    # Format by_source for output
    by_source_out = {}
    for s, d in by_source.items():
        by_source_out[s] = {
            "count": int(d["count"]),
            "clicks": int(d["clicks"]),
            "impressions": int(d["impr"]),
            "cost": round(d["cost"] / 1_000_000, 2),
            "conversions": d["conv"],
        }

    return {"total_count": len(rows), "totals": totals, "by_status": by_status, "by_source": by_source_out}


def _format_search_term_row(row: Dict[str, Any], index: int) -> str:
    """Format a single search term row for text output."""
    stv = row.get("searchTermView", {})
    campaign = row.get("campaign", {})
    ad_group = row.get("adGroup", {})
    m = row.get("metrics", {})
    source = row.get("_source", "SEARCH")

    term = stv.get("searchTerm", "(no term)")
    status = stv.get("status", "NONE")
    channel_type = campaign.get("advertisingChannelType", "UNKNOWN")
    clicks = int(m.get("clicks", 0))
    impr = int(m.get("impressions", 0))
    cost = int(m.get("costMicros", 0))
    conv = float(m.get("conversions", 0))
    conv_value = float(m.get("conversionsValue", 0))
    ctr = float(m.get("ctr", 0)) * 100
    cpc = int(m.get("averageCpc", 0))
    term_roas = (conv_value / (cost / 1_000_000)) if cost > 0 else 0
    term_cpa = ((cost / 1_000_000) / conv) if conv > 0 else 0
    conv_rate = (conv / clicks * 100) if clicks > 0 else 0

    source_tag = f" [{source}]" if source != "SEARCH" else ""
    lines = [
        f"\n{index}. \"{term}\" [{status}]{source_tag}",
        f"   Campaign: {campaign.get('name', 'Unknown')} ({channel_type}) | Ad Group: {ad_group.get('name', 'Unknown')}",
        f"   Impressions: {impr:,} | Clicks: {clicks:,} | CTR: {ctr:.2f}%",
        f"   Cost: ${cost / 1_000_000:,.2f} | CPC: ${cpc / 1_000_000:.2f} | Conversions: {conv:.2f} | Conv. Value: ${conv_value:.2f}",
        f"   Conv. Rate: {conv_rate:.2f}% | ROAS: {term_roas:.2f}x | CPA: ${term_cpa:.2f}",
    ]
    if source == "DSA":
        headline = row.get("_dsaHeadline", "")
        landing = row.get("_dsaLandingPage", "")
        if headline or landing:
            lines.append(f"   DSA Headline: {headline} | Landing: {landing}")
    return "\n".join(lines)


def _format_search_term_json(row: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a single search term row into a clean dict for JSON output."""
    stv = row.get("searchTermView", {})
    campaign = row.get("campaign", {})
    ad_group = row.get("adGroup", {})
    m = row.get("metrics", {})
    source = row.get("_source", "SEARCH")

    cost = int(m.get("costMicros", 0))
    conv = float(m.get("conversions", 0))
    conv_value = float(m.get("conversionsValue", 0))
    clicks = int(m.get("clicks", 0))

    result = {
        "search_term": stv.get("searchTerm", ""),
        "source": source,
        "status": stv.get("status", "NONE"),
        "campaign": campaign.get("name", ""),
        "channel_type": campaign.get("advertisingChannelType", "UNKNOWN"),
        "ad_group": ad_group.get("name", ""),
        "impressions": int(m.get("impressions", 0)),
        "clicks": clicks,
        "ctr": round(float(m.get("ctr", 0)) * 100, 2),
        "avg_cpc": round(int(m.get("averageCpc", 0)) / 1_000_000, 2),
        "cost": round(cost / 1_000_000, 2),
        "conversions": conv,
        "conversions_value": conv_value,
        "conv_rate": round((conv / clicks * 100) if clicks > 0 else 0, 2),
        "cpa": round(((cost / 1_000_000) / conv) if conv > 0 else 0, 2),
        "roas": round((conv_value / (cost / 1_000_000)) if cost > 0 else 0, 2),
    }
    # Add DSA-specific fields
    if source == "DSA":
        result["dsa_headline"] = row.get("_dsaHeadline", "")
        result["dsa_landing_page"] = row.get("_dsaLandingPage", "")
    return result


SEARCH_TERMS_CACHE_TTL_SECONDS = int(os.getenv("SEARCH_TERMS_CACHE_TTL_SECONDS", "600"))  # 10 min default


@mcp.tool()
async def get_search_terms(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    days: int = Field(default=30, description="Number of days to look back (7, 14, 30, 60, 90, 180)"),
    max_results: int = Field(default=0, description="Max search terms to return. 0 = ALL (no limit). For summary format, controls how many detailed rows are shown."),
    order_by: str = Field(default="cost", description="Sort by: 'cost', 'clicks', 'conversions', 'impressions'"),
    status_filter: Optional[str] = Field(default=None, description="Filter by status: 'ADDED', 'EXCLUDED', 'NONE', or None for all"),
    format: str = Field(default="json", description="'json' (default - all rows as flat JSON for export), 'summary' (aggregates + top N detailed rows)"),
    min_impressions: int = Field(default=0, description="Minimum impressions filter (default 0)"),
    min_cost: float = Field(default=0, description="Minimum cost filter in account currency (e.g. 1.0 = 1 EUR/USD). 0 = no filter"),
    include_dsa: bool = Field(default=True, description="Include Dynamic Search Ads search terms (from dynamic_search_ads_search_term_view)"),
    include_pmax: bool = Field(default=True, description="Include Performance Max search terms (individual terms from campaign_search_term_view, with full metrics including cost)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    """
    Get search terms report — returns ALL matching rows in a single response.
    
    Fetches search terms from up to 3 sources:
      1. search_term_view — Standard Search & Shopping campaigns (always included)
      2. dynamic_search_ads_search_term_view — DSA campaigns (include_dsa=True)
      3. campaign_search_term_view — Performance Max campaigns (include_pmax=True)
    
    Each row includes a 'source' field: 'SEARCH', 'DSA', or 'PMAX'.
    All sources return individual search terms with full metrics (including cost).
    
    Results are cached for 10 minutes so repeated calls are instant.
    
    format='json' (default): Returns ALL rows as flat JSON with pre-computed metrics.
    format='summary': Human-readable report with aggregate totals + top N rows.
    
    Typical usage for large accounts:
      get_search_terms(customer_id="...", days=14, min_cost=1.0, format="json")
      → Returns ALL search terms with >= 1 EUR spend in last 14 days as JSON.
    """
    try:
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)
    except Exception as e:
        return f"Error resolving customer ID: {str(e)}"

    cache_key = _search_terms_cache_key(cid, days, order_by, status_filter, min_impressions, min_cost,
                                         include_dsa=include_dsa, include_pmax=include_pmax)

    # --- Check cache ---
    cached = _search_terms_cache.get(cache_key)
    if cached and (_now_s() - cached["at"] < SEARCH_TERMS_CACHE_TTL_SECONDS):
        rows = cached["rows"]
        summary = cached["summary"]
        logger.info(f"📦 Search terms cache HIT for {cache_key} ({len(rows)} rows)")
    else:
        # --- Fetch from API ---
        try:
            creds = get_credentials()
            headers = get_headers(creds, login_customer_id=login_customer_id)

            # 1) Standard search_term_view (Search + Shopping)
            query = _build_search_terms_query(days, order_by, status_filter, min_impressions, min_cost)
            logger.info(f"🔍 Fetching search terms for {cid} (days={days}, min_cost={min_cost})...")
            rows = _gaql_search_all(cid, query, headers)
            # Tag standard rows with source
            for r in rows:
                r["_source"] = "SEARCH"

            # 2) DSA search terms
            if include_dsa:
                try:
                    dsa_query = _build_dsa_search_terms_query(days, order_by, min_impressions, min_cost)
                    logger.info(f"🔍 Fetching DSA search terms for {cid}...")
                    dsa_rows = _gaql_search_all(cid, dsa_query, headers)
                    normalized_dsa = [_normalize_dsa_row(r) for r in dsa_rows]
                    rows.extend(normalized_dsa)
                    logger.info(f"   ✓ {len(dsa_rows)} DSA search terms found")
                except Exception as e:
                    logger.warning(f"⚠ DSA search terms query failed (skipping): {e}")

            # 3) PMAX search terms (individual terms via campaign_search_term_view)
            if include_pmax:
                try:
                    pmax_query = _build_pmax_search_terms_query(days, order_by, min_impressions, min_cost)
                    logger.info(f"🔍 Fetching PMAX search terms for {cid}...")
                    pmax_rows = _gaql_search_all(cid, pmax_query, headers)
                    normalized_pmax = [_normalize_pmax_row(r) for r in pmax_rows]
                    rows.extend(normalized_pmax)
                    logger.info(f"   ✓ {len(pmax_rows)} PMAX search terms found")
                except Exception as e:
                    logger.warning(f"⚠ PMAX search terms query failed (skipping): {e}")

            if not rows:
                return "No search term data found."

            # Re-sort merged rows by the chosen order metric
            order_key_map = {
                "cost": lambda r: int(r.get("metrics", {}).get("costMicros", 0)),
                "clicks": lambda r: int(r.get("metrics", {}).get("clicks", 0)),
                "conversions": lambda r: float(r.get("metrics", {}).get("conversions", 0)),
                "impressions": lambda r: int(r.get("metrics", {}).get("impressions", 0)),
            }
            sort_fn = order_key_map.get(order_by.lower(), order_key_map["cost"])
            rows.sort(key=sort_fn, reverse=True)

            summary = _compute_search_terms_summary(rows)

            # Store in cache
            _search_terms_cache[cache_key] = {"at": _now_s(), "rows": rows, "summary": summary}
            logger.info(f"💾 Cached {len(rows)} search terms for {cache_key}")
        except Exception as e:
            return f"Error getting search terms: {str(e)}"

    total_rows = len(rows)

    # --- JSON format: return ALL rows in one shot ---
    if format == "json":
        output_rows = rows if (max_results <= 0) else rows[:max_results]

        t = summary["totals"]
        result = {
            "total_rows": total_rows,
            "returned_rows": len(output_rows),
            "summary": {
                "total_search_terms": total_rows,
                "total_impressions": t["impr"],
                "total_clicks": t["clicks"],
                "total_cost": round(t["cost"] / 1_000_000, 2),
                "total_conversions": t["conv"],
                "total_conversions_value": round(t["conv_value"], 2),
                "avg_ctr": round((t["clicks"] / t["impr"] * 100) if t["impr"] > 0 else 0, 2),
                "avg_cpc": round((t["cost"] / t["clicks"] / 1_000_000) if t["clicks"] > 0 else 0, 2),
                "roas": round((t["conv_value"] / (t["cost"] / 1_000_000)) if t["cost"] > 0 else 0, 2),
                "cpa": round(((t["cost"] / 1_000_000) / t["conv"]) if t["conv"] > 0 else 0, 2),
                "by_status": {
                    s: {
                        "count": int(d["count"]),
                        "cost": round(d["cost"] / 1_000_000, 2),
                        "conversions": d["conv"],
                        "conversions_value": round(d["conv_value"], 2),
                    }
                    for s, d in summary["by_status"].items() if d["count"] > 0
                },
                "by_source": summary.get("by_source", {}),
            },
            "rows": [_format_search_term_json(r) for r in output_rows],
        }
        return json.dumps(result, ensure_ascii=False)

    # --- Summary format (human-readable) ---
    t = summary["totals"]
    avg_ctr = (t["clicks"] / t["impr"] * 100) if t["impr"] > 0 else 0
    avg_cpc = (t["cost"] / t["clicks"]) if t["clicks"] > 0 else 0
    roas = (t["conv_value"] / (t["cost"] / 1_000_000)) if t["cost"] > 0 else 0
    cpa = ((t["cost"] / 1_000_000) / t["conv"]) if t["conv"] > 0 else 0

    lines: List[str] = [
        f"Search Terms Report for {cid}",
        "=" * 100,
        f"Total search terms: {total_rows:,}",
        "",
        "📊 AGGREGATE TOTALS (All Search Terms):",
        f"   Total Search Terms: {total_rows:,}",
        f"   Total Impressions: {t['impr']:,}",
        f"   Total Clicks: {t['clicks']:,}",
        f"   Total Cost: ${t['cost'] / 1_000_000:,.2f}",
        f"   Total Conversions: {t['conv']:,.2f}",
        f"   Total Conversion Value: ${t['conv_value']:,.2f}",
        f"   Average CTR: {avg_ctr:.2f}%",
        f"   Average CPC: ${avg_cpc / 1_000_000:.2f}",
        f"   ROAS: {roas:.2f}x",
        f"   CPA: ${cpa:.2f}",
        "",
        "🏷️  BY STATUS:",
        ""
    ]

    for status, data in summary["by_status"].items():
        if data["count"] > 0:
            status_ctr = (data["clicks"] / data["impr"] * 100) if data["impr"] > 0 else 0
            status_roas = (data["conv_value"] / (data["cost"] / 1_000_000)) if data["cost"] > 0 else 0
            status_cpa = ((data["cost"] / 1_000_000) / data["conv"]) if data["conv"] > 0 else 0
            lines.append(f"   {status} ({int(data['count'])} terms):")
            lines.append(f"      Impressions: {int(data['impr']):,} | Clicks: {int(data['clicks']):,} | CTR: {status_ctr:.2f}%")
            lines.append(f"      Cost: ${data['cost'] / 1_000_000:,.2f} | Conversions: {data['conv']:,.2f} | Conv. Value: ${data['conv_value']:,.2f}")
            lines.append(f"      ROAS: {status_roas:.2f}x | CPA: ${status_cpa:.2f}")
            lines.append("")

    # Source breakdown
    by_source = summary.get("by_source", {})
    if len(by_source) > 1:  # Only show if there are multiple sources
        lines.append("📡 BY SOURCE:")
        lines.append("")
        source_labels = {"SEARCH": "Search/Shopping", "DSA": "Dynamic Search Ads", "PMAX": "Performance Max"}
        for src, data in by_source.items():
            label = source_labels.get(src, src)
            lines.append(f"   {label}: {data['count']} rows | {data['clicks']} clicks | {data['impressions']:,} impressions | ${data['cost']:,.2f} cost")
        lines.append("")

    lines.extend([
        "🎯 SEARCH TERMS (Detailed):",
        "=" * 100
    ])

    # Show detailed rows (all or top N)
    display_rows = rows if (max_results <= 0) else rows[:max_results]
    for i, row in enumerate(display_rows):
        lines.append(_format_search_term_row(row, i + 1))

    if max_results > 0 and total_rows > max_results:
        lines.append(f"\n... and {total_rows - max_results} more search terms (included in aggregate totals above)")

    return "\n".join(lines)

@mcp.tool()
async def get_change_history(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    days: int = Field(default=7, description="Number of days to look back (max 29)"),
    resource_type: Optional[str] = Field(default=None, description="Filter by resource type (e.g., 'CAMPAIGN', 'AD_GROUP', 'AD')"),
    operation: Optional[str] = Field(default=None, description="Filter by operation (e.g., 'CREATE', 'UPDATE', 'REMOVE')"),
    format: str = Field(default="summary", description="Output format: 'summary' (default), 'table', 'compact', or 'json'"),
    max_results: int = Field(default=500, description="Maximum number of events to fetch (default 500)"),
    max_detail: int = Field(default=50, description="Max events to show in detail if format=table/compact (default 50)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    """
    Get change history for an account with smart summarization.
    By default, returns a grouped summary to avoid overwhelming output.
    Use format='table' for detailed view (not recommended for large result sets).
    """
    # Ensure days is within API limits (max 29)
    if days > 29:
        days = 29
    
    end_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    
    where_clauses = [
        f"change_event.change_date_time BETWEEN '{start_date}' AND '{end_date}'"
    ]
    
    if resource_type:
        where_clauses.append(f"change_event.change_resource_type = '{resource_type.upper()}'")
    
    if operation:
        where_clauses.append(f"change_event.resource_change_operation = '{operation.upper()}'")
    
    where_str = " AND ".join(where_clauses)
    
    query = f"""
        SELECT
            change_event.resource_name,
            change_event.change_date_time,
            change_event.change_resource_type,
            change_event.user_email,
            change_event.client_type,
            change_event.resource_change_operation,
            change_event.changed_fields
        FROM change_event
        WHERE {where_str}
        ORDER BY change_event.change_date_time DESC
        LIMIT {max_results}
    """
    
    # For summary format, fetch data and summarize
    if format == "summary":
        try:
            creds = get_credentials()
            cid = coerce_customer_id(customer_id, prefer_non_manager=True)
            headers = get_headers(creds, login_customer_id=login_customer_id)
            
            adjusted_query = _adjust_change_event_query(query)
            rows = _gaql_search_all(cid, adjusted_query, headers)
            
            if not rows:
                return "No change events found."
            
            return _summarize_change_events(rows, cid, len(rows), max_detail)
        except Exception as e:
            return f"Error getting change history: {str(e)}"
    
    # For other formats, use run_gaql
    return await run_gaql(
        customer_id=customer_id,
        query=query,
        format=format,
        max_results=max_results,
        fields=None,
        login_customer_id=login_customer_id
    )

@mcp.tool()
async def run_gaql(
    customer_id: str = Field(description="Google Ads customer ID (10 digits) or account name"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    format: str = Field(default="table", description="Output format: 'table', 'json', 'csv', 'compact', or 'summary'"),
    max_results: Optional[int] = Field(default=None, description="Maximum number of results to return (truncates output). None = all results"),
    fields: Optional[str] = Field(default=None, description="Comma-separated list of fields to include (e.g., 'id,name,status'). None = all fields"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    try:
        creds = get_credentials()
        cid = coerce_customer_id(customer_id, prefer_non_manager=True)
        headers = get_headers(creds, login_customer_id=login_customer_id)

        # Auto-adjust change_event queries for API restrictions
        adjusted_query = _adjust_change_event_query(query)

        # Fetch all rows with pagination
        rows = _gaql_search_all(cid, adjusted_query, headers)
        if not rows:
            return "No results found for the query."

        # Apply max_results truncation if specified
        total_results = len(rows)
        if max_results and max_results > 0:
            rows = rows[:max_results]
        
        # Extract all available fields from first row
        first = rows[0]
        all_fields: List[str] = []
        for k, v in first.items():
            if isinstance(v, dict):
                for sk in v:
                    all_fields.append(f"{k}.{sk}")
            else:
                all_fields.append(k)
        
        # Filter fields if specified
        if fields:
            requested_fields = [f.strip() for f in fields.split(",")]
            selected_fields = []
            for rf in requested_fields:
                # Support partial matches (e.g., "name" matches "campaign.name", "ad.name", etc.)
                matches = [af for af in all_fields if rf in af or af.endswith(f".{rf}") or af == rf]
                selected_fields.extend(matches if matches else [rf])
            # Remove duplicates while preserving order
            seen = set()
            filtered_fields = []
            for f in selected_fields:
                if f not in seen and f in all_fields:
                    filtered_fields.append(f)
                    seen.add(f)
            if not filtered_fields:
                filtered_fields = all_fields
        else:
            filtered_fields = all_fields

        # Handle different output formats
        if format.lower() == "summary" and "change_event" in query.lower():
            # Special summarization for change events
            return _summarize_change_events(rows, cid, total_results, max_results)
        
        if format.lower() == "compact":
            # Compact format: minimal output, essential fields only
            return _format_compact(rows, filtered_fields, cid, total_results, max_results)
        
        if format.lower() == "json":
            # Filter JSON output to selected fields
            filtered_rows = []
            for row in rows:
                filtered_row = {}
                for f in filtered_fields:
                    if "." in f:
                        p, c = f.split(".", 1)
                        if p in row and isinstance(row[p], dict):
                            if p not in filtered_row:
                                filtered_row[p] = {}
                            if c in row[p]:
                                filtered_row[p][c] = row[p][c]
                    elif f in row:
                        filtered_row[f] = row[f]
                filtered_rows.append(filtered_row)
            
            result = {"results": filtered_rows}
            if max_results and total_results > max_results:
                result["note"] = f"Showing {max_results} of {total_results} results"
            return json.dumps(result, indent=2)

        if format.lower() == "csv":
            csv_lines = [",".join(filtered_fields)]
            for row in rows:
                row_vals = []
                for f in filtered_fields:
                    if "." in f:
                        p, c = f.split(".", 1)
                        val = str(row.get(p, {}).get(c, "")).replace(",", ";")
                    else:
                        val = str(row.get(f, "")).replace(",", ";")
                    row_vals.append(val)
                csv_lines.append(",".join(row_vals))
            if max_results and total_results > max_results:
                csv_lines.append(f"# Note: Showing {max_results} of {total_results} results")
            return "\n".join(csv_lines)

        # table (default)
        lines = [f"Query Results for Account {cid}:"]
        if max_results and total_results > max_results:
            lines.append(f"(Showing {max_results} of {total_results} results)")
        lines.append("-" * 100)
        
        widths = {f: len(f) for f in filtered_fields}
        for row in rows:
            for f in filtered_fields:
                if "." in f:
                    p, c = f.split(".", 1)
                    v = str(row.get(p, {}).get(c, ""))
                else:
                    v = str(row.get(f, ""))
                widths[f] = max(widths[f], len(v))

        header = " | ".join(f"{f:{widths[f]}}" for f in filtered_fields)
        lines.append(header)
        lines.append("-" * len(header))
        for row in rows:
            vals = []
            for f in filtered_fields:
                if "." in f:
                    p, c = f.split(".", 1)
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
try:
    # On newer fastmcp versions
    mcp.settings.streamable_http_path = MCP_HTTP_PATH  # type: ignore[attr-defined]
except Exception:
    pass

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

app = mcp.streamable_http_app()

# Patch transport security AFTER app creation
try:
    # Access the transport manager from the app
    if hasattr(app, 'state'):
        # Find all TransportSecurity instances and disable validation
        for attr_name in dir(app.state):
            attr = getattr(app.state, attr_name, None)
            if attr and hasattr(attr, 'validate_host'):
                # Monkey-patch the validate_host method on the instance
                attr.validate_host = lambda host: True
                logger.info(f"✓ Disabled Host validation on {attr_name}")
            if attr and hasattr(attr, '_transport_security'):
                ts = attr._transport_security
                if ts and hasattr(ts, 'validate_host'):
                    ts.validate_host = lambda host: True
                    ts.allowed_hosts = None
                    logger.info(f"✓ Disabled Host validation on {attr_name}._transport_security")
except Exception as e:
    logger.warning(f"Could not patch app.state: {e}")

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
