from typing import Any, Dict, List, Optional, Union
from pydantic import Field
import os
import json
import requests
from datetime import datetime, timedelta
import re

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import logging

# MCP
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('google_ads_server')

mcp = FastMCP(
    "google-ads-server",
    dependencies=[
        "google-auth-oauthlib",
        "google-auth",
        "requests",
        "python-dotenv"
    ]
)

# Constants and configuration
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v19"  # Google Ads API version

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    logger.info("Environment variables loaded from .env file")
except ImportError:
    logger.warning("python-dotenv not installed, skipping .env file loading")

# Get credentials from environment variables
GOOGLE_ADS_CREDENTIALS_PATH = os.environ.get("GOOGLE_ADS_CREDENTIALS_PATH")
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
GOOGLE_ADS_AUTH_TYPE = os.environ.get("GOOGLE_ADS_AUTH_TYPE", "oauth")  # oauth or service_account
DEFAULT_GOOGLE_ADS_CUSTOMER_ID = os.environ.get("DEFAULT_GOOGLE_ADS_CUSTOMER_ID")  # optional

def normalize_customer_id(value: Optional[str]) -> str:
    """
    Accepts '123-456-7890' or '1234567890' and returns digits-only (10 chars).
    Raises ValueError on missing/malformed.
    """
    if value is None or str(value).strip() == "":
        # allow fallback to default env if present
        if DEFAULT_GOOGLE_ADS_CUSTOMER_ID:
            value = DEFAULT_GOOGLE_ADS_CUSTOMER_ID
        else:
            raise ValueError("customer_id is required (e.g., '123-456-7890').")
    digits = re.sub(r"\D", "", str(value))
    if not re.fullmatch(r"\d{10}", digits):
        raise ValueError(f"Invalid customer_id: {value!r}. Expected 10 digits.")
    return digits

def normalize_login_customer_id(value: Optional[str]) -> Optional[str]:
    """
    Normalize optional MCC/login ID. Returns digits-only or None if not provided.
    """
    if not value:
        return None
    digits = re.sub(r"\D", "", str(value))
    if not re.fullmatch(r"\d{10}", digits):
        raise ValueError(f"Invalid login_customer_id: {value!r}. Expected 10 digits.")
    return digits

def get_credentials():
    """
    Get and refresh OAuth credentials or service account credentials based on the auth type.
    """
    if not GOOGLE_ADS_CREDENTIALS_PATH:
        raise ValueError("GOOGLE_ADS_CREDENTIALS_PATH environment variable not set")

    auth_type = GOOGLE_ADS_AUTH_TYPE.lower()
    logger.info(f"Using authentication type: {auth_type}")

    if auth_type == "service_account":
        try:
            return get_service_account_credentials()
        except Exception as e:
            logger.error(f"Error with service account authentication: {str(e)}")
            raise

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
    """Get and refresh OAuth user credentials."""
    creds = None
    client_config = None

    token_path = GOOGLE_ADS_CREDENTIALS_PATH
    if os.path.exists(token_path) and not os.path.basename(token_path).endswith('.json'):
        token_dir = os.path.dirname(token_path)
        token_path = os.path.join(token_dir, 'google_ads_token.json')

    if os.path.exists(token_path):
        try:
            logger.info(f"Loading OAuth credentials from {token_path}")
            with open(token_path, 'r') as f:
                creds_data = json.load(f)
                if "installed" in creds_data or "web" in creds_data:
                    client_config = creds_data
                    logger.info("Found OAuth client configuration")
                else:
                    logger.info("Found existing OAuth token")
                    creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in token file: {token_path}")
            creds = None
        except Exception as e:
            logger.warning(f"Error loading credentials: {str(e)}")
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and getattr(creds, "refresh_token", None):
            try:
                logger.info("Refreshing expired token")
                creds.refresh(Request())
                logger.info("Token successfully refreshed")
            except RefreshError as e:
                logger.warning(f"Error refreshing token: {str(e)}, will try to get new token")
                creds = None
            except Exception as e:
                logger.error(f"Unexpected error refreshing token: {str(e)}")
                raise

        if not creds:
            if not client_config:
                logger.info("Creating OAuth client config from environment variables")
                client_id = os.environ.get("GOOGLE_ADS_CLIENT_ID")
                client_secret = os.environ.get("GOOGLE_ADS_CLIENT_SECRET")

                if not client_id or not client_secret:
                    raise ValueError("GOOGLE_ADS_CLIENT_ID and GOOGLE_ADS_CLIENT_SECRET must be set if no client config file exists")

                client_config = {
                    "installed": {
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                    }
                }

            logger.info("Starting OAuth authentication flow")
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            creds = flow.run_local_server(port=0)
            logger.info("OAuth flow completed successfully")

        try:
            logger.info(f"Saving credentials to {token_path}")
            os.makedirs(os.path.dirname(token_path), exist_ok=True)
            with open(token_path, 'w') as f:
                f.write(creds.to_json())
        except Exception as e:
            logger.warning(f"Could not save credentials: {str(e)}")

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
                    logger.info("Token successfully refreshed in get_headers")
                except RefreshError as e:
                    logger.error(f"Error refreshing token in get_headers: {str(e)}")
                    raise ValueError(f"Failed to refresh OAuth token: {str(e)}")
            else:
                raise ValueError("OAuth credentials are invalid and cannot be refreshed")
        token = creds.token

    headers = {
        'Authorization': f'Bearer {token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json'
    }

    # Prefer per-call override, else env
    login_id = normalize_login_customer_id(login_customer_id) or normalize_login_customer_id(GOOGLE_ADS_LOGIN_CUSTOMER_ID)
    if login_id:
        headers['login-customer-id'] = login_id

    return headers

# ----------------------------- TOOLS -----------------------------

@mcp.tool()
async def list_accounts() -> str:
    """
    Lists all accessible Google Ads accounts.
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return f"Error accessing accounts [{response.status_code}]: {response.text}"

        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accessible accounts found."

        lines = ["Accessible Google Ads Accounts:", "-" * 50]
        for resource_name in customers['resourceNames']:
            cid = resource_name.split('/')[-1]
            lines.append(f"Account ID: {normalize_customer_id(cid)}")
        return "\n".join(lines)

    except Exception as e:
        return f"Error listing accounts: {str(e)}"

@mcp.tool()
async def execute_gaql_query(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID to use as login-customer-id override")
) -> str:
    """
    Execute a custom GAQL query against the specified customer_id.
    """
    try:
        creds = get_credentials()
        formatted_customer_id = normalize_customer_id(customer_id)
        headers = get_headers(creds, login_customer_id=login_customer_id)

        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            return f"Error executing query [{response.status_code}]: {response.text}"

        results = response.json()
        if not results.get('results'):
            return "No results found for the query."

        # Build a simple table from the first row's structure
        fields = []
        first = results['results'][0]
        for k, v in first.items():
            if isinstance(v, dict):
                for sk in v:
                    fields.append(f"{k}.{sk}")
            else:
                fields.append(k)

        lines = [f"Query Results for Account {formatted_customer_id}:", "-" * 80]
        lines.append(" | ".join(fields))
        lines.append("-" * 80)

        for row in results['results']:
            row_vals = []
            for field in fields:
                if "." in field:
                    parent, child = field.split(".")
                    val = str(row.get(parent, {}).get(child, ""))
                else:
                    val = str(row.get(field, ""))
                row_vals.append(val)
            lines.append(" | ".join(row_vals))

        return "\n".join(lines)

    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_campaign_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 14, 30, 90, etc.)"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    # GAQL supports LAST_7_DAYS, LAST_14_DAYS, LAST_30_DAYS, LAST_90_DAYS, etc.
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
        LIMIT 50
    """
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def get_ad_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 14, 30, 90, etc.)"),
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
        LIMIT 50
    """
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def run_gaql(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    format: str = Field(default="table", description="Output format: 'table', 'json', or 'csv'"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    try:
        creds = get_credentials()
        cid = normalize_customer_id(customer_id)
        headers = get_headers(creds, login_customer_id=login_customer_id)

        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            return f"Error executing query [{response.status_code}]: {response.text}"

        results = response.json()
        if not results.get('results'):
            return "No results found for the query."

        if format.lower() == "json":
            return json.dumps(results, indent=2)

        # Build fields
        fields = []
        first = results['results'][0]
        for k, v in first.items():
            if isinstance(v, dict):
                for sk in v:
                    fields.append(f"{k}.{sk}")
            else:
                fields.append(k)

        if format.lower() == "csv":
            csv_lines = [",".join(fields)]
            for row in results['results']:
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

        # Default: table
        lines = [f"Query Results for Account {cid}:", "-" * 100]
        # widths
        widths = {f: len(f) for f in fields}
        for row in results['results']:
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
        for row in results['results']:
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
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
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
        LIMIT 50
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = normalize_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"
        response = requests.post(url, headers=headers, json={"query": query})

        if response.status_code != 200:
            return f"Error retrieving ad creatives [{response.status_code}]: {response.text}"

        results = response.json()
        if not results.get('results'):
            return "No ad creatives found for this customer ID."

        out = [f"Ad Creatives for Customer ID {cid}:", "=" * 80]
        for i, res in enumerate(results['results'], 1):
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
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
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
            logger.info("Credentials not valid, attempting refresh...")
            if getattr(creds, 'refresh_token', None):
                creds.refresh(Request())
                logger.info("Credentials refreshed successfully")
            else:
                raise ValueError("Invalid credentials and no refresh token available")

        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = normalize_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        response = requests.post(url, headers=headers, json={"query": query})
        if response.status_code != 200:
            return f"Error retrieving account currency [{response.status_code}]: {response.text}"

        results = response.json()
        if not results.get('results'):
            return "No account information found for this customer ID."

        customer = results['results'][0].get('customer', {})
        currency_code = customer.get('currencyCode', 'Not specified')
        return f"Account {cid} uses currency: {currency_code}"

    except Exception as e:
        logger.error(f"Error retrieving account currency: {str(e)}")
        return f"Error retrieving account currency: {str(e)}"

@mcp.resource("gaql://reference")
def gaql_reference() -> str:
    return """
    # Google Ads Query Language (GAQL) Reference
    (shortened for brevity)
    """

@mcp.prompt("google_ads_workflow")
def google_ads_workflow() -> str:
    return """
    1) list_accounts()
    2) get_account_currency(customer_id="...")
    3) get_campaign_performance / get_ad_performance / get_ad_creatives
    4) run_gaql(customer_id="...", query="...")
    """

@mcp.prompt("gaql_help")
def gaql_help() -> str:
    return """
    Examples:
    SELECT campaign.name, metrics.clicks FROM campaign WHERE segments.date DURING LAST_30_DAYS LIMIT 10
    """

@mcp.tool()
async def get_image_assets(  # <-- keep signature identical, add optional MCC override
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    limit: int = Field(default=50, description="Maximum number of image assets to return"),
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
        LIMIT {limit}
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = normalize_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        response = requests.post(url, headers=headers, json={"query": query})
        if response.status_code != 200:
            return f"Error retrieving image assets [{response.status_code}]: {response.text}"

        results = response.json()
        if not results.get('results'):
            return "No image assets found for this customer ID."

        out = [f"Image Assets for Customer ID {cid}:", "=" * 80]
        for i, res in enumerate(results['results'], 1):
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
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
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
        cid = normalize_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        resp = requests.post(url, headers=headers, json={"query": query})
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
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    asset_id: str = Field(default=None, description="Optional: specific asset ID to look up (leave empty to get all image assets)"),
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
        LIMIT 100
    """

    associations_query = f"""
        SELECT campaign.id, campaign.name, asset.id, asset.name, asset.type
        FROM campaign_asset
        WHERE {where_clause}
        LIMIT 500
    """

    ad_group_query = f"""
        SELECT ad_group.id, ad_group.name, asset.id, asset.name, asset.type
        FROM ad_group_asset
        WHERE {where_clause}
        LIMIT 500
    """

    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = normalize_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        assets_resp = requests.post(url, headers=headers, json={"query": assets_query})
        if assets_resp.status_code != 200:
            return f"Error retrieving assets [{assets_resp.status_code}]: {assets_resp.text}"
        assets_results = assets_resp.json()
        if not assets_results.get('results'):
            return f"No {asset_type} assets found for this customer ID."

        assoc_resp = requests.post(url, headers=headers, json={"query": associations_query})
        if assoc_resp.status_code != 200:
            return f"Error retrieving asset associations [{assoc_resp.status_code}]: {assoc_resp.text}"
        assoc_results = assoc_resp.json()

        out = [f"Asset Usage for Customer ID {cid}:", "=" * 80]
        asset_usage: Dict[str, Dict[str, Any]] = {}

        for r in assets_results.get('results', []):
            a = r.get('asset', {})
            aid = a.get('id')
            if aid:
                asset_usage[aid] = {
                    "name": a.get('name', 'Unnamed asset'),
                    "type": a.get('type', 'Unknown'),
                    "usage": []
                }

        for r in assoc_results.get('results', []):
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
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
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
        LIMIT 200
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id=login_customer_id)
        cid = normalize_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        resp = requests.post(url, headers=headers, json={"query": query})
        if resp.status_code != 200:
            return f"Error analyzing image assets [{resp.status_code}]: {resp.text}"

        results = resp.json()
        if not results.get('results'):
            return "No image asset performance data found for this customer ID and time period."

        assets_data: Dict[str, Dict[str, Any]] = {}
        for r in results.get('results', []):
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

        out = [f"Image Asset Performance Analysis for Customer ID {cid} ({date_range.replace('_', ' ').title()}):",
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

@mcp.tool()
async def list_resources(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    login_customer_id: Optional[str] = Field(default=None, description="Optional MCC ID override")
) -> str:
    query = """
        SELECT
            google_ads_field.name,
            google_ads_field.category,
            google_ads_field.data_type
        FROM google_ads_field
        WHERE google_ads_field.category = 'RESOURCE'
        ORDER BY google_ads_field.name
    """
    return await run_gaql(customer_id, query, "table", login_customer_id)

# --- HTTP runner for Render ---
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    path = os.getenv("MCP_HTTP_PATH", "/mcp")
    mcp.run(transport="http", port=port, path=path)
