"""
OAuth Configuration Management for Google Ads MCP

Centralizes OAuth-related configuration. Supports both OAuth 2.0 and OAuth 2.1
with automatic client capability detection.
"""

import os
from typing import List, Optional, Dict, Any

from auth.scopes import get_current_scopes


class OAuthConfig:
    """Centralized OAuth configuration for Google Ads MCP."""

    def __init__(self):
        self.base_uri = os.getenv("GOOGLE_ADS_MCP_BASE_URI", "http://localhost")
        self.port = int(os.getenv("PORT", "8000"))
        self.base_url = f"{self.base_uri}:{self.port}"

        self.external_url = os.getenv("GOOGLE_ADS_MCP_EXTERNAL_URL")

        # OAuth client configuration (shared with legacy env vars)
        self.client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID") or os.getenv("GOOGLE_ADS_CLIENT_ID")
        self.client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET") or os.getenv("GOOGLE_ADS_CLIENT_SECRET")

        # OAuth 2.1 mode
        self.oauth21_enabled = os.getenv("MCP_ENABLE_OAUTH21", "false").lower() in ("1", "true", "yes")
        self.pkce_required = self.oauth21_enabled
        self.supported_code_challenge_methods = ["S256"] if self.oauth21_enabled else ["S256", "plain"]

        self._transport_mode = "stdio"

        self.redirect_uri = self._get_redirect_uri()

    def _get_redirect_uri(self) -> str:
        explicit_uri = os.getenv("GOOGLE_OAUTH_REDIRECT_URI")
        if explicit_uri:
            return explicit_uri
        return f"{self.base_url}/oauth2callback"

    def get_redirect_uris(self) -> List[str]:
        uris = [self.redirect_uri]
        custom_uris = os.getenv("OAUTH_CUSTOM_REDIRECT_URIS")
        if custom_uris:
            uris.extend([uri.strip() for uri in custom_uris.split(",")])
        return list(dict.fromkeys(uris))

    def get_allowed_origins(self) -> List[str]:
        origins = [
            self.base_url,
            "vscode-webview://",
            "https://vscode.dev",
            "https://github.dev",
        ]
        custom_origins = os.getenv("OAUTH_ALLOWED_ORIGINS")
        if custom_origins:
            origins.extend([origin.strip() for origin in custom_origins.split(",")])
        return list(dict.fromkeys(origins))

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def get_oauth_base_url(self) -> str:
        if self.external_url:
            return self.external_url
        return self.base_url

    def is_oauth21_enabled(self) -> bool:
        return self.oauth21_enabled

    def set_transport_mode(self, mode: str) -> None:
        self._transport_mode = mode

    def get_transport_mode(self) -> str:
        return self._transport_mode

    def get_authorization_server_metadata(self, scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get OAuth authorization server metadata per RFC 8414."""
        oauth_base = self.get_oauth_base_url()
        metadata = {
            "issuer": oauth_base,
            "authorization_endpoint": f"{oauth_base}/oauth2/authorize",
            "token_endpoint": f"{oauth_base}/oauth2/token",
            "registration_endpoint": f"{oauth_base}/oauth2/register",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": self.supported_code_challenge_methods,
        }
        if scopes is not None:
            metadata["scopes_supported"] = scopes
        if self.oauth21_enabled:
            metadata["pkce_required"] = True
            metadata["require_exact_redirect_uri"] = True
        return metadata


# Global config singleton
_oauth_config = None


def get_oauth_config() -> OAuthConfig:
    global _oauth_config
    if _oauth_config is None:
        _oauth_config = OAuthConfig()
    return _oauth_config


def reload_oauth_config() -> OAuthConfig:
    global _oauth_config
    _oauth_config = OAuthConfig()
    return _oauth_config
