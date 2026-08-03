"""
Google Ads OAuthProvider for FastMCP.

Full OAuth Authorization Server that:
1. Issues its own MCP tokens (auth codes, access tokens, refresh tokens)
2. Proxies authorization to Google for user consent
3. Stores Google credentials server-side, mapped to MCP tokens
4. Verifies MCP tokens on each /mcp request

Google tokens NEVER leave the server — the MCP client only sees MCP-issued tokens.

Refresh-token rotation strategy
-------------------------------
Refresh tokens are rotated on every use (OAuth 2.1 best practice), but with two
robustness features layered on top:

* Replay grace window (default 60 s). When a refresh token is rotated, the old
  token is moved into a replay cache that remembers the successor tokens. If
  the same old token is presented again within the grace window, the same
  successor tokens are returned. This makes refresh idempotent and survives
  network blips, concurrent retries, and lost responses.

* Reuse detection. When a refresh token is presented AFTER the grace window
  has expired AND we know it was rotated, that's treated as a possible token
  theft: the entire refresh-token family rooted at the original authorization
  code is revoked. The legitimate client is forced to re-authorize.

A per-family ``asyncio.Lock`` serializes concurrent refresh attempts so the
replay cache is observed consistently.
"""

import os
import asyncio
import threading
import secrets
import time
import logging
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

import aiohttp
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.routing import Route
from google.oauth2.credentials import Credentials as GoogleCredentials

from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from fastmcp.server.auth.auth import OAuthProvider, AccessToken, ClientRegistrationOptions

from auth.scopes import SCOPES as ADS_SCOPES
from auth.credential_store import get_credential_store, get_credential_storage_directory
from auth import mcp_oauth_state_store as _oauth_state_store
from auth.mcp_client_auth_compat import apply_mcp_client_auth_compat

logger = logging.getLogger(__name__)

apply_mcp_client_auth_compat()


class _OAuthTokenWithIdToken(OAuthToken):
    """Extends OAuthToken to carry the Google id_token through to the client."""
    id_token: str | None = None


DEFAULT_AUTH_CODE_EXPIRY = 5 * 60
_DEFAULT_ACCESS_TOKEN_TTL = 60 * 60
_DEFAULT_REFRESH_TOKEN_TTL = 30 * 24 * 60 * 60
_DEFAULT_REFRESH_GRACE_SECONDS = 60


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


class GoogleOAuthProvider(OAuthProvider):
    """
    OAuth Authorization Server that proxies to Google for user consent,
    then issues its own MCP tokens for the transport layer.
    """

    def __init__(self, *, base_url: str):
        self.google_client_id = (
            os.getenv("GOOGLE_OAUTH_CLIENT_ID")
            or os.getenv("GOOGLE_ADS_CLIENT_ID")
        )
        self.google_client_secret = (
            os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
            or os.getenv("GOOGLE_ADS_CLIENT_SECRET")
        )
        if not self.google_client_id or not self.google_client_secret:
            raise ValueError(
                "GOOGLE_OAUTH_CLIENT_ID (or GOOGLE_ADS_CLIENT_ID) and "
                "GOOGLE_OAUTH_CLIENT_SECRET (or GOOGLE_ADS_CLIENT_SECRET) are required"
            )

        self.google_callback_uri = f"{base_url.rstrip('/')}/oauth2callback"

        super().__init__(
            base_url=base_url,
            required_scopes=ADS_SCOPES,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=ADS_SCOPES,
                default_scopes=ADS_SCOPES,
            ),
        )

        self.access_token_ttl = max(60, _int_env("MCP_ACCESS_TOKEN_TTL_SECONDS", _DEFAULT_ACCESS_TOKEN_TTL))
        self.refresh_token_ttl = max(
            3600, _int_env("MCP_REFRESH_TOKEN_TTL_SECONDS", _DEFAULT_REFRESH_TOKEN_TTL)
        )
        self.refresh_grace_seconds = max(
            0, _int_env("MCP_REFRESH_TOKEN_GRACE_SECONDS", _DEFAULT_REFRESH_GRACE_SECONDS)
        )
        self.reuse_detection_enabled = _bool_env(
            "MCP_REFRESH_TOKEN_REUSE_DETECTION", True
        )
        self._oauth_persist = _bool_env("MCP_OAUTH_STATE_PERSIST", True)
        self._oauth_state_path = _oauth_state_store.mcp_oauth_state_path(
            get_credential_storage_directory()
        )
        self._oauth_state_lock = threading.Lock()

        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}

        self.pending_authorizations: dict[str, dict] = {}
        self.auth_code_to_email: dict[str, str] = {}
        self._auth_code_to_id_token: dict[str, str] = {}
        self._user_id_tokens: dict[str, str] = {}
        self.token_to_email: dict[str, str] = {}
        self._pending_tombstones: dict[str, float] = {}
        self._auth_code_tombstones: dict[str, float] = {}

        # Refresh-token rotation bookkeeping
        # refresh_token_str -> family_id
        self._refresh_lineage: dict[str, str] = {}
        # family_id -> {"refresh_tokens": [...], "access_tokens": [...]}
        self._lineage_index: dict[str, dict[str, list[str]]] = {}
        # old_refresh_token -> replay entry
        self._replay_cache: dict[str, dict] = {}

        # Lazy per-family locks; created on first use within an event loop.
        self._family_locks: dict[str, asyncio.Lock] = {}

        if self._oauth_persist:
            self._load_oauth_state_from_disk_sync()

        logger.info(
            "GoogleOAuthProvider initialized: base_url=%s, google_callback=%s, "
            "oauth_state_persist=%s, access_ttl=%ss, refresh_ttl=%ss, "
            "refresh_grace=%ss, reuse_detection=%s",
            base_url,
            self.google_callback_uri,
            self._oauth_persist,
            self.access_token_ttl,
            self.refresh_token_ttl,
            self.refresh_grace_seconds,
            self.reuse_detection_enabled,
        )

    # ------------------------------------------------------------------
    # Persistence helpers (file lock + merge-before-write)
    # ------------------------------------------------------------------

    def _unpack_deserialized(self, parts: tuple) -> None:
        (
            clients,
            access_tokens,
            refresh_tokens,
            token_to_email,
            refresh_lineage,
            lineage_index,
            replay_cache,
            pending_authorizations,
            auth_codes,
            auth_code_to_email,
            auth_code_to_id_token,
            user_id_tokens,
            pending_tombstones,
            auth_code_tombstones,
        ) = parts
        self.clients = clients
        self.access_tokens = access_tokens
        self.refresh_tokens = refresh_tokens
        self.token_to_email = token_to_email
        self._refresh_lineage = refresh_lineage
        self._lineage_index = lineage_index
        self._replay_cache = replay_cache
        self.pending_authorizations = pending_authorizations
        self.auth_codes = auth_codes
        self.auth_code_to_email = auth_code_to_email
        self._auth_code_to_id_token = auth_code_to_id_token
        self._user_id_tokens = user_id_tokens
        self._pending_tombstones = pending_tombstones
        self._auth_code_tombstones = auth_code_tombstones

    def _merge_disk_into_memory(self, parts: tuple) -> None:
        (
            clients,
            access_tokens,
            refresh_tokens,
            token_to_email,
            refresh_lineage,
            lineage_index,
            replay_cache,
            pending_authorizations,
            auth_codes,
            auth_code_to_email,
            auth_code_to_id_token,
            user_id_tokens,
            pending_tombstones,
            auth_code_tombstones,
        ) = parts
        self.clients = _oauth_state_store.merge_dict(clients, self.clients)
        self.access_tokens = _oauth_state_store.merge_dict(
            access_tokens, self.access_tokens
        )
        self.refresh_tokens = _oauth_state_store.merge_dict(
            refresh_tokens, self.refresh_tokens
        )
        self.token_to_email = _oauth_state_store.merge_dict(
            token_to_email, self.token_to_email
        )
        self._refresh_lineage = _oauth_state_store.merge_dict(
            refresh_lineage, self._refresh_lineage
        )
        self._lineage_index = _oauth_state_store.merge_dict(
            lineage_index, self._lineage_index
        )
        self._replay_cache = _oauth_state_store.merge_dict(
            replay_cache, self._replay_cache
        )
        self.pending_authorizations = _oauth_state_store.merge_dict(
            pending_authorizations, self.pending_authorizations
        )
        self.auth_codes = _oauth_state_store.merge_dict(auth_codes, self.auth_codes)
        self.auth_code_to_email = _oauth_state_store.merge_dict(
            auth_code_to_email, self.auth_code_to_email
        )
        self._auth_code_to_id_token = _oauth_state_store.merge_dict(
            auth_code_to_id_token, self._auth_code_to_id_token
        )
        self._user_id_tokens = _oauth_state_store.merge_dict(
            user_id_tokens, self._user_id_tokens
        )
        self._pending_tombstones = _oauth_state_store.merge_dict(
            pending_tombstones, self._pending_tombstones
        )
        self._auth_code_tombstones = _oauth_state_store.merge_dict(
            auth_code_tombstones, self._auth_code_tombstones
        )
        for state in self._pending_tombstones:
            self.pending_authorizations.pop(state, None)
        for code in self._auth_code_tombstones:
            self.auth_codes.pop(code, None)
            self.auth_code_to_email.pop(code, None)
            self._auth_code_to_id_token.pop(code, None)

    def _serialize_current_state(self) -> dict:
        return _oauth_state_store.serialize_state(
            self.clients,
            self.access_tokens,
            self.refresh_tokens,
            self.token_to_email,
            self._refresh_lineage,
            self._lineage_index,
            self._replay_cache,
            self.pending_authorizations,
            self.auth_codes,
            self.auth_code_to_email,
            self._auth_code_to_id_token,
            self._user_id_tokens,
            self._pending_tombstones,
            self._auth_code_tombstones,
        )

    def _prune_current_state(self) -> None:
        _oauth_state_store.prune_expired(
            self.access_tokens,
            self.refresh_tokens,
            self.token_to_email,
            self._refresh_lineage,
            self._lineage_index,
            self._replay_cache,
            self.pending_authorizations,
            self.auth_codes,
            self.auth_code_to_email,
            self._auth_code_to_id_token,
        )

    def _load_oauth_state_from_disk_sync(self) -> bool:
        """Load persisted MCP OAuth state at startup (under file lock)."""
        try:
            with _oauth_state_store.oauth_state_file_lock(self._oauth_state_path):
                raw = _oauth_state_store.read_mcp_oauth_state(self._oauth_state_path)
                if not raw:
                    return False
                self._unpack_deserialized(
                    _oauth_state_store.deserialize_state(raw)
                )
                self._prune_current_state()
                _oauth_state_store.write_mcp_oauth_state_atomic(
                    self._oauth_state_path,
                    self._serialize_current_state(),
                )
            logger.info(
                "Restored MCP OAuth state from disk: %d clients, %d access tokens, "
                "%d refresh tokens, %d pending, %d auth codes, %d families",
                len(self.clients),
                len(self.access_tokens),
                len(self.refresh_tokens),
                len(self.pending_authorizations),
                len(self.auth_codes),
                len(self._lineage_index),
            )
            return True
        except Exception as e:
            logger.warning("Could not load MCP OAuth state from disk: %s", e, exc_info=True)
            return False

    def _persist_oauth_state_sync(self) -> None:
        """Merge-before-write under cross-process lock (avoids last-writer-wins)."""
        if not self._oauth_persist:
            return
        with self._oauth_state_lock:
            with _oauth_state_store.oauth_state_file_lock(self._oauth_state_path):
                raw = _oauth_state_store.read_mcp_oauth_state(self._oauth_state_path)
                if raw:
                    self._merge_disk_into_memory(
                        _oauth_state_store.deserialize_state(raw)
                    )
                self._prune_current_state()
                _oauth_state_store.write_mcp_oauth_state_atomic(
                    self._oauth_state_path,
                    self._serialize_current_state(),
                )

    async def _persist_oauth_state(self) -> None:
        await asyncio.to_thread(self._persist_oauth_state_sync)

    def _reload_oauth_state_from_disk_locked(self) -> None:
        if not self._oauth_persist:
            return
        with self._oauth_state_lock:
            with _oauth_state_store.oauth_state_file_lock(self._oauth_state_path):
                raw = _oauth_state_store.read_mcp_oauth_state(self._oauth_state_path)
                if not raw:
                    return
                self._merge_disk_into_memory(
                    _oauth_state_store.deserialize_state(raw)
                )
                self._prune_current_state()
            logger.info(
                "Merged MCP OAuth state from disk: %d clients, %d pending, %d auth codes",
                len(self.clients),
                len(self.pending_authorizations),
                len(self.auth_codes),
            )

    def _tombstone_pending(self, google_state: str) -> None:
        self.pending_authorizations.pop(google_state, None)
        self._pending_tombstones[google_state] = time.time()

    def _tombstone_auth_code(self, code: str) -> None:
        self.auth_codes.pop(code, None)
        self.auth_code_to_email.pop(code, None)
        self._auth_code_to_id_token.pop(code, None)
        self._auth_code_tombstones[code] = time.time()

    # ------------------------------------------------------------------
    # Family / lineage helpers
    # ------------------------------------------------------------------

    def _new_family_id(self) -> str:
        return secrets.token_urlsafe(16)

    def _family_lock(self, family_id: str) -> asyncio.Lock:
        lock = self._family_locks.get(family_id)
        if lock is None:
            lock = asyncio.Lock()
            self._family_locks[family_id] = lock
        return lock

    def _register_family_member(
        self,
        family_id: str,
        refresh_token: Optional[str] = None,
        access_token: Optional[str] = None,
    ) -> None:
        entry = self._lineage_index.setdefault(
            family_id, {"refresh_tokens": [], "access_tokens": []}
        )
        if refresh_token and refresh_token not in entry["refresh_tokens"]:
            entry["refresh_tokens"].append(refresh_token)
            self._refresh_lineage[refresh_token] = family_id
        if access_token and access_token not in entry["access_tokens"]:
            entry["access_tokens"].append(access_token)

    def _purge_replay_entry(self, token: str) -> None:
        self._replay_cache.pop(token, None)

    def _prune_replay_cache(self, now: Optional[float] = None) -> None:
        t = now if now is not None else time.time()
        for tok, entry in list(self._replay_cache.items()):
            if float(entry.get("replay_expires_at", 0)) < t:
                self._replay_cache.pop(tok, None)

    async def _revoke_family(self, family_id: str, reason: str) -> None:
        """Revoke every token in a refresh-token family."""
        idx = self._lineage_index.pop(family_id, None)
        if not idx:
            return
        for at in idx.get("access_tokens", []):
            self.access_tokens.pop(at, None)
            self.token_to_email.pop(at, None)
        for rt in idx.get("refresh_tokens", []):
            self.refresh_tokens.pop(rt, None)
            self.token_to_email.pop(rt, None)
            self._refresh_lineage.pop(rt, None)
            self._purge_replay_entry(rt)
        self._family_locks.pop(family_id, None)
        logger.warning(
            "Revoked refresh-token family %s (%s)", family_id, reason
        )
        await self._persist_oauth_state()

    # ------------------------------------------------------------------
    # Client registration
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        client = self.clients.get(client_id)
        if client is not None:
            return client
        if self._oauth_persist:
            await asyncio.to_thread(self._reload_oauth_state_from_disk_locked)
            client = self.clients.get(client_id)
        if client is None:
            logger.error(
                "/token or auth lookup: unknown DCR client_id=%s "
                "(not in memory or disk — multi-instance wipe or never registered)",
                client_id,
            )
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info
        logger.info("Registered MCP client: %s", client_info.client_id)
        await self._persist_oauth_state()

    # ------------------------------------------------------------------
    # Authorization  (MCP client → Google consent → callback → MCP client)
    # ------------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        google_state = secrets.token_urlsafe(32)

        scopes = params.scopes if params.scopes else list(ADS_SCOPES)

        self.pending_authorizations[google_state] = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "state": params.state,
            "code_challenge": params.code_challenge,
            "scopes": scopes,
            "created_at": time.time(),
        }
        await self._persist_oauth_state()

        google_params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.google_client_id,
            "redirect_uri": self.google_callback_uri,
            "scope": " ".join(ADS_SCOPES + ["openid", "email"]),
            "state": google_state,
            "access_type": "offline",
            "prompt": "consent",
        }

        logger.info(
            "authorize(): redirecting to Google (state=%s, client=%s)",
            google_state,
            client.client_id,
        )
        return (
            "https://accounts.google.com/o/oauth2/v2/auth?"
            + urlencode(google_params)
        )

    # ------------------------------------------------------------------
    # Google callback  (/oauth2callback)
    # ------------------------------------------------------------------

    async def _handle_google_callback(self, request: Request):
        """
        Receives Google's auth code, exchanges it for Google tokens,
        stores Google credentials, generates an MCP auth code, and
        redirects to the MCP client's redirect_uri.
        """
        error = request.query_params.get("error")
        if error:
            logger.error("Google returned error: %s", error)
            return RedirectResponse(
                construct_redirect_uri(
                    "about:blank",
                    error="access_denied",
                    error_description=f"Google error: {error}",
                )
            )

        google_code = request.query_params.get("code")
        google_state = request.query_params.get("state")

        if not google_code or not google_state:
            logger.error("Missing code or state in Google callback")
            return RedirectResponse(
                construct_redirect_uri(
                    "about:blank",
                    error="invalid_request",
                    error_description="Missing code or state",
                )
            )

        pending = self.pending_authorizations.pop(google_state, None)
        if not pending and self._oauth_persist:
            await asyncio.to_thread(self._reload_oauth_state_from_disk_locked)
            pending = self.pending_authorizations.pop(google_state, None)
        if pending is not None:
            self._tombstone_pending(google_state)
        if not pending:
            logger.error(
                "Unknown state in Google callback: %s "
                "(authorize and callback must share the same process memory or "
                "persisted OAuth state; multi-instance hosts need sticky sessions "
                "or a shared store)",
                google_state,
            )
            return RedirectResponse(
                construct_redirect_uri(
                    "about:blank",
                    error="invalid_request",
                    error_description=(
                        "Unknown or expired OAuth state. This usually means the "
                        "MCP host lost in-flight login state (restart or another "
                        "instance). Retry sign-in; if it keeps failing, the host "
                        "must use a single instance, sticky sessions, or shared "
                        "OAuth state persistence."
                    ),
                )
            )

        token_data = await self._exchange_google_code(google_code)
        if not token_data or "access_token" not in token_data:
            logger.error("Google token exchange failed: %s", token_data)
            return RedirectResponse(
                construct_redirect_uri(
                    pending["redirect_uri"],
                    error="server_error",
                    error_description="Failed to exchange Google authorization code",
                    state=pending["state"],
                )
            )

        user_email = await self._extract_user_email(token_data)
        if not user_email:
            logger.error("Could not determine user email from Google tokens")
            return RedirectResponse(
                construct_redirect_uri(
                    pending["redirect_uri"],
                    error="server_error",
                    error_description="Could not determine user identity",
                    state=pending["state"],
                )
            )

        self._store_google_credentials(user_email, token_data)

        google_id_token = token_data.get("id_token")

        mcp_code = secrets.token_urlsafe(32)
        self.auth_codes[mcp_code] = AuthorizationCode(
            code=mcp_code,
            client_id=pending["client_id"],
            redirect_uri=AnyHttpUrl(pending["redirect_uri"]),
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            scopes=pending["scopes"],
            expires_at=time.time() + DEFAULT_AUTH_CODE_EXPIRY,
            code_challenge=pending["code_challenge"],
        )
        self.auth_code_to_email[mcp_code] = user_email
        if google_id_token:
            self._auth_code_to_id_token[mcp_code] = google_id_token
            self._user_id_tokens[user_email] = google_id_token

        await self._persist_oauth_state()

        logger.info(
            "Google callback success: user=%s, redirecting to client", user_email
        )
        return RedirectResponse(
            construct_redirect_uri(
                pending["redirect_uri"],
                code=mcp_code,
                state=pending["state"],
            )
        )

    async def _exchange_google_code(self, code: str) -> Optional[dict]:
        """Exchange a Google authorization code for tokens."""
        payload = {
            "code": code,
            "client_id": self.google_client_id,
            "client_secret": self.google_client_secret,
            "redirect_uri": self.google_callback_uri,
            "grant_type": "authorization_code",
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://oauth2.googleapis.com/token",
                    data=payload,
                ) as resp:
                    data = await resp.json()
                    if resp.status != 200:
                        logger.error("Google token exchange HTTP %d: %s", resp.status, data)
                        return None
                    return data
        except Exception as e:
            logger.error("Google token exchange error: %s", e, exc_info=True)
            return None

    async def _extract_user_email(self, token_data: dict) -> Optional[str]:
        """
        Get user email from id_token or userinfo endpoint.

        Signature verification is skipped because the id_token was received
        directly from Google's token endpoint over TLS in _exchange_google_code(),
        not from the client. This is a standard server-side OAuth pattern.
        """
        id_token = token_data.get("id_token")
        if id_token:
            try:
                import jwt as pyjwt
                claims = pyjwt.decode(id_token, options={"verify_signature": False})
                email = claims.get("email")
                if email and claims.get("email_verified", False):
                    return email
            except Exception as e:
                logger.debug("id_token decode failed: %s", e)

        access_token = token_data.get("access_token")
        if access_token:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://www.googleapis.com/oauth2/v3/userinfo",
                        headers={"Authorization": f"Bearer {access_token}"},
                    ) as resp:
                        if resp.status == 200:
                            info = await resp.json()
                            email = info.get("email")
                            if email and info.get("email_verified", False):
                                return email
            except Exception as e:
                logger.debug("userinfo fetch failed: %s", e)

        return None

    def _store_google_credentials(self, user_email: str, token_data: dict) -> None:
        """Persist Google credentials to the credential store."""
        expiry = None
        if "expires_in" in token_data:
            expiry = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])

        creds = GoogleCredentials(
            token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=self.google_client_id,
            client_secret=self.google_client_secret,
            scopes=token_data.get("scope", "").split() or None,
            expiry=expiry,
        )

        store = get_credential_store()
        if store.store_credential(user_email, creds):
            logger.info("Stored Google credentials for %s", user_email)
        else:
            logger.error("Failed to store Google credentials for %s", user_email)

    # ------------------------------------------------------------------
    # Token exchange  (MCP auth code → MCP access/refresh tokens)
    # ------------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[AuthorizationCode]:
        ac = self.auth_codes.get(authorization_code)
        if ac is None and self._oauth_persist:
            await asyncio.to_thread(self._reload_oauth_state_from_disk_locked)
            ac = self.auth_codes.get(authorization_code)
        if not ac:
            logger.error(
                "/token: authorization code not found (code_prefix=%s…, client_id=%s). "
                "Callback may have hit another worker whose auth_codes were wiped, "
                "or the code expired/already consumed.",
                authorization_code[:8] if authorization_code else "",
                client.client_id,
            )
            return None
        if ac.client_id != client.client_id:
            logger.error(
                "/token: authorization code client_id mismatch "
                "(code client=%s, request client=%s)",
                ac.client_id,
                client.client_id,
            )
            return None
        if ac.expires_at < time.time():
            logger.error(
                "/token: authorization code expired (client_id=%s)",
                client.client_id,
            )
            self._tombstone_auth_code(authorization_code)
            await self._persist_oauth_state()
            return None
        return ac

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        user_email = self.auth_code_to_email.get(authorization_code.code)
        google_id_token = self._auth_code_to_id_token.get(authorization_code.code)
        if user_email is None and self._oauth_persist:
            await asyncio.to_thread(self._reload_oauth_state_from_disk_locked)
            user_email = self.auth_code_to_email.get(authorization_code.code)
            google_id_token = (
                self._auth_code_to_id_token.get(authorization_code.code)
                or google_id_token
            )
        if user_email is None:
            logger.error(
                "/token: auth code has no email mapping (client_id=%s, code_prefix=%s…)",
                client.client_id,
                authorization_code.code[:8],
            )
        self._tombstone_auth_code(authorization_code.code)

        access_token_value = secrets.token_urlsafe(32)
        refresh_token_value = secrets.token_urlsafe(32)
        now = int(time.time())
        expires_at = now + self.access_token_ttl

        self.access_tokens[access_token_value] = AccessToken(
            token=access_token_value,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
            claims={"email": user_email},
        )

        self.refresh_tokens[refresh_token_value] = RefreshToken(
            token=refresh_token_value,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=now + self.refresh_token_ttl,
        )

        self.token_to_email[access_token_value] = user_email
        self.token_to_email[refresh_token_value] = user_email

        family_id = self._new_family_id()
        self._register_family_member(
            family_id,
            refresh_token=refresh_token_value,
            access_token=access_token_value,
        )

        logger.info(
            "Issued MCP tokens for user=%s (client=%s, family=%s)",
            user_email,
            client.client_id,
            family_id,
        )

        await self._persist_oauth_state()

        return _OAuthTokenWithIdToken(
            access_token=access_token_value,
            token_type="Bearer",
            expires_in=self.access_token_ttl,
            refresh_token=refresh_token_value,
            scope=" ".join(authorization_code.scopes),
            id_token=google_id_token,
        )

    # ------------------------------------------------------------------
    # Refresh token exchange  (with rotation, grace window, reuse detection)
    # ------------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[RefreshToken]:
        """
        Validate a refresh token for the token endpoint.

        * Live token              -> return it (will be rotated by exchange_refresh_token).
        * Within replay grace     -> return a synthetic RefreshToken; the
                                     successor tokens are served from the
                                     replay cache by exchange_refresh_token.
        * Past replay grace, but
          known to have been
          rotated previously      -> reuse detected; revoke the entire family
                                     and return None (handler emits 400).
        * Unknown                 -> return None.
        """
        now = time.time()
        self._prune_replay_cache(now)

        rt = self.refresh_tokens.get(refresh_token)
        if rt is None and self._oauth_persist:
            await asyncio.to_thread(self._reload_oauth_state_from_disk_locked)
            rt = self.refresh_tokens.get(refresh_token)
        if rt is not None:
            if rt.client_id != client.client_id:
                return None
            if rt.expires_at is not None and rt.expires_at < now:
                self.refresh_tokens.pop(refresh_token, None)
                self.token_to_email.pop(refresh_token, None)
                self._refresh_lineage.pop(refresh_token, None)
                await self._persist_oauth_state()
                return None
            return rt

        replay = self._replay_cache.get(refresh_token)
        if replay is not None:
            if replay.get("client_id") and replay["client_id"] != client.client_id:
                return None
            if float(replay.get("replay_expires_at", 0)) >= now:
                return RefreshToken(
                    token=refresh_token,
                    client_id=client.client_id,
                    scopes=list(replay.get("scopes") or []),
                    expires_at=int(float(replay["replay_expires_at"])),
                )
            # Past grace window but we still remember the rotation -> reuse.
            if self.reuse_detection_enabled:
                family_id = replay.get("family") or self._refresh_lineage.get(
                    refresh_token
                )
                if family_id:
                    await self._revoke_family(
                        family_id,
                        reason="refresh token reused past grace window",
                    )
            return None

        # No live entry, no replay entry, but lineage remembers this token —
        # the legitimate client has already rotated it. Treat as reuse.
        family_id = self._refresh_lineage.get(refresh_token)
        if family_id and self.reuse_detection_enabled:
            await self._revoke_family(
                family_id,
                reason="refresh token reused after rotation",
            )
            return None

        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        token_value = refresh_token.token

        family_id = self._refresh_lineage.get(token_value)
        if family_id is None:
            replay_entry = self._replay_cache.get(token_value)
            if replay_entry is not None:
                family_id = replay_entry.get("family") or None

        if family_id is None:
            family_id = self._new_family_id()
            self._register_family_member(family_id, refresh_token=token_value)
            logger.info(
                "Adopting legacy refresh token into new family %s", family_id
            )

        async with self._family_lock(family_id):
            now = time.time()
            self._prune_replay_cache(now)

            replay_entry = self._replay_cache.get(token_value)
            if replay_entry is not None:
                if float(replay_entry.get("replay_expires_at", 0)) >= now:
                    new_access = replay_entry["new_access"]
                    if new_access in self.access_tokens:
                        remaining = max(
                            1,
                            int(self.access_tokens[new_access].expires_at - now)
                            if self.access_tokens[new_access].expires_at
                            else self.access_token_ttl,
                        )
                    else:
                        remaining = self.access_token_ttl
                    logger.info(
                        "Replay-served rotated refresh for family %s (client=%s)",
                        family_id,
                        client.client_id,
                    )
                    return _OAuthTokenWithIdToken(
                        access_token=new_access,
                        token_type="Bearer",
                        expires_in=remaining,
                        refresh_token=replay_entry["new_refresh"],
                        scope=" ".join(replay_entry.get("scopes") or scopes),
                        id_token=replay_entry.get("id_token"),
                    )
                # past grace window → reuse detected
                if self.reuse_detection_enabled:
                    await self._revoke_family(
                        family_id,
                        reason="refresh token reused past grace window",
                    )
                    raise self._invalid_grant("refresh token has been rotated")
                # if reuse detection disabled, drop stale replay entry
                self._purge_replay_entry(token_value)

            live = self.refresh_tokens.get(token_value)
            if live is None:
                # Not live, no replay entry, but lineage existed → token has
                # been rotated and reused outside the grace window.
                if self.reuse_detection_enabled and family_id in self._lineage_index:
                    await self._revoke_family(
                        family_id,
                        reason="refresh token reused after rotation",
                    )
                raise self._invalid_grant("refresh token does not exist")

            if live.client_id != client.client_id:
                raise self._invalid_grant("refresh token does not exist")
            if live.expires_at is not None and live.expires_at < now:
                self.refresh_tokens.pop(token_value, None)
                self.token_to_email.pop(token_value, None)
                self._refresh_lineage.pop(token_value, None)
                raise self._invalid_grant("refresh token has expired")

            user_email = self.token_to_email.get(token_value)
            if user_email:
                self._try_refresh_google_token(user_email)

            new_access = secrets.token_urlsafe(32)
            new_refresh = secrets.token_urlsafe(32)
            now_i = int(now)
            access_expires_at = now_i + self.access_token_ttl

            self.access_tokens[new_access] = AccessToken(
                token=new_access,
                client_id=client.client_id,
                scopes=scopes,
                expires_at=access_expires_at,
                claims={"email": user_email},
            )
            self.refresh_tokens[new_refresh] = RefreshToken(
                token=new_refresh,
                client_id=client.client_id,
                scopes=scopes,
                expires_at=now_i + self.refresh_token_ttl,
            )

            self.token_to_email[new_access] = user_email
            self.token_to_email[new_refresh] = user_email

            self._register_family_member(
                family_id,
                refresh_token=new_refresh,
                access_token=new_access,
            )

            # Move the old refresh token into the replay cache and out of the
            # live pool. Keep token_to_email and lineage so we can detect
            # reuse even after the grace window.
            self.refresh_tokens.pop(token_value, None)

            google_id_token = (
                self._user_id_tokens.get(user_email) if user_email else None
            )

            if self.refresh_grace_seconds > 0:
                self._replay_cache[token_value] = {
                    "new_access": new_access,
                    "new_refresh": new_refresh,
                    "expires_in": self.access_token_ttl,
                    "scopes": list(scopes),
                    "id_token": google_id_token,
                    "rotated_at": now,
                    "replay_expires_at": now + self.refresh_grace_seconds,
                    "family": family_id,
                    "client_id": client.client_id,
                }

            logger.info(
                "Rotated MCP tokens for user=%s (family=%s, grace=%ss)",
                user_email,
                family_id,
                self.refresh_grace_seconds,
            )

            await self._persist_oauth_state()

            return _OAuthTokenWithIdToken(
                access_token=new_access,
                token_type="Bearer",
                expires_in=self.access_token_ttl,
                refresh_token=new_refresh,
                scope=" ".join(scopes),
                id_token=google_id_token,
            )

    @staticmethod
    def _invalid_grant(description: str) -> Exception:
        """Build a TokenError(invalid_grant=…) the way the MCP handler expects."""
        from mcp.server.auth.provider import TokenError
        return TokenError(error="invalid_grant", error_description=description)

    def _try_refresh_google_token(self, user_email: str) -> None:
        """Attempt to refresh the stored Google token for a user."""
        try:
            from google.auth.transport.requests import Request as GoogleAuthRequest
            store = get_credential_store()
            creds = store.get_credential(user_email)
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(GoogleAuthRequest())
                store.store_credential(user_email, creds)
                logger.info("Refreshed Google token for %s", user_email)
        except Exception as e:
            logger.warning("Could not refresh Google token for %s: %s", user_email, e)

    # ------------------------------------------------------------------
    # Token verification  (called on every /mcp request)
    # ------------------------------------------------------------------

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        at = self.access_tokens.get(token)
        if at is None and self._oauth_persist:
            await asyncio.to_thread(self._reload_oauth_state_from_disk_locked)
            at = self.access_tokens.get(token)
        if not at:
            return None
        if at.expires_at is not None and at.expires_at < time.time():
            self.access_tokens.pop(token, None)
            self.token_to_email.pop(token, None)
            await self._persist_oauth_state()
            return None
        return at

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        return await self.load_access_token(token)

    # ------------------------------------------------------------------
    # Token revocation
    # ------------------------------------------------------------------

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self.access_tokens.pop(token.token, None)
            self.token_to_email.pop(token.token, None)
        elif isinstance(token, RefreshToken):
            self.refresh_tokens.pop(token.token, None)
            self.token_to_email.pop(token.token, None)
            self._purge_replay_entry(token.token)
            self._refresh_lineage.pop(token.token, None)
        await self._persist_oauth_state()

    # ------------------------------------------------------------------
    # Routes: add /oauth2callback alongside standard OAuth routes
    # ------------------------------------------------------------------

    def get_routes(self) -> list[Route]:
        routes = super().get_routes()
        routes.append(
            Route(
                "/oauth2callback",
                endpoint=self._handle_google_callback,
                methods=["GET"],
            )
        )
        return routes

    # ------------------------------------------------------------------
    # Helper: look up user email from an MCP access token string
    # ------------------------------------------------------------------

    def get_user_email(self, token: str) -> Optional[str]:
        return self.token_to_email.get(token)
