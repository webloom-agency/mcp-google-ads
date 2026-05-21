"""
Persist FastMCP / MCP OAuth authorization-server state to disk.

Survives process restarts (e.g. Render deploys) so registered clients and
MCP access/refresh tokens remain valid while Google user credentials are
stored separately by the credential store.

Schema:
    v1: clients + access_tokens + refresh_tokens + token_to_email
    v2: v1  + refresh_lineage  + lineage_index + replay_cache
        (refresh-token-rotation grace window and reuse detection)

The reader accepts both v1 and v2 payloads; the writer always emits v2.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from typing import Any

from mcp.server.auth.provider import RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from fastmcp.server.auth.auth import AccessToken

logger = logging.getLogger(__name__)

STATE_VERSION = 2
SUPPORTED_VERSIONS = (1, 2)
SUBDIR_NAME = "mcp_oauth"
STATE_FILENAME = "server_state.json"


def mcp_oauth_state_path(base_dir: str) -> str:
    return os.path.join(base_dir, SUBDIR_NAME, STATE_FILENAME)


def write_mcp_oauth_state_atomic(path: str, payload: dict[str, Any]) -> None:
    """Write JSON atomically with restrictive permissions."""
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".mcp_oauth_state_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_mcp_oauth_state(path: str) -> dict[str, Any] | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not read MCP OAuth state file %s: %s", path, e)
        return None


def deserialize_state(
    raw: dict[str, Any],
) -> tuple[
    dict[str, OAuthClientInformationFull],
    dict[str, AccessToken],
    dict[str, RefreshToken],
    dict[str, str],
    dict[str, str],
    dict[str, dict[str, list[str]]],
    dict[str, dict[str, Any]],
]:
    """
    Deserialize persisted OAuth state.

    Returns:
        clients, access_tokens, refresh_tokens, token_to_email,
        refresh_lineage, lineage_index, replay_cache
    """
    clients: dict[str, OAuthClientInformationFull] = {}
    access_tokens: dict[str, AccessToken] = {}
    refresh_tokens: dict[str, RefreshToken] = {}
    token_to_email: dict[str, str] = {}
    refresh_lineage: dict[str, str] = {}
    lineage_index: dict[str, dict[str, list[str]]] = {}
    replay_cache: dict[str, dict[str, Any]] = {}

    version = raw.get("version")
    if version not in SUPPORTED_VERSIONS:
        logger.warning(
            "Ignoring MCP OAuth state file: unsupported version %r",
            version,
        )
        return (
            clients,
            access_tokens,
            refresh_tokens,
            token_to_email,
            refresh_lineage,
            lineage_index,
            replay_cache,
        )

    for cid, cdata in (raw.get("clients") or {}).items():
        try:
            clients[cid] = OAuthClientInformationFull.model_validate(cdata)
        except Exception as e:
            logger.warning("Skipping invalid OAuth client %s: %s", cid, e)

    for tok, tdata in (raw.get("access_tokens") or {}).items():
        try:
            access_tokens[tok] = AccessToken.model_validate(tdata)
        except Exception as e:
            logger.warning("Skipping invalid access token entry: %s", e)

    for tok, tdata in (raw.get("refresh_tokens") or {}).items():
        try:
            refresh_tokens[tok] = RefreshToken.model_validate(tdata)
        except Exception as e:
            logger.warning("Skipping invalid refresh token entry: %s", e)

    token_to_email = dict(raw.get("token_to_email") or {})

    if version >= 2:
        refresh_lineage = dict(raw.get("refresh_lineage") or {})
        for fam, entry in (raw.get("lineage_index") or {}).items():
            lineage_index[fam] = {
                "refresh_tokens": list(entry.get("refresh_tokens") or []),
                "access_tokens": list(entry.get("access_tokens") or []),
            }
        for tok, entry in (raw.get("replay_cache") or {}).items():
            try:
                replay_cache[tok] = {
                    "new_access": str(entry["new_access"]),
                    "new_refresh": str(entry["new_refresh"]),
                    "expires_in": int(entry["expires_in"]),
                    "scopes": list(entry.get("scopes") or []),
                    "id_token": entry.get("id_token"),
                    "rotated_at": float(entry["rotated_at"]),
                    "replay_expires_at": float(entry["replay_expires_at"]),
                    "family": str(entry.get("family") or ""),
                    "client_id": str(entry.get("client_id") or ""),
                }
            except (KeyError, TypeError, ValueError) as e:
                logger.warning("Skipping invalid replay-cache entry: %s", e)

    return (
        clients,
        access_tokens,
        refresh_tokens,
        token_to_email,
        refresh_lineage,
        lineage_index,
        replay_cache,
    )


def serialize_state(
    clients: dict[str, OAuthClientInformationFull],
    access_tokens: dict[str, AccessToken],
    refresh_tokens: dict[str, RefreshToken],
    token_to_email: dict[str, str],
    refresh_lineage: dict[str, str] | None = None,
    lineage_index: dict[str, dict[str, list[str]]] | None = None,
    replay_cache: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    refresh_lineage = refresh_lineage or {}
    lineage_index = lineage_index or {}
    replay_cache = replay_cache or {}
    return {
        "version": STATE_VERSION,
        "saved_at": time.time(),
        "clients": {
            k: v.model_dump(mode="json") for k, v in clients.items()
        },
        "access_tokens": {
            k: v.model_dump(mode="json") for k, v in access_tokens.items()
        },
        "refresh_tokens": {
            k: v.model_dump(mode="json") for k, v in refresh_tokens.items()
        },
        "token_to_email": dict(token_to_email),
        "refresh_lineage": dict(refresh_lineage),
        "lineage_index": {
            fam: {
                "refresh_tokens": list(entry.get("refresh_tokens") or []),
                "access_tokens": list(entry.get("access_tokens") or []),
            }
            for fam, entry in lineage_index.items()
        },
        "replay_cache": {
            k: {
                "new_access": v["new_access"],
                "new_refresh": v["new_refresh"],
                "expires_in": int(v["expires_in"]),
                "scopes": list(v.get("scopes") or []),
                "id_token": v.get("id_token"),
                "rotated_at": float(v["rotated_at"]),
                "replay_expires_at": float(v["replay_expires_at"]),
                "family": v.get("family", ""),
                "client_id": v.get("client_id", ""),
            }
            for k, v in replay_cache.items()
        },
    }


def prune_expired(
    access_tokens: dict[str, AccessToken],
    refresh_tokens: dict[str, RefreshToken],
    token_to_email: dict[str, str],
    refresh_lineage: dict[str, str] | None = None,
    lineage_index: dict[str, dict[str, list[str]]] | None = None,
    replay_cache: dict[str, dict[str, Any]] | None = None,
    now: float | None = None,
) -> None:
    """Remove expired MCP access/refresh tokens, replay entries, and orphans."""
    t = now if now is not None else time.time()

    for key, at in list(access_tokens.items()):
        if at.expires_at is not None and at.expires_at < t:
            access_tokens.pop(key, None)
            token_to_email.pop(key, None)

    for key, rt in list(refresh_tokens.items()):
        if rt.expires_at is not None and rt.expires_at < t:
            refresh_tokens.pop(key, None)
            token_to_email.pop(key, None)
            if refresh_lineage is not None:
                refresh_lineage.pop(key, None)

    if replay_cache is not None:
        for key, entry in list(replay_cache.items()):
            if float(entry.get("replay_expires_at", 0)) < t:
                replay_cache.pop(key, None)

    valid_keys = set(access_tokens) | set(refresh_tokens)
    for key in list(token_to_email.keys()):
        if key not in valid_keys:
            token_to_email.pop(key, None)

    if lineage_index is not None and refresh_lineage is not None:
        live_refresh = set(refresh_tokens)
        live_access = set(access_tokens)
        live_replay = set(replay_cache or {})
        for fam, entry in list(lineage_index.items()):
            rt_list = entry.get("refresh_tokens", [])
            at_list = entry.get("access_tokens", [])
            family_active = (
                any(rt in live_refresh for rt in rt_list)
                or any(rt in live_replay for rt in rt_list)
                or any(at in live_access for at in at_list)
            )
            if not family_active:
                # Family is fully dead; drop its lineage entries so we don't
                # leak memory remembering rotations of long-gone tokens.
                for rt in rt_list:
                    refresh_lineage.pop(rt, None)
                lineage_index.pop(fam, None)
            else:
                # Drop dead access tokens but keep refresh-token history so we
                # can still detect reuse of rotated tokens within the family.
                entry["access_tokens"] = [at for at in at_list if at in live_access]
