"""
Persist FastMCP / MCP OAuth authorization-server state to disk.

Survives process restarts and coordinates multiple workers via an exclusive
file lock + merge-before-write so one process cannot wipe another's in-flight
login or freshly registered DCR clients.

Schema:
    v1: clients + access_tokens + refresh_tokens + token_to_email
    v2: v1 + refresh_lineage + lineage_index + replay_cache
    v2 (extended): also pending_authorizations, auth_codes, email/id maps,
        tombstones (backward compatible — old readers ignore unknown keys;
        this writer always emits v2 with the extended fields)

The reader accepts v1 and v2 payloads; the writer always emits v2.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from contextlib import contextmanager
from typing import Any, Iterator

from mcp.server.auth.provider import AuthorizationCode, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from fastmcp.server.auth.auth import AccessToken

logger = logging.getLogger(__name__)

STATE_VERSION = 2
SUPPORTED_VERSIONS = (1, 2)
SUBDIR_NAME = "mcp_oauth"
STATE_FILENAME = "server_state.json"
LOCK_FILENAME = "server_state.lock"

DEFAULT_PENDING_TTL_SECONDS = 15 * 60
DEFAULT_TOMBSTONE_TTL_SECONDS = 15 * 60


def mcp_oauth_state_path(base_dir: str) -> str:
    return os.path.join(base_dir, SUBDIR_NAME, STATE_FILENAME)


def mcp_oauth_lock_path(state_path: str) -> str:
    return os.path.join(os.path.dirname(state_path), LOCK_FILENAME)


@contextmanager
def oauth_state_file_lock(state_path: str) -> Iterator[None]:
    """Cross-process exclusive lock around read-merge-write of server_state.json."""
    lock_path = mcp_oauth_lock_path(state_path)
    parent = os.path.dirname(lock_path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl

            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except ImportError:
            logger.warning(
                "fcntl unavailable — OAuth state file lock is process-local only"
            )
        yield
    finally:
        try:
            import fcntl

            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            os.close(lock_fd)
        except OSError:
            pass


def write_mcp_oauth_state_atomic(path: str, payload: dict[str, Any]) -> None:
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


def _prune_tombstones(
    tombstones: dict[str, float], now: float, ttl: float = DEFAULT_TOMBSTONE_TTL_SECONDS
) -> dict[str, float]:
    return {k: ts for k, ts in tombstones.items() if ts + ttl >= now}


def merge_dict(disk: dict, memory: dict) -> dict:
    out = dict(disk)
    out.update(memory)
    return out


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
    dict[str, dict],
    dict[str, AuthorizationCode],
    dict[str, str],
    dict[str, str],
    dict[str, str],
    dict[str, float],
    dict[str, float],
]:
    """
    Returns:
        clients, access_tokens, refresh_tokens, token_to_email,
        refresh_lineage, lineage_index, replay_cache,
        pending_authorizations, auth_codes, auth_code_to_email,
        auth_code_to_id_token, user_id_tokens,
        pending_tombstones, auth_code_tombstones
    """
    clients: dict[str, OAuthClientInformationFull] = {}
    access_tokens: dict[str, AccessToken] = {}
    refresh_tokens: dict[str, RefreshToken] = {}
    token_to_email: dict[str, str] = {}
    refresh_lineage: dict[str, str] = {}
    lineage_index: dict[str, dict[str, list[str]]] = {}
    replay_cache: dict[str, dict[str, Any]] = {}
    pending_authorizations: dict[str, dict] = {}
    auth_codes: dict[str, AuthorizationCode] = {}
    auth_code_to_email: dict[str, str] = {}
    auth_code_to_id_token: dict[str, str] = {}
    user_id_tokens: dict[str, str] = {}
    pending_tombstones: dict[str, float] = {}
    auth_code_tombstones: dict[str, float] = {}

    empty = (
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
    )

    version = raw.get("version")
    if version not in SUPPORTED_VERSIONS:
        logger.warning(
            "Ignoring MCP OAuth state file: unsupported version %r",
            version,
        )
        return empty

    now = time.time()
    pending_tombstones = _prune_tombstones(
        {
            str(k): float(v)
            for k, v in dict(raw.get("pending_tombstones") or {}).items()
            if isinstance(v, (int, float))
        },
        now,
    )
    auth_code_tombstones = _prune_tombstones(
        {
            str(k): float(v)
            for k, v in dict(raw.get("auth_code_tombstones") or {}).items()
            if isinstance(v, (int, float))
        },
        now,
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

    saved_at = raw.get("saved_at")
    pending_fallback_created_at = (
        saved_at if isinstance(saved_at, (int, float)) else now
    )
    for state, pdata in (raw.get("pending_authorizations") or {}).items():
        if state in pending_tombstones:
            continue
        if not isinstance(pdata, dict):
            continue
        entry = dict(pdata)
        created_at = entry.get("created_at")
        if not isinstance(created_at, (int, float)):
            entry["created_at"] = pending_fallback_created_at
            created_at = pending_fallback_created_at
        if created_at + DEFAULT_PENDING_TTL_SECONDS < now:
            continue
        pending_authorizations[state] = entry

    for code, cdata in (raw.get("auth_codes") or {}).items():
        if code in auth_code_tombstones:
            continue
        try:
            ac = AuthorizationCode.model_validate(cdata)
            if ac.expires_at < now:
                continue
            auth_codes[code] = ac
        except Exception as e:
            logger.warning("Skipping invalid auth code entry: %s", e)

    auth_code_to_email = {
        k: v
        for k, v in dict(raw.get("auth_code_to_email") or {}).items()
        if k in auth_codes
    }
    auth_code_to_id_token = {
        k: v
        for k, v in dict(raw.get("auth_code_to_id_token") or {}).items()
        if k in auth_codes
    }
    user_id_tokens = {
        k: v for k, v in dict(raw.get("user_id_tokens") or {}).items() if isinstance(v, str)
    }

    return (
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
    )


def serialize_state(
    clients: dict[str, OAuthClientInformationFull],
    access_tokens: dict[str, AccessToken],
    refresh_tokens: dict[str, RefreshToken],
    token_to_email: dict[str, str],
    refresh_lineage: dict[str, str] | None = None,
    lineage_index: dict[str, dict[str, list[str]]] | None = None,
    replay_cache: dict[str, dict[str, Any]] | None = None,
    pending_authorizations: dict[str, dict] | None = None,
    auth_codes: dict[str, AuthorizationCode] | None = None,
    auth_code_to_email: dict[str, str] | None = None,
    auth_code_to_id_token: dict[str, str] | None = None,
    user_id_tokens: dict[str, str] | None = None,
    pending_tombstones: dict[str, float] | None = None,
    auth_code_tombstones: dict[str, float] | None = None,
) -> dict[str, Any]:
    now = time.time()
    refresh_lineage = refresh_lineage or {}
    lineage_index = lineage_index or {}
    replay_cache = replay_cache or {}
    pending = dict(pending_authorizations or {})
    codes = dict(auth_codes or {})
    code_emails = dict(auth_code_to_email or {})
    code_id_tokens = dict(auth_code_to_id_token or {})
    id_tokens = dict(user_id_tokens or {})
    pending_tombs = _prune_tombstones(dict(pending_tombstones or {}), now)
    code_tombs = _prune_tombstones(dict(auth_code_tombstones or {}), now)

    for k in pending_tombs:
        pending.pop(k, None)
    for k in code_tombs:
        codes.pop(k, None)
        code_emails.pop(k, None)
        code_id_tokens.pop(k, None)

    auth_codes_snap: dict[str, Any] = {}
    for k, v in codes.items():
        dumped = v.model_dump(mode="json")
        if "redirect_uri" in dumped and not isinstance(dumped["redirect_uri"], str):
            dumped["redirect_uri"] = str(v.redirect_uri)
        auth_codes_snap[k] = dumped

    return {
        "version": STATE_VERSION,
        "saved_at": now,
        "clients": {
            k: v.model_dump(mode="json") for k, v in dict(clients).items()
        },
        "access_tokens": {
            k: v.model_dump(mode="json") for k, v in dict(access_tokens).items()
        },
        "refresh_tokens": {
            k: v.model_dump(mode="json") for k, v in dict(refresh_tokens).items()
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
        "pending_authorizations": pending,
        "auth_codes": auth_codes_snap,
        "auth_code_to_email": code_emails,
        "auth_code_to_id_token": code_id_tokens,
        "user_id_tokens": id_tokens,
        "pending_tombstones": pending_tombs,
        "auth_code_tombstones": code_tombs,
    }


def prune_expired(
    access_tokens: dict[str, AccessToken],
    refresh_tokens: dict[str, RefreshToken],
    token_to_email: dict[str, str],
    refresh_lineage: dict[str, str] | None = None,
    lineage_index: dict[str, dict[str, list[str]]] | None = None,
    replay_cache: dict[str, dict[str, Any]] | None = None,
    pending_authorizations: dict[str, dict] | None = None,
    auth_codes: dict[str, AuthorizationCode] | None = None,
    auth_code_to_email: dict[str, str] | None = None,
    auth_code_to_id_token: dict[str, str] | None = None,
    now: float | None = None,
) -> None:
    """Remove expired MCP tokens, replay entries, pending states, auth codes."""
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
                for rt in rt_list:
                    refresh_lineage.pop(rt, None)
                lineage_index.pop(fam, None)
            else:
                entry["access_tokens"] = [at for at in at_list if at in live_access]

    if pending_authorizations is not None:
        for state, pdata in list(pending_authorizations.items()):
            created_at = pdata.get("created_at") if isinstance(pdata, dict) else None
            if not isinstance(created_at, (int, float)):
                pending_authorizations.pop(state, None)
                continue
            if created_at + DEFAULT_PENDING_TTL_SECONDS < t:
                pending_authorizations.pop(state, None)

    if auth_codes is not None:
        for code, ac in list(auth_codes.items()):
            if ac.expires_at < t:
                auth_codes.pop(code, None)
                if auth_code_to_email is not None:
                    auth_code_to_email.pop(code, None)
                if auth_code_to_id_token is not None:
                    auth_code_to_id_token.pop(code, None)
        if auth_code_to_email is not None:
            for code in list(auth_code_to_email.keys()):
                if code not in auth_codes:
                    auth_code_to_email.pop(code, None)
        if auth_code_to_id_token is not None:
            for code in list(auth_code_to_id_token.keys()):
                if code not in auth_codes:
                    auth_code_to_id_token.pop(code, None)
