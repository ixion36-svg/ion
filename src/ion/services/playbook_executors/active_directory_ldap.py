"""Active Directory (LDAP) adapter — ``disable_account`` / ``reset_password``.

Uses the third-party ``ldap3`` library (synchronous) wrapped in
``asyncio.to_thread`` so the adapter honours the common async
``execute`` contract.  The operation flow:

1. Bind to ``exec_ad_ldap_uri`` with ``exec_ad_bind_dn`` +
   ``exec_ad_bind_password``.  LDAPS is strongly recommended for any
   password-reset flow (AD rejects ``unicodePwd`` updates over an
   unencrypted channel).
2. Search ``exec_ad_user_search_base`` for the account by
   ``sAMAccountName``.
3. For ``disable_account``: flip the ``ACCOUNTDISABLE`` bit (``0x2``) on
   ``userAccountControl`` via a modify-replace.
4. For ``reset_password``: set ``unicodePwd`` to the new password (UTF-16
   little-endian wrapped in quotes, per Microsoft spec) and mark
   ``pwdLastSet`` = 0 to force change at next logon.

Dependency: ``ldap3>=2.9`` — add to pyproject.toml (see Integration
Checklist).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import string
from datetime import datetime, timezone
from typing import Any

from ion.services.playbook_executors import ExecutorResult
from ion.services.playbook_executors.audit import redact

logger = logging.getLogger(__name__)

ADAPTER_NAME = "active_directory_ldap"
SUPPORTED_ACTIONS = ("disable_account", "reset_password")

# AD userAccountControl bits (subset)
_UAC_ACCOUNTDISABLE = 0x0002


def is_configured(config) -> bool:
    return bool(
        getattr(config, "exec_ad_ldap_uri", "")
        and getattr(config, "exec_ad_bind_dn", "")
        and getattr(config, "exec_ad_bind_password", "")
        and getattr(config, "exec_ad_user_search_base", "")
    )


def _generate_password(length: int = 20) -> str:
    """Generate a random complex password that satisfies AD complexity rules."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}"
    # Ensure we include at least one of each category
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(not c.isalnum() for c in pwd)
        ):
            return pwd


def _encode_ad_password(pwd: str) -> bytes:
    """Encode a plaintext password the way Active Directory expects it.

    AD requires ``unicodePwd`` to be the new password wrapped in double
    quotes and encoded as UTF-16 little-endian.
    """
    return ('"' + pwd + '"').encode("utf-16-le")


def _perform_ldap_action(
    action_type: str,
    target_sam: str,
    new_password: str | None,
    *,
    ldap_uri: str,
    bind_dn: str,
    bind_password: str,
    search_base: str,
    verify_ssl: bool,
) -> tuple[bool, str, dict]:
    """Synchronous worker run via ``asyncio.to_thread``.

    Returns ``(success, message, response_payload)``.  ``response_payload``
    is already safe for redaction — it carries only LDAP result codes,
    description strings, and the target DN (no secrets).
    """
    # Import lazily so the module loads even if ldap3 isn't installed
    # (dry-run mode should still work).
    try:
        import ssl as _ssl

        import ldap3
        from ldap3 import ALL, MODIFY_REPLACE, Connection, Server, Tls
    except ImportError as exc:
        return (
            False,
            f"ldap3 library not installed ({exc}); add ldap3>=2.9 to dependencies",
            {"error": "ldap3_not_installed"},
        )

    tls = None
    if ldap_uri.lower().startswith("ldaps://"):
        tls = Tls(
            validate=_ssl.CERT_REQUIRED if verify_ssl else _ssl.CERT_NONE,
        )

    server = Server(ldap_uri, use_ssl=ldap_uri.lower().startswith("ldaps://"),
                    tls=tls, get_info=ALL)
    try:
        conn = Connection(server, user=bind_dn, password=bind_password,
                          auto_bind=True, raise_exceptions=False)
    except Exception as exc:  # ldap3 wraps many error types
        return (False, f"LDAP bind failed: {exc}", {"error": "bind_failed"})

    try:
        search_filter = f"(sAMAccountName={target_sam})"
        ok = conn.search(
            search_base=search_base,
            search_filter=search_filter,
            attributes=["distinguishedName", "userAccountControl", "sAMAccountName"],
        )
        if not ok or not conn.entries:
            return (
                False,
                f"User '{target_sam}' not found in {search_base}",
                {"ldap_result": dict(conn.result)},
            )

        entry = conn.entries[0]
        user_dn = str(entry.distinguishedName.value)
        current_uac = int(entry.userAccountControl.value or 0)

        if action_type == "disable_account":
            new_uac = current_uac | _UAC_ACCOUNTDISABLE
            mod_ok = conn.modify(
                user_dn,
                {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]},
            )
            resp = {
                "user_dn": user_dn,
                "old_userAccountControl": current_uac,
                "new_userAccountControl": new_uac,
                "ldap_result": dict(conn.result),
            }
            if mod_ok:
                return (True, f"Disabled AD account {target_sam}", resp)
            return (False, f"Failed to disable {target_sam}: {conn.result.get('description')}", resp)

        if action_type == "reset_password":
            pwd = new_password or _generate_password()
            mod_ok = conn.modify(
                user_dn,
                {
                    "unicodePwd": [(MODIFY_REPLACE, [_encode_ad_password(pwd)])],
                    # Force password change on next logon
                    "pwdLastSet": [(MODIFY_REPLACE, [0])],
                },
            )
            # Do NOT include the password in the response payload.
            resp = {
                "user_dn": user_dn,
                "ldap_result": dict(conn.result),
                "force_change_on_next_logon": True,
            }
            if mod_ok:
                return (True, f"Reset password for AD account {target_sam}", resp)
            return (False, f"Failed to reset password for {target_sam}: {conn.result.get('description')}", resp)

        return (
            False,
            f"Unsupported AD action_type: {action_type}",
            {"error": "unsupported_action_type"},
        )

    finally:
        try:
            conn.unbind()
        except Exception:
            pass


async def execute(action_type: str, params: dict[str, Any], config) -> ExecutorResult:
    """Execute ``disable_account`` or ``reset_password`` against AD.

    Args:
        action_type: ``disable_account`` or ``reset_password``.
        params: ``{"target": "<sAMAccountName>", "new_password": "<optional>"}``.
                For ``reset_password`` a random complex password is
                generated if ``new_password`` is not supplied.  The
                plaintext password is NEVER stored in the result.
        config: ION Config instance.
    """
    started = datetime.now(timezone.utc)
    target = str(params.get("target", "") or "")
    request_payload = {"sAMAccountName": target, "action_type": action_type}

    if action_type not in SUPPORTED_ACTIONS:
        return ExecutorResult(
            success=False,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message=f"Unsupported action_type for AD adapter: {action_type}",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_payload),
            response_payload={},
            error="unsupported_action_type",
        )

    if getattr(config, "exec_dry_run", True):
        verb = "disable" if action_type == "disable_account" else "reset password for"
        return ExecutorResult(
            success=True,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message=f"DRY_RUN — would {verb} AD account {target}",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_payload),
            response_payload={},
            dry_run=True,
        )

    if not is_configured(config):
        return ExecutorResult(
            success=False,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message="AD LDAP adapter not configured",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_payload),
            response_payload={},
            error="not_configured",
        )

    try:
        success, message, response_payload = await asyncio.to_thread(
            _perform_ldap_action,
            action_type,
            target,
            params.get("new_password"),
            ldap_uri=str(config.exec_ad_ldap_uri),
            bind_dn=str(config.exec_ad_bind_dn),
            bind_password=str(config.exec_ad_bind_password),
            search_base=str(config.exec_ad_user_search_base),
            verify_ssl=bool(getattr(config, "exec_ad_verify_ssl", True)),
        )
    except Exception as exc:
        logger.exception("AD adapter crashed for %s on %s", action_type, target)
        return ExecutorResult(
            success=False,
            adapter=ADAPTER_NAME,
            action_type=action_type,
            target=target,
            message=f"AD adapter error: {exc}",
            started_at=started,
            completed_at=datetime.now(timezone.utc),
            request_payload=redact(request_payload),
            response_payload={},
            error=str(exc),
        )

    completed = datetime.now(timezone.utc)
    return ExecutorResult(
        success=success,
        adapter=ADAPTER_NAME,
        action_type=action_type,
        target=target,
        message=message,
        started_at=started,
        completed_at=completed,
        request_payload=redact(request_payload),
        response_payload=redact(response_payload),
        error=None if success else message,
    )
