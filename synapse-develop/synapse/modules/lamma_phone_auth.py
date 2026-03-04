"""
Lamma Phone Auth Module
=======================
Adds phone-number-based registration and login to Synapse.

Legacy endpoints (kept for backward compat):
  POST /_synapse/client/lamma/request_otp
    Body: { "phone": "+1234567890" }
    Response: { "success": true }

  Matrix login flow (org.lamma.login.phone_otp):
    POST /_matrix/client/v3/login
      Body: { "type": "org.lamma.login.phone_otp", "phone": "+1234567890", "otp": "123456" }

v1 endpoints (used by Lamma iOS):
  POST /_synapse/client/lamma/v1/auth/otp/start
    Body: { "phone_e164": "+1234567890" }
    Response: { "session_id": "+1234567890", "expires_in": 300 }

  POST /_synapse/client/lamma/v1/auth/otp/verify
    Body: { "session_id": "+1234567890", "code": "123456" }
    Response: { "login_token": "...", "user_id": "@...:lamma", "matrix_homeserver": "http://localhost:8008" }

  POST /_synapse/client/lamma/v1/key-backup  (upsert encrypted key backup)
  GET  /_synapse/client/lamma/v1/key-backup  (fetch encrypted key backup)

For production: replace _send_otp() with a real SMS gateway (Twilio, etc.)
For development: OTP is printed to Synapse logs.
"""

import hashlib
import json
import logging
import random
import re
import time
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

from twisted.internet import defer
from twisted.web import http
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET, Request

from twisted.internet.threads import deferToThread

from synapse.module_api import JsonDict, LoginResponse, ModuleApi

try:
    import requests as http_requests
except ImportError:
    http_requests = None

logger = logging.getLogger(__name__)

OTP_TTL = 300  # seconds (5 minutes)
MATRIX_HOMESERVER_URL = "http://192.168.1.125:8008"
# Internal password set for every OTP user so Matrix UIA (encryption reset, etc.) works.
# The iOS app auto-submits this — the user never sees a password prompt.
LAMMA_INTERNAL_PASSWORD = "_lamma_otp_internal_"

# In-memory store: { phone_e164: (otp_or_auth_id, expiry_timestamp) }
_otp_store: Dict[str, Tuple[str, float]] = {}


# ---------------------------------------------------------------------------
# Omantel OTP provider
# ---------------------------------------------------------------------------

class OmantelOTPProvider:
    """Sends and validates OTP via Omantel API (production)."""

    def __init__(self, config: dict) -> None:
        if http_requests is None:
            raise RuntimeError("'requests' package is required for Omantel OTP. pip install requests")
        self.base_url = config.get("omantel_base_url", "https://apigw.omantel.om").rstrip("/")
        self.client_id = config["omantel_client_id"]
        self.client_secret = config["omantel_client_secret"]
        self.scope = config.get("omantel_scope", "one-time-password-sms:send-validate")
        self.sender = config.get("omantel_sender", "Lamma")
        self.message_template = config.get("omantel_message", "Your Lamma code is {{code}}")
        self._token: Optional[str] = None
        self._token_expiry: float = 0

    def _get_token(self) -> str:
        """Get a cached or fresh OAuth2 access token."""
        if self._token and time.time() < self._token_expiry:
            return self._token
        resp = http_requests.post(
            f"{self.base_url}/oauth2/accesstoken",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": self.scope,
            },
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        # Refresh 60s before actual expiry
        self._token_expiry = time.time() + int(data.get("expires_in", 3600)) - 60
        logger.info("[Lamma] Omantel OAuth2 token acquired")
        return self._token

    def send_otp(self, phone: str) -> str:
        """Send OTP via Omantel. Returns authenticationId."""
        token = self._get_token()
        resp = http_requests.post(
            f"{self.base_url}/v1/otp/send-code",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-otp-sms-header": self.sender,
            },
            json={"phoneNumber": phone, "message": self.message_template},
            timeout=15,
        )
        resp.raise_for_status()
        auth_id = resp.json()["authenticationId"]
        logger.info("[Lamma] Omantel OTP sent to %s (authId=%s...)", phone, auth_id[:8])
        return auth_id

    def validate_otp(self, authentication_id: str, code: str) -> bool:
        """Validate OTP via Omantel. Returns True if valid (HTTP 204)."""
        token = self._get_token()
        resp = http_requests.post(
            f"{self.base_url}/v1/otp/validate-code",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "x-otp-sms-header": self.sender,
            },
            json={"authenticationId": authentication_id, "code": code},
            timeout=15,
        )
        return resp.status_code == 204


def _normalise_phone(phone: str) -> str:
    """Strip whitespace/dashes, keep digits and leading +."""
    return re.sub(r"[^\d+]", "", phone.strip())


def _phone_to_localpart(phone: str) -> str:
    """Convert +1234567890 → p1234567890.
    Prefix 'p' avoids Synapse's reserved numeric-only localpart restriction."""
    return "p" + phone.lstrip("+")


def _json_response(request: Request, code: int, data: dict) -> None:
    request.setResponseCode(code)
    request.setHeader(b"Content-Type", b"application/json")
    request.write(json.dumps(data).encode())
    request.finish()


# ---------------------------------------------------------------------------
# Legacy endpoint
# ---------------------------------------------------------------------------

class OtpRequestResource(Resource):
    """Handles POST /_synapse/client/lamma/request_otp (legacy)"""

    isLeaf = True

    def __init__(self, module: "LammaPhoneAuthModule") -> None:
        super().__init__()
        self._module = module

    def render_POST(self, request: Request) -> bytes:
        request.setHeader(b"Content-Type", b"application/json")

        try:
            body = json.loads(request.content.read().decode("utf-8"))
        except Exception:
            request.setResponseCode(http.BAD_REQUEST)
            return json.dumps({"errcode": "M_BAD_JSON", "error": "Invalid JSON"}).encode()

        phone = _normalise_phone(body.get("phone", ""))
        if not phone or not phone.startswith("+"):
            request.setResponseCode(http.BAD_REQUEST)
            return json.dumps(
                {"errcode": "M_INVALID_PARAM", "error": "Provide phone in E.164 format, e.g. +1234567890"}
            ).encode()

        otp = "123456"  # DEV: fixed test OTP
        _otp_store[phone] = (otp, time.time() + OTP_TTL)

        self._module._send_otp(phone, otp)

        return json.dumps({"success": True}).encode()


# ---------------------------------------------------------------------------
# v1 endpoints
# ---------------------------------------------------------------------------

class OtpV1StartResource(Resource):
    """
    POST /_synapse/client/lamma/v1/auth/otp/start
    Body: { "phone_e164": "+1234567890" }
    Response 200: { "session_id": "+1234567890", "expires_in": 300 }
    """

    isLeaf = True

    def __init__(self, module: "LammaPhoneAuthModule") -> None:
        super().__init__()
        self._module = module

    def render_POST(self, request: Request) -> object:
        defer.ensureDeferred(self._start(request))
        return NOT_DONE_YET

    async def _start(self, request: Request) -> None:
        try:
            body = json.loads(request.content.read().decode("utf-8"))
        except Exception:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_BAD_JSON", "error": "Invalid JSON"})
            return

        phone = _normalise_phone(body.get("phone_e164", ""))
        if not phone or not re.match(r"^\+[1-9]\d{7,14}$", phone):
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_INVALID_PARAM", "error": "phone_e164 must be a valid E.164 number"})
            return

        if self._module.use_omantel:
            try:
                auth_id = await deferToThread(self._module.omantel.send_otp, phone)
                _otp_store[phone] = (auth_id, time.time() + OTP_TTL)
            except Exception as e:
                logger.error("[Lamma] Omantel send failed for %s: %s", phone, e)
                _json_response(request, http.INTERNAL_SERVER_ERROR,
                               {"errcode": "M_UNKNOWN", "error": "Failed to send OTP via SMS"})
                return
        else:
            otp = "123456"  # DEV: fixed test OTP
            _otp_store[phone] = (otp, time.time() + OTP_TTL)
            self._module._send_otp(phone, otp)

        _json_response(request, http.OK, {"session_id": phone, "expires_in": OTP_TTL})


class OtpV1VerifyResource(Resource):
    """
    POST /_synapse/client/lamma/v1/auth/otp/verify
    Body: { "session_id": "+1234567890", "code": "123456" }
    Response 200: { "login_token": "...", "user_id": "@...:lamma", "matrix_homeserver": "http://..." }
    """

    isLeaf = True

    def __init__(self, module: "LammaPhoneAuthModule") -> None:
        super().__init__()
        self._module = module

    def render_POST(self, request: Request) -> object:
        try:
            body = json.loads(request.content.read().decode("utf-8"))
        except Exception:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_BAD_JSON", "error": "Invalid JSON"})
            return NOT_DONE_YET

        session_id = body.get("session_id", "")
        code = str(body.get("code", "")).strip()

        if not session_id or not code:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_MISSING_PARAM", "error": "session_id and code are required"})
            return NOT_DONE_YET

        defer.ensureDeferred(self._verify(request, session_id, code))
        return NOT_DONE_YET

    async def _verify(self, request: Request, session_id: str, code: str) -> None:
        phone = _normalise_phone(session_id)

        stored = _otp_store.get(phone)
        if not stored:
            _json_response(request, http.UNAUTHORIZED,
                           {"errcode": "ORG_LAMMA_WRONG_CODE", "error": "No pending OTP for this number"})
            return

        stored_value, expiry = stored
        if time.time() > expiry:
            _otp_store.pop(phone, None)
            _json_response(request, http.UNAUTHORIZED,
                           {"errcode": "ORG_LAMMA_EXPIRED_CODE", "error": "OTP has expired"})
            return

        if self._module.use_omantel:
            # stored_value is the Omantel authenticationId
            try:
                valid = await deferToThread(
                    self._module.omantel.validate_otp, stored_value, code
                )
            except Exception as e:
                logger.error("[Lamma] Omantel validate failed for %s: %s", phone, e)
                _json_response(request, http.INTERNAL_SERVER_ERROR,
                               {"errcode": "M_UNKNOWN", "error": "Failed to validate OTP"})
                return
            if not valid:
                _json_response(request, http.UNAUTHORIZED,
                               {"errcode": "ORG_LAMMA_WRONG_CODE", "error": "Incorrect code"})
                return
        else:
            # Dev mode: stored_value is the OTP code itself
            if code != stored_value:
                _json_response(request, http.UNAUTHORIZED,
                               {"errcode": "ORG_LAMMA_WRONG_CODE", "error": "Incorrect code"})
                return

        # Consume the OTP
        _otp_store.pop(phone, None)

        # Ensure the user exists
        localpart = _phone_to_localpart(phone)
        user_id = f"@{localpart}:{self._module.server_name}"

        try:
            existing = await self._module.api.check_user_exists(user_id)
            if not existing:
                await self._module.api.register_user(localpart=localpart, displayname=phone)
                logger.info("[Lamma] Registered new user %s", user_id)
            else:
                # Reactivate the account if it was previously deactivated
                store = self._module.api._hs.get_datastores().main
                user_info = await store.get_user_by_id(user_id)
                if user_info and user_info.is_deactivated:
                    await store.set_user_deactivated_status(user_id, False)
                    logger.info("[Lamma] Reactivated previously deactivated user %s", user_id)

            # Ensure the user has the internal password so Matrix UIA works
            auth_handler = self._module.api._hs.get_auth_handler()
            pw_hash = await auth_handler.hash(LAMMA_INTERNAL_PASSWORD)
            store = self._module.api._hs.get_datastores().main
            await store.user_set_password_hash(user_id, pw_hash)

            # Create a short-lived Matrix login token
            login_token = await self._module.api.create_login_token(user_id)
        except Exception as e:
            logger.error("[Lamma] Error creating session for %s: %s", user_id, e)
            _json_response(request, http.INTERNAL_SERVER_ERROR,
                           {"errcode": "M_UNKNOWN", "error": "Failed to create session"})
            return

        _json_response(request, http.OK, {
            "login_token": login_token,
            "user_id": user_id,
            "matrix_homeserver": MATRIX_HOMESERVER_URL,
        })
        logger.info("[Lamma] Issued login_token for %s", user_id)


# ---------------------------------------------------------------------------
# Account deactivation (bypasses UIA — auth via Bearer token)
# ---------------------------------------------------------------------------

class AccountDeactivateResource(Resource):
    """
    POST /_synapse/client/lamma/v1/account/deactivate
    Headers: Authorization: Bearer <access_token>
    Body: { "erase": true/false }
    Response 200: {}

    Bypasses Matrix UIA so phone-OTP users can delete their account without
    needing to re-authenticate with a password.
    """

    isLeaf = True

    def __init__(self, module: "LammaPhoneAuthModule") -> None:
        super().__init__()
        self._module = module

    def render_POST(self, request: Request) -> object:
        defer.ensureDeferred(self._deactivate(request))
        return NOT_DONE_YET

    async def _deactivate(self, request: Request) -> None:
        try:
            requester = await self._module.api.get_user_by_req(request)
        except Exception as e:
            _json_response(request, http.UNAUTHORIZED,
                           {"errcode": "M_UNAUTHORIZED", "error": str(e)})
            return

        user_id = requester.user.to_string()

        try:
            body = json.loads(request.content.read().decode("utf-8"))
        except Exception:
            body = {}

        erase = bool(body.get("erase", False))

        try:
            deactivate_handler = self._module.api._hs.get_deactivate_account_handler()
            await deactivate_handler.deactivate_account(user_id, erase_data=erase, requester=requester, by_admin=True)
        except Exception as e:
            logger.error("[Lamma] Failed to deactivate %s: %s", user_id, e)
            _json_response(request, http.INTERNAL_SERVER_ERROR,
                           {"errcode": "M_UNKNOWN", "error": "Failed to deactivate account"})
            return

        logger.info("[Lamma] Account deactivated: %s", user_id)
        _json_response(request, http.OK, {})


# ---------------------------------------------------------------------------
# Contacts sync
# ---------------------------------------------------------------------------

def _hash_phone(phone_e164: str) -> str:
    """SHA-256 hex hash of an E.164 phone number."""
    return hashlib.sha256(phone_e164.encode()).hexdigest()


def _normalise_to_e164(raw: str, default_country_code: str = "968") -> Optional[str]:
    """Best-effort normalisation to E.164.
    +968xxxxxxxx → kept as-is (already E.164).
    00968xxxxxxxx → +968xxxxxxxx
    8-digit number → +968 + number (Oman default).
    Returns None if the result doesn't look like E.164."""
    digits = re.sub(r"[^\d+]", "", raw.strip())
    if digits.startswith("+"):
        phone = digits
    elif digits.startswith("00"):
        phone = "+" + digits[2:]
    elif len(digits) == 8:
        phone = "+" + default_country_code + digits
    else:
        phone = "+" + digits
    if re.match(r"^\+[1-9]\d{7,14}$", phone):
        return phone
    return None


class ContactsSyncResource(Resource):
    """
    POST /_synapse/client/lamma/v1/contacts/sync
    Headers: Authorization: Bearer <access_token>
    Body: {
      "device_contacts": [
        { "name": "Ahmed", "phones": ["+96891234567"], "local_id": "ABCD" }
      ]
    }
    Response 200: {
      "contacts_on_lamma": [ ... ],
      "contacts_not_on_lamma": [ ... ]
    }

    Matches phone hashes against registered Lamma users.
    """

    isLeaf = True
    MAX_PHONES = 5000  # safety limit

    def __init__(self, module: "LammaPhoneAuthModule") -> None:
        super().__init__()
        self._module = module

    def render_POST(self, request: Request) -> object:
        defer.ensureDeferred(self._sync(request))
        return NOT_DONE_YET

    async def _sync(self, request: Request) -> None:
        # Authenticate via Matrix access token
        try:
            requester = await self._module.api.get_user_by_req(request)
        except Exception as e:
            _json_response(request, http.UNAUTHORIZED,
                           {"errcode": "M_UNAUTHORIZED", "error": str(e)})
            return

        try:
            body = json.loads(request.content.read().decode("utf-8"))
        except Exception:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_BAD_JSON", "error": "Invalid JSON"})
            return

        device_contacts = body.get("device_contacts", [])
        if not isinstance(device_contacts, list):
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_INVALID_PARAM", "error": "device_contacts must be a list"})
            return

        # Build hash → contact mapping
        # hash_to_contact: { sha256_hex: (local_id, name, phone_e164) }
        hash_to_contact: Dict[str, Tuple[str, str, str]] = {}
        phone_count = 0
        for c in device_contacts:
            local_id = c.get("local_id", "")
            name = c.get("name", "")
            for raw_phone in c.get("phones", []):
                if phone_count >= self.MAX_PHONES:
                    break
                e164 = _normalise_to_e164(raw_phone)
                if e164:
                    h = _hash_phone(e164)
                    hash_to_contact[h] = (local_id, name, e164)
                    phone_count += 1

        if not hash_to_contact:
            _json_response(request, http.OK,
                           {"contacts_on_lamma": [], "contacts_not_on_lamma": []})
            return

        # Query all registered Lamma users whose phone hash matches.
        # We look up users by their localpart convention: p<digits> = phone.
        # Rather than a separate DB table, we derive the phone_e164 from
        # the localpart (p968XXXXXXXX → +968XXXXXXXX), hash it, and compare.
        store = self._module.api._hs.get_datastores().main
        server_name = self._module.server_name

        # Collect all Lamma users by iterating hash_to_contact keys
        on_lamma: List[dict] = []
        matched_local_ids = set()

        for h, (local_id, name, phone_e164) in hash_to_contact.items():
            # Derive the expected localpart from the phone
            localpart = _phone_to_localpart(phone_e164)
            user_id = f"@{localpart}:{server_name}"

            user_info = await store.get_user_by_id(user_id)
            if user_info and not user_info.is_deactivated:
                # Fetch profile (display name, avatar)
                try:
                    profile = await store.get_profileinfo(localpart)
                    display_name = profile.display_name if profile else None
                    avatar_url = profile.avatar_url if profile else None
                except Exception:
                    display_name = None
                    avatar_url = None

                on_lamma.append({
                    "local_id": local_id,
                    "name": name,
                    "phone": phone_e164,
                    "matrix_user_id": user_id,
                    "display_name": display_name or phone_e164,
                    "avatar_url": avatar_url,
                    "is_active": True,
                })
                matched_local_ids.add(local_id)

        # Build not-on-lamma from unmatched contacts
        not_on_lamma: List[dict] = []
        seen_local_ids = set()
        for h, (local_id, name, phone_e164) in hash_to_contact.items():
            if local_id not in matched_local_ids and local_id not in seen_local_ids:
                not_on_lamma.append({
                    "local_id": local_id,
                    "name": name,
                    "phone": phone_e164,
                })
                seen_local_ids.add(local_id)

        logger.info("[Lamma] Contacts sync for %s: %d on lamma, %d not on lamma",
                    requester.user.to_string(), len(on_lamma), len(not_on_lamma))

        _json_response(request, http.OK, {
            "contacts_on_lamma": on_lamma,
            "contacts_not_on_lamma": not_on_lamma,
        })


# ---------------------------------------------------------------------------
# Encrypted key backup
# ---------------------------------------------------------------------------

# In-memory rate limiter: { user_id: [timestamp, ...] }
_key_backup_rate: Dict[str, List[float]] = {}
KEY_BACKUP_RATE_LIMIT = 5       # max requests
KEY_BACKUP_RATE_WINDOW = 60.0   # per 60 seconds
MAX_ENCRYPTED_BLOB_SIZE = 1_048_576  # 1 MB base64


def _check_key_backup_rate(user_id: str) -> bool:
    """Return True if the request is allowed, False if rate-limited."""
    now = time.time()
    timestamps = _key_backup_rate.get(user_id, [])
    # Remove entries older than the window
    timestamps = [t for t in timestamps if now - t < KEY_BACKUP_RATE_WINDOW]
    if len(timestamps) >= KEY_BACKUP_RATE_LIMIT:
        _key_backup_rate[user_id] = timestamps
        return False
    timestamps.append(now)
    _key_backup_rate[user_id] = timestamps
    return True


async def _ensure_key_backup_table(api: ModuleApi) -> None:
    """Create the lamma_key_backup table if it does not exist."""
    store = api._hs.get_datastores().main

    def _create(txn):
        txn.execute("""
            CREATE TABLE IF NOT EXISTS lamma_key_backup (
                user_id        TEXT PRIMARY KEY,
                salt           TEXT NOT NULL,
                iterations     INTEGER NOT NULL,
                wrapped_dek    TEXT NOT NULL,
                encrypted_blob TEXT NOT NULL,
                version        INTEGER NOT NULL DEFAULT 1,
                created_at     BIGINT NOT NULL,
                updated_at     BIGINT NOT NULL
            )
        """)

    await store.db_pool.runInteraction("lamma_create_key_backup_table", _create)
    logger.info("[Lamma] key_backup table ensured")


class KeyBackupResource(Resource):
    """
    POST /_synapse/client/lamma/v1/key-backup
    Headers: Authorization: Bearer <access_token>
    Body: {
        "salt": "<base64>",
        "iterations": 200000,
        "wrapped_dek": "<base64>",
        "encrypted_blob": "<base64>",
        "version": 1
    }
    Response 200: {}

    GET /_synapse/client/lamma/v1/key-backup
    Headers: Authorization: Bearer <access_token>
    Response 200: { salt, iterations, wrapped_dek, encrypted_blob, version, created_at, updated_at }
    Response 404: { "errcode": "M_NOT_FOUND" }
    """

    isLeaf = True

    def __init__(self, module: "LammaPhoneAuthModule") -> None:
        super().__init__()
        self._module = module

    # -- POST (upsert) -------------------------------------------------------

    def render_POST(self, request: Request) -> object:
        defer.ensureDeferred(self._upsert(request))
        return NOT_DONE_YET

    async def _upsert(self, request: Request) -> None:
        # Authenticate
        try:
            requester = await self._module.api.get_user_by_req(request)
        except Exception as e:
            _json_response(request, http.UNAUTHORIZED,
                           {"errcode": "M_UNAUTHORIZED", "error": str(e)})
            return

        user_id = requester.user.to_string()

        # Rate limit
        if not _check_key_backup_rate(user_id):
            _json_response(request, 429, {
                "errcode": "M_LIMIT_EXCEEDED",
                "error": "Too many key-backup requests",
                "retry_after_ms": 60000,
            })
            return

        # Parse body
        try:
            body = json.loads(request.content.read().decode("utf-8"))
        except Exception:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_BAD_JSON", "error": "Invalid JSON"})
            return

        # Validate required fields
        salt = body.get("salt", "")
        iterations = body.get("iterations", 0)
        wrapped_dek = body.get("wrapped_dek", "")
        encrypted_blob = body.get("encrypted_blob", "")
        version = body.get("version", 0)

        if not salt or not isinstance(salt, str) or len(salt) > 64:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_INVALID_PARAM", "error": "salt must be a non-empty string (max 64 chars)"})
            return
        if not isinstance(iterations, int) or iterations < 100000:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_INVALID_PARAM", "error": "iterations must be an integer >= 100000"})
            return
        if not wrapped_dek or not isinstance(wrapped_dek, str) or len(wrapped_dek) > 256:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_INVALID_PARAM", "error": "wrapped_dek must be a non-empty string (max 256 chars)"})
            return
        if not encrypted_blob or not isinstance(encrypted_blob, str):
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_INVALID_PARAM", "error": "encrypted_blob must be a non-empty string"})
            return
        if len(encrypted_blob) > MAX_ENCRYPTED_BLOB_SIZE:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_TOO_LARGE", "error": "encrypted_blob exceeds 1 MB"})
            return
        if not isinstance(version, int) or version < 1:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_INVALID_PARAM", "error": "version must be an integer >= 1"})
            return

        now_ms = int(time.time() * 1000)
        store = self._module.api._hs.get_datastores().main

        def _do_upsert(txn):
            txn.execute(
                """
                INSERT INTO lamma_key_backup
                    (user_id, salt, iterations, wrapped_dek, encrypted_blob, version, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                    salt = EXCLUDED.salt,
                    iterations = EXCLUDED.iterations,
                    wrapped_dek = EXCLUDED.wrapped_dek,
                    encrypted_blob = EXCLUDED.encrypted_blob,
                    version = EXCLUDED.version,
                    updated_at = EXCLUDED.updated_at
                """,
                (user_id, salt, iterations, wrapped_dek, encrypted_blob, version, now_ms, now_ms),
            )

        try:
            await store.db_pool.runInteraction("lamma_upsert_key_backup", _do_upsert)
        except Exception as e:
            logger.error("[Lamma] Failed to upsert key backup for %s: %s", user_id, e)
            _json_response(request, http.INTERNAL_SERVER_ERROR,
                           {"errcode": "M_UNKNOWN", "error": "Failed to store key backup"})
            return

        logger.info("[Lamma] Key backup upserted for %s (version=%d)", user_id, version)
        _json_response(request, http.OK, {})

    # -- GET (fetch) ----------------------------------------------------------

    def render_GET(self, request: Request) -> object:
        defer.ensureDeferred(self._fetch(request))
        return NOT_DONE_YET

    async def _fetch(self, request: Request) -> None:
        # Authenticate
        try:
            requester = await self._module.api.get_user_by_req(request)
        except Exception as e:
            _json_response(request, http.UNAUTHORIZED,
                           {"errcode": "M_UNAUTHORIZED", "error": str(e)})
            return

        user_id = requester.user.to_string()
        store = self._module.api._hs.get_datastores().main

        def _do_fetch(txn):
            txn.execute(
                """
                SELECT salt, iterations, wrapped_dek, encrypted_blob, version, created_at, updated_at
                FROM lamma_key_backup
                WHERE user_id = %s
                """,
                (user_id,),
            )
            return txn.fetchone()

        try:
            row = await store.db_pool.runInteraction("lamma_fetch_key_backup", _do_fetch)
        except Exception as e:
            logger.error("[Lamma] Failed to fetch key backup for %s: %s", user_id, e)
            _json_response(request, http.INTERNAL_SERVER_ERROR,
                           {"errcode": "M_UNKNOWN", "error": "Failed to fetch key backup"})
            return

        if row is None:
            _json_response(request, http.NOT_FOUND,
                           {"errcode": "M_NOT_FOUND", "error": "No key backup found"})
            return

        _json_response(request, http.OK, {
            "salt": row[0],
            "iterations": row[1],
            "wrapped_dek": row[2],
            "encrypted_blob": row[3],
            "version": row[4],
            "created_at": row[5],
            "updated_at": row[6],
        })


# ---------------------------------------------------------------------------
# Recovery key storage (server-stored SDK recovery key for auto-restore)
# ---------------------------------------------------------------------------

async def _ensure_recovery_key_table(api: ModuleApi) -> None:
    """Create the lamma_recovery_key table if it does not exist."""
    store = api._hs.get_datastores().main

    def _create(txn):
        txn.execute("""
            CREATE TABLE IF NOT EXISTS lamma_recovery_key (
                user_id      TEXT PRIMARY KEY,
                recovery_key TEXT NOT NULL,
                updated_at   BIGINT NOT NULL
            )
        """)

    await store.db_pool.runInteraction("lamma_create_recovery_key_table", _create)
    logger.info("[Lamma] recovery_key table ensured")


class RecoveryKeyResource(Resource):
    """
    POST /_synapse/client/lamma/v1/recovery-key
    Body: { "recovery_key": "<string>" }
    Response 200: {}

    GET /_synapse/client/lamma/v1/recovery-key
    Response 200: { "recovery_key": "<string>" }
    Response 404: { "errcode": "M_NOT_FOUND" }
    """

    isLeaf = True

    def __init__(self, module: "LammaPhoneAuthModule") -> None:
        super().__init__()
        self._module = module

    # -- POST (store) ---------------------------------------------------------

    def render_POST(self, request: Request) -> object:
        defer.ensureDeferred(self._store(request))
        return NOT_DONE_YET

    async def _store(self, request: Request) -> None:
        try:
            requester = await self._module.api.get_user_by_req(request)
        except Exception as e:
            _json_response(request, http.UNAUTHORIZED,
                           {"errcode": "M_UNAUTHORIZED", "error": str(e)})
            return

        user_id = requester.user.to_string()

        try:
            body = json.loads(request.content.read().decode("utf-8"))
        except Exception:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_BAD_JSON", "error": "Invalid JSON"})
            return

        recovery_key = body.get("recovery_key", "")
        if not recovery_key or not isinstance(recovery_key, str) or len(recovery_key) > 1024:
            _json_response(request, http.BAD_REQUEST,
                           {"errcode": "M_INVALID_PARAM",
                            "error": "recovery_key must be a non-empty string (max 1024 chars)"})
            return

        now_ms = int(time.time() * 1000)
        store = self._module.api._hs.get_datastores().main

        def _do_upsert(txn):
            txn.execute(
                """
                INSERT INTO lamma_recovery_key (user_id, recovery_key, updated_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET
                    recovery_key = EXCLUDED.recovery_key,
                    updated_at = EXCLUDED.updated_at
                """,
                (user_id, recovery_key, now_ms),
            )

        try:
            await store.db_pool.runInteraction("lamma_upsert_recovery_key", _do_upsert)
        except Exception as e:
            logger.error("[Lamma] Failed to store recovery key for %s: %s", user_id, e)
            _json_response(request, http.INTERNAL_SERVER_ERROR,
                           {"errcode": "M_UNKNOWN", "error": "Failed to store recovery key"})
            return

        logger.info("[Lamma] Recovery key stored for %s", user_id)
        _json_response(request, http.OK, {})

    # -- GET (fetch) ----------------------------------------------------------

    def render_GET(self, request: Request) -> object:
        defer.ensureDeferred(self._fetch(request))
        return NOT_DONE_YET

    async def _fetch(self, request: Request) -> None:
        try:
            requester = await self._module.api.get_user_by_req(request)
        except Exception as e:
            _json_response(request, http.UNAUTHORIZED,
                           {"errcode": "M_UNAUTHORIZED", "error": str(e)})
            return

        user_id = requester.user.to_string()
        store = self._module.api._hs.get_datastores().main

        def _do_fetch(txn):
            txn.execute(
                "SELECT recovery_key FROM lamma_recovery_key WHERE user_id = %s",
                (user_id,),
            )
            return txn.fetchone()

        try:
            row = await store.db_pool.runInteraction("lamma_fetch_recovery_key", _do_fetch)
        except Exception as e:
            logger.error("[Lamma] Failed to fetch recovery key for %s: %s", user_id, e)
            _json_response(request, http.INTERNAL_SERVER_ERROR,
                           {"errcode": "M_UNKNOWN", "error": "Failed to fetch recovery key"})
            return

        if row is None:
            _json_response(request, http.NOT_FOUND,
                           {"errcode": "M_NOT_FOUND", "error": "No recovery key found"})
            return

        _json_response(request, http.OK, {"recovery_key": row[0]})


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------

class LammaPhoneAuthModule:
    def __init__(self, config: dict, api: ModuleApi) -> None:
        self.api = api
        self.server_name = api.server_name

        # Omantel OTP toggle: true = production (real SMS), false = dev (fixed code)
        self.use_omantel: bool = config.get("use_omantel_otp", False)
        self.omantel: Optional[OmantelOTPProvider] = None

        if self.use_omantel:
            self.omantel = OmantelOTPProvider(config)
            logger.info("[Lamma] Omantel OTP ENABLED (production mode)")
        else:
            logger.info("[Lamma] Omantel OTP DISABLED (dev mode — fixed code 123456)")

        # Legacy endpoint
        api.register_web_resource(
            "/_synapse/client/lamma/request_otp",
            OtpRequestResource(self),
        )

        # v1 endpoints
        api.register_web_resource(
            "/_synapse/client/lamma/v1/auth/otp/start",
            OtpV1StartResource(self),
        )
        api.register_web_resource(
            "/_synapse/client/lamma/v1/auth/otp/verify",
            OtpV1VerifyResource(self),
        )
        api.register_web_resource(
            "/_synapse/client/lamma/v1/account/deactivate",
            AccountDeactivateResource(self),
        )
        api.register_web_resource(
            "/_synapse/client/lamma/v1/contacts/sync",
            ContactsSyncResource(self),
        )
        api.register_web_resource(
            "/_synapse/client/lamma/v1/key-backup",
            KeyBackupResource(self),
        )
        api.register_web_resource(
            "/_synapse/client/lamma/v1/recovery-key",
            RecoveryKeyResource(self),
        )

        # Create tables on startup
        defer.ensureDeferred(_ensure_key_backup_table(api))
        defer.ensureDeferred(_ensure_recovery_key_table(api))

        # Legacy Matrix login type
        api.register_password_auth_provider_callbacks(
            auth_checkers={
                ("org.lamma.login.phone_otp", ("phone", "otp")): self._check_phone_otp,
            }
        )

        logger.info("[Lamma] Phone auth module loaded. Server: %s", self.server_name)

    @staticmethod
    def parse_config(config: dict) -> dict:
        return config

    def _send_otp(self, phone: str, otp: str) -> None:
        """
        Send OTP to the user.
        DEV MODE: logs to console.
        PRODUCTION: replace with Twilio/AWS SNS/etc.
        """
        logger.warning("=" * 50)
        logger.warning("[Lamma] OTP for %s  →  %s", phone, otp)
        logger.warning("=" * 50)

        # --- Twilio example (uncomment and configure) ---
        # from twilio.rest import Client
        # client = Client(self._config.get("twilio_sid"), self._config.get("twilio_token"))
        # client.messages.create(
        #     body=f"Your Lamma code: {otp}",
        #     from_=self._config.get("twilio_from"),
        #     to=phone,
        # )

    async def _check_phone_otp(
        self,
        user: str,
        login_type: str,
        login_dict: JsonDict,
    ) -> Optional[Tuple[str, Optional[Callable[[LoginResponse], Awaitable[None]]]]]:
        """Called by Synapse when a client sends type=org.lamma.login.phone_otp (legacy)."""

        phone = _normalise_phone(login_dict.get("phone", ""))
        otp = str(login_dict.get("otp", "")).strip()

        if not phone or not otp:
            return None

        stored = _otp_store.get(phone)
        if not stored:
            logger.info("[Lamma] No OTP found for %s", phone)
            return None

        stored_otp, expiry = stored
        if time.time() > expiry:
            _otp_store.pop(phone, None)
            logger.info("[Lamma] OTP expired for %s", phone)
            return None

        if otp != stored_otp:
            logger.info("[Lamma] Wrong OTP for %s", phone)
            return None

        # OTP valid — consume it
        _otp_store.pop(phone, None)

        localpart = _phone_to_localpart(phone)
        user_id = f"@{localpart}:{self.server_name}"

        # Create user if first login
        existing = await self.api.check_user_exists(user_id)
        if not existing:
            await self.api.register_user(localpart=localpart, displayname=phone)
            logger.info("[Lamma] Registered new user %s", user_id)

        logger.info("[Lamma] Login success for %s", user_id)
        return user_id, None
