"""Public-client hosted login helpers for Snaplink.

The helper is framework-neutral: the first ``login`` call returns a redirect
URL, and the callback call validates state/issuer and exchanges the code with
PKCE. A web framework can return the URL as its 302 response without adding a
separate BFF layer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Sequence, Union

try:
    from .client import SSOClient, SSOError
except ImportError:  # Allow the two SDK files to be vendored side by side.
    from client import SSOClient, SSOError


class StateStore(Protocol):
    """Storage for one short-lived state/verifier transaction."""

    def take(self, key: str) -> Optional[str]: ...

    def set(self, key: str, value: str) -> None: ...


class MemoryStateStore:
    """Small in-process store for development and single-process examples."""

    def __init__(self) -> None:
        self._values: Dict[str, str] = {}

    def take(self, key: str) -> Optional[str]:
        return self._values.pop(key, None)

    def set(self, key: str, value: str) -> None:
        self._values[key] = value

@dataclass
class LoginResult:
    """Either a redirect action or the completed public-client token result."""

    redirect_url: Optional[str] = None
    tokens: Optional[Dict[str, Any]] = None
    return_to: Optional[str] = None

    @property
    def complete(self) -> bool:
        return self.tokens is not None


class Snaplink:
    """One-call hosted-login facade for Python web applications."""

    def __init__(
        self,
        store: Optional[StateStore] = None,
        *,
        client_factory: Callable[..., SSOClient] = SSOClient,
    ) -> None:
        self._store = store or MemoryStateStore()
        self._client_factory = client_factory
        self._client: Optional[SSOClient] = None
        self._tokens: Optional[Dict[str, Any]] = None
        self._client_id: Optional[str] = None
        self._base_url: Optional[str] = None
        self._pending_setup: Optional[Dict[str, Any]] = None
        self._activation_context: Optional[Dict[str, Any]] = None

    @property
    def is_logged_in(self) -> bool:
        return bool(self._tokens and self._tokens.get("access_token"))

    @property
    def access_token(self) -> Optional[str]:
        if not self._tokens:
            return None
        token = self._tokens.get("access_token")
        return token if isinstance(token, str) else None

    @property
    def account_context(self) -> Optional[Dict[str, Any]]:
        """The latest server-derived product/account context, if available."""

        return self._activation_context

    @property
    def api(self) -> SSOClient:
        if self._client is None:
            raise SSOError(0, "login_required", "call snaplink.login() before using the API client")
        return self._client

    def login(self, options: Mapping[str, Any]) -> LoginResult:
        """Start or finish hosted login using a public client and S256 PKCE.

        The initial call returns ``LoginResult.redirect_url``. Pass the full
        callback URL as ``callback_url`` on the next call; the same method then
        returns ``LoginResult.tokens`` and exposes the bearer-backed API at
        ``snaplink.api``.
        """

        _reject_secrets(options)
        allow_insecure = _allow_insecure_http(options)
        base_url = _normalize_base_url(_required(options, "base_url"), allow_insecure)
        client_id = _required(options, "client_id")
        redirect_uri = _normalize_redirect_uri(options.get("redirect_uri"), allow_insecure)
        return_to = _normalize_return_to(options.get("return_to"), redirect_uri)
        ttl = _positive_integer(options.get("transaction_ttl_seconds", 600), "transaction_ttl_seconds")
        self._configure_client(base_url, client_id)

        callback = _callback_values(options, redirect_uri, allow_insecure)
        if callback is None and options.get("setup") is not None:
            setup = options.get("setup")
            if not isinstance(setup, Mapping):
                raise TypeError("setup must be a mapping")
            self._prepare_setup(base_url, client_id, setup)
        if callback is not None:
            return self._finish_login(base_url, client_id, callback, ttl)
        if self.is_logged_in and self._base_url == base_url and self._client_id == client_id:
            self._claim_pending_setup(base_url, client_id)
            return LoginResult(tokens=dict(self._tokens or {}), return_to=return_to)

        state = _random_urlsafe(32)
        verifier = _random_urlsafe(64)
        transaction = {
            "base_url": base_url,
            "client_id": client_id,
            "code_verifier": verifier,
            "created_at": int(time.time()),
            "redirect_uri": redirect_uri,
            "return_to": return_to,
            "state": state,
        }
        if self._pending_setup is not None:
            transaction.update({
                "activation_ticket": self._pending_setup["activation_ticket"],
                "product_id": self._pending_setup["product_id"],
            })
        self._store.set(_store_key(client_id), json.dumps(transaction, separators=(",", ":")))
        login_page = options.get("login_page_url") or urllib.parse.urljoin(base_url + "/", "/login/")
        login_url = _build_login_url(
            login_page,
            client_id,
            redirect_uri,
            state,
            _pkce_challenge(verifier),
            options,
            allow_insecure,
        )
        return LoginResult(redirect_url=login_url, return_to=return_to)

    def setup(self, options: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare a one-time license or invitation activation ticket."""

        _reject_secrets(options)
        allow_insecure = _allow_insecure_http(options)
        base_url = _normalize_base_url(_required(options, "base_url"), allow_insecure)
        client_id = _required(options, "client_id")
        self._configure_client(base_url, client_id)
        return self._prepare_setup(base_url, client_id, options)

    def get_account_context(self, product_id: Optional[str] = None) -> Dict[str, Any]:
        """Return the server-derived entitlement and quota context."""

        if self._client is None or not self.access_token:
            raise SSOError(401, "login_required", "login is required")
        resolved_product = product_id or (self._activation_context or {}).get("product_id")
        if not isinstance(resolved_product, str) or not resolved_product.strip():
            raise TypeError("product_id is required")
        response = self.api.get_my_account_context({"product_id": resolved_product})
        context = response.get("context") if isinstance(response, Mapping) else None
        if not isinstance(context, dict):
            raise SSOError(0, "invalid_response", "account context response was invalid")
        self._activation_context = dict(context)
        return dict(context)

    def logout(self) -> None:
        try:
            if self._tokens and self._client:
                self._client.post_logout({})
        finally:
            self._tokens = None
            self._client = None
            self._client_id = None
            self._base_url = None
            self._pending_setup = None
            self._activation_context = None

    def _configure_client(self, base_url: str, client_id: str) -> None:
        if self._client and self._base_url == base_url and self._client_id == client_id:
            return
        self._tokens = None
        self._pending_setup = None
        self._activation_context = None
        self._base_url = base_url
        self._client_id = client_id
        self._client = self._client_factory(
            base_url,
            client_id=client_id,
            get_access_token=lambda: self.access_token,
        )

    def _finish_login(
        self,
        base_url: str,
        client_id: str,
        callback: Mapping[str, str],
        ttl: int,
    ) -> LoginResult:
        key = _store_key(client_id)
        transaction = _take_transaction(self._store, key)
        if transaction is None or int(time.time()) - int(transaction["created_at"]) > ttl:
            raise SSOError(0, "invalid_request", "the hosted-login transaction is missing or expired")
        if transaction.get("client_id") != client_id or _canonical_url(str(transaction.get("base_url", ""))) != _canonical_url(base_url):
            raise SSOError(0, "invalid_request", "the hosted-login transaction belongs to another client")
        if callback.get("state") != transaction["state"]:
            raise SSOError(0, "invalid_request", "the hosted-login state did not match")
        if _canonical_url(callback.get("iss", "")) != _canonical_url(base_url):
            raise SSOError(0, "invalid_request", "the authorization issuer did not match Snaplink")
        if callback.get("error"):
            raise SSOError(0, callback["error"], callback.get("error_description"))
        code = callback.get("code")
        if not code:
            raise SSOError(0, "invalid_request", "the authorization response did not contain a code")
        tokens = self.api.post_token({
            "grant_type": "authorization_code",
            "client_id": transaction["client_id"],
            "code": code,
            "code_verifier": transaction["code_verifier"],
            "redirect_uri": transaction["redirect_uri"],
        })
        self._tokens = dict(tokens)
        try:
            ticket = transaction.get("activation_ticket")
            product_id = transaction.get("product_id")
            if isinstance(ticket, str) and isinstance(product_id, str):
                self._claim_activation(base_url, client_id, ticket, product_id)
        except Exception:
            self._tokens = None
            raise
        return LoginResult(tokens=dict(tokens), return_to=transaction["return_to"])

    def _prepare_setup(
        self,
        base_url: str,
        client_id: str,
        setup: Mapping[str, Any],
    ) -> Dict[str, Any]:
        _reject_secrets(setup)
        body = _activation_request(client_id, setup)
        response = self.api.post_activation_prepare(body)
        if not isinstance(response, Mapping):
            raise SSOError(0, "invalid_response", "activation endpoint returned an invalid response")
        ticket = response.get("activation_ticket")
        product_id = response.get("product_id")
        if not isinstance(ticket, str) or not ticket or not isinstance(product_id, str) or not product_id:
            raise SSOError(0, "invalid_response", "activation endpoint returned an invalid ticket")
        self._pending_setup = {
            "activation_ticket": ticket,
            "base_url": base_url,
            "client_id": client_id,
            "created_at": int(time.time()),
            "product_id": product_id,
        }
        return dict(response)

    def _claim_pending_setup(self, base_url: str, client_id: str) -> None:
        pending = self._pending_setup
        if not pending or pending.get("base_url") != base_url or pending.get("client_id") != client_id:
            return
        self._claim_activation(base_url, client_id, pending["activation_ticket"], pending["product_id"])

    def _claim_activation(self, base_url: str, client_id: str, ticket: str, product_id: str) -> None:
        response = self.api.post_my_activation_claim({
            "activation_ticket": ticket,
            "product_id": product_id,
        })
        context = response.get("context") if isinstance(response, Mapping) else None
        if not isinstance(context, dict):
            raise SSOError(0, "invalid_response", "activation claim response was invalid")
        self._activation_context = dict(context)
        if (
            self._pending_setup
            and self._pending_setup.get("activation_ticket") == ticket
            and self._pending_setup.get("client_id") == client_id
        ):
            self._pending_setup = None


snaplink = Snaplink()


def _callback_values(
    options: Mapping[str, Any], redirect_uri: str, allow_insecure: bool
) -> Optional[Dict[str, str]]:
    callback_url = options.get("callback_url")
    if callback_url:
        parsed = urllib.parse.urlsplit(str(callback_url))
        _validate_http_url(parsed, "callback_url", allow_query=True, allow_insecure=allow_insecure)
        if parsed.fragment or parsed.username or parsed.password:
            raise TypeError("callback_url must not contain credentials or a fragment")
        if _canonical_url(str(callback_url)) != _canonical_url(redirect_uri):
            raise TypeError("callback_url does not match redirect_uri")
        values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not values:
            return None
        return {key: item[0] for key, item in values.items() if item}
    raw = options.get("callback_params")
    if not raw:
        return None
    if not isinstance(raw, Mapping):
        raise TypeError("callback_params must be a mapping")
    return {str(key): _first(value) for key, value in raw.items()}


def _first(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return str(value)


def _take_transaction(store: StateStore, key: str) -> Optional[Dict[str, Any]]:
    raw = store.take(key)
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _build_login_url(
    login_page: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    challenge: str,
    options: Mapping[str, Any],
    allow_insecure: bool,
) -> str:
    parsed = urllib.parse.urlsplit(login_page)
    _validate_http_url(parsed, "login_page_url", allow_query=True, allow_insecure=allow_insecure)
    if parsed.fragment or parsed.username or parsed.password:
        raise TypeError("login_page_url must not contain credentials or a fragment")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    managed = {
        "client_id", "redirect_uri", "response_type", "response_mode", "scope", "state",
        "code_challenge", "code_challenge_method", "resource", "prompt", "max_age",
        "login_hint", "acr_values", "ui_locales",
    }
    query = [(key, value) for key, value in query if key not in managed]
    scopes = options.get("scope") or ["openid", "profile", "email"]
    if not isinstance(scopes, Sequence) or isinstance(scopes, (str, bytes)) or not scopes:
        raise TypeError("scope must contain at least one value")
    if any(not isinstance(scope, str) or not scope or any(char.isspace() for char in scope) for scope in scopes):
        raise TypeError("scope values must be non-empty and must not contain whitespace")
    query.extend([
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("response_mode", "query"),
        ("scope", " ".join(scopes)),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ])
    for key, value in (("prompt", options.get("prompt")), ("login_hint", options.get("login_hint")),
                       ("max_age", options.get("max_age")), ("acr_values", options.get("acr_values")),
                       ("ui_locales", options.get("ui_locales"))):
        if value is not None:
            query.append((key, _space_values(value, key)))
    resources = options.get("resource") or []
    for resource in resources:
        if not isinstance(resource, str) or not resource:
            raise TypeError("resource values must be non-empty strings")
        query.append(("resource", resource))
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ""))


def _space_values(value: Union[str, Sequence[str]], name: str) -> str:
    values = [value] if isinstance(value, str) else list(value)
    if not values or any(not isinstance(item, str) or not item or any(char.isspace() for char in item) for item in values):
        raise TypeError(f"{name} values must be non-empty and must not contain whitespace")
    return " ".join(values)


def _normalize_base_url(value: Any, allow_insecure: bool = False) -> str:
    parsed = urllib.parse.urlsplit(_required_value(value, "base_url"))
    _validate_http_url(parsed, "base_url", allow_insecure=allow_insecure)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise TypeError("base_url must not contain credentials, a query, or a fragment")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _normalize_redirect_uri(value: Any, allow_insecure: bool = False) -> str:
    parsed = urllib.parse.urlsplit(_required_value(value, "redirect_uri"))
    _validate_http_url(parsed, "redirect_uri", allow_insecure=allow_insecure)
    if parsed.fragment or parsed.username or parsed.password:
        raise TypeError("redirect_uri must not contain credentials or a fragment")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))


def _normalize_return_to(value: Any, redirect_uri: str) -> str:
    if value is None:
        return redirect_uri
    parsed = urllib.parse.urlsplit(str(value))
    target = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment))
    redirect = urllib.parse.urlsplit(redirect_uri)
    if (parsed.scheme, parsed.netloc) != (redirect.scheme, redirect.netloc):
        raise TypeError("return_to must use the redirect URI origin")
    return target


def _validate_http_url(
    parsed: urllib.parse.SplitResult,
    name: str,
    allow_query: bool = False,
    allow_insecure: bool = False,
) -> None:
    if not parsed.scheme or not parsed.netloc:
        raise TypeError(f"{name} must be an absolute HTTP(S) URL")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and (_loopback(parsed.hostname or "") or allow_insecure)
    ):
        raise TypeError(f"{name} must use HTTPS or loopback HTTP")
    if not allow_query and parsed.query:
        raise TypeError(f"{name} must not contain a query")


def _loopback(host: str) -> bool:
    return host.lower().strip("[]") in {"localhost", "127.0.0.1", "::1"}


def _canonical_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _required(options: Mapping[str, Any], key: str) -> str:
    return _required_value(options.get(key), key)


def _allow_insecure_http(options: Mapping[str, Any]) -> bool:
    value = options.get("allow_insecure_http_for_development")
    if value is None:
        value = options.get("allowInsecureHttpForDevelopment")
    if value is None:
        return False
    if not isinstance(value, bool):
        raise TypeError("allow_insecure_http_for_development must be a boolean")
    return value


def _required_value(value: Any, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{key} is required")
    return value


def _positive_integer(value: Any, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{key} must be a positive integer")
    return value


def _random_urlsafe(size: int) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(size)).rstrip(b"=").decode("ascii")


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _store_key(client_id: str) -> str:
    return "snaplink.login.v1:" + urllib.parse.quote(client_id, safe="")


def _reject_secrets(options: Mapping[str, Any]) -> None:
    if "client_secret" in options or "clientSecret" in options:
        raise TypeError("hosted browser login does not accept client secrets")


def _activation_request(client_id: str, setup: Mapping[str, Any]) -> Dict[str, Any]:
    product_id = _required_value(_setup_option(setup, "product_id", "productId"), "product_id")
    license_key = _optional_text(_setup_option(setup, "license_key", "licenseKey"))
    invitation_code = _optional_text(_setup_option(setup, "invitation_code", "invitationCode"))
    if (license_key == "") == (invitation_code == ""):
        raise SSOError(0, "invalid_request", "exactly one of license_key or invitation_code is required")
    body: Dict[str, Any] = {"client_id": client_id, "product_id": product_id}
    if license_key:
        body["license_key"] = license_key
    if invitation_code:
        body["invitation_code"] = invitation_code
    for snake, camel in (("tenant_hint", "tenantHint"), ("locale", "locale"), ("app_version", "appVersion")):
        value = _setup_option(setup, snake, camel)
        if isinstance(value, str) and value:
            body[snake] = value
    return body


def _setup_option(options: Mapping[str, Any], snake: str, camel: str) -> Any:
    if snake in options:
        return options[snake]
    return options.get(camel)


def _optional_text(value: Any) -> str:
    return value if isinstance(value, str) else ""
