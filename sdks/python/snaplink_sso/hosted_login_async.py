"""Hosted login for asyncio applications.

The blocking facade in :mod:`.hosted_login` and this module are two views of
one flow, not two flows: the transaction record, its validation, the login URL,
and the activation body all come from the same module-level helpers. Only the
I/O differs, and it runs through an injected
:class:`~snaplink_sso.client.AsyncTransport`, so no call blocks the event loop.

Use :class:`AsyncSnaplink` in an async web application and the blocking
:class:`~snaplink_sso.hosted_login.Snaplink` in a worker, WSGI view, or script.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any, Callable, Dict, Mapping, Optional

from .client import AsyncSSOClient, SSOError
from .entitlement import (
    Entitlement,
    Feature,
    LicenseState,
    entitlement_from_account_context,
    license_state_from_account_context,
    unix_now,
)
from .hosted_login import (
    LoginResult,
    MemoryStateStore,
    StateStore,
    _activation_request,
    _allow_insecure_http,
    _build_login_url,
    _callback_values,
    _canonical_url,
    _new_transaction,
    _normalize_base_url,
    _normalize_redirect_uri,
    _normalize_return_to,
    _pkce_challenge,
    _positive_integer,
    _reject_secrets,
    _required,
    _store_key,
    _take_transaction,
    _validate_callback,
)


class AsyncSnaplink:
    """One-call hosted-login facade for asyncio web applications.

    Every method is a coroutine. The first ``login()`` returns the Console
    redirect; passing ``callback_url`` to the next call exchanges the code with
    PKCE and exposes the bearer-backed client at :attr:`api`.
    """

    def __init__(
        self,
        store: Optional[StateStore] = None,
        *,
        client_factory: Callable[..., AsyncSSOClient] = AsyncSSOClient,
        transport: Optional[Any] = None,
    ) -> None:
        self._store = store or MemoryStateStore()
        self._client_factory = client_factory
        self._transport = transport
        self._client: Optional[AsyncSSOClient] = None
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
        """The latest server-derived account context, in its raw wire shape.

        Prefer :attr:`entitlement` and :meth:`license_state` for gating: an
        entitlement can be present and still grant nothing.
        """

        return self._activation_context

    @property
    def entitlement(self) -> Optional[Entitlement]:
        """The latest entitlement as a typed value, or ``None`` if never activated."""

        return entitlement_from_account_context(self._activation_context)

    def license_state(self, now: Optional[int] = None) -> LicenseState:
        """Classify the current licence, at ``now`` or now by default."""

        return license_state_from_account_context(
            self._activation_context, unix_now() if now is None else now
        )

    def has_feature(self, feature: Feature, now: Optional[int] = None) -> bool:
        """Whether ``feature`` is granted, at ``now`` or now by default."""

        state = self.license_state(now)
        return state.is_active and state.entitlement.has(feature, unix_now() if now is None else now)

    @property
    def api(self) -> AsyncSSOClient:
        if self._client is None:
            raise SSOError(0, "login_required", "call snaplink.login() before using the API client")
        return self._client

    async def login(self, options: Mapping[str, Any]) -> LoginResult:
        """Start or finish hosted login using a public client and S256 PKCE."""

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
            await self._prepare_setup(base_url, client_id, setup)
        if callback is not None:
            return await self._finish_login(base_url, client_id, callback, ttl)
        if self.is_logged_in and self._base_url == base_url and self._client_id == client_id:
            await self._claim_pending_setup(base_url, client_id)
            return LoginResult(tokens=dict(self._tokens or {}), return_to=return_to)
        return self._start(options, base_url, client_id, redirect_uri, return_to, allow_insecure)

    async def setup(self, options: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare a one-time license or invitation activation ticket."""

        _reject_secrets(options)
        allow_insecure = _allow_insecure_http(options)
        base_url = _normalize_base_url(_required(options, "base_url"), allow_insecure)
        client_id = _required(options, "client_id")
        self._configure_client(base_url, client_id)
        return await self._prepare_setup(base_url, client_id, options)

    async def get_account_context(self, product_id: Optional[str] = None) -> Dict[str, Any]:
        """Return the server-derived entitlement and quota context."""

        if self._client is None or not self.access_token:
            raise SSOError(401, "login_required", "login is required")
        resolved_product = product_id or (self._activation_context or {}).get("product_id")
        if not isinstance(resolved_product, str) or not resolved_product.strip():
            raise TypeError("product_id is required")
        response = await self.api.get_my_account_context({"product_id": resolved_product})
        context = response.get("context") if isinstance(response, Mapping) else None
        if not isinstance(context, dict):
            raise SSOError(0, "invalid_response", "account context response was invalid")
        self._activation_context = dict(context)
        return dict(context)

    async def refresh(self) -> Dict[str, Any]:
        """Renew tokens explicitly, preserving a refresh token the server omits."""

        refresh_token = (self._tokens or {}).get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise SSOError(0, "login_required", "no refresh token is held")
        if not self._client_id:
            raise SSOError(0, "login_required", "login is required")
        tokens = dict(await self.api.post_token({
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "refresh_token": refresh_token,
        }))
        if not isinstance(tokens.get("access_token"), str) or not tokens["access_token"]:
            raise SSOError(0, "invalid_response", "token endpoint returned an invalid token response")
        if not tokens.get("refresh_token"):
            tokens["refresh_token"] = refresh_token
        self._tokens = tokens
        return dict(tokens)

    def clear(self) -> None:
        """Forget local tokens and account context without contacting Snaplink."""

        self._tokens = None
        self._activation_context = None

    async def logout(self) -> None:
        """Revoke server-side state, then clear local tokens even on failure."""

        try:
            if self._tokens and self._client:
                await self._client.post_logout({})
        finally:
            self.clear()

    def _start(
        self,
        options: Mapping[str, Any],
        base_url: str,
        client_id: str,
        redirect_uri: str,
        return_to: str,
        allow_insecure: bool,
    ) -> LoginResult:
        transaction = _new_transaction(base_url, client_id, redirect_uri, return_to, self._pending_setup)
        self._store.set(_store_key(client_id), json.dumps(transaction, separators=(",", ":")))
        login_page = options.get("login_page_url") or urllib.parse.urljoin(base_url + "/", "/login/")
        login_url = _build_login_url(
            login_page,
            client_id,
            redirect_uri,
            transaction["state"],
            _pkce_challenge(transaction["code_verifier"]),
            options,
            allow_insecure,
        )
        return LoginResult(redirect_url=login_url, return_to=return_to)

    async def _finish_login(
        self,
        base_url: str,
        client_id: str,
        callback: Mapping[str, str],
        ttl: int,
    ) -> LoginResult:
        transaction = _take_transaction(self._store, _store_key(client_id))
        if transaction is None:
            raise SSOError(0, "invalid_request", "the hosted-login transaction is missing or expired")
        code = _validate_callback(transaction, callback, base_url, client_id, ttl)
        tokens = await self.api.post_token({
            "grant_type": "authorization_code",
            "client_id": transaction["client_id"],
            "code": code,
            "code_verifier": transaction["code_verifier"],
            "redirect_uri": transaction["redirect_uri"],
        })
        self._tokens = dict(tokens)
        ticket = transaction.get("activation_ticket")
        product_id = transaction.get("product_id")
        if isinstance(ticket, str) and isinstance(product_id, str):
            try:
                await self._claim_activation(ticket, product_id)
            except Exception:
                self._tokens = None
                raise
        return LoginResult(tokens=dict(tokens), return_to=transaction["return_to"])

    async def _prepare_setup(
        self,
        base_url: str,
        client_id: str,
        setup: Mapping[str, Any],
    ) -> Dict[str, Any]:
        _reject_secrets(setup)
        response = await self.api.post_activation_prepare(_activation_request(client_id, setup))
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
            "product_id": product_id,
        }
        return dict(response)

    async def _claim_pending_setup(self, base_url: str, client_id: str) -> None:
        pending = self._pending_setup
        if not pending or pending.get("base_url") != base_url or pending.get("client_id") != client_id:
            return
        await self._claim_activation(pending["activation_ticket"], pending["product_id"])

    async def _claim_activation(self, ticket: str, product_id: str) -> None:
        response = await self.api.post_my_activation_claim({
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
            and self._pending_setup.get("client_id") == self._client_id
        ):
            self._pending_setup = None

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
            **({"transport": self._transport} if self._transport is not None else {}),
        )


async_snaplink = AsyncSnaplink()
