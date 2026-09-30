package main

// pyAsyncRuntimePrelude is the event-loop transport seam. It is emitted
// after the blocking prelude because AsyncioTransport delegates to it.
const pyAsyncRuntimePrelude = `class AsyncTransport(Protocol):
    """The event-loop seam. Implement it with any async HTTP client."""

    async def send(self, request: HttpRequest) -> HttpResponse: ...


class AsyncioTransport:
    """Default async transport.

    The stdlib has no async HTTP client, so the blocking call runs in the event
    loop's executor: the loop is never blocked, and a caller who wants a real
    async stack injects its own AsyncTransport rather than making this package
    take a dependency. Redirects are refused for the same reason the blocking
    transport refuses them.
    """

    def __init__(self, timeout: Optional[float] = None) -> None:
        self._delegate = UrllibTransport(timeout)

    async def send(self, request: HttpRequest) -> HttpResponse:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._delegate.send, request)
`

// pyAsyncClientHeader opens the event-loop twin of SSOClient. It carries no
// login/logout convenience wrapper on purpose: the hosted-login lifecycle lives
// in the hand-written hosted_login_async module, so the two surfaces cannot
// disagree about when a session is renewed.
const pyAsyncClientHeader = `class AsyncSSOClient:
    """The same operation surface as SSOClient, for asyncio callers.

    Every method is a coroutine and every request goes through an injected
    AsyncTransport, so no call blocks the event loop.
    """

    def __init__(
        self,
        base_url: str,
        get_access_token: Optional[Callable[[], Optional[str]]] = None,
        *,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        request_timeout: Optional[float] = None,
        transport: Optional[AsyncTransport] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.request_timeout = request_timeout
        self.transport: AsyncTransport = transport or AsyncioTransport(request_timeout)
        self._token: Optional[str] = None
        self.get_access_token = get_access_token or (lambda: self._token)

    @property
    def is_logged_in(self) -> bool:
        return bool(self._token)

    @property
    def access_token(self) -> Optional[str]:
        return self._token

    def set_access_token(self, token: Optional[str]) -> None:
        """Adopt a token this application persisted itself."""

        self._token = token

    async def _request(
        self,
        method: str,
        path: str,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
        auth: bool = False,
        form: bool = False,
        form_blocked_fields: Optional[List[str]] = None,
        client_auth: bool = False,
    ) -> Any:
        url = self.base_url + path
        if query:
            filtered = {k: v for k, v in query.items() if v is not None}
            if filtered:
                url += "?" + urllib.parse.urlencode(filtered)
        headers = {"Accept": "application/json"}
        authenticated_body = self._with_client_auth(body, headers) if client_auth else body
        data = None
        if authenticated_body is not None:
            if form:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                data = _form_encode(authenticated_body, form_blocked_fields).encode("utf-8")
            else:
                headers["Content-Type"] = "application/json"
                data = json.dumps(authenticated_body).encode("utf-8")
        if auth and self.get_access_token:
            token = self.get_access_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        response = await self.transport.send({
            "method": method,
            "url": url,
            "headers": headers,
            "body": data,
        })
        status = int(response["status"])
        raw = response["body"] or b""
        if status < 200 or status >= 300:
            raise _protocol_error(status, raw) from None
        return _parse_body(status, raw)

    def _with_client_auth(self, body: Optional[Any], headers: Dict[str, str]) -> Optional[Any]:
        if not self.client_secret:
            return body
        body_map = body if isinstance(body, dict) else {}
        client_id = self.client_id or body_map.get("client_id")
        if not client_id:
            raise SSOError(0, "invalid_request", "client_id is required with client_secret")
        credentials = f"{client_id}:{self.client_secret}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(credentials).decode("ascii")
        if not isinstance(body, dict):
            return body
        without_credentials = dict(body)
        without_credentials.pop("client_id", None)
        without_credentials.pop("client_secret", None)
        return without_credentials


`
