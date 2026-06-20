-- Small helpers shared across the SSO Lua modules. No external state.
local _M = {}

-- Where the SSO server lives. Override per-deployment via the env var
-- SSO_UPSTREAM; defaults to the same host:port the upstream block uses.
_M.upstream = os.getenv("SSO_UPSTREAM") or "http://127.0.0.1:8080"

-- Random hex string of len chars. Used as a fallback X-Request-Id when
-- callers don't bring one (TracingMiddleware on the Go side echoes it back).
function _M.rand_hex(len)
    local chars = "0123456789abcdef"
    local out = {}
    math.randomseed(ngx.now() * 1e6 + ngx.worker.pid())
    for i = 1, len do
        local idx = math.random(1, 16)
        out[i] = chars:sub(idx, idx)
    end
    return table.concat(out)
end

-- bearer_token reads "Authorization: Bearer ..." and returns the token.
-- Returns nil when the header is missing or doesn't have the Bearer prefix.
function _M.bearer_token()
    local h = ngx.var.http_authorization
    if not h then return nil end
    local prefix = "Bearer "
    if h:sub(1, #prefix) ~= prefix then return nil end
    return h:sub(#prefix + 1)
end

-- json_decode that survives malformed input. Returns (table, nil) on success
-- and (nil, err) on failure.
local cjson = require("cjson.safe")
function _M.json_decode(s)
    local t, err = cjson.decode(s)
    if err then return nil, err end
    return t, nil
end

function _M.json_encode(t)
    return cjson.encode(t)
end

return _M
