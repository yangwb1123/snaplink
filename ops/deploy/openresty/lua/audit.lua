-- Per-request audit emission. Runs in log_by_lua_block, which means the
-- response is already on the wire — slowness here only delays the next
-- request on the same connection, never the user-visible response.
--
-- The default sink is the access_log line nginx itself writes (see
-- log_format audit_jsonl in nginx.conf). This module additionally enriches
-- the log line with structured info if you want to emit to a network sink.
--
-- For network sinks: replace the body of `log()` with an ngx.timer.at(0, ...)
-- that XADDs to a Redis stream or POSTs to a Kafka REST proxy. Don't do
-- network I/O synchronously here — log_by_lua runs on every request.

local utils = require("utils")

local _M = {}

-- emit returns the JSON-Lines audit line for the current request. Same
-- shape as audit.Event in the Go SDK so both sides share a schema.
local function build_event()
    local req_id = ngx.var.http_x_request_id
    if not req_id or req_id == "" then
        req_id = utils.rand_hex(32)
    end

    return {
        type        = "gateway_request",
        outcome     = (ngx.status < 400) and "success" or "failure",
        timestamp   = ngx.utctime(),                -- "YYYY-MM-DD HH:MM:SS"
        request_id  = req_id,
        traceparent = ngx.var.http_traceparent,
        actor_ip    = ngx.var.remote_addr,
        user_agent  = ngx.var.http_user_agent,
        actor_id    = ngx.var.http_x_auth_subject,  -- set by auth.verify()
        client_id   = ngx.var.http_x_auth_audience,
        metadata    = {
            method      = ngx.var.request_method,
            path        = ngx.var.request_uri,
            status      = tostring(ngx.status),
            latency_ms  = tostring(ngx.var.request_time),
            upstream    = ngx.var.upstream_addr or "",
        },
    }
end

function _M.log()
    local evt = build_event()

    -- Default: print to stderr in JSON-Lines so a stdout-tailing log shipper
    -- (Vector / Filebeat / Promtail) picks it up and ships to ES/Loki/Kafka.
    -- Replace with redis.XADD or http.post for direct streaming.
    ngx.log(ngx.NOTICE, "AUDIT ", utils.json_encode(evt))
end

return _M
