local cjson = require("cjson.safe")

local M = {}

local request_id_pattern = "^[A-Za-z0-9._:-]+$"

local function usable_request_id(value)
    return value
        and #value > 0
        and #value <= 128
        and ngx.re.find(value, request_id_pattern, "jo")
end

local function surface(uri)
    if uri == "/" then
        return "landing"
    end
    if ngx.re.find(uri, "^/(admin|login|portal|developer|setup|device)(/|$)", "jo") then
        return "console"
    end
    if uri == "/app" or uri:sub(1, 5) == "/app/" then
        return "console-asset"
    end
    if uri == "/docs" or uri:sub(1, 6) == "/docs/" then
        return "docs"
    end
    if uri == "/sample" or uri:sub(1, 8) == "/sample/" then
        return "sample"
    end
    if uri == "/example" or uri:sub(1, 9) == "/example/" then
        return "sample-redirect"
    end
    if uri == "/_gateway/health" then
        return "gateway-health"
    end
    return "sso-api"
end

local function strip_auth_headers()
    local headers = ngx.req.get_headers(0, true)
    for name in pairs(headers) do
        if name:lower():sub(1, 7) == "x-auth-" then
            ngx.req.clear_header(name)
        end
    end
end

function M.access()
    strip_auth_headers()

    local request_id = ngx.var.http_x_request_id
    if not usable_request_id(request_id) then
        request_id = ngx.var.request_id
    end

    ngx.var.gateway_request_id = request_id
    ngx.var.gateway_surface = surface(ngx.var.uri)
    ngx.req.set_header("X-Request-ID", request_id)
end

function M.login_access()
    M.access()

    local provider = ngx.var.arg_provider
    if ngx.req.get_method() ~= "GET" or (provider and #provider > 0) then
        return
    end

    local target = "/login/"
    local args = ngx.var.args
    if args and #args > 0 then
        target = target .. "?" .. args
    end

    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Pragma"] = "no-cache"
    return ngx.redirect(target, ngx.HTTP_MOVED_TEMPORARILY)
end

function M.headers()
    ngx.header["X-Request-ID"] = ngx.var.gateway_request_id
    ngx.header["X-Snaplink-Gateway"] = "openresty-lua"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    ngx.header["Referrer-Policy"] = "strict-origin-when-cross-origin"
end

function M.health()
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({
        status = "ok",
        gateway = "openresty-lua",
        routes = { "landing", "console", "docs", "sample", "sso-api" },
    }))
end

function M.audit()
    if ngx.status < 400 then
        return
    end
    ngx.log(ngx.WARN, "gateway_error ", cjson.encode({
        request_id = ngx.var.gateway_request_id,
        surface = ngx.var.gateway_surface,
        method = ngx.req.get_method(),
        uri = ngx.var.request_uri,
        status = ngx.status,
        upstream = ngx.var.upstream_addr or "",
        duration = tonumber(ngx.var.request_time) or 0,
    }))
end

return M
