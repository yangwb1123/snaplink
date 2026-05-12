-- Edge auth: parse the bearer JWT, verify the signature against a cached
-- JWKS, check exp/nbf, and propagate the resolved subject downstream via
-- `X-Auth-Subject` so backend handlers don't need to re-decode.
--
-- Routes that also need permission gating call `verify_with_permission(perm)`.
-- Permission lookup is cached (see permission_cache.lua); on miss a single
-- HTTP call to /permissions/me is made.

local jwt   = require("resty.jwt")
local jwks  = require("jwks_cache")
local perms = require("permission_cache")
local utils = require("utils")

local _M = {}

local function deny(status, code, msg)
    ngx.status = status
    ngx.header.content_type = "application/json"
    ngx.say(string.format('{"error":"%s","error_description":"%s"}', code, msg or ""))
    return ngx.exit(status)
end

-- decode_jwt_header pulls the header to find the kid without verifying.
-- We need the kid before we can pick the right verification key.
local function decode_jwt_header(token)
    local first_dot = token:find("%.")
    if not first_dot then return nil end
    local raw = token:sub(1, first_dot - 1)
    raw = raw:gsub("-", "+"):gsub("_", "/")
    local pad = #raw % 4
    if pad > 0 then raw = raw .. string.rep("=", 4 - pad) end
    return utils.json_decode(ngx.decode_base64(raw))
end

-- verify is the entry point used by access_by_lua_block. Aborts with 401
-- when the token is missing / malformed / expired / signature invalid;
-- otherwise sets X-Auth-Subject on the upstream request.
function _M.verify()
    local token = utils.bearer_token()
    if not token then return deny(401, "missing_token") end

    local hdr = decode_jwt_header(token)
    if not hdr or not hdr.kid then return deny(401, "invalid_token", "missing kid") end

    local key_map, err = jwks.get()
    if not key_map then
        ngx.log(ngx.ERR, "jwks unavailable: ", err)
        return deny(503, "jwks_unavailable")
    end

    local pubkey = key_map[hdr.kid]
    if not pubkey then
        -- Possibly a key rotation we haven't cached yet — force a refresh.
        local fresh = jwks.refresh()
        key_map = fresh and require("jwks_cache").get() or nil
        pubkey = key_map and key_map[hdr.kid]
        if not pubkey then return deny(401, "invalid_token", "unknown kid") end
    end

    local verified = jwt:verify(pubkey, token)
    if not verified.verified then
        return deny(401, "invalid_token", verified.reason)
    end

    -- The JWT library already checked exp/nbf if present; defensive recheck.
    local now = ngx.time()
    if verified.payload.exp and now >= verified.payload.exp then
        return deny(401, "invalid_token", "expired")
    end

    -- Pass identity downstream so handlers don't re-parse.
    ngx.req.set_header("X-Auth-Subject", verified.payload.sub or "")
    if verified.payload.aud then
        local aud = verified.payload.aud
        if type(aud) == "table" then aud = aud[1] end
        ngx.req.set_header("X-Auth-Audience", aud)
    end
end

-- verify_with_permission gates the route on a permission code. It calls
-- verify() first, then checks /permissions/me (cached) for the code.
-- Use this from per-route access_by_lua_block when a route needs more than
-- "logged-in":
--     access_by_lua_block { require("auth").verify_with_permission("user:read") }
function _M.verify_with_permission(required)
    _M.verify()

    local token = utils.bearer_token()
    local client_id = ngx.var.http_x_auth_audience or ngx.req.get_uri_args()["client_id"]
    local set, err = perms.get_permissions(token, client_id)
    if not set then
        ngx.log(ngx.ERR, "permission lookup failed: ", err)
        return deny(503, "permission_lookup_failed")
    end
    if not perms.has(set, required) then
        return deny(403, "forbidden", "missing permission " .. required)
    end
end

return _M
