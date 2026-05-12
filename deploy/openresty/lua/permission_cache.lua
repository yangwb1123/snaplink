-- Per-token permission cache. On first hit the gateway calls
-- /permissions/me?client_id=X with the user's bearer token; the response is
-- cached for 60s in the `permission_cache` shared dict, keyed by
--   <token-fingerprint> "|" <client_id>
-- The token fingerprint is just the first 32 chars of the access token —
-- collision-resistant for cache purposes, and storing the full token in a
-- shared dict is wasteful.

local http  = require("resty.http")
local utils = require("utils")

local _M = {}

local CACHE_TTL = 60 -- seconds

local cache = ngx.shared.permission_cache

local function fingerprint(token)
    if #token <= 32 then return token end
    return token:sub(1, 32)
end

-- get_permissions returns a {code -> true} set. Returns nil + error on
-- transport failure; on cache hit returns the stored set without I/O.
function _M.get_permissions(token, client_id)
    if not token or token == "" then
        return nil, "no token"
    end
    local key = fingerprint(token) .. "|" .. (client_id or "")
    local cached = cache:get(key)
    if cached then
        return utils.json_decode(cached)
    end

    local httpc = http.new()
    httpc:set_timeout(2000)

    local url = utils.upstream .. "/permissions/me"
    if client_id and client_id ~= "" then
        url = url .. "?client_id=" .. ngx.escape_uri(client_id)
    end

    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = { ["Authorization"] = "Bearer " .. token },
    })
    if not res then return nil, "perm fetch: " .. err end
    if res.status == 401 or res.status == 403 then
        return nil, "perm fetch: unauthorized"
    end
    if res.status ~= 200 then return nil, "perm fetch: status " .. res.status end

    local body, jerr = utils.json_decode(res.body)
    if not body then return nil, "perm parse: " .. jerr end

    -- Flatten {permissions: [{code, ...}]} into a set for O(1) membership.
    local set = {}
    for _, p in ipairs(body.permissions or {}) do
        if p.code then set[p.code] = true end
    end

    cache:set(key, utils.json_encode(set), CACHE_TTL)
    return set, nil
end

-- has checks set membership with the same wildcard semantics as the Go
-- permissions.Matches function: exact, "<domain>:*", or "*".
function _M.has(set, want)
    if not want or want == "" then return true end
    if not set then return false end
    if set[want] or set["*"] then return true end
    -- Walk to find a domain wildcard match.
    for code in pairs(set) do
        local domain = code:match("^(.+):%*$")
        if domain and want:sub(1, #domain + 1) == (domain .. ":") then
            return true
        end
    end
    return false
end

return _M
