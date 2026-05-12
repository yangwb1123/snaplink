-- Fetches and caches the SSO server's JWKS (Ed25519 public keys). Backed by
-- the `jwks_cache` ngx.shared.DICT. Cache TTL is short (60s) so key rotation
-- propagates quickly; the SSO server can also push invalidations via Redis
-- pub/sub if you wire that up later.

local http  = require("resty.http")
local utils = require("utils")

local _M = {}

local CACHE_KEY = "doc"          -- single entry — the whole JWKS document
local CACHE_TTL = 60             -- seconds
local LOCK_KEY  = "jwks_refresh" -- used by lua-resty-lock to coalesce refreshes

local cache = ngx.shared.jwks_cache

-- decode_b64url is needed because Ed25519 JWKs use base64url without padding.
local function decode_b64url(s)
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad > 0 then s = s .. string.rep("=", 4 - pad) end
    return ngx.decode_base64(s)
end

-- key_by_kid converts a JWKS document into a `kid -> raw_pubkey_bytes` map
-- so the verifier can look up the right key per token without scanning.
local function key_by_kid(jwks)
    local out = {}
    for _, k in ipairs(jwks.keys or {}) do
        if k.kty == "OKP" and k.crv == "Ed25519" and k.kid and k.x then
            out[k.kid] = decode_b64url(k.x)
        end
    end
    return out
end

-- refresh fetches /.well-known/jwks.json and stores the parsed key map.
-- Safe to call from init_worker and from the per-request fallback path.
function _M.refresh()
    local httpc = http.new()
    httpc:set_timeout(2000)

    local res, err = httpc:request_uri(utils.upstream .. "/.well-known/jwks.json", {
        method = "GET",
    })
    if not res then return nil, "jwks fetch: " .. err end
    if res.status ~= 200 then return nil, "jwks fetch: status " .. res.status end

    local jwks, jerr = utils.json_decode(res.body)
    if not jwks then return nil, "jwks parse: " .. jerr end

    -- Store the raw doc; verifier rebuilds the kid map (cheap, dozens of keys).
    cache:set(CACHE_KEY, res.body, CACHE_TTL)
    return jwks, nil
end

-- get returns the current `kid -> pubkey` map. Refreshes on miss with a
-- single-flight lock so a thundering herd of requests doesn't stampede the
-- SSO server during cache eviction.
function _M.get()
    local body = cache:get(CACHE_KEY)
    if body then
        local jwks, err = utils.json_decode(body)
        if jwks then return key_by_kid(jwks), nil end
        ngx.log(ngx.WARN, "jwks cache decode failed: ", err)
    end

    -- Single-flight: only one worker re-fetches; others wait then re-read.
    local lock = require("resty.lock"):new("locks")
    local elapsed, lerr = lock:lock(LOCK_KEY)
    if not elapsed then return nil, "lock: " .. lerr end

    -- Double-check: another worker may have populated while we waited.
    body = cache:get(CACHE_KEY)
    if body then
        lock:unlock()
        local jwks = utils.json_decode(body)
        if jwks then return key_by_kid(jwks), nil end
    end

    local jwks, ferr = _M.refresh()
    lock:unlock()
    if not jwks then return nil, ferr end
    return key_by_kid(jwks), nil
end

return _M
