-- Fetches and caches the SSO server's network policies, then classifies
-- incoming requests at the edge (before they hit the Go upstream). Backed by
-- the `netpolicy_cache` ngx.shared.DICT and refreshed periodically by a
-- worker timer.
--
-- Why classify at the edge:
--   * The Host header / X-Forwarded-For value arriving here is the
--     authoritative one; once we proxy upstream, the Go server sees nginx's
--     own IP unless we forward XFF (which we already do for logging).
--   * Stamping X-Network: intranet|public|... on the request lets every
--     backend make consistent decisions without re-implementing CIDR
--     matching in N languages.
--
-- The Go side serves /api/v1/netpolicy/policies as the source of truth.

local http  = require("resty.http")
local utils = require("utils")

local _M = {}

local CACHE_KEY    = "policies"      -- single entry — JSON-encoded list
local CACHE_TTL    = 30              -- seconds; classify is hot, slightly stale is fine
local LOCK_KEY     = "netpolicy_refresh"
local REFRESH_FREQ = 20              -- worker timer interval; < CACHE_TTL for safety

local cache = ngx.shared.netpolicy_cache

-- compile pre-parses CIDR strings into ngx.re-friendly net+mask pairs and
-- builds a hostname set so classify is allocation-light on the hot path.
-- We avoid pulling in a CIDR library and do it by hand for IPv4; IPv6 is
-- compared by full address string for now (edge classification of v6 callers
-- is uncommon in this kind of deployment).
local function parse_cidr_v4(s)
    -- s is "10.0.0.0/8" or "10.0.0.0" (bare IP → /32)
    local addr, prefix = s:match("^([%d%.]+)/(%d+)$")
    if not addr then
        addr   = s
        prefix = "32"
    end
    local a, b, c, d = addr:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    local plen = tonumber(prefix)
    if not plen or plen < 0 or plen > 32 then return nil end
    local net = a * 2^24 + b * 2^16 + c * 2^8 + d
    local mask = plen == 0 and 0 or (0xFFFFFFFF - (2^(32 - plen) - 1))
    return { net = bit.band(net, mask), mask = mask }
end

local function ip_to_uint32(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    return tonumber(a) * 2^24 + tonumber(b) * 2^16 + tonumber(c) * 2^8 + tonumber(d)
end

local function strip_port(host)
    if not host or host == "" then return host end
    -- "[::1]:8080" → "[::1]";  "host:8080" → "host"
    if host:sub(1, 1) == "[" then
        local close = host:find("]")
        return close and host:sub(1, close) or host
    end
    local colon = host:find(":")
    if colon then return host:sub(1, colon - 1) end
    return host
end

local function compile(policies)
    local out = {}
    for _, p in ipairs(policies or {}) do
        local cp = { policy = p, cidrs = {}, hostnames = {} }
        for _, h in ipairs(p.hostnames or {}) do
            cp.hostnames[strip_port(h):lower()] = true
        end
        for _, c in ipairs(p.cidrs or {}) do
            local m = parse_cidr_v4(c)
            if m then cp.cidrs[#cp.cidrs + 1] = m end
        end
        out[#out + 1] = cp
    end
    -- Sort by priority desc (stable).
    table.sort(out, function(a, b)
        return (a.policy.priority or 0) > (b.policy.priority or 0)
    end)
    return out
end

-- refresh pulls the full policy list and stores it under CACHE_KEY. Called
-- by init_worker, by the periodic timer, and on per-request cache miss.
function _M.refresh()
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(utils.upstream .. "/api/v1/netpolicy/policies", { method = "GET" })
    if not res then return nil, "netpolicy fetch: " .. err end
    if res.status ~= 200 then return nil, "netpolicy fetch: status " .. res.status end
    local doc, jerr = utils.json_decode(res.body)
    if not doc then return nil, "netpolicy parse: " .. jerr end
    cache:set(CACHE_KEY, res.body, CACHE_TTL)
    return doc.policies or {}, nil
end

-- get_compiled returns the compiled-and-priority-sorted policy list. Tries
-- cache first; refreshes (single-flight) on miss.
function _M.get_compiled()
    local body = cache:get(CACHE_KEY)
    if body then
        local doc = utils.json_decode(body)
        if doc then return compile(doc.policies or {}), nil end
    end
    local lock = require("resty.lock"):new("locks")
    local elapsed, lerr = lock:lock(LOCK_KEY)
    if not elapsed then return nil, "lock: " .. lerr end
    body = cache:get(CACHE_KEY)
    if body then
        lock:unlock()
        local doc = utils.json_decode(body)
        if doc then return compile(doc.policies or {}), nil end
    end
    local policies, rerr = _M.refresh()
    lock:unlock()
    if rerr then return nil, rerr end
    return compile(policies), nil
end

-- classify returns the matching policy name for (remote_addr, host) or "".
-- Matching mirrors the Go classifier exactly: hostnames beat CIDRs, priority
-- desc breaks ties.
function _M.classify(remote_addr, host)
    local compiled, err = _M.get_compiled()
    if err then
        ngx.log(ngx.WARN, "netpolicy classify failed: ", err)
        return ""
    end
    host = strip_port(host or ""):lower()
    -- Pass 1: hostname match.
    for _, cp in ipairs(compiled) do
        if host ~= "" and cp.hostnames[host] then
            return cp.policy.name
        end
    end
    -- Pass 2: CIDR match (IPv4 only).
    local ip = ip_to_uint32(remote_addr or "")
    if ip then
        for _, cp in ipairs(compiled) do
            for _, m in ipairs(cp.cidrs) do
                if bit.band(ip, m.mask) == m.net then
                    return cp.policy.name
                end
            end
        end
    end
    return ""
end

-- start_refresh_timer schedules a recurring refresh on one worker. Call from
-- init_worker_by_lua_block.
function _M.start_refresh_timer()
    if ngx.worker.id() ~= 0 then return end
    local function tick(premature)
        if premature then return end
        local _, err = _M.refresh()
        if err then ngx.log(ngx.WARN, "netpolicy refresh: ", err) end
        local ok, err2 = ngx.timer.at(REFRESH_FREQ, tick)
        if not ok then ngx.log(ngx.ERR, "netpolicy timer reschedule: ", err2) end
    end
    local ok, err = ngx.timer.at(0, tick)
    if not ok then ngx.log(ngx.ERR, "netpolicy timer start: ", err) end
end

-- stamp_header reads the current request's source/host, classifies, and sets
-- X-Network for the upstream. Call from access_by_lua_block (after auth has
-- run, so the trust boundary is established before we annotate).
function _M.stamp_header()
    local addr = ngx.var.remote_addr
    local host = ngx.var.http_host
    -- Prefer the leftmost X-Forwarded-For when present and trusted.
    local xff = ngx.var.http_x_forwarded_for
    if xff and xff ~= "" then
        local comma = xff:find(",")
        addr = comma and xff:sub(1, comma - 1):gsub("%s+", "") or xff
    end
    local class = _M.classify(addr, host)
    if class ~= "" then
        ngx.req.set_header("X-Network", class)
    end
end

return _M
