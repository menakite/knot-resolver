-- SPDX-License-Identifier: GPL-3.0-or-later
local ffi = require('ffi')

-- Protection from DNS rebinding attacks
local kres = require('kres')
local renumber = require('kres_modules.renumber')
local policy = require('kres_modules.policy')
local ahocorasick = require('ahocorasick')

local M = {}
M.layer = {}

local blacklist = {
	-- https://www.iana.org/assignments/iana-ipv4-special-registry
	-- + IPv4-to-IPv6 mapping
	renumber.prefix('0.0.0.0/8', '0.0.0.0'),
	renumber.prefix('::ffff:0.0.0.0/104', '::'),
	renumber.prefix('10.0.0.0/8', '0.0.0.0'),
	renumber.prefix('::ffff:10.0.0.0/104', '::'),
	renumber.prefix('100.64.0.0/10', '0.0.0.0'),
	renumber.prefix('::ffff:100.64.0.0/106', '::'),
	renumber.prefix('127.0.0.0/8', '0.0.0.0'),
	renumber.prefix('::ffff:127.0.0.0/104', '::'),
	renumber.prefix('169.254.0.0/16', '0.0.0.0'),
	renumber.prefix('::ffff:169.254.0.0/112', '::'),
	renumber.prefix('172.16.0.0/12', '0.0.0.0'),
	renumber.prefix('::ffff:172.16.0.0/108', '::'),
	renumber.prefix('192.168.0.0/16', '0.0.0.0'),
	renumber.prefix('::ffff:192.168.0.0/112', '::'),
	-- https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
	renumber.prefix('::/128', '::'),
	renumber.prefix('::1/128', '::'),
	renumber.prefix('fc00::/7', '::'),
	renumber.prefix('fe80::/10', '::'),
} -- second parameter for renumber module is ignored except for being v4 or v6

local domains_whitelist = {
	-- Always allow localhost to be resolved.
	'localhost'
}
local suffix_whitelist = {}

policy.todnames(domains_whitelist)

local function is_qname_whitelisted(qname)
	for i = 1, #domains_whitelist do
		if ffi.C.knot_dname_is_equal(qname, domains_whitelist[i]) then
			return true
		end
	end

	local tree = ahocorasick.create(suffix_whitelist)
	local match = ahocorasick.match(tree, qname)
	if match ~= nil then
		return true
	end

	return false
end

local function is_rr_blacklisted(rr)
	for i = 1, #blacklist do
		local prefix = blacklist[i]
		-- Match record type to address family and record address to given subnet
		if renumber.match_subnet(prefix[1], prefix[2], prefix[4], rr) then
			return true
		end
	end
	return false
end

local function check_section(pkt, section)
	local records = pkt:section(section)
	local count = #records
	if count == 0 then
		return nil end
	for i = 1, count do
		local rr = records[i]
		if rr.type == kres.type.A or rr.type == kres.type.AAAA then
			local result = is_rr_blacklisted(rr)
			if result then
				return rr end
		end
	end
end

local function check_pkt(pkt)
	for _, section in ipairs({kres.section.ANSWER,
				  kres.section.AUTHORITY,
				  kres.section.ADDITIONAL}) do
		local bad_rr = check_section(pkt, section)
		if bad_rr then
			return bad_rr
		end
	end
end

local function deny(req)
	local msg = 'Blocked by DNS rebinding protection'
	policy.DENY_MSG(msg)(_, req)
	return kres.DONE
end

function M.config(conf)
	if conf.domains ~= nil and type(conf.domains) ~= 'table' then
		error('[rebinding_whitelist] domains configuration must be a non-empty table (domains = { ... , ... })') end

	if conf.suffixes ~= nil and type(conf.suffixes) ~= 'table' then
		error('[rebinding_whitelist] suffixes configuration must be a non-empty table (suffixes = { ... , ... })') end

	domains_whitelist = conf.domains or {}
	suffix_whitelist = conf.suffixes or {}

	-- Always allow localhost to be resolved.
	table.insert(domains_whitelist, 'localhost')

	domains_whitelist = policy.todnames(domains_whitelist)
	suffix_whitelist = policy.todnames(suffix_whitelist)
end

-- act on DNS queries which were not answered from cache
function M.layer.consume(state, req, pkt)
	if state == kres.FAIL then
		return state end

	local qry = req:current()
	if qry.flags.ALLOW_LOCAL then
		return state end

	-- Check whitelists first
	if is_qname_whitelisted(qry:name()) then
		return state end

	local bad_rr = check_pkt(pkt)
	if not bad_rr then
		return state end

	qry.flags.RESOLVED = 1  -- stop iteration
	qry.flags.CACHED = 1  -- do not cache

	--[[ In case we're in a sub-query, we do not touch the final req answer.
		Only this sub-query will get finished without a result - there we
		rely on the iterator reacting to flags.RESOLVED
		Typical example: NS address resolution -> only this NS won't be used
		but others may still be OK (or we SERVFAIL due to no NS being usable).
	--]]
	if qry.parent == nil then
		state = deny(req)
	end
	log_qry(qry, ffi.C.LOG_GRP_REBIND,
		'blocking blacklisted IP in RR \'%s\'\n', kres.rr2str(bad_rr))
	return state
end

return M
