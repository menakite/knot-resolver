-- SPDX-License-Identifier: GPL-3.0-or-later

-- Implements RFC 9462 (Discovery of Designated Resolvers)

local kres = require('kres')
local ffi = require('ffi')
local policy = require('kres_modules.policy')

-- Module declaration
local dns_resolver_arpa = { layer = {} }
local cfg = {
	['hostname'] = nil,
	-- Whether to advertise DNS over HTTPS as preferred (first priority), in
	-- case both DoH and DoT are available. Default is to prefer DNS over TLS.
	['prefer_doh'] = false
}
local services = {
	['dot'] = { ['port'] = nil, ['ipv4'] = {}, ['ipv6'] = {} },
	['h2'] = { ['port'] = nil, ['ipv4'] = {}, ['ipv6'] = {} }
}

-- Whether the "refuse_nord" module is loaded or not
local have_refuse_nord = false

function dns_resolver_arpa.config(conf)
	if conf.hostname ~= nil and type(conf.hostname) == 'string' then
		if #conf.hostname == 0 then
			error('[dns_resolver_arpa] hostname configuration must be a non-empty string')
		else
			cfg.hostname = kres.str2dname(conf.hostname)
		end
	end

	if conf.prefer_doh ~= nil and type(conf.prefer_doh) == 'boolean' then
		local count = 0
		for entry in pairs(services) do
			if entry['port'] ~= nil then
				count = count + 1 end
		end
		if count > 1 then
			cfg.prefer_doh = conf.prefer_doh end
	end
end

function dns_resolver_arpa.layer.answer_finalize(state, req)
	local qry = req:resolved()

	if qry == nil then
		return state
	end

	if have_refuse_nord and ffi.C.knot_dname_in_bailiwick(qry:name(), kres.str2dname('resolver.arpa.')) >= 0
	and req.answer:rcode() == kres.rcode.REFUSED
	and req.extended_error.info_code == kres.extended_error.NOTAUTH
	and state == kres.DONE then
		req.answer:rcode(kres.rcode.NOERROR)
		req:set_extended_error(kres.extended_error.NONE)
	end

	return state
end

function dns_resolver_arpa.answer(state, req)
	local qry = req:current()

	if qry.sclass ~= kres.class.IN then
		return state
	end

	local answer = req:ensure_answer()
	if answer == nil then return kres.FAIL end
	ffi.C.kr_pkt_make_auth_header(answer)
	answer:rcode(kres.rcode.NOERROR)

	local qname = qry:name()
	if ffi.C.knot_dname_is_equal(qname, kres.str2dname('_dns.resolver.arpa.')) and qry.stype == kres.type.SVCB then
		local to_parse = {}
		local ipv4_addresses = {}
		local ipv6_addresses = {}
		local priority = nil
		for kind, params in pairs(services) do
			if #params.ipv4 > 0 or #params.ipv6 > 0 then
				if kind == 'h2' then
					priority = cfg.prefer_doh and 1 or 2
				elseif kind == 'dot' then
					priority = not cfg.prefer_doh and 1 or 2
				end
				local entry = string.format('SVCB %d %s alpn="%s"', priority, kres.dname2str(cfg.hostname), kind)

				-- Add the "port" parameter in case of non-standard port
				if (kind == 'tls' and params.port ~= nil and params.port ~= 853)
					or (kind == 'h2' and params.port ~= nil and params.port ~= 443) then
					entry = entry .. string.format(' port="%d"', params.port)
				end

				if #params.ipv4 > 0 then
					for _, address in pairs(params.ipv4) do
						ipv4_addresses[address] = address
					end

					local addresses = table.concat(params.ipv4, ',')
					entry = entry .. string.format(' ipv4hint="%s"', addresses)
				end
				if #params.ipv6 > 0 then
					for _, address in pairs(params.ipv6) do
						ipv6_addresses[address] = address
					end

					local addresses = table.concat(params.ipv6, ',')
					entry = entry .. string.format(' ipv6hint="%s"', addresses)
				end
				if kind == 'h2' then
					entry = entry .. ' dohpath="/dns-query{?dns}"'
				end

				table.insert(to_parse, entry)
			end
		end

		answer:begin(kres.section.ANSWER)
		local records = kres.parse_rdata(to_parse)
		for _, entry in ipairs(records) do
			answer:put(qname, 86400, kres.class.IN, kres.type.SVCB, entry)
		end

		answer:begin(kres.section.ADDITIONAL)
		-- A records
		for _, address in pairs(ipv4_addresses) do
			answer:put(cfg.hostname, 86400, kres.class.IN, kres.type.A, kres.str2ip(address))
		end

		-- AAAA records
		for _, address in pairs(ipv6_addresses) do
			answer:put(cfg.hostname, 86400, kres.class.IN, kres.type.AAAA, kres.str2ip(address))
		end
	else
		answer:begin(kres.section.AUTHORITY)
		local rdata = kres.parse_rdata({ 'SOA localhost. nobody.invalid. 1 3600 1200 604800 10800' })
		answer:put(kres.str2dname('resolver.arpa.'), 10800, kres.class.IN, kres.type.SOA, rdata[1])
	end

	qry.flags.RESOLVED = true
	qry.flags.CACHED = true
	return kres.DONE
end

function dns_resolver_arpa.init()
	local loaded_modules = modules.list()
	for i = 1, #loaded_modules do
		if loaded_modules[i] == 'refuse_nord' then
			have_refuse_nord = true
			break
		end
	end

	-- Auto-discover configuration
	cfg.hostname = kres.str2dname(hostname())

	for _, entry in ipairs(net.list()) do
		if entry.kind == 'tls' then
			dest = 'dot'
		elseif entry.kind == 'doh2' then
			dest = 'h2'
		end

		if entry.kind == 'tls' or entry.kind == 'doh2' then
			if entry.transport.family == 'inet4' then
				table.insert(services[dest].ipv4, entry.transport.ip)
				services[dest].port = entry.transport.port
			elseif entry.transport.family == 'inet6' then
				table.insert(services[dest].ipv6, entry.transport.ip)
				services[dest].port = entry.transport.port
			end
		end
	end

	policy.add(policy.suffix(dns_resolver_arpa.answer, { todname('resolver.arpa') }))
end

return dns_resolver_arpa
