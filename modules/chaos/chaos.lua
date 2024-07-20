-- SPDX-License-Identifier: GPL-3.0-or-later

-- Adds support for the CHAOS class, providing
-- answers for "id.server" and "version.server".
-- No "*.bind" compatibility is provided.

local chaos = { layer = {} }

local ffi = require('ffi')
local kres = require('kres')

-- Module configuration
local cfg = {
	['identity'] = nsid.name(),
	['version'] = 'Knot Resolver ' .. package_version()
}

-- Whether the "refuse_nord" module is loaded or not
local have_refuse_nord = false

function chaos.init()
	local loaded_modules = modules.list()
	for i = 1, #loaded_modules do
		if loaded_modules[i] == 'refuse_nord' then
			have_refuse_nord = true
			break
		end
	end
end

function chaos.config(conf)
	if conf.identity ~= nil then
		if type(conf.identity) ~= 'string' then
			error('[chaos] identity configuration must be a string (an empty string to disable)')
		else
			cfg.identity = conf.identity
		end
	end

	if conf.version ~= nil then
		if type(conf.version) ~= 'string' then
			error('[chaos] version configuration must be a string (an empty string to disable)')
		else
			cfg.version = conf.version
		end
	end
end

local function clear_extended_error(req)
	if have_refuse_nord and req.extended_error.info_code == kres.extended_error.NOTAUTH then
		req:set_extended_error(kres.extended_error.NONE)
	end
end

local function refuse(req, notimp)
	assert(type(notimp) == 'boolean')

	local qry = req:current()
	local answer = req:ensure_answer()
	if answer == nil then
		return kres.FAIL
	end

	ffi.C.kr_pkt_make_auth_header(answer)
	if notimp then
		answer:rcode(kres.rcode.NOTIMPL)
		clear_extended_error(req)
		req:set_extended_error(kres.extended_error.NOTSUP, 'CXVL')
	else
		answer:rcode(kres.rcode.REFUSED)
		clear_extended_error(req)
	end

	qry.flags.RESOLVED = true
	qry.flags.CACHED = true
	qry.flags.DNSSEC_WANT = false
	return kres.DONE
end

function chaos.layer.begin(state, req)
	local qry = req:current()
	if qry.sclass ~= kres.class.CH then
		return state
	elseif qry.stype ~= kres.type.TXT then
		return refuse(req, true)
	end

	local response_text = ''
	if ffi.C.knot_dname_is_equal(qry:name(), kres.str2dname('id.server.')) then
		response_text = cfg.identity
	elseif ffi.C.knot_dname_is_equal(qry:name(), kres.str2dname('version.server.')) then
		response_text = cfg.version
	end

	if #response_text == 0 then
		return refuse(req, false)
	else
		local answer = req:ensure_answer()
		if answer == nil then
			return kres.FAIL
		end

		ffi.C.kr_pkt_make_auth_header(answer)
		answer:rcode(kres.rcode.NOERROR)

		answer:begin(kres.section.ANSWER)
		local rdata = kres.parse_rdata({ string.format('TXT "%s"', response_text) })
		answer:put(qry:name(), 0, kres.class.CH, kres.type.TXT, rdata[1])

		clear_extended_error(req)
		qry.flags.RESOLVED = true
		qry.flags.CACHED = true
	end

	return kres.DONE
end

return chaos
