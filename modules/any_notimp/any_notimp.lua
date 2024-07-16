-- SPDX-License-Identifier: GPL-3.0-or-later

-- Answer ANY queries with NOTIMP and extended error Not Supported,
-- instead of the default SERVFAIL.

-- Module declaration
local any_notimp = { layer = {} }

local ffi = require('ffi')

function any_notimp.layer.begin(state, req)
	local qry = req:current()
	if qry.stype ~= kres.type.ANY or state == kres.DONE then
		return state
	end

	local answer = req:ensure_answer()
	if answer == nil then
		return kres.FAIL
	end

	ffi.C.kr_pkt_make_auth_header(answer)
	answer:rcode(kres.rcode.NOTIMPL)
	req:set_extended_error(kres.extended_error.NOTSUP, 'Q6GZ')
	qry.flags.CACHED = true
	qry.flags.DNSSEC_WANT = false
	return kres.DONE
end

return any_notimp
