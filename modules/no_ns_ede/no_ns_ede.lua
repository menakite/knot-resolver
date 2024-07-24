-- SPDX-License-Identifier: GPL-3.0-or-later

-- Always set extended error No Reachable Authority if all nameservers are unreachable.

local no_ns_ede = { layer = {} }

local ffi = require('ffi')

function no_ns_ede.layer.answer_finalize(state, req)
	local qry_initial = req:initial()
	local qry_resolved = req:resolved()

	if qry_initial.flags.NO_NS_FOUND or (qry_resolved ~= nil and qry_resolved.flags.NO_NS_FOUND and
	  ffi.C.knot_dname_is_equal(qry_initial.zone_cut.name, qry_resolved:name())) then
		local zone_cut = kres.dname2str(qry_initial.zone_cut.name)
		req:set_extended_error(kres.extended_error.NREACH_AUTH, string.format('At delegation %s (2IFV)', zone_cut))
	end

	return state
end

return no_ns_ede
