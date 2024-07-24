.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-no_ns_ede:

Set extended error if unreachable
=================================

Always set extended error "No Reachable Authority" if all nameservers for
delegation are unreachable.

To enable this module insert the following line into your configuration file:

.. code-block:: lua

    modules.load('no_ns_ede < extended_error')
