.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-rebinding_whitelist:

Rebinding protection
====================

This module provides protection from `DNS Rebinding attack`_ by blocking
answers which contain IPv4_ or IPv6_ addresses for private use
(or some other special-use addresses).

To enable this module insert the following line into your configuration file:

.. code-block:: lua

  modules.load('rebinding_whitelist')

The module can be configured to whitelist specific FQDNs or suffixes.
Please note that this module does not offer configuration options to whitelist subnets.

Configure to whitelist queries for `router.local` and any name ending with `dns-bl.example.net` or `abusers.blocklist.example.org`:

.. code-block:: lua

  modules.load('rebinding_whitelist < iterate')
  rebinding_whitelist.config({ domains = policy.todnames({ 'router.local' }), suffixes = policy.todnames({ 'dns-bl.example.net', 'abusers.blocklist.example.org' }) })

.. warning:: DNS Blacklists (`RFC 5782`_) often use `127.0.0.0/8` to blacklist
   a domain. Using the rebinding module prevents DNSBL from functioning
   properly, unless whitelisted (see `suffixes` in the example above).

.. _`DNS Rebinding attack`: https://en.wikipedia.org/wiki/DNS_rebinding
.. _IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
.. _IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
.. _`RFC 5782`: https://tools.ietf.org/html/rfc5782#section-2.1
