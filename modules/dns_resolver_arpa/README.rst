.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-dns_resolver_arpa:

Discovery of Designated Resolvers
=================================

This module adds support for `Discovery of Designated Resolvers` as defined
in `RFC 9462`_, a set of mechanisms for DNS clients to use DNS records to
discover a resolver's encrypted DNS configuration, such as `DNS over TLS (DoT)`_
and/or `DNS over HTTPS (DoH)`_.

To enable this module insert the following line into your configuration file:

.. code-block:: lua

  modules.load('dns_resolver_arpa < extended_error')

The supported encrypted protocols configured are auto-discovered.

You may need to adjust the advertised `host name` of the resolver, in case
it is set to a short name and not a FQDN.

If both DoH and DoT are configured, by default DoT is advertised as the
preferred encryption protocol.

Configure with hostname `recursor-invalid.nic.cz`, preferring DoH over
DoT:

.. code-block:: lua

  modules.load('dns_resolver_arpa < extended_error')
  dns_resolver_arpa.config({ hostname = 'recursor-invalid.nic.cz', prefer_doh = true })

.. _`RFC 9462`: https://www.rfc-editor.org/rfc/rfc9462.html
.. _`DNS over TLS (DoT)`: https://en.wikipedia.org/wiki/DNS_over_TLS
.. _`DNS over HTTPS (DoH)`: https://en.wikipedia.org/wiki/DNS_over_HTTPS
