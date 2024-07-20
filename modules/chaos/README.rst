.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-chaos:

CHAOS class
===========

This module adds support for the CHAOS class, providing answers to TXT queries
for `id.server` and `version.server`.

Both responses are configurable. Set to an empty string to disable.

To enable this module insert the following line into your configuration file:

.. code-block:: lua

    modules.load('chaos')

Configure to refuse queries for `version.server`:

.. code-block:: lua

    modules.load('chaos')
    chaos.config({ version = '' })
