.. SPDX-License-Identifier: GPL-3.0-or-later

.. _mod-any_notimp:

Answer NOTIMP to ANY queries
============================

Changes default answer for ANY queries from SERVFAIL, which may be confusing,
to NOTIMP (Not Implemented), also setting Extended Error (EDE) to "Not Supported".

To enable this module insert the following line into your configuration file:

.. code-block:: lua

    modules.load('any_notimp')
