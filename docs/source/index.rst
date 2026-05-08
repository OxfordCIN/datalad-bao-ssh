DataLad extension Oxcin-Login
**************************

This extension will setup your SSH environment for authentication
with short-lived SSH certificates, signed by an OpenBao server.
Ordinarily you only need to run this once, unless something in your
environment changes (e.g. a server address needs to be updated) or
if your ~/.ssh/config file is lost.

The command will attempt to download some basic configuration, if
this fails you will be prompted for this configuration information.

API
===

High-level API commands
-----------------------

.. toctree::
   :maxdepth: 2

   python_reference.rst


Command line reference
----------------------

.. toctree::
   :maxdepth: 2

   cli_reference.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. |---| unicode:: U+02014 .. em dash
