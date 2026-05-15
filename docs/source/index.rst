DataLad extension Oxcin-Login
**************************

This extension will setup your SSH environment for authentication
with short-lived SSH certificates, signed by an OpenBao server. These
can be used with suitably configured GitLab/Hub and SSH based RIA hosts
as provided by your Datalad dataset service.
Ordinarily you only need to run this once, unless something in your
environment changes (e.g. a server address needs to be updated) or
if your ~/.ssh/config file is lost.

The command will attempt to download some basic configuration provided
by the server referenced in the Datalad setting
'datalad.bao-ssh-config-url'. Datalad service administrators should make
available at this URL a JSON format file (see :ref:`JSON Configuration`)
that provides the main configuration for the service.
If this site is unavailable you will be prompted for this configuration
information (see :ref:`Configuration`).
If your system doesn't have the 'bao' command installed, this will be
installed in your 'bin' folder.

After initial configuration you will be prompted to enter your user name
on each RIA host you have specified (or has been auto-configured), and
for the Git service, if you have specified that this needs a user name
(for most Git services, e.g. GitLab or GitHub you will use a generic
account 'git').

With this information your SSH client configuration will be updated to
run a script each time you connect to the RIA/Git hosts. This script will
ensure that you have a valid short-term SSH certificate. Where you don't
you will be prompted to log into the authentication server.

Configuration
=============

Git configuration options:

* datalad.bao-ssh-config-url: URL of JSON configuration file
* datalad.bao-ssh-bao-install-dir: Path to install 'bao' client in -
   defaults to '.baobin' in the user's home folder

User questions:

   "Would you like to quit so that you can connect to a VPN and try again?"
      - If the JSON configuration server is behind a restrictive firewall
        and your institution provides a VPN service, answer 'y' to quit.
        Connect to your VPN and try again.

Please ask your Datalad/OpenBao administrator for the answers to the
following questions.

   "OpenBao role that allows signing of SSH certificates"
   "OpenBao 'principal' that identifies users of Datalad"
   "SSH certificate type to generate" (usually accepting the default it correct)
   "Hostname of the OpenBao authentication server"
   "Port that OpenBao is listening on"
   "Authentication backend URL component on OpenBao server"
   "Does your remote git server(s) use a per-user username?"

You then need to enter the RIA and Git service host names - again, your
administrator can provide these details. Provide the servers, one per line and
press 'Return' on an empty line when finished with that server type.

   "Enter Datalad RIA endpoint host name (hit return to end)"
   "Enter Datalad GitLab/Hub host name (hit return to end)"

JSON Configuration
==================

The web-available JSON configuration needs the following keys, equivalent
to the questions asked without it:

ROLE: Openbao role for the signing process
PRINCIPAL: The generic principal to apply - used by Git services to filter
   users
CERTTYPE: SSH certificate type - see `ssh-keygen` for allowed values
BAOHOST: Hostname of the OpenBao server
BAOPORT: Port OpenBao is listening on
BAOAUTH: Authentication plugin to use
GIT_REQUIRES_USERNAME: If your Git server provides per-user accounts set
   this to true
GIT_SSH_HOSTS: List of hostnames for your Git server hosts
RIA_HOSTS: List of hostnames for your RIA hosts


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
