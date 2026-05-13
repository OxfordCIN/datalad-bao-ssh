"""DataLad OpenBao managed SSH certificates extension"""

__docformat__ = 'restructuredtext'
from . import version

import logging
lgr = logging.getLogger('datalad_bao_ss')

# Defines a datalad command suite.
# This variable must be bound as a setuptools entrypoint
# to be found by datalad
command_suite = (
    # description of the command suite, displayed in cmdline help
    "OpenBao SSH certificates DataLad command suite",
    [
        # specification of a command, any number of commands can be defined
        (
            # importable module that contains the command implementation
            'datalad_bao_ssh.bao_setup',
            # name of the command class implementation in above module
            'bao_setup',
            # optional name of the command in the cmdline API
            'bao-setup',
            # optional name of the command in the Python API
            'bao_setup'
        ),
    ]
)

__version__ = version.VERSION
