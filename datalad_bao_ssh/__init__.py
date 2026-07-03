"""DataLad OpenBao managed SSH certificates extension"""
from pathlib import Path
from datalad.support.extensions import register_config

__docformat__ = 'restructuredtext'

from . import version

import logging
lgr = logging.getLogger('datalad_bao_ssh')

# Defines a datalad command suite.
# This variable must be bound as a setuptools entrypoint
# to be found by datalad
command_suite = (
    # description of the command suite, displayed in cmdline help
    "OpenBao SSH logins command suite",
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


register_config(
    name="datalad.bao-ssh-config-url",
    title="URL of configuration server to attempt auto-configuration from",
    type=str,  # pyright: ignore[reportArgumentType]
    default="https://neurodata.fmrib.ox.ac.uk/bao_config/openbao_ssh.json",  # pyright: ignore[reportArgumentType] # noqa: E501
    description="This URL, if contactable, will return a JSON configuration"
    " that will be used to automatically configure the client. If it cannot"
    " be contacted, the user will be prompted for option values",
    scope="global"  # pyright: ignore[reportArgumentType]
)

register_config(
    name="datalad.bao-ssh-bao-install-dir",
    title="Directory to install 'bao' command in",
    type=str,  # pyright: ignore[reportArgumentType]
    default=Path.home() / ".baobin",   # pyright: ignore[reportArgumentType]
    description="If the bao command is not installed system-wide, where"
    " to install the script",
    scope="global"  # pyright: ignore[reportArgumentType]
)


__version__ = version.VERSION
