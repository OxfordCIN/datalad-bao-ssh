"""DataLad OxCIN login command"""
from __future__ import annotations

__docformat__ = 'restructuredtext'

from importlib.resources import as_file, files
from pathlib import Path

from datalad import cfg as dlcfg
from datalad.interface.base import Interface
from datalad.interface.base import build_doc
from datalad.distribution.dataset import datasetmethod
from datalad.interface.base import eval_results
from datalad.support.extensions import register_config
from datalad.ui import ui
from datalad.interface.results import get_status_dict

import getpass
import logging
import os
import os.path
import platform
import requests
import tempfile


lgr = logging.getLogger('datalad.bao_ssh.setup_ssh')


register_config(
    name="datalad.bao-ssh-config-url",
    title="URL of configuration server to attempt auto-configuration from",
    type=str,
    default="https://datalad.fmrib.ox.ac.uk/bao_conf/ssh_conf.json",
    description="This URL, if contactable, will return a JSON configuration"
    " that will be used to automatically configure the client. If it cannot"
    " be contacted, the user will be prompted for option values",
    scope="global"
)


# decoration auto-generates standard help
@build_doc
# all commands must be derived from Interface
class setup_ssh(Interface):
    # first docstring line is used a short description in the cmdline help
    # the rest is put in the verbose help and manpage
    """Configure SSH to use short-lived OpenBao signed SSH certificates

    This creates a short-lived SSH key pair and then uses an OpenBao
    server to sign this. The user's SSH configuration is then updated to
    point at the appropriate key pair when accessing one of the RIA
    hosts and to check for and renew expired certificates.
    """

    # parameters of the command, must be exhaustive
    _params_ = dict()

    def shell(self):
        shell = os.environ['SHELL']
        executable = os.path.basename(shell)
        if executable == 'tcsh':
            system = platform.system()
            if system == 'Darwin':
                shell = '/bin/zsh'
            elif system == 'Linux':
                shell = '/bin/bash'
            else:
                shell = '/bin/sh'
                lgr.warning("Unrecognised OS - renewal script may not work")
        return shell

    def prompt_for_config(self):
        config = {}

        ui.message(
            "The configuration server was not contactable."
        )
        if ui.yesno(
                "Would you like to quit so that you can connect to a VPN "
                "and try again?",
                default=False
                ):
            return config
        options = [
            ("ROLE", "datalad-role",
             "OpenBao role that allows signing of SSH certificates"),
            ("PRINCIPAL", "dataladUsers",
             "OpenBao 'principal' that identifies users of Datalad"),
            ("CERTTYPE", "ed25519",
             "SSH certificate type to generate"),
            ("BAOHOST", "",
             "Hostname of the OpenBao authentication server"),
            ("BAOPORT", "8200",
             "Port that OpenBao is listening on"),
            ("BAOAUTH", "ldap",
             "Authentication backend URL component on OpenBao server"),
            ("GIT_REQUIRES_USERNAME", False,
             "Does your remote git server(s) use a per-user username?")
        ]
        for opt in options:
            config[opt[0]] = ui.question(
                opt[0],
                default=opt[1],
                title=opt[2]
            )
        ssh_host = 'NOHOST'
        config['RIA_HOSTS'] = []
        while ssh_host != '':
            ssh_host = ui.question(
                "Enter Datalad RIA endpoint host name (hit return to end)"
            )
            if ssh_host != '':
                config['RIA_HOSTS'].append(ssh_host)

        config['GIT_SSH_HOSTS'] = []
        ssh_host = 'NOHOST'
        while ssh_host != '':
            ssh_host = ui.question(
                "Enter Datalad Git server host name (hit return to end)"
            )
            if ssh_host != '':
                config['GIT_SSH_HOSTS'].append(ssh_host)

        return config

    def ssh_host_stanza(
            self, host, identity_file, exec,
            cert_ext="-cert.pub", username=None):
        '''Templates the Match statement for a SSH target that calls the
        renewal script'''

        template = f'''Match host {host} exec "{exec}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{identity_file}{cert_ext}"
'''
        if username is not None:
            template += f'    User "{username}"\n\n'
        else:
            template += '\n'

        return template

    @staticmethod
    # decorator binds the command to the Dataset class as a method
    @datasetmethod(name='ssh_setup')
    # generic handling of command results (logging, rendering, filtering, ...)
    @eval_results
    # signature must match parameter list above
    # additional generic arguments are added by decorators
    def __call__(self):

        session = requests.Session()
        lgr.info("Attempting to download configuration")

        try:
            r = session.get(
                dlcfg.get("datalad.bao-ssh-config-url"),
                timeout=10
            )
            config = r.json()
        except Exception:
            config = self.prompt_for_config()

        status_dict = {'action': 'setup_ssh', 'status': 'ok'}
        if config:
            usernames = {}
            username_servers = config['RIA_HOSTS']
            ssh_servers = config['RIA_HOSTS'] + config['GIT_SSH_HOSTS']
            if config['GIT_REQUIRES_USERNAME']:
                username_servers.extend(config['GIT_SSH_HOSTS'])
            for ssh_host in username_servers:
                usernames[ssh_host] = ui.question(
                        "USERNAME",
                        default=getpass.getuser(),
                        title=f"Enter your username on the server {ssh_host}: "
                    )

            ssh_folder = Path.home() / '.ssh'
            stage = "Installing renewal script"
            lgr.info(stage)
            ssh_exec = files("datalad_bao_ssh").joinpath(
                "openbao_certificate_renew.sh"
            )
            user_ssh_exec = (
                ssh_folder
                / f'{config['BAOHOST'].replace('.', '-')}-renew.sh')
            skiplines = (
                'RIA_HOSTS', 'GIT_REQUIRES_USERNAME',
                'GIT_SSH_HOSTS', )
            try:
                with as_file(ssh_exec) as ssh_exec_path:
                    with open(ssh_exec_path, 'r') as sshef:
                        with open(user_ssh_exec, 'w') as usshef:
                            for line in sshef.readlines():
                                if line == '#!/bin/bash\n':
                                    line = f'#!{self.shell()}\n'
                                else:
                                    for k, v in config.items():
                                        if k in skiplines:
                                            continue
                                        if f'**{k}**' in line:
                                            line = line.replace(
                                                f'**{k}**', str(v))
                                lgr.debug(line)
                                usshef.write(line)
                os.chmod(user_ssh_exec, 0o700)
                stage = (
                    "Building SSH configuration for Bao authenticated"
                    " servers")
                lgr.info(stage)

                cert_ext = '-cert.pub'
                idfile = (
                    ssh_folder
                    / f'id-{config['BAOHOST'].replace('.', '-')}')
                ssh_conf_file = (
                    ssh_folder
                    / f'{config['BAOHOST'].replace('.', '-')}.conf')

                with open(ssh_conf_file, 'w') as sshcf:
                    for host in ssh_servers:
                        sshcf.write(
                            self.ssh_host_stanza(
                                host,
                                idfile,
                                user_ssh_exec,
                                cert_ext,
                                username=usernames.get(host, None)))

                stage = "Including SSH configuration into main config file"
                lgr.info(stage)

                main_ssh_conf = ssh_folder / 'config'
                include_line = (
                    "# OpenBao renewals\nInclude"
                    f' "{os.path.basename(ssh_conf_file)}"')
                with open(main_ssh_conf, 'r') as msshc:
                    found = include_line in msshc.read()

                    if not found:
                        stage = "Updating main SSH configuration file"
                        lgr.info(stage)
                        with tempfile.NamedTemporaryFile(
                                mode='w',
                                delete=False,
                                dir=ssh_folder) as newsshf:
                            newsshf.write(include_line + '\n\n')
                            msshc.seek(0)
                            for line in msshc.readlines():
                                newsshf.write(line)
                            new_conf = newsshf.name
                        os.replace(new_conf, main_ssh_conf)
                status_dict.update(
                    {'msg': "OpenBao certificate renewals configured"})
            except (PermissionError, IOError, ) as exc:
                status_dict.update(
                    {
                        'status': 'error',
                        'exc': exc,
                        'error_message': f"Failed at {stage}"
                    })

        # commands should be implemented as generators and should
        # report any results by yielding status dictionaries
        yield get_status_dict(**status_dict)
