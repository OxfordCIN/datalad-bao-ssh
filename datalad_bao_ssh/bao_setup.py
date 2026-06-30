"""DataLad OxCIN login command"""
from __future__ import annotations

__docformat__ = 'restructuredtext'

from importlib.resources import as_file, files
from importlib.metadata import (packages_distributions, version)
from packaging.version import Version
from pathlib import Path

from datalad import cfg as dlcfg
from datalad.distribution.dataset import datasetmethod
from datalad.interface.base import (Interface, build_doc, eval_results)
from datalad.interface.results import get_status_dict
from datalad.support.extensions import register_config
from datalad.support.param import Parameter
from datalad.ui import ui
from sigstore.verify import Verifier
from sigstore.errors import VerificationError
from sigstore.models import Bundle
from sigstore.verify.policy import Identity
from .version import VERSION

import certifi
import getpass
import inspect
import logging
import os
import os.path
import platform
import re
import requests
import shutil
import stat
import subprocess
import tarfile
import tempfile
import truststore
import zipfile


lgr = logging.getLogger('datalad-extension-bao-ssh.bao_setup')
REKOR_IDX = "https://rekor.sigstore.dev/api/v1/index/retrieve"
REKOR_ENT = "https://rekor.sigstore.dev/api/v1/log/entries/{uuid}"


register_config(
    name="datalad.bao-ssh-config-url",
    title="URL of configuration server to attempt auto-configuration from",
    type=str,
    default="https://neurodata.fmrib.ox.ac.uk/bao_config/openbao_ssh.json",
    description="This URL, if contactable, will return a JSON configuration"
    " that will be used to automatically configure the client. If it cannot"
    " be contacted, the user will be prompted for option values",
    scope="global"
)

register_config(
    name="datalad.bao-ssh-bao-install-dir",
    title="Directory to install 'bao' command in",
    type=str,
    default=Path.home() / ".baobin",
    description="If the bao command is not installed system-wide, where"
    " to install the script",
    scope="global"
)


class BaoInstallError(Exception):
    pass


def safe_extract_zip(zip_file: Path, path: Path):
    abs_path = os.path.abspath(path)
    for member in zip_file.namelist():
        member_path = os.path.abspath(os.path.join(path, member))
        if not member_path.startswith(abs_path + os.sep):
            raise BaoInstallError(f"Unsafe zip entry: {member}")
    zip_file.extractall(path)


def safe_extract_tar(tar_file: Path, path: Path):
    if 'filter' in inspect.signature(tar_file.extractall).parameters:
        tar_file.extractall(path, filter='data')
    else:
        abs_path = os.path.abspath(path)
        for member in tar_file.getmembers():
            member_path = os.path.abspath(
                os.path.join(path, member.name)
            )
            if not member_path.startswith(abs_path + os.sep):
                raise BaoInstallError(f"Unsafe tar entry: {member.name}")
        tar_file.extractall(path)


def bao_version(install_dir: Path) -> str | None:
    bao_bin = install_dir / 'bao'
    version = None
    if os.path.exists(bao_bin):
        try:
            output = subprocess.run(
                [str(bao_bin), 'version'],
                text=True,
                capture_output=True,
                check=True
            )
            version = output.stdout.strip().split()[1].replace('v', '')
        except Exception as exc:
            raise BaoInstallError(
                f"{bao_bin} doesn't work as expected "
                f"({exc})")

    return version


def check_for_bao_update(install_dir: Path) -> tuple[bool, str]:
    message = ""
    current_version = bao_version(install_dir)
    if current_version is None:
        success = False
        message = (
            "'bao' is not installed - re-run without check"
            " argument to install.")
    else:
        try:
            success = True
            latest_release = bao_available()
            latest_version = latest_release['tag_name'].replace('v', '')
            if latest_version != current_version:
                ui.message(
                    f"Version {latest_version} available...")
                install_bao(install_dir, latest_release)
                message = (
                    f"'bao' upgraded to {latest_version}"
                )
            else:
                message = ("'bao' is latest version")
        except BaoInstallError as exc:
            success = False
            message = str(exc)
    return success, message


def bao_available(
        release_url: str = "https://api.github.com/repos"
        "/openbao/openbao/releases/latest") -> dict:

    try:
        resp = requests.get(
            release_url, verify=certifi.where())
        resp.raise_for_status()
        release = resp.json()
    except Exception as exc:
        raise BaoInstallError(
            f"Unable to find Bao releases on GitHub ({str(exc)})")

    lgr.debug("Latest Bao version:", release["tag_name"])
    return release


def install_bao(install_dir: Path, release: dict = bao_available()) -> str:
    ui.message(
            f"Attempting to install Openbao client 'bao' into {install_dir}"
        )
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        raise BaoInstallError(f"Unrecognised architecture {machine}")

    if system == "linux":
        fnend = f"_linux_{arch}.tar.gz"
    elif system == "darwin":
        fnend = f"_darwin_{arch}.tar.gz"
    elif system == "windows":
        fnend = f"_windows_{arch}.zip"
    else:
        raise BaoInstallError(f"Unsupported OS: {system}")

    asset = None
    bundle = None
    for a in release["assets"]:
        name = a["name"].lower()
        if name.lower().endswith(fnend):
            asset = dict(a)
            break
    for a in release["assets"]:
        name = a["name"].lower()
        if name.lower().endswith(f'{fnend}.sigstore.json'):
            bundle = dict(a)
            break
    if not asset:
        raise BaoInstallError("Could not find a release for this OS")
    if not bundle:
        raise BaoInstallError(
            "Could not find a signature for this release")

    ui.message("Downloading bao ")
    try:
        with tempfile.TemporaryDirectory() as td:
            tpath = Path(td)
            lgr.debug(f"Downloading {asset['browser_download_url']}")
            download_resp = requests.get(
                asset['browser_download_url'],
                stream=True,
                verify=certifi.where())
            download_resp.raise_for_status()
            archive_path = tpath / Path(asset["name"])
            with open(archive_path, "wb") as f:
                for chunk in download_resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            lgr.debug(f"Downloading {bundle['browser_download_url']}")
            download_resp = requests.get(
                bundle['browser_download_url'],
                stream=True,
                verify=certifi.where())
            download_resp.raise_for_status()

            bundle_path = tpath / Path(bundle["name"])
            with open(bundle_path, 'wb') as f:
                for chunk in download_resp.iter_content(chunk_size=8192):
                    f.write(chunk)

            with bundle_path.open("r") as f:
                bundle = Bundle.from_json(f.read())

            expected_identity = Identity(
                identity="https://github.com/openbao/openbao/.github/"
                f"workflows/release.yml@refs/tags/{release['tag_name']}",
                issuer="https://token.actions.githubusercontent.com")

            verifier = Verifier.production()
            try:
                with archive_path.open("rb") as artifact_file:
                    verifier.verify_artifact(
                        input_=artifact_file,
                        bundle=bundle,
                        policy=expected_identity)
            except VerificationError:
                raise BaoInstallError("Download failed verification")

            if not isinstance(install_dir, Path):
                install_dir = Path(install_dir)

            install_dir.mkdir(exist_ok=True)
            extract_dir = tpath / "extracted"
            extract_dir.mkdir()
            if os.path.splitext(archive_path)[1] == '.zip':
                # Zip file
                with zipfile.ZipFile(archive_path, 'r') as z:
                    safe_extract_zip(z, extract_dir)
            else:
                # Tar.gz file
                with tarfile.open(archive_path, 'r:gz') as tar:
                    if 'filter' in inspect.signature(
                            tar.extractall).parameters:
                        tar.extractall(extract_dir, filter='data')
                    else:
                        safe_extract_tar(tar, extract_dir)

            bao_cmd = "bao.exe" if system == "windows" else "bao"
            temp_bao_binary = extract_dir / bao_cmd
            bao_binary = install_dir / bao_cmd

            # Make executable on Unix
            if system != "windows":
                temp_bao_binary.chmod(
                    temp_bao_binary.stat().st_mode | stat.S_IEXEC)
            shutil.copy(temp_bao_binary, bao_binary)

    except Exception as exc:
        raise BaoInstallError(str(exc)) from exc

    ui.message(f"'bao' {release['tag_name']} installed.")
    ui.message(
        "If you want to use 'bao' outside of the configured"
        f" servers then you will need to add {install_dir}"
        " to your PATH environment variable")
    return str(bao_binary)


def shell() -> str:
    shell = os.environ.get('SHELL', '/bin/sh')
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


def prompt_for_config() -> dict:
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
            "OpenBao 'principal' that identifies users of DataLad"),
        ("CERTTYPE", "ed25519",
            "SSH certificate type to generate"),
        ("BAOHOST", "",
            "Hostname of the OpenBao authentication server"),
        ("BAOPORT", "8200",
            "Port that OpenBao is listening on"),
        ("BAOAUTH", "ldap",
            "Authentication backend URL component on OpenBao server"),
    ]
    for opt in options:
        config[opt[0]] = ui.question(
            opt[0],
            default=opt[1],
            title=opt[2]
        )
    config['GIT_REQUIRES_USERNAME'] = ui.yesno(
            "Does your remote git server(s) use a per-user username?"
            " (Ordinarily GitLab/Hub server endpoints will have any"
            " required username encoded into the repository so this"
            " will probably be 'no')",
            default=False)

    ssh_host = 'NOHOST'
    config['RIA_HOSTS'] = []
    while ssh_host != '':
        ssh_host = ui.question(
            "Enter DataLad RIA endpoint host name (hit return to end)"
        )
        if ssh_host != '':
            config['RIA_HOSTS'].append(ssh_host)

    config['GIT_SSH_HOSTS'] = []
    ssh_host = 'NOHOST'
    while ssh_host != '':
        ssh_host = ui.question(
            "Enter DataLad GitLab/Hub host name (hit return to end)"
        )
        if ssh_host != '':
            config['GIT_SSH_HOSTS'].append(ssh_host)

    return config


def ssh_host_stanza(
        host: str, identity_file: Path, exec: Path,
        cert_ext: str = "-cert.pub",
        username: str | None = None) -> str:
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


def get_renewal_confs(ssh_folder: Path) -> list[str]:
    main_ssh_conf = ssh_folder / 'config'
    confs = []
    found = False
    with open(main_ssh_conf, 'r') as ssh_conf:
        in_my_conf = False
        for line in ssh_conf:
            if line.startswith("# OpenBao renewals "):
                in_my_conf = True
                found = True
                continue
            if in_my_conf:
                if line.startswith('Include "datalad-'):
                    confs.append(
                        line.split(' ')[1].strip('\n').strip('"'))
                    in_my_conf = False
    if not found:
        raise BaoInstallError(
            "OpenBao doesn't appear to be configured for your DataLad"
            " servers - please run without the update flag")
    if not confs:
        raise BaoInstallError(
            "OpenBao doesn't appear to be configured correctly for your "
            "DataLad servers - please run without the update flag")
    return confs


def get_config_from_renewal_conf(conf: Path) -> tuple[Path, dict]:
    config_keys = (
        'VERSION',
        'ROLE',
        'PRINCIPAL',
        'CERTTYPE',
        'BAOHOST',
        'BAOPORT',
        'BAOAUTH',
        'BAOOPENID',
        'BAOBIN',
        'BAOUSERNAME', )
    config = {}
    match_host = re.compile(r'^Match host\b.*?\bexec\s+"([^"]+)"$')
    script = None
    with open(conf, 'r') as ssh_conf_include:
        for line in ssh_conf_include:
            if m := match_host.match(line):
                script = m.group(1)
    if script is None:
        raise BaoInstallError(
            f"Include file {conf} missing Match host statement")
    scriptp = conf.parent / script
    with open(scriptp, 'r') as usshef:
        for line in usshef.readlines():
            if line == '#!/bin/bash\n':
                continue
            elif line == '## End of configuration ##\n':
                break
            else:
                for k in config_keys:
                    if line.startswith(f'{k}="'):
                        config[k] = line.split('=')[1].strip('\n').\
                            strip('"').strip("'")
            lgr.debug(line)
    return script, config


def install_certificate_renewal_script(
        ssh_folder: Path, config: dict) -> Path:
    ssh_exec = files("datalad_bao_ssh").joinpath(
        "openbao_certificate_renew.sh")
    user_ssh_exec = (
        ssh_folder /
        f"{config['BAOHOST'].replace('.', '-')}-renew.sh")

    skiplines = (
        'RIA_HOSTS', 'GIT_REQUIRES_USERNAME',
        'GIT_SSH_HOSTS', )
    with as_file(ssh_exec) as ssh_exec_path:
        with open(ssh_exec_path, 'r') as sshef:
            with open(user_ssh_exec, 'w') as usshef:
                for line in sshef.readlines():
                    if line == '#!/bin/bash\n':
                        line = f'#!{shell()}\n'
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
    return user_ssh_exec


def update_renewal_scripts(ssh_folder: Path, version: Version) -> list[str]:
    messages = []
    renewal_confs = get_renewal_confs(ssh_folder)
    for conf in renewal_confs:
        script, config = get_config_from_renewal_conf(ssh_folder / conf)
        if config['VERSION'] != version:
            lgr.info(f"Updating renewal script ({script})")
            config['VERSION'] = version
            install_certificate_renewal_script(ssh_folder, config)
            messages.append(
                f"Renewal script {os.path.basename(script)} updated to version"
                f" {version}")
    return messages


def check_package_update(package: str, current: Version) ->\
       tuple[bool | None, Version, Version, str]:
    try:
        r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=5)
        r.raise_for_status()
        latest = Version(r.json()["info"]["version"])
    except requests.exceptions.RequestException:
        # Network/server problem. Ignore.
        return (
            None, current, current,
            f"Failed to check for update of {package} "
            "- cannot access project URL")
    except (KeyError, ValueError):
        return (
            None, current, current,
            f"Unexpected version information obtained from PyPi for {package}"
        )
    return (latest > current, current, latest, package, )


# decoration auto-generates standard help
@build_doc
# all commands must be derived from Interface
class bao_setup(Interface):
    # first docstring line is used a short description in the cmdline help
    # the rest is put in the verbose help and manpage
    """Configure SSH to use short-lived OpenBao signed SSH certificates

    This creates a short-lived SSH key pair and then uses an OpenBao
    server to sign this. The user's SSH configuration is then updated to
    point at the appropriate key pair when accessing one of the RIA
    hosts and to check for and renew expired certificates.
    """

    # parameters of the command, must be exhaustive
    _params_ = dict(
        update=Parameter(
            args=("--update", ),
            doc="Check for an update",
            action="store_true",
        ),
    )

    @staticmethod
    # decorator binds the command to the Dataset class as a method
    @datasetmethod(name='ssh_setup')
    # generic handling of command results (logging, rendering, filtering, ...)
    @eval_results
    # signature must match parameter list above
    # additional generic arguments are added by decorators
        truststore.inject_into_ssl()
        ui.message(f"DataLad OpenBao SSH certificate integration ({VERSION})")
        install_dir = dlcfg.obtain("datalad.bao-ssh-bao-install-dir")
        system_bao = shutil.which("bao")
        ssh_folder = Path.home() / '.ssh'

        if system_bao is not None:
            system = platform.system().lower()
            bao_binary = (
                "bao.exe" if system == "windows" else "bao")
        else:
            bao_binary = ''
        if update:
            messages = []
            # Check for updates to this package
            available, current, latest, package_name = check_package_update(
                packages_distributions()[__package__][0], Version(VERSION))
            if available:
                messages.append(
                    f"Update available for this plugin: {current} ->"
                    f" {latest}\n"
                    "Use your Python package manager to update, e.g.\n"
                    f"  pip install --upgrade {package_name}\n"
                    "or\n"
                    f"  uv lock --upgrade-package {package_name}\n"
                    "  uv sync\n"
                    "\n"
                    "Then re-run the updater with\n"
                    "  datalad bao_setup --update")
            elif available is None:
                messages.append(package_name)

            # Check for updates to DataLad
            available, current, latest, package_name = check_package_update(
                'datalad', Version(version("datalad")))
            if available:
                messages.append(
                    f"Update available for DataLad: {current} -> {latest}\n"
                    "Use your Python package manager to update, e.g.\n"
                    f"  pip install --upgrade datalad\n"
                    "or\n"
                    f"  uv lock --upgrade-package datalad\n"
                    "  uv sync"
                    )
            elif available is None:
                messages.append(package_name)

            # Check for user's SSH script being out of date
            try:
                messages.extend(update_renewal_scripts(ssh_folder, VERSION))
            except Exception as exc:
                messages.append(str(exc))
                mess_str = '\n'.join(messages)
                status_dict.update(
                    {
                        'status': 'error',
                        'exc': exc,
                        'error_message': (
                            "Failed updating renewal script(s) "
                            f"({mess_str})"
                        ),
                    })
            else:
                if system_bao is None:
                    success, message = check_for_bao_update(install_dir)
                    if not success:
                        status_dict['status'] = 'error'
                        status_dict['error_message'] = message
                    else:
                        messages.append(message)
                        status_dict['msg'] = '\n'.join(messages)
                else:
                    messages.append(
                        f"bao installed externally "
                        f"as {system_bao}, ignoring")
                    status_dict['msg'] = '\n'.join(messages)

        else:
            if bao_binary == "":
                try:
                    bao_binary = install_bao(install_dir=install_dir)
                except BaoInstallError:
                    bao_binary = ""

            session = requests.Session()
            lgr.info("Attempting to download configuration")
            try:
                r = session.get(
                    dlcfg.obtain("datalad.bao-ssh-config-url"),
                    timeout=10
                )
                config = r.json()
            except Exception:
                config = prompt_for_config()

            # The following is a list of OpenBao methods that use external
            # services to collect the password
            no_password_methods = ['oidc', ]
            if config:
                config['VERSION'] = VERSION
                bao_username = ui.question(
                    "BAOUSERNAME",
                    default=getpass.getuser(),
                    title=(
                        "Enter your username for the DataLad service: ")
                )
                config['BAOUSERNAME'] = bao_username
                if config['BAOAUTH'] in no_password_methods:
                    config['BAOOPENID'] = 1
                else:
                    config['BAOOPENID'] = 0
                config['BAOBIN'] = bao_binary
                ssh_servers = config['RIA_HOSTS'] + config['GIT_SSH_HOSTS']
                try:
                    stage = "Checking your .ssh folder"
                    if not ssh_folder.exists():
                        ssh_folder.mkdir()
                        ssh_folder.chmod(0o700)
                    if not (ssh_folder / 'config').exists():
                        (ssh_folder / 'config').write_text('')
                    try:
                        with tempfile.TemporaryFile(dir=ssh_folder):
                            pass
                    except Exception:
                        raise BaoInstallError(
                            "Unable to write to your .ssh folder")
                    stage = "Installing renewal script"
                    lgr.info(stage)

                    user_ssh_exec = install_certificate_renewal_script(
                        ssh_folder, config)
                    stage = (
                        "Building SSH configuration for Bao authenticated"
                        " servers")
                    lgr.info(stage)

                    cert_ext = '-cert.pub'
                    idfile = (
                        ssh_folder
                        / (f"id-{config['CERTTYPE']}-"
                            f"{config['BAOHOST'].replace('.', '-')}"))
                    ssh_conf_file = (
                        ssh_folder
                        / f"datalad-{config['BAOHOST'].replace('.', '-')}.conf"
                        )

                    with open(ssh_conf_file, 'w') as sshcf:
                        for host in ssh_servers:
                            username = bao_username
                            if (
                                    host in config['GIT_SSH_HOSTS']
                                    and not config['GIT_REQUIRES_USERNAME']):
                                username = None

                            sshcf.write(
                                ssh_host_stanza(
                                    host,
                                    idfile,
                                    user_ssh_exec,
                                    cert_ext,
                                    username=username))

                    stage = "Including SSH configuration into main config file"
                    lgr.info(stage)

                    main_ssh_conf = ssh_folder / 'config'
                    include_line = (
                        f"# OpenBao renewals {config['BAOHOST']}\nInclude"
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
                except Exception as exc:
                    status_dict.update(
                        {
                            'status': 'error',
                            'exc': exc,
                            'error_message': f"Failed at {stage}"
                        })

        # commands should be implemented as generators and should
        # report any results by yielding status dictionaries
        yield get_status_dict(**status_dict)
