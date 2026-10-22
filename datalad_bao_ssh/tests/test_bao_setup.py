import datetime
import io
import json
import os
import os.path
import pexpect
import platform
import pytest
import requests
import shutil
import ssl
import stat
import subprocess as sp
import tarfile
import time
import trustme
import truststore
import zipfile

from importlib.metadata import entry_points
from io import StringIO
from pytest_httpserver import HTTPServer
from packaging.version import Version
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock
from urllib.parse import urlsplit
from werkzeug.wrappers import Response

from datalad_bao_ssh.version import VERSION
from datalad_bao_ssh import bao_setup
from datalad.cli.parser import setup_parser
from datalad.support.exceptions import IncompleteResultsError


# Session level fixtures

@pytest.fixture(scope="session")
def ca():
    return trustme.CA()


@pytest.fixture(scope="session")
def httpserver_ssl_context(ca):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    localhost_cert = ca.issue_cert("localhost")
    localhost_cert.configure_cert(context)
    return context


@pytest.fixture(scope="session")
def ca_cert_path(ca):
    with ca.cert_pem.tempfile() as path:
        yield path


# Test level fixtures
@pytest.fixture
def requests_ca_bundle(monkeypatch, ca):
    monkeypatch.setenv("DATALAD_BAO_SSH_CA_CERT", str(ca))
    monkeypatch.setenv("DATALAD_BAO_SSH_DEBUG", "1")
    with ca.cert_pem.tempfile() as ca_pem:
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ca_pem))
        yield str(ca_pem)


@pytest.fixture
def bao(tmp_path, monkeypatch):
    bao_script = bao_setup.install_bao(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path), prepend=os.pathsep)
    return bao_script


@pytest.fixture
def mock_bao(mocker, tmp_path):
    bao_script = tmp_path / 'bao'
    test_dir = Path(__file__).parent
    test_bao_script = test_dir / 'fake_bao.sh'
    shutil.copy(test_bao_script, bao_script)
    os.chmod(bao_script, 0o755)
    which = mocker.patch(
        "datalad_bao_ssh.bao_setup.shutil.which",
        return_value=str(bao_script))
    return {
        'which': which,
        'script': bao_script,
    }


@pytest.fixture
def mock_no_bao(mocker):
    mocker.patch(
        "datalad_bao_ssh.bao_setup.shutil.which",
        return_value=None)
    mocker.patch(
        "datalad_bao_ssh.bao_setup.install_bao",
        side_effect=bao_setup.BaoInstallError()
    )


@pytest.fixture
def datalad_ui(mocker):
    def create(yesnos=[], questions=[]):
        fake_ui = SimpleNamespace(
            message=Mock(),
            yesno=Mock(side_effect=yesnos),
            question=Mock(side_effect=questions)
        )
        ui = mocker.patch(
            "datalad_bao_ssh.bao_setup.ui",
            fake_ui
        )
        return ui
    return create


@pytest.fixture
def mock_ui_message(datalad_ui):
    ui = datalad_ui()
    return {
        'ui': ui
    }


@pytest.fixture
def renew_certificate(
        monkeypatch, tmp_path,
        httpserver: HTTPServer,
        requests_ca_bundle, ca_cert_path):
    def create(openid=False, bao=""):
        mod_dir = Path(__file__).parent.parent
        home_dir = tmp_path
        ca_key = _make_ca_keypair(home_dir)
        ssh_dir = home_dir / '.ssh'
        os.mkdir(ssh_dir)
        os.chmod(ssh_dir, 0o700)

        username = 'joebloggs'
        password = '1234567890'
        token = 'ABCDEFGHIJKLMNOPQRSTUVW0123456789'

        baourl = httpserver.url_for('')
        split_url = urlsplit(baourl)
        baosrv = split_url.hostname
        baoport = str(split_url.port)
        config = {
            "ROLE": "datalad-role",
            "PRINCIPAL": "dataladUsers",
            "CERTTYPE": "ed25519",
            "BAOHOST": baosrv,
            "BAOPORT": baoport,
            "BAOAUTH": "ldap" if not openid else 'oidc',
            "BAOOPENID": "1" if openid else "0",
            "BAOBIN": bao,
            "BAOUSERNAME": username,
            "VERSION": VERSION
        }
        renew_scripts = {
            'bash': ssh_dir / 'openbao_certificate_renew.bash',
            'zsh': ssh_dir / 'openbao_certificate_renew.zsh',
        }
        for shell in ('bash', 'zsh'):
            with open(
                    mod_dir / 'openbao_certificate_renew.sh',
                    'r') as template:
                with open(renew_scripts[shell], 'w') as script:
                    for line in template.readlines():
                        if line == '#!/bin/bash\n':
                            line = f'#!/bin/{shell}\n'
                        else:
                            for k, v in config.items():
                                if f'**{k}**' in line:
                                    line = line.replace(f'**{k}**', v)
                        script.write(line)
            os.chmod(renew_scripts[shell], 0o700)

        server_response = dict(config)
        server_response.update({
            "GIT_REQUIRES_USERNAME": False,
            "RIA_HOSTS": [
                "ria1.com",
                "ria2.com"
            ],
            "GIT_SSH_HOSTS": [
                "git1.com",
            ]
        })

        monkeypatch.setenv('HOME', str(tmp_path))
        monkeypatch.setenv('DATALAD_BAO_SSH_CA_CERT', ca_cert_path)
        return {
            'home_dir': home_dir,
            'ca_key': ca_key,
            'ssh_dir': ssh_dir,
            'baosrv': baosrv,
            'config': config,
            'renew_scripts': renew_scripts,
            'httpserver': httpserver,
            'username': username,
            'password': password,
            'token': token,
            'server_response': server_response,
        }
    return create


@pytest.fixture
def ssh_environment(tmp_path, mocker, datalad_ui):
    shell = os.environ.get('SHELL', '/bin/bash')
    executable = os.path.basename(shell)
    if executable == 'tcsh':
        system = platform.system()
        if system == 'Darwin':
            shell = '/bin/zsh'
        elif system == 'Linux':
            shell = '/bin/bash'
        else:
            shell = '/bin/sh'

    username = 'joebloggs'
    ssh_dir = tmp_path / '.ssh'
    ssh_config = ssh_dir / 'config'
    os.mkdir(ssh_dir)
    with open(ssh_config, 'w') as empty_conf:
        empty_conf.write('\n')

    user_response = {
        "ROLE": "sshuser-role",
        "PRINCIPAL": "sshUsers",
        "CERTTYPE": "rsa",
        "BAOHOST": "baoserver.co.uk",
        "BAOPORT": "8200",
        "BAOAUTH": "ldap",
        "GIT_REQUIRES_USERNAME": False,
        "GIT_SSH_HOSTS": [
            'git1.com'
        ],
        "RIA_HOSTS": [
            "ria3.com",
            "ria4.com"
        ]
    }
    skiplines = (
                'RIA_HOSTS', 'GIT_REQUIRES_USERNAME',
                'GIT_SSH_HOSTS', )
    vpn_connect = False

    fake_ui = datalad_ui(
        yesnos=(
            False, user_response['GIT_REQUIRES_USERNAME']),
        questions=[
            user_response['ROLE'],
            user_response['PRINCIPAL'],
            user_response["CERTTYPE"],
            user_response["BAOHOST"],
            user_response["BAOPORT"],
            user_response["BAOAUTH"],
            user_response["RIA_HOSTS"][0],
            user_response["RIA_HOSTS"][1],
            "",
            user_response['GIT_SSH_HOSTS'][0],
            "",
            username,
        ]
    )
    patches = {
        "Path.home": mocker.patch(
            "datalad_bao_ssh.bao_setup.Path.home",
            return_value=Path(tmp_path)),
        "ui": mocker.patch(
            "datalad_bao_ssh.bao_setup.ui",
            fake_ui),
    }

    return {
        'shell': shell,
        'patches': patches,
        'ssh_dir': ssh_dir,
        'tmp_path': tmp_path,
        'user_response': user_response,
        'ssh_config': ssh_config,
        'vpn_connect': vpn_connect,
        'username': username,
        'skiplines': skiplines,
        'principal': user_response['PRINCIPAL'],
    }


@pytest.fixture
def mock_github(
        httpserver, tmp_path, monkeypatch, ca, ca_cert_path):
    def create(
            archive_type=".tar.gz", version="1.2.4",
            os="Linux", arch="x86_64", no_sig=False, fail=False):
        archive = f"bao_{version}_{os}_{arch}{archive_type}"
        sig = f"{archive}.sigstore.json"
        url_path = '/repos/openbao/openbao/releases/latest'
        download_url_path = f'/openbao/openbao/releases/download/v{version}'
        server_response = {
            "tag_name": f"v{version}",
            "assets": [
                {
                    "name": archive,
                    "browser_download_url": httpserver.url_for(
                            download_url_path + '/' + archive)
                },
                {
                    "name": sig,
                    "browser_download_url": httpserver.url_for(
                            download_url_path + '/' + sig)
                }
            ]
        }
        if no_sig:
            server_response['assets'].pop(-1)
        monkeypatch.setattr(
            "datalad_bao_ssh.bao_setup.certifi.where", lambda: ca_cert_path)

        if not fail:
            httpserver.expect_request(
                url_path).respond_with_json(
                    server_response)
        else:
            if fail is True:
                code = '500'
            else:
                code = fail
            httpserver.expect_request(
                url_path).respond_with_data(
                    "Internal Server Error",
                    status=code,
                    content_type="text/plain"
                )
        return {
            'archive': archive,
            'sig': sig,
            'url_path': url_path,
            'download_url_path': download_url_path,
            'url': httpserver.url_for(url_path),
            'server_response': server_response
        }
    return create


def entrypoint_registered():
    return any(
        ep.name == "bao_setup"
        for ep in entry_points(group="datalad.extensions")
    )


def make_zip(entries: dict[str, bytes]) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return zipfile.ZipFile(buf, mode="r")


def make_zip_file(
        tmp_path, zipname, entries: dict[str, bytes]) -> zipfile.ZipFile:
    tf = tmp_path / zipname
    with zipfile.ZipFile(tf, mode="w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return tf


def make_tar(entries: dict[str, bytes]) -> tarfile.TarFile:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return tarfile.open(fileobj=buf, mode="r")


def make_tar_file(
        tmp_path, tarname, entries: dict[str, bytes]) -> tarfile.TarFile:
    tf = tmp_path / tarname
    with tarfile.open(tf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return tf


def test_safe_extract_zip_extracts_files(tmp_path: Path):
    zip_file = make_zip({"good.txt": b"hello"})
    outdir = tmp_path / "out"

    bao_setup.safe_extract_zip(zip_file, outdir)

    assert (outdir / "good.txt").read_text() == "hello"


def test_safe_extract_zip_rejects_traversal(tmp_path: Path):
    zip_file = make_zip({"../evil.txt": b"bad"})
    outdir = tmp_path / "out"

    with pytest.raises(
            bao_setup.BaoInstallError,
            match="Unsafe zip entry: ../evil.txt"):
        bao_setup.safe_extract_zip(zip_file, outdir)


def test_safe_extract_tar_uses_filter_when_supported(
        monkeypatch, tmp_path: Path):
    class TarWithFilter:
        def __init__(self):
            self.called = None

        def extractall(self, path, filter=None):
            self.called = (path, filter)

        def getmembers(self):
            raise AssertionError(
                "getmembers should not be used when filter is supported")

    tar_file = TarWithFilter()
    outdir = tmp_path / "out"

    bao_setup.safe_extract_tar(cast(tarfile.TarFile, tar_file), outdir)

    assert tar_file.called == (outdir, "data")


def test_safe_extract_tar_fallback_extracts_files(
        tmp_path: Path, monkeypatch):
    extracted = {}

    class FakeTar:
        def getmembers(self):
            return [SimpleNamespace(name="good.txt")]

        def extractall(self, path):
            extracted["path"] = path
            (path / "good.txt").write_text("hello")

    class FakeSignature:
        parameters = {}

    monkeypatch.setattr(
        bao_setup.inspect,
        "signature",
        lambda _func: FakeSignature()
    )

    outdir = tmp_path / "out"
    outdir.mkdir()

    tar_file = FakeTar()
    bao_setup.safe_extract_tar(cast(tarfile.TarFile, tar_file), outdir)

    assert extracted["path"] == outdir
    assert (outdir / "good.txt").read_text() == "hello"


def test_safe_extract_tar_fallback_rejects_traversal(
        monkeypatch, tmp_path: Path):
    class FakeTar:
        def __init__(self):
            self.extractall_called = False

        def getmembers(self):
            return [SimpleNamespace(name="../evil.txt")]

        def extractall(self, path):
            self.extractall_called = True

    class FakeSignature:
        parameters = {}

    monkeypatch.setattr(
        bao_setup.inspect,
        "signature", lambda _func: FakeSignature())

    tar_file = FakeTar()
    outdir = tmp_path / "out"

    with pytest.raises(
            bao_setup.BaoInstallError,
            match="Unsafe tar entry: ../evil.txt"):
        bao_setup.safe_extract_tar(cast(tarfile.TarFile, tar_file), outdir)

    assert not tar_file.extractall_called


@pytest.mark.parametrize(
        "system,machine,ext,special,exe",
        [
            ('Linux', 'x86_64', '.tar.gz', None, 'bao', ),
            ('Linux', 'arm64', '.tar.gz', None, 'bao', ),
            ('Darwin', 'x86_64', '.tar.gz', None, 'bao', ),
            ('Darwin', 'arm64', '.tar.gz', None, 'bao', ),
            ('Windows', 'x86_64', '.zip', None, 'bao.exe', ),
            ('Windows', 'arm64', '.zip', None, 'bao.exe', ),
            ('FreeBSD', 'x86_64', '.tar.gz', None, 'bao', ),
            ('Linux', 'ppc64', '.tar.gz', None, 'bao', ),
            ('Linux', 'x86_64', '.tar.gz', 'nosig', 'bao', ),
            ('Linux', 'x86_64', '.tar.gz', 'noverify', 'bao', ),
            ('Linux', 'x86_64', '.tar.gz', 'nofilter', 'bao', ),
            ('Linux', 'x86_64', '.tar.gz', 'missing', 'bao', ),
            ('Linux', 'x86_64', '.tar.gz', 'asstr', 'bao', ),
        ])
def test_install_bao(
        system, machine, ext, special, exe, tmp_path,
        mock_ui_message, mock_github, mocker,
        monkeypatch, httpserver):
    mocker.patch(
        'datalad_bao_ssh.bao_setup.platform.system',
        return_value=system)

    mocker.patch(
        'datalad_bao_ssh.bao_setup.platform.machine',
        return_value=machine)
    no_sig = True if special == 'nosig' else False
    gh = mock_github(
        archive_type=ext, os=system, arch=machine, no_sig=no_sig)
    if special == 'missing':
        gh['server_response']['assets'][0]['name'] = 'nothing'
    mocker.patch(
        'datalad_bao_ssh.bao_setup.bao_available',
        return_value=gh['server_response']
    )
    if special == 'noverify':
        fake_verifier = SimpleNamespace(
            verify_artifact=Mock(
                side_effect=bao_setup.VerificationError)
        )
    else:
        fake_verifier = SimpleNamespace(
            verify_artifact=Mock()
        )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.Verifier.production',
        Mock(return_value=fake_verifier)
    )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.Bundle.from_json',
        return_value="{'bundle': 'signature', }")
    version = '1.2.3'
    fname = f"bao_{version}_{system}_{machine}{ext}"
    fpath = tmp_path / fname

    if ext == '.zip':
        make_zip_file(
            tmp_path,
            f'{fname}',
            {exe: b'#!/bin/bash\necho "Hello"\n', },
        )
        ctype = "application/zip"
    else:
        make_tar_file(
            tmp_path,
            f'{fname}',
            {exe: b'#!/bin/bash\necho "Hello"\n', },
        )
        ctype = "application/gzip"

    httpserver.expect_request(
        f"{gh['download_url_path']}/{gh['archive']}"
        ).respond_with_data(
            fpath.read_bytes(),
            content_type=ctype)
    if not special == 'nosig':
        sig = tmp_path / f'{fname}.sigstore.json'
        sig.write_text("1234")
        httpserver.expect_request(
            f"{gh['download_url_path']}/{gh['archive']}.sigstore.json"
            ).respond_with_data(
                sig.read_bytes(),
                content_type='application/json')

    install_dir = tmp_path / 'install_dir'
    if system == 'FreeBSD':
        with pytest.raises(
                bao_setup.BaoInstallError,
                match=f"Unsupported OS: {system.lower()}"):
            bao_setup.install_bao(
                install_dir=install_dir,
                release=gh['server_response']
            )
    elif machine == 'ppc64':
        with pytest.raises(
                bao_setup.BaoInstallError,
                match=f"Unrecognised architecture {machine}"):
            bao_setup.install_bao(
                install_dir=install_dir,
                release=gh['server_response']
            )
    elif special == 'nosig':
        with pytest.raises(
                bao_setup.BaoInstallError,
                match="Could not find a signature for this release"):
            bao_setup.install_bao(
                install_dir=install_dir,
                release=gh['server_response']
            )
    elif special == 'noverify':
        with pytest.raises(
                bao_setup.BaoInstallError,
                match="Download failed verification"):
            bao_setup.install_bao(
                install_dir=install_dir,
                release=gh['server_response']
            )
    elif special == 'missing':
        with pytest.raises(
                bao_setup.BaoInstallError,
                match="Could not find a release for this OS"):
            bao_setup.install_bao(
                install_dir=install_dir,
                release=gh['server_response']
            )
    else:
        if special == 'asstr':
            idir = str(install_dir)
        else:
            idir = install_dir
        if special == 'nofilter':
            real_open = bao_setup.tarfile.open

            def fake_open(*args, **kwargs):
                real_tar = real_open(*args, **kwargs)
                return NoFilterTar(real_tar)

            # patch where your code looks up tarfile.open
            monkeypatch.setattr(
                bao_setup.tarfile,
                "open", fake_open)
        bao_setup.install_bao(
            install_dir=idir,
            release=gh['server_response']
        )


class NoFilterTar:
    def __init__(self, real_tar):
        self._real_tar = real_tar

    def __enter__(self):
        self._real_tar.__enter__()
        return self

    def __exit__(self, *exc):
        return self._real_tar.__exit__(*exc)

    def extractall(self, path=".", members=None, *, numeric_owner=False):
        return self._real_tar.extractall(
            path=path,
            members=members,
            numeric_owner=numeric_owner,
            filter='data'
        )

    def __getattr__(self, name):
        return getattr(self._real_tar, name)


def test_bao_version(tmp_path):
    install_dir = tmp_path
    bao_bin = install_dir / 'bao'
    bao_bin.write_bytes(b'''#!/bin/sh
echo "OpenBao v1.2.3"
''')
    os.chmod(bao_bin, 0o755)
    assert bao_setup.bao_version(install_dir) == '1.2.3'


def test_bao_available(mock_github):
    gh = mock_github()
    assert bao_setup.bao_available(
        release_url=gh['url'])['tag_name'] == 'v1.2.4'


@pytest.mark.parametrize(
        "failure", ['404', '403', '500']
)
def test_bao_available_exception(failure, mock_github):
    gh = mock_github(fail=failure)
    with pytest.raises(bao_setup.BaoInstallError):
        bao_setup.bao_available(
            release_url=gh['url'])


def test_bad_bao(mock_bao):
    os.chmod(str(mock_bao['script']), 0o644)
    with pytest.raises(
            bao_setup.BaoInstallError):
        bao_setup.bao_version(
            Path(mock_bao['script']).parent
        )


def test_check_package_update(mocker):
    response = mocker.Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "info": {
            "version": "2.0.0"
        }
    }

    mocker.patch(
        'datalad_bao_ssh.bao_setup.requests.get',
        return_value=response
    )

    assert bao_setup.check_package_update(
        'datalad-bao-ssh', Version('1.0.0')) ==\
        (
            True, Version('1.0.0'), Version('2.0.0'),
            'datalad-bao-ssh')

    assert bao_setup.check_package_update(
        'datalad-bao-ssh', Version('2.0.0')) ==\
        (
            False, Version('2.0.0'), Version('2.0.0'),
            'datalad-bao-ssh')

    assert bao_setup.check_package_update(
        'datalad-bao-ssh', Version('3.0.0')) ==\
        (
            False, Version('3.0.0'), Version('2.0.0'),
            'datalad-bao-ssh')


def test_check_package_update_neterr(mocker):
    mocker.patch(
        'datalad_bao_ssh.bao_setup.requests.get',
        side_effect=requests.exceptions.RequestException
    )

    assert bao_setup.check_package_update(
        'datalad-bao-ssh', Version('1.0.0')) ==\
        (
            None, Version('1.0.0'), Version('1.0.0'),
            'Failed to check for update of datalad-bao-ssh - '
            'cannot access project URL')


def test_check_package_update_jsonerr(mocker):
    response = mocker.Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "noinfo": {
            "version": "2.0.0"
        }
    }

    mocker.patch(
        'datalad_bao_ssh.bao_setup.requests.get',
        return_value=response
    )

    assert bao_setup.check_package_update(
        'datalad-bao-ssh', Version('1.0.0')) ==\
        (
            None, Version('1.0.0'), Version('1.0.0'),
            'Unexpected version information obtained from PyPi'
            ' for datalad-bao-ssh')


def test_get_config_from_renewal_conf(tmp_path):
    baosrv = 'bao.domain.com'
    baofile = baosrv.replace('.', '-')
    include_file = tmp_path / f'datalad-{baofile}.conf'
    script_file = tmp_path / f'{baofile}-renew.sh'

    config = {
        'VERSION': '1.2.3',
        'ROLE': 'dataladr',
        'PRINCIPAL': 'dataladp',
        'CERTTYPE': 'ed25519',
        'BAOHOST': baosrv,
        'BAOPORT': '999',
        'BAOAUTH': 'myauth',
        'BAOOPENID': '0',
        'BAOBIN': '/usr/bin/bao',
        'BAOUSERNAME': 'freddy',
    }
    with open(include_file, 'w') as include_cf:
        include_cf.write(
            f'''Match host {baosrv} exec "{script_file.name}"
    IdentitiesOnly yes
    IdentityFile "id-ed25519-{baofile}"
    CertificateFile "id-ed25519-{baofile}.crt"
''')

    with open(script_file, 'w') as scriptf:
        scriptf.write(
            f'''#!/bin/bash
set -euo pipefail

DEBUG="${'{'}DATALAD_BAO_SSH_DEBUG:-0{'}'}"
CACERT="${'{'}DATALAD_BAO_SSH_CA_CERT:-{'}'}"
VERSION="{config['VERSION']}"
ROLE="{config['ROLE']}"
PRINCIPAL="{config['PRINCIPAL']}"
CERTTYPE="{config['CERTTYPE']}"
BAOHOST="{config['BAOHOST']}"
BAOPORT="{config['BAOPORT']}"
BAOAUTH="{config['BAOAUTH']}"
BAOOPENID="{config['BAOOPENID']}"
BAOBIN="{config['BAOBIN']}"
BAOUSERNAME="{config['BAOUSERNAME']}"

BAOSRV="https://${'{'}BAOHOST{'}'}:${'{'}BAOPORT{'}'}"
KEYFILE="id-${'{'}CERTTYPE{'}'}-${'{'}BAOHOST//./-{'}'}"
PUBFILE="${'{'}KEYFILE{'}'}.pub"
CERTFILE="${'{'}KEYFILE{'}'}-cert.pub"
KEY="${'{'}HOME{'}'}/.ssh/${'{'}KEYFILE{'}'}"
PUB="${'{'}HOME{'}'}/.ssh/${'{'}PUBFILE{'}'}"
CERT="${'{'}HOME{'}'}/.ssh/${'{'}CERTFILE{'}'}"

## End of configuration ##

''')

    script, captured_config = (
        bao_setup.get_config_from_renewal_conf(
            include_file)
    )

    assert str(script) == script_file.name
    assert config == captured_config


def test_get_config_from_renewal_conf_no_match(tmp_path):
    baosrv = 'bao.domain.com'
    baofile = baosrv.replace('.', '-')
    include_file = tmp_path / f'datalad-{baofile}.conf'

    with open(include_file, 'w') as include_cf:
        include_cf.write('')

    with pytest.raises(
        bao_setup.BaoInstallError,
        match=f'Include file {include_file} missing Match host statement'
    ):
        bao_setup.get_config_from_renewal_conf(
            include_file)


def test_update_renewal_scripts_none(tmp_path):
    with open(tmp_path / 'config', 'w') as main_cf:
        main_cf.write("")

    with pytest.raises(
            bao_setup.BaoInstallError,
            match=(
                "OpenBao doesn't appear to be configured for your DataLad"
                " servers - please run without the update flag")
    ):
        bao_setup.update_renewal_scripts(
            tmp_path, Version('1.0.0'))


def test_update_requested_update_renewal_scripts_none(
        mocker, mock_ui_message):

    cpu = [
        (False, Version('1.0.0'), Version('1.0.0'),
            'datalad-bao-ssh'),
        (False, Version('1.0.0'), Version('1.0.0'),
            'datalad'),
    ]

    mocker.patch(
        'datalad_bao_ssh.bao_setup.check_package_update',
        side_effect=cpu
    )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.shutil.which',
        return_value="/usr/bin/bao"
    )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.update_renewal_scripts',
        side_effect=Exception(
            "OpenBao doesn't appear to be configured for your DataLad"
            " servers - please run without the update flag"
        )
    )

    with pytest.raises(
            IncompleteResultsError,
            match=(
                "OpenBao doesn't appear to be configured for your "
                "DataLad servers - please run without the update flag"
            )):
        status = bao_setup.bao_setup.__call__(update=True)

        assert status == [{
            'action': 'bao_setup',
            'error_message': (
                "Failed updating renewal script(s) (OpenBao doesn't appear "
                'to be configured for your DataLad servers - please run '
                'without the update flag)'),
            'exc': Exception(
                "OpenBao doesn't appear to be configured for your "
                "DataLad servers - please run without the update flag"),
            'status': 'error'}]


def test_get_renewal_confs_none(tmp_path):
    with open(tmp_path / 'config', 'w') as main_cf:
        main_cf.write("")

    with pytest.raises(
            bao_setup.BaoInstallError,
            match=(
                "OpenBao doesn't appear to be configured for your DataLad"
                " servers - please run without the update flag")
    ):
        bao_setup.get_renewal_confs(tmp_path)


def test_get_renewal_confs_no_includes(tmp_path):
    with open(tmp_path / 'config', 'w') as main_cf:
        main_cf.write("# OpenBao renewals \n")

    with pytest.raises(
            bao_setup.BaoInstallError,
            match=(
                "OpenBao doesn't appear to be configured correctly for your "
                "DataLad servers - please run without the update flag")
    ):
        bao_setup.get_renewal_confs(tmp_path)


def test_get_renewal_confs(tmp_path):
    conf = "datalad-baohost-domain-com.conf"
    with open(tmp_path / 'config', 'w') as main_cf:
        main_cf.write(
            f'''# OpenBao renewals baohost.domain.com
Include "{conf}"
''')

    assert (
        bao_setup.get_renewal_confs(tmp_path)
        == [conf]
    )


def test_get_renewal_confs_multiple(tmp_path):
    confs = [
        "datalad-baohost-domain-com.conf",
        "datalad-baohost2-domain-com.conf"]
    with open(tmp_path / 'config', 'w') as main_cf:
        for c in confs:
            main_cf.write(
                f'''# OpenBao renewals {
                    c.replace('datalad-', '').replace('-', '.')}
Include "{c}"
''')
    includes = bao_setup.get_renewal_confs(tmp_path)
    assert includes == confs


def test_check_for_renewal_script_update(tmp_path, mocker):
    mocker.patch(
        'datalad_bao_ssh.bao_setup.shell',
        return_value='/bin/bash')
    n_version = Version('2.0')
    i_version = Version('1.0')
    baosrv = "baoserver.com"
    server_response = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOBIN": '/usr/local/bin/bao',
        "BAOPORT": "8200",
        "BAOAUTH": "ldap",
        "BAOOPENID": "0",
        "BAOUSERNAME": 'test_user',
        "VERSION": str(i_version),
        "GIT_REQUIRES_USERNAME": False,
        "GIT_SSH_HOSTS": [
            "git1.com",
        ],
        "RIA_HOSTS": [
            "ria1.com",
            "ria2.com"
        ]
    }
    ssh_dir = tmp_path
    baosuffix = f'{baosrv.replace(".", "-")}'
    exec_script = ssh_dir / f'{baosuffix}-renew.sh'
    id_file = f'id-ed25519-{baosuffix}'

    with open(ssh_dir / 'config', 'w') as ssh_conf:
        ssh_conf.write(
            f"# OpenBao renewals {baosrv}\nInclude"
            f' "datalad-{baosuffix}.conf"\n')
    with open(ssh_dir / f'datalad-{baosuffix}.conf', 'w') as host_conf:
        host_conf.write(
            f'''Match host {baosrv} exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{id_file}"
    CertificateFile "{id_file}.crt"
'''
        )
    mod_dir = Path(__file__).parent.parent
    cscript = ''
    with open(mod_dir / 'openbao_certificate_renew.sh', 'r') as template:
        with open(exec_script, 'w') as escript:
            for line in template.readlines():
                for k, v in server_response.items():
                    if f'**{k}**' in line:
                        line = line.replace(f'**{k}**', v)
                escript.write(line)
                cscript += line
            escript.write("# Meaningless change")

    messages = bao_setup.update_renewal_scripts(
        ssh_dir, n_version)
    assert messages == [
        f'Renewal script {os.path.basename(exec_script)} updated '
        f'to version {n_version}']
    with open(exec_script) as ascript:
        actual_script = ascript.read()

    assert actual_script == cscript.replace(
        f'VERSION="{i_version}"', f'VERSION="{n_version}"')


def test_check_for_bao_update(
        mock_bao, mock_github, mocker,
        mock_ui_message):
    gh = mock_github()
    ib = mocker.patch(
        'datalad_bao_ssh.bao_setup.install_bao')
    bv = mocker.patch(
        'datalad_bao_ssh.bao_setup.bao_version',
        return_value='1.2.3'
    )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.bao_available',
        return_value=gh['server_response']
    )
    bao_bin = Path(mock_bao['script'])
    assert bao_setup.check_for_bao_update(
        bao_bin.parent) == (True, "'bao' upgraded to 1.2.4", )
    ib.assert_called_once()

    bv.reset_mock()
    ib.reset_mock()
    bv.return_value = None
    assert bao_setup.check_for_bao_update(
        bao_bin.parent) == (
            False,
            "'bao' is not installed - re-run without check"
            " argument to install.")
    ib.assert_not_called()

    bv.reset_mock()
    bv.return_value = '1.2.3'
    ib.reset_mock()
    ib.side_effect = bao_setup.BaoInstallError(
        'Install failure')
    assert bao_setup.check_for_bao_update(
        bao_bin.parent) == (False, "Install failure", )

    bv.reset_mock()
    bv.return_value = '1.2.4'
    ib.reset_mock()
    ib.side_effect = None
    assert bao_setup.check_for_bao_update(
        bao_bin.parent) == (True, "'bao' is latest version", )


@pytest.mark.skipif(
    not entrypoint_registered(),
    reason="extension not installed")
def test_version():
    proc = sp.run(
        ["datalad", "bao-setup", "--version"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "datalad_bao_ssh" in proc.stdout.lower()


@pytest.mark.skipif(
    not entrypoint_registered(),
    reason="extension not installed")
def test_command_visible_to_datalad():
    parser = setup_parser(["datalad", "bao-setup"])
    assert parser is not None


@pytest.mark.parametrize(
    "package_status",
    [
        (
            (
                '''Update available for this plugin: 1.0.1 -> 1.0.2
Use your Python package manager to update, e.g.
  pip install --upgrade datalad-bao-ssh
or
  uv lock --upgrade-package datalad-bao-ssh
  uv sync

Then re-run the updater with
  datalad bao_setup --update''',
                True,
                '1.0.1',
                '1.0.2',
                'datalad-bao-ssh',
            ),
            (
                '''Update available for DataLad: 1.0.1 -> 1.0.2
Use your Python package manager to update, e.g.
  pip install --upgrade datalad
or
  uv lock --upgrade-package datalad
  uv sync''',
                True,
                '1.0.1',
                '1.0.2',
                'datalad',
            ),
        ),
        (
            (
                '',
                False,
                '1.0.1',
                '1.0.1',
                'datalad-bao-ssh',
            ),
            (
                '',
                False,
                '1.0.1',
                '1.0.1',
                'datalad',
            ),
        ),
    ]
    )
def test_update_requested_pymods(
        package_status, mocker, mock_ui_message):
    returns = [r[1:] for r in package_status]
    messages = [r[0] for r in package_status if r[0] != '']
    messages.append(
        "bao installed externally "
        "as /usr/bin/bao, ignoring")
    mocker.patch(
        'datalad_bao_ssh.bao_setup.check_package_update',
        side_effect=returns
    )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.shutil.which',
        return_value="/usr/bin/bao"
    )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.check_for_bao_update',
        return_value=(False, "", ))
    mocker.patch(
        'datalad_bao_ssh.bao_setup.update_renewal_scripts',
        return_value=[]
    )

    status = list(bao_setup.bao_setup.__call__(update=True))
    msgs = status[0]['msg']

    assert '\n'.join(messages) == msgs


def test_update_requested_check_package_update_neterr(mocker):
    mocker.patch(
        'datalad_bao_ssh.bao_setup.requests.get',
        side_effect=requests.exceptions.RequestException
    )

    mocker.patch(
        'datalad_bao_ssh.bao_setup.shutil.which',
        return_value="/usr/bin/bao"
    )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.check_for_bao_update',
        return_value=(False, "", ))
    mocker.patch(
        'datalad_bao_ssh.bao_setup.update_renewal_scripts',
        return_value=[]
    )

    status = list(bao_setup.bao_setup.__call__(update=True))
    msgs = status[0]['msg']

    assert msgs == '\n'.join([
        'Failed to check for update of datalad-bao-ssh - '
        'cannot access project URL',
        'Failed to check for update of datalad - '
        'cannot access project URL',
        'bao installed externally as /usr/bin/bao, ignoring',
    ])


def test_update_requested_bao(mocker, mock_ui_message):
    cu = mocker.patch(
        'datalad_bao_ssh.bao_setup.check_for_bao_update',
        return_value=(True, "updated", ))
    cpu_se = [
            (False, Version('1.0'), Version('1.0'), 'datalad_bao_ssh'),
            (False, Version('1.0'), Version('1.0'), 'datalad'),
        ]
    cpu = mocker.patch(
        'datalad_bao_ssh.bao_setup.check_package_update',
        side_effect=cpu_se
    )
    mocker.patch(
        'datalad_bao_ssh.bao_setup.update_renewal_scripts',
        return_value=[]
    )

    for pfm in ("linux", "windows", ):
        mocker.patch(
            'datalad_bao_ssh.bao_setup.platform.system',
            return_value=pfm)

        if pfm == "linux":
            exe = 'bao'
        else:
            exe = 'bao.exe'
        mocker.patch(
            'datalad_bao_ssh.bao_setup.shutil.which',
            return_value=f"/usr/bin/{exe}"
        )
        status = bao_setup.bao_setup.__call__(update=True)
        assert status == [{
            'action': 'bao_setup',
            'status': 'ok',
            'msg': f"bao installed externally as /usr/bin/{exe}, ignoring",
            }]
        cpu.side_effect = cpu_se

    mocker.patch(
            'datalad_bao_ssh.bao_setup.shutil.which',
            return_value=None
    )
    cpu.side_effect = cpu_se

    status = bao_setup.bao_setup.__call__(update=True)
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': "updated", }]

    cu.return_value = (False, 'Failed', )
    cpu.side_effect = cpu_se

    with pytest.raises(IncompleteResultsError):
        status = bao_setup.bao_setup.__call__(update=True)

        assert status == [{
            'action': 'bao_setup',
            'status': 'error',
            'error_message': "Failed", }]


@pytest.mark.parametrize(
        "authmethod", ['ldap', 'oidc', ]
)
def test_bao_setup(
        authmethod, httpserver: HTTPServer, requests_ca_bundle,
        ssh_environment, mocker,
        mock_no_bao):
    shell = ssh_environment['shell']

    baosrv = "baoserver.com"
    server_response = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOPORT": "8200",
        "BAOAUTH": authmethod,
        "GIT_REQUIRES_USERNAME": False,
        "GIT_SSH_HOSTS": [
            "git1.com",
        ],
        "RIA_HOSTS": [
            "ria1.com",
            "ria2.com"
        ]
    }
    httpserver.expect_request(
        "/ssh_conf.json").respond_with_json(
            server_response)
    mocker.patch(
        "datalad_bao_ssh.bao_setup.dlcfg.obtain",
        return_value=(
            f"{httpserver.url_for('/ssh_conf.json')}")
    )
    ssh_dir = ssh_environment['ssh_dir']
    ssh_environment['patches']['ui'].question.side_effect = [
        ssh_environment['username'], ]

    status = list(bao_setup.bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    exec_script = ssh_dir / f'{baosuffix}-renew.sh'
    identity_file = ssh_dir / f'id-ed25519-{baosuffix}'
    # public_file = f'{identity_file}.pub'
    certificate_file = f'{identity_file}-cert.pub'

    expected_config = f'''Match host ria1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['username']}"

Match host ria2.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['username']}"

Match host git1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"

'''
    ria_conf_file = ssh_dir / f"datalad-{baosuffix}.conf"
    assert os.path.exists(ria_conf_file)
    with open(ria_conf_file) as ria_conf:
        actual_config = ria_conf.read()
    assert actual_config == expected_config

    include_line = (
        f"# OpenBao renewals {baosrv}\nInclude"
        f' "{os.path.basename(ria_conf_file)}"')
    with open(ssh_dir / 'config', 'r') as main_conf:
        found = include_line in main_conf.read()

    assert found is True

    expected_script = ssh_environment['tmp_path'] / 'renewal_script'
    mod_dir = Path(__file__).parent.parent
    server_response['BAOOPENID'] = "1" if authmethod == 'oidc' else "0"
    server_response['BAOBIN'] = ""
    server_response['BAOUSERNAME'] = ssh_environment['username']
    server_response['VERSION'] = VERSION
    with open(mod_dir / 'openbao_certificate_renew.sh', 'r') as template:
        with open(expected_script, 'w') as escript:
            for line in template.readlines():
                if line == '#!/bin/bash\n':
                    line = f'#!{shell}\n'
                else:
                    for k, v in server_response.items():
                        if k in ssh_environment['skiplines']:
                            continue
                        if f'**{k}**' in line:
                            line = line.replace(f'**{k}**', v)
                escript.write(line)
    assert os.path.exists(ssh_dir / f'{baosuffix}-renew.sh')
    generated_script = ssh_dir / f'{baosuffix}-renew.sh'
    with open(generated_script) as ascript:
        actual_script = ascript.read()
    with open(expected_script) as escript:
        required_script = escript.read()
    mode = stat.S_IMODE(generated_script.stat().st_mode)
    assert mode == 0o700
    for k in server_response.keys():
        if k in ssh_environment['skiplines']:
            continue
        assert f'**{k}**' not in actual_script
        assert f'**{k}**' not in required_script
    assert actual_script == required_script

    for test_shell in ('/bin/bash', '/bin/zsh', ):
        mocker.patch(
            "datalad_bao_ssh.bao_setup.shell",
            return_value=test_shell)
        ssh_environment['patches']['ui'].question.side_effect = [
            ssh_environment['username']]
        status = list(bao_setup.bao_setup.__call__())

        with open(mod_dir / 'openbao_certificate_renew.sh', 'r') as template:
            with open(expected_script, 'w') as escript:
                for line in template.readlines():
                    if line == '#!/bin/bash\n':
                        line = f'#!{test_shell}\n'
                    else:
                        for k, v in server_response.items():
                            if k in ssh_environment['skiplines']:
                                continue
                            if f'**{k}**' in line:
                                line = line.replace(f'**{k}**', v)
                    escript.write(line)

        assert os.path.exists(ssh_dir / f'{baosuffix}-renew.sh')
        with open(ssh_dir / f'{baosuffix}-renew.sh') as ascript:
            actual_script = ascript.read()
        with open(expected_script) as escript:
            required_script = escript.read()
        for k in server_response.keys():
            if k in ssh_environment['skiplines']:
                continue
            assert f'**{k}**' not in actual_script
            assert f'**{k}**' not in required_script
        assert actual_script == required_script


def test_bao_setup_gituser(
        httpserver: HTTPServer, requests_ca_bundle,
        ssh_environment, mocker,
        mock_no_bao):
    shell = ssh_environment['shell']

    baosrv = "baoserver.com"
    server_response = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOPORT": "8200",
        "BAOAUTH": "ldap",
        "GIT_REQUIRES_USERNAME": True,
        "GIT_SSH_HOSTS": [
            "git1.com",
        ],
        "RIA_HOSTS": [
            "ria1.com",
            "ria2.com"
        ]
    }
    httpserver.expect_request(
        "/ssh_conf.json").respond_with_json(
            server_response)
    mocker.patch(
        "datalad_bao_ssh.bao_setup.dlcfg.obtain",
        return_value=(
            f"{httpserver.url_for('/ssh_conf.json')}")
    )

    ssh_dir = ssh_environment['ssh_dir']
    ssh_environment['patches']['ui'].question.side_effect = [
        ssh_environment['username']]

    status = list(bao_setup.bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    exec_script = ssh_dir / f'{baosuffix}-renew.sh'
    identity_file = ssh_dir / f'id-ed25519-{baosuffix}'
    # public_file = f'{identity_file}.pub'
    certificate_file = f'{identity_file}-cert.pub'

    expected_config = f'''Match host ria1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['username']}"

Match host ria2.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['username']}"

Match host git1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['username']}"

'''
    ria_conf_file = ssh_dir / f"datalad-{baosuffix}.conf"
    assert os.path.exists(ria_conf_file)
    with open(ria_conf_file) as ria_conf:
        actual_config = ria_conf.read()
    assert actual_config == expected_config

    include_line = (
        f"# OpenBao renewals {baosrv}\nInclude"
        f' "{os.path.basename(ria_conf_file)}"')
    with open(ssh_dir / 'config', 'r') as main_conf:
        found = include_line in main_conf.read()

    assert found is True

    expected_script = ssh_environment['tmp_path'] / 'renewal_script'
    mod_dir = Path(__file__).parent.parent
    server_response['BAOOPENID'] = "0"
    server_response['BAOBIN'] = ""
    server_response['BAOUSERNAME'] = ssh_environment['username']
    server_response['VERSION'] = VERSION
    with open(mod_dir / 'openbao_certificate_renew.sh', 'r') as template:
        with open(expected_script, 'w') as escript:
            for line in template.readlines():
                if line == '#!/bin/bash\n':
                    line = f'#!{shell}\n'
                else:
                    for k, v in server_response.items():
                        if k in ssh_environment['skiplines']:
                            continue
                        if f'**{k}**' in line:
                            line = line.replace(f'**{k}**', v)
                escript.write(line)

    assert os.path.exists(ssh_dir / f'{baosuffix}-renew.sh')
    with open(ssh_dir / f'{baosuffix}-renew.sh') as ascript:
        actual_script = ascript.read()
    with open(expected_script) as escript:
        required_script = escript.read()

    for k in server_response.keys():
        if k in ssh_environment['skiplines']:
            continue
        assert f'**{k}**' not in actual_script
        assert f'**{k}**' not in required_script
    assert actual_script == required_script


def test_bao_setup_existing_config(
        httpserver: HTTPServer, requests_ca_bundle,
        ssh_environment, mocker, mock_no_bao):
    baosrv = "baoserver.com"
    server_response = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOPORT": "8200",
        "BAOAUTH": "ldap",
        "GIT_REQUIRES_USERNAME": False,
        "RIA_HOSTS": [
            "ria1.com",
            "ria2.com"
        ],
        "GIT_SSH_HOSTS": [
            "git1.com",
        ]
    }
    httpserver.expect_request(
        "/ssh_conf.json").respond_with_json(
            server_response)
    mocker.patch(
        "datalad_bao_ssh.bao_setup.dlcfg.obtain",
        return_value=(
            f"{httpserver.url_for('/ssh_conf.json')}")
    )

    ssh_dir = ssh_environment['ssh_dir']
    ssh_config = ssh_environment['ssh_config']
    existing_config = '''Host myhost
    user remote-user

Host myotherhost
    user other-remote-user
'''
    with open(ssh_config, 'w') as main_config:
        main_config.write(existing_config)

    status = list(bao_setup.bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    ria_conf_file = ssh_dir / f"datalad-{baosuffix}.conf"

    include_line = (
        f"# OpenBao renewals {baosrv}\nInclude"
        f' "{os.path.basename(ria_conf_file)}"')
    with open(ssh_config, 'r') as main_conf:
        content = main_conf.read()
    found = include_line in content
    assert found is True
    assert content.count(include_line) == 1
    assert content == f'{include_line}\n\n{existing_config}'
    status = list(bao_setup.bao_setup.__call__())
    with open(ssh_config, 'r') as main_conf:
        content = main_conf.read()
    found = include_line in content
    assert found is True
    assert content.count(include_line) == 1
    assert content == f'{include_line}\n\n{existing_config}'


def test_bao_setup_bad_dns(
        ssh_environment, requests_ca_bundle,
        mocker, mock_no_bao):
    shell = ssh_environment['shell']

    user_response = ssh_environment['user_response']
    baosrv = user_response['BAOHOST']
    mocker.patch(
        "datalad_bao_ssh.bao_setup.dlcfg.obtain",
        return_value=(
            "http://test.invalid/ssh_conf.json')}")
    )
    ssh_dir = ssh_environment['ssh_dir']

    status = list(bao_setup.bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    exec_script = ssh_dir / f'{baosuffix}-renew.sh'
    identity_file = ssh_dir / f'id-rsa-{baosuffix}'
    # public_file = f'{identity_file}.pub'
    certificate_file = f'{identity_file}-cert.pub'

    expected_config = f'''Match host ria3.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['username']}"

Match host ria4.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['username']}"

Match host git1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"

'''
    ria_conf_file = ssh_dir / f"datalad-{baosuffix}.conf"
    assert os.path.exists(ria_conf_file)
    with open(ria_conf_file) as ria_conf:
        actual_config = ria_conf.read()
    assert actual_config == expected_config

    include_line = (
        f"# OpenBao renewals {baosrv}\nInclude"
        f' "{os.path.basename(ria_conf_file)}"')
    with open(ssh_dir / 'config', 'r') as main_conf:
        found = include_line in main_conf.read()

    assert found is True

    expected_script = ssh_environment['tmp_path'] / 'renewal_script'
    mod_dir = Path(__file__).parent.parent
    user_response['BAOOPENID'] = "0"
    user_response['BAOBIN'] = ""
    user_response['BAOUSERNAME'] = ssh_environment['username']
    user_response['VERSION'] = VERSION
    with open(mod_dir / 'openbao_certificate_renew.sh', 'r') as template:
        with open(expected_script, 'w') as escript:
            for line in template.readlines():
                if line == '#!/bin/bash\n':
                    line = f'#!{shell}\n'
                else:
                    for k, v in user_response.items():
                        if k in ssh_environment['skiplines']:
                            continue
                        if f'**{k}**' in line:
                            line = line.replace(f'**{k}**', v)
                escript.write(line)
    assert os.path.exists(ssh_dir / f'{baosuffix}-renew.sh')
    with open(ssh_dir / f'{baosuffix}-renew.sh') as ascript:
        actual_script = ascript.read()
    with open(expected_script) as escript:
        required_script = escript.read()

    for k in user_response.keys():
        if k in ssh_environment['skiplines']:
            continue
        assert f'**{k}**' not in actual_script
        assert f'**{k}**' not in required_script
    assert actual_script == required_script


def test_bao_setup_create_ssh(
        httpserver: HTTPServer, requests_ca_bundle,
        ssh_environment, mocker,
        mock_no_bao):
    shutil.rmtree(ssh_environment['ssh_dir'])

    baosrv = "baoserver.com"
    server_response = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOPORT": "8200",
        "BAOAUTH": 'ldap',
        "GIT_REQUIRES_USERNAME": False,
        "GIT_SSH_HOSTS": [
            "git1.com",
        ],
        "RIA_HOSTS": [
            "ria1.com",
            "ria2.com"
        ]
    }
    httpserver.expect_request(
        "/ssh_conf.json").respond_with_json(
            server_response)
    mocker.patch(
        "datalad_bao_ssh.bao_setup.dlcfg.obtain",
        return_value=(
            f"{httpserver.url_for('/ssh_conf.json')}")
    )
    ssh_dir = ssh_environment['ssh_dir']
    ssh_environment['patches']['ui'].question.side_effect = [
        ssh_environment['username'], ]

    status = list(bao_setup.bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    ria_conf_file = ssh_dir / f"datalad-{baosuffix}.conf"
    assert os.path.exists(ria_conf_file)
    assert os.path.exists(ssh_dir / f'{baosuffix}-renew.sh')
    assert os.path.exists(ssh_dir)


def test_bao_setup_user_exit(
        ssh_environment, requests_ca_bundle,
        mock_no_bao, mocker):
    mocker.patch(
        'datalad_bao_ssh.bao_setup.get_config',
        side_effect=Exception("Test"))
    ssh_environment['patches']['ui'].yesno.side_effect = (True, )
    status = list(bao_setup.bao_setup.__call__())

    assert status == [{'action': 'bao_setup', 'status': 'ok'}]


def test_bao_setup_permissions_issue(
        ssh_environment, requests_ca_bundle,
        mock_no_bao, mocker):
    mocker.patch(
        "datalad_bao_ssh.bao_setup.tempfile.TemporaryFile",
        side_effect=PermissionError("denied"),
    )

    with pytest.raises(IncompleteResultsError) as exc_info:
        list(bao_setup.bao_setup.__call__())
    assert "Failed at Checking your .ssh folder" in str(exc_info.value)


def test_bao_setup_shell_tcsh(
        monkeypatch, mocker,
        mock_no_bao):
    monkeypatch.setenv('SHELL', '/bin/tcsh')
    for system in (
            ('Darwin', '/bin/zsh', ),
            ('Linux', '/bin/bash', ),
            ('Another', '/bin/sh', ), ):
        mocker.patch(
            "datalad_bao_ssh.bao_setup.platform.system",
            return_value=system[0])

        shell = bao_setup.shell()
        assert shell == system[1]

# Testing BASH renewal script


def _make_ca_keypair(tmp_path: Path) -> Path:
    ca_key = tmp_path / "ssh_ca"
    sp.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(ca_key)],
        check=True,
    )
    return ca_key


def _sign_public_key(
        ca_key: Path, public_key: str,
        principals: str, tmp_path: Path,
        validity: str, id: str) -> str:
    pub_file = tmp_path / "user_key.pub"
    cert_file = tmp_path / "user_key-cert.pub"
    pub_file.write_text(public_key)

    sp.run(
        [
            "ssh-keygen",
            "-q",
            "-s",
            str(ca_key),
            "-I",
            id,
            "-n",
            principals,
            "-V",
            validity,
            str(pub_file),
        ],
        check=True,
    )

    cert_file = cert_file.with_name("user_key-cert.pub")
    return cert_file.read_text().strip()


def make_handler(ca_key, tmp_path, token, rc, config):
    def handler(request):
        assert request.headers.get("X-Vault-Token") == token
        assert request.headers.get("X-Vault-Request") == 'true'

        payload = json.loads(request.data.decode("utf-8"))
        public_key = payload["public_key"]
        valid_principals = payload["valid_principals"]
        assert valid_principals == (
            f"{rc['server_response']['PRINCIPAL']}"
            f",{rc['username']}")
        signed_key = _sign_public_key(
            ca_key=ca_key,
            public_key=public_key,
            principals=valid_principals,
            tmp_path=tmp_path,
            validity=config['validity'],
            id=f"ldap-{rc['username']}"
        )

        return Response(
            json.dumps(
                {
                    "data": {
                        "signed_key": signed_key,
                    }
                }
            ),
            status=200,
            mimetype="application/json",
        )
    return handler


def test_renew_certificate(
        httpserver, tmp_path, renew_certificate, bao):
    rc = renew_certificate(bao=bao)
    token = rc['token']
    ca_key = rc['ca_key']

    token_response = {
        'auth': {
            'client_token': rc['token'],
        }}
    config = {'validity': "+10s"}
    pause = False
    for shell in ['bash', 'zsh']:
        if pause:
            time.sleep(10)
        httpserver.expect_request(
            f"/v1/auth/{rc['config']['BAOAUTH']}/login/{rc['username']}",
            method="PUT",
            json={"password": rc['password'], },
            headers={"X-Vault-Request": "true", }
        ).respond_with_json(token_response)

        httpserver.expect_request(
            "/v1/ssh-client-signer/sign/"
            f"{rc['config']['ROLE']}",
            method="PUT",
        ).respond_with_handler(
            make_handler(
                ca_key, tmp_path, token, rc,
                config))
        buf = StringIO()
        child = pexpect.spawn(
            str(rc['renew_scripts'][shell]),
            encoding='utf-8',
            timeout=10
        )
        child.logfile = buf
        child.expect_exact("Password (will be hidden): ")
        child.sendline(rc["password"])
        child.expect(pexpect.EOF)
        full_output = buf.getvalue()
        child.close()
        now = datetime.datetime.now()
        if child.exitstatus != 0:
            print(full_output)

        assert child.exitstatus == 0

        ssh_dir = rc['ssh_dir']
        key_file = (
            ssh_dir
            / (
                f"id-{rc['config']['CERTTYPE']}"
                f"-{rc['httpserver'].host.replace('.', '-')}"
                ))
        pub_file = f'{key_file}.pub'
        cert_file = f'{key_file}-cert.pub'
        for sshfile in (key_file, pub_file, cert_file):
            assert os.path.exists(sshfile)

        exp_out = sp.run(
            ['ssh-keygen', '-L', '-f', cert_file],
            check=True,
            capture_output=True,
            text=True
        )
        end = None
        principals = []
        id = None
        in_principals = False
        for line in exp_out.stdout.splitlines():
            line = line.strip()
            if line.startswith('Valid: '):
                end = datetime.datetime.strptime(
                    line.split(' ')[4],
                    '%Y-%m-%dT%H:%M:%S'
                )
                continue
            if line.startswith('Key ID: '):
                id = line.split(' ')[2].strip('"')
                continue
            if line.startswith('Principals:'):
                in_principals = True
                continue
            if line.startswith('Critical Options'):
                in_principals = False
                continue
            if in_principals:
                principals.append(line)

        assert end is not None
        assert (end - now).seconds <= 10
        assert rc['username'] in principals
        assert rc['config']['PRINCIPAL'] in principals
        assert id == f"ldap-{rc['username']}"
        pause = True


# To properly test would need to setup fake OpenID server
# and run dev openbao server
def test_renew_certificate_openid(
        tmp_path, renew_certificate, mock_bao, monkeypatch):
    rc = renew_certificate(bao=str(mock_bao['script']), openid=True)
    fake_home = tmp_path / 'home'
    monkeypatch.setenv(
        "BAO_FAKE_HOME", str(fake_home)
    )
    monkeypatch.setenv(
        "BAO_FAKE_TTL", '10s'
    )
    monkeypatch.setenv(
        "PATH", str(mock_bao['script'].parent), prepend=os.pathsep)
    for shell in ['bash', 'zsh']:
        shutil.rmtree(fake_home, ignore_errors=True)
        fake_home.mkdir()
        output = sp.run(
            rc['renew_scripts'][shell],
            capture_output=True,
            text=True)
        now = datetime.datetime.now()
        assert output.returncode == 0
        ssh_dir = rc['ssh_dir']
        key_file = (
            ssh_dir
            / (
                f"id-{rc['config']['CERTTYPE']}"
                f"-{rc['httpserver'].host.replace('.', '-')}"
                ))
        pub_file = f'{key_file}.pub'
        cert_file = f'{key_file}-cert.pub'
        for sshfile in (key_file, pub_file, cert_file):
            assert os.path.exists(sshfile)

        exp_out = sp.run(
            ['ssh-keygen', '-L', '-f', cert_file],
            check=True,
            capture_output=True,
            text=True
        )
        end = None
        principals = []
        id = None
        in_principals = False
        for line in exp_out.stdout.splitlines():
            line = line.strip()
            if line.startswith('Valid: '):
                end = datetime.datetime.strptime(
                    line.split(' ')[4],
                    '%Y-%m-%dT%H:%M:%S'
                )
                continue
            if line.startswith('Key ID: '):
                id = line.split(' ')[2].strip('"')
                continue
            if line.startswith('Principals:'):
                in_principals = True
                continue
            if line.startswith('Critical Options'):
                in_principals = False
                continue
            if in_principals:
                principals.append(line)

        assert end is not None
        assert (end - now).seconds <= 10
        assert rc['username'] in principals
        assert rc['config']['PRINCIPAL'] in principals
        assert id == f"fake-{rc['config']['ROLE']}"


def test_existing_certificate(
        httpserver, tmp_path, renew_certificate, bao):
    rc = renew_certificate(bao=bao)
    token = rc['token']
    ca_key = rc['ca_key']

    token_response = {
        'auth': {
            'client_token': rc['token'],
        }}
    config = {'validity': "+10s"}
    for shell in ['bash', 'zsh']:
        httpserver.expect_request(
            f"/v1/auth/ldap/login/{rc['username']}",
            method="PUT",
            headers={"X-Vault-Request": "true", }
        ).respond_with_json(token_response)
        ssh_dir = rc['ssh_dir']
        key_file = (
            ssh_dir
            / (
                f"id-{rc['config']['CERTTYPE']}"
                f"-{rc['httpserver'].host.replace('.', '-')}"
                ))
        pub_file = f'{key_file}.pub'
        cert_file = f'{key_file}-cert.pub'
        for sshfile in (key_file, pub_file, cert_file):
            try:
                os.unlink(sshfile)
            except Exception:
                pass
        config = {"validity": "+8h"}
        httpserver.expect_request(
            "/v1/ssh-client-signer/sign/"
            f"{rc['config']['ROLE']}",
            method="PUT",
        ).respond_with_handler(make_handler(
                ca_key, tmp_path, token, rc,
                config))
        child = pexpect.spawn(
            str(rc['renew_scripts'][shell]),
            encoding='utf-8',
            timeout=10
        )
        output = []
        child.expect_exact("Password (will be hidden): ")
        child.sendline(rc["password"])
        output.append(child.before)
        output.append(child.read())
        child.expect(pexpect.EOF)
        child.close()
        assert child.exitstatus == 0
        assert f'DataLad OpenBao SSH integration version {VERSION}' in\
            output[0]
        assert 'Logging into access control server...' in output[0]
        assert 'Success! You are now authenticated.' in output[1]
        assert 'SSH logins enabled until ' in output[1]

        output = sp.run(
            rc['renew_scripts'][shell],
            capture_output=True,
            text=True)

        assert output.returncode == 0
        assert 'Logging into access control server...' not in output.stderr


def test_renew_certificate_curl(httpserver, tmp_path, renew_certificate):
    rc = renew_certificate(bao="")
    token = rc['token']
    ca_key = rc['ca_key']

    token_response = {
        'auth': {
            'client_token': rc['token'],
        }}
    config = {'validity': "+10s"}
    pause = False
    for shell in ['bash', 'zsh']:
        if pause:
            time.sleep(10)
        httpserver.expect_request(
            f"/v1/auth/ldap/login/{rc['username']}",
            method="PUT",
            json={"password": rc['password'], },
            headers={"X-Vault-Request": "true", }
        ).respond_with_json(token_response)

        httpserver.expect_request(
            "/v1/ssh-client-signer/sign/"
            f"{rc['config']['ROLE']}",
            method="PUT",
        ).respond_with_handler(
            make_handler(
                ca_key, tmp_path, token, rc,
                config))
        # The curl fallback reads the passphrase from /dev/tty so it works
        # when this script is run by ssh's Match exec. Exercise it through a
        # pty rather than stdin, which is not connected to /dev/tty.
        child = pexpect.spawn(
            str(rc['renew_scripts'][shell]),
            encoding='utf-8',
            timeout=10
        )
        output = StringIO()
        child.logfile = output
        child.expect_exact("Passphrase: ")
        child.sendline(rc['password'])
        child.expect(pexpect.EOF)
        child.close()
        full_output = output.getvalue()
        assert child.exitstatus == 0, full_output
        now = datetime.datetime.now()

        ssh_dir = rc['ssh_dir']
        key_file = (
            ssh_dir
            / (
                f"id-{rc['config']['CERTTYPE']}"
                f"-{rc['httpserver'].host.replace('.', '-')}"
                ))
        pub_file = f'{key_file}.pub'
        cert_file = f'{key_file}-cert.pub'
        for sshfile in (key_file, pub_file, cert_file):
            assert os.path.exists(sshfile)

        exp_out = sp.run(
            ['ssh-keygen', '-L', '-f', cert_file],
            check=True,
            capture_output=True,
            text=True
        )
        end = None
        principals = []
        id = None
        in_principals = False
        for line in exp_out.stdout.splitlines():
            line = line.strip()
            if line.startswith('Valid: '):
                end = datetime.datetime.strptime(
                    line.split(' ')[4],
                    '%Y-%m-%dT%H:%M:%S'
                )
                continue
            if line.startswith('Key ID: '):
                id = line.split(' ')[2].strip('"')
                continue
            if line.startswith('Principals:'):
                in_principals = True
                continue
            if line.startswith('Critical Options'):
                in_principals = False
                continue
            if in_principals:
                principals.append(line)

        assert end is not None
        assert (end - now).seconds <= 10
        assert rc['username'] in principals
        assert rc['config']['PRINCIPAL'] in principals
        assert id == f"ldap-{rc['username']}"
        pause = True


def test_renew_certificate_curl_openid(renew_certificate):
    rc = renew_certificate(bao="", openid=True)
    for shell in ['bash', 'zsh']:
        output = sp.run(
            rc['renew_scripts'][shell],
            capture_output=True,
            text=True)

        assert output.returncode == 1
        assert output.stderr == (
            f"[DEBUG] DataLad OpenBao SSH integration version {VERSION}\n"
            "[ERROR] Can't find the 'bao' client necessary for logins\n")


def test_existing_certificate_curl(httpserver, tmp_path, renew_certificate):
    rc = renew_certificate(bao="")
    token = rc['token']
    ca_key = rc['ca_key']

    token_response = {
        'auth': {
            'client_token': rc['token'],
        }}
    config = {'validity': "+10s"}
    for shell in ['bash', 'zsh']:
        httpserver.expect_request(
            f"/v1/auth/ldap/login/{rc['username']}",
            headers={"X-Vault-Request": "true", },
            method="PUT"
        ).respond_with_json(token_response)
        ssh_dir = rc['ssh_dir']
        key_file = (
            ssh_dir
            / (
                f"id-{rc['config']['CERTTYPE']}"
                f"-{rc['httpserver'].host.replace('.', '-')}"
                ))
        pub_file = f'{key_file}.pub'
        cert_file = f'{key_file}-cert.pub'
        for sshfile in (key_file, pub_file, cert_file):
            try:
                os.unlink(sshfile)
            except Exception:
                pass
        config = {"validity": "+8h"}
        httpserver.expect_request(
            "/v1/ssh-client-signer/sign/"
            f"{rc['config']['ROLE']}",
            method="PUT",
        ).respond_with_handler(make_handler(
                ca_key, tmp_path, token, rc,
                config))
        # The curl fallback reads its passphrase from the controlling tty.
        child = pexpect.spawn(
            str(rc['renew_scripts'][shell]),
            encoding='utf-8',
            timeout=10
        )
        output = StringIO()
        child.logfile = output
        child.expect_exact("Passphrase: ")
        child.sendline(rc['password'])
        child.expect(pexpect.EOF)
        child.close()
        full_output = output.getvalue()
        assert child.exitstatus == 0, full_output
        assert 'Logging into access control server...' in full_output

        output = sp.run(
            rc['renew_scripts'][shell],
            capture_output=True,
            text=True)

        assert output.returncode == 0
        assert 'Logging into access control server...' not in output.stderr


# Must be run last to avoid breaking other TLS tests
def test_tls_certs():
    truststore.inject_into_ssl()
    requests.get(
        "https://www.google.com"
    )
