import datetime
import json
import os
import os.path
import platform
import pytest
import ssl
import stat
import subprocess as sp
import time
import trustme

from importlib.metadata import entry_points
from pytest_httpserver import HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlsplit
from werkzeug.wrappers import Response

from datalad_bao_ssh.bao_setup import bao_setup
from datalad.cli.parser import setup_parser
from datalad.support.exceptions import IncompleteResultsError


def entrypoint_registered():
    return any(
        ep.name == "bao_setup"
        for ep in entry_points(group="datalad.extensions")
    )


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


@pytest.fixture
def ssh_environment(tmp_path, mocker):
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

    ria_username = 'joebloggs'
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
    fake_ui = SimpleNamespace(
        message=Mock(),
        yesno=Mock(side_effect=(
            False, user_response['GIT_REQUIRES_USERNAME'])),
        question=Mock(side_effect=[
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
                ria_username,
                ria_username,
            ])
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
        'ria_username': ria_username,
        'skiplines': skiplines,
        'principal': user_response['PRINCIPAL'],
    }


def test_bao_setup(
        httpserver: HTTPServer, requests_ca_bundle,
        ssh_environment, mocker):
    shell = ssh_environment['shell']

    baosrv = "baoserver.com"
    server_response = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOPORT": "8200",
        "BAOAUTH": "ldap",
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
        "datalad_bao_ssh.bao_setup.dlcfg.get",
        return_value=(
            f"{httpserver.url_for('/ssh_conf.json')}")
    )

    ssh_dir = ssh_environment['ssh_dir']
    ssh_environment['patches']['ui'].question.side_effect = [
        ssh_environment['ria_username'],
        ssh_environment['ria_username'],
    ]
    status = list(bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    exec_script = ssh_dir / f'{baosuffix}-renew.sh'
    identity_file = ssh_dir / f'id-{baosuffix}'
    # public_file = f'{identity_file}.pub'
    certificate_file = f'{identity_file}-cert.pub'

    expected_config = f'''Match host ria1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['ria_username']}"

Match host ria2.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['ria_username']}"

Match host git1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"

'''
    ria_conf_file = ssh_dir / f"{baosuffix}.conf"
    assert os.path.exists(ria_conf_file)
    with open(ria_conf_file) as ria_conf:
        actual_config = ria_conf.read()
    assert actual_config == expected_config

    include_line = (
        "# OpenBao renewals\nInclude"
        f' "{os.path.basename(ria_conf_file)}"')
    with open(ssh_dir / 'config', 'r') as main_conf:
        found = include_line in main_conf.read()

    assert found is True

    expected_script = ssh_environment['tmp_path'] / 'renewal_script'
    mod_dir = Path(__file__).parent.parent

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
            "datalad_bao_ssh.bao_setup.bao_setup.shell",
            return_value=test_shell)
        ssh_environment['patches']['ui'].question.side_effect = [
            ssh_environment['ria_username'],
            ssh_environment['ria_username'],
        ]
        status = list(bao_setup.__call__())

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
        ssh_environment, mocker):
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
        "datalad_bao_ssh.bao_setup.dlcfg.get",
        return_value=(
            f"{httpserver.url_for('/ssh_conf.json')}")
    )

    ssh_dir = ssh_environment['ssh_dir']
    git_username = 'git'
    ssh_environment['patches']['ui'].question.side_effect = [
        ssh_environment['ria_username'],
        ssh_environment['ria_username'],
        git_username,
    ]
    status = list(bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    exec_script = ssh_dir / f'{baosuffix}-renew.sh'
    identity_file = ssh_dir / f'id-{baosuffix}'
    # public_file = f'{identity_file}.pub'
    certificate_file = f'{identity_file}-cert.pub'

    expected_config = f'''Match host ria1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['ria_username']}"

Match host ria2.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['ria_username']}"

Match host git1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{git_username}"

'''
    ria_conf_file = ssh_dir / f"{baosuffix}.conf"
    assert os.path.exists(ria_conf_file)
    with open(ria_conf_file) as ria_conf:
        actual_config = ria_conf.read()
    assert actual_config == expected_config

    include_line = (
        "# OpenBao renewals\nInclude"
        f' "{os.path.basename(ria_conf_file)}"')
    with open(ssh_dir / 'config', 'r') as main_conf:
        found = include_line in main_conf.read()

    assert found is True

    expected_script = ssh_environment['tmp_path'] / 'renewal_script'
    mod_dir = Path(__file__).parent.parent

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
        ssh_environment, mocker):
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
        "datalad_bao_ssh.bao_setup.dlcfg.get",
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

    status = list(bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    ria_conf_file = ssh_dir / f"{baosuffix}.conf"

    include_line = (
        "# OpenBao renewals\nInclude"
        f' "{os.path.basename(ria_conf_file)}"')
    with open(ssh_config, 'r') as main_conf:
        content = main_conf.read()
    found = include_line in content
    assert found is True
    assert content.count(include_line) == 1
    assert content == f'{include_line}\n\n{existing_config}'
    status = list(bao_setup.__call__())
    with open(ssh_config, 'r') as main_conf:
        content = main_conf.read()
    found = include_line in content
    assert found is True
    assert content.count(include_line) == 1
    assert content == f'{include_line}\n\n{existing_config}'


def test_bao_setup_bad_dns(
        ssh_environment, requests_ca_bundle, mocker):
    shell = ssh_environment['shell']

    user_response = ssh_environment['user_response']
    baosrv = user_response['BAOHOST']
    mocker.patch(
        "datalad_bao_ssh.bao_setup.dlcfg.get",
        return_value=(
            "http://test.invalid/ssh_conf.json')}")
    )
    ssh_dir = ssh_environment['ssh_dir']

    status = list(bao_setup.__call__())
    assert status == [{
        'action': 'bao_setup',
        'status': 'ok',
        'msg': 'OpenBao certificate renewals configured',
    }]
    baosuffix = f'{baosrv.replace(".", "-")}'
    exec_script = ssh_dir / f'{baosuffix}-renew.sh'
    identity_file = ssh_dir / f'id-{baosuffix}'
    # public_file = f'{identity_file}.pub'
    certificate_file = f'{identity_file}-cert.pub'

    expected_config = f'''Match host ria3.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['ria_username']}"

Match host ria4.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"
    User "{ssh_environment['ria_username']}"

Match host git1.com exec "{exec_script}"
    IdentitiesOnly yes
    IdentityFile "{identity_file}"
    CertificateFile "{certificate_file}"

'''
    ria_conf_file = ssh_dir / f"{baosuffix}.conf"
    assert os.path.exists(ria_conf_file)
    with open(ria_conf_file) as ria_conf:
        actual_config = ria_conf.read()
    assert actual_config == expected_config

    include_line = (
        "# OpenBao renewals\nInclude"
        f' "{os.path.basename(ria_conf_file)}"')
    with open(ssh_dir / 'config', 'r') as main_conf:
        found = include_line in main_conf.read()

    assert found is True

    expected_script = ssh_environment['tmp_path'] / 'renewal_script'
    mod_dir = Path(__file__).parent.parent

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


def test_bao_setup_user_exit(
        ssh_environment, requests_ca_bundle):
    ssh_environment['patches']['ui'].yesno.side_effect = (True, )
    status = list(bao_setup.__call__())

    assert status == [{'action': 'bao_setup', 'status': 'ok'}]


def test_bao_setup_permissions_issue(
        ssh_environment, requests_ca_bundle):
    os.chmod(ssh_environment['ssh_dir'], 0o555)
    with pytest.raises(IncompleteResultsError):
        status = list(bao_setup.__call__())
        assert status['status'] == 'error'
        assert status['error_message'] == "Failed at Installing renewal script"


def test_bao_setup_shell_tcsh(monkeypatch, mocker):
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


@pytest.fixture
def requests_ca_bundle(monkeypatch, ca):
    monkeypatch.setenv("DATALAD_BAO_SSH_CA_CERT", ca)
    monkeypatch.setenv("DATALAD_BAO_SSH_DEBUG", "1")
    with ca.cert_pem.tempfile() as ca_pem:
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(ca_pem))
        yield str(ca_pem)


@pytest.fixture
def renew_certificate(
        monkeypatch, tmp_path,
        httpserver: HTTPServer,
        requests_ca_bundle, ca_cert_path):
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
        "BAOAUTH": "ldap",
    }
    renew_scripts = {
        'bash': ssh_dir / 'openbao_certificate_renew.bash',
        'zsh': ssh_dir / 'openbao_certificate_renew.zsh',
    }
    for shell in ('bash', 'zsh'):
        with open(mod_dir / 'openbao_certificate_renew.sh', 'r') as template:
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

    monkeypatch.setenv('HOME', tmp_path)
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


def make_handler(ca_key, tmp_path, token, renew_certificate, config):
    def handler(request):
        assert request.headers.get("X-Vault-Token") == token

        payload = json.loads(request.data.decode("utf-8"))
        public_key = payload["public_key"]
        valid_principals = payload["valid_principals"]
        assert valid_principals == \
            f"{renew_certificate['server_response']['PRINCIPAL']},{
                renew_certificate['username']}"
        signed_key = _sign_public_key(
            ca_key=ca_key,
            public_key=public_key,
            principals=valid_principals,
            tmp_path=tmp_path,
            validity=config['validity'],
            id=f"ldap-{renew_certificate['username']}"
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


def test_renew_certificate(httpserver, tmp_path, renew_certificate):
    token = renew_certificate['token']
    ca_key = renew_certificate['ca_key']

    token_response = {
        'auth': {
            'client_token': renew_certificate['token'],
        }}
    config = {'validity': "+10s"}
    for shell in ['bash', 'zsh']:
        time.sleep(10)
        httpserver.expect_request(
            f"/v1/auth/ldap/login/{renew_certificate['username']}",
            method="POST",
            json={"password": renew_certificate['password'], },
            headers={"Content-Type": "application/json", }
        ).respond_with_json(token_response)

        httpserver.expect_request(
            f"/v1/ssh-client-signer/sign/{
                renew_certificate['config']['ROLE']}",
            method="POST",
        ).respond_with_handler(
            make_handler(
                ca_key, tmp_path, token, renew_certificate,
                config))
        output = sp.run(
            renew_certificate['renew_scripts'][shell],
            capture_output=True,
            text=True,
            input=(
                f'{renew_certificate['username']}\n'
                f'{renew_certificate['password']}\n'))
        now = datetime.datetime.now()
        assert output.returncode == 0

        ssh_dir = renew_certificate['ssh_dir']
        key_file = (
            ssh_dir
            / f'id-{renew_certificate[
                'config']['CERTTYPE']}-{renew_certificate[
                        'httpserver'].host.replace('.', '-')}')
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
        assert renew_certificate['username'] in principals
        assert renew_certificate['config']['PRINCIPAL'] in principals
        assert id == f"ldap-{renew_certificate['username']}"


def test_existing_certificate(httpserver, tmp_path, renew_certificate):
    token = renew_certificate['token']
    ca_key = renew_certificate['ca_key']

    token_response = {
        'auth': {
            'client_token': renew_certificate['token'],
        }}
    config = {'validity': "+10s"}
    for shell in ['bash', 'zsh']:
        httpserver.expect_request(
            f"/v1/auth/ldap/login/{renew_certificate['username']}"
        ).respond_with_json(token_response)
        ssh_dir = renew_certificate['ssh_dir']
        key_file = (
            ssh_dir
            / f'id-{renew_certificate[
                'config']['CERTTYPE']}-{renew_certificate[
                        'httpserver'].host.replace('.', '-')}')
        pub_file = f'{key_file}.pub'
        cert_file = f'{key_file}-cert.pub'
        for sshfile in (key_file, pub_file, cert_file):
            try:
                os.unlink(sshfile)
            except Exception:
                pass
        config = {"validity": "+8h"}
        httpserver.expect_request(
            f"/v1/ssh-client-signer/sign/{
                renew_certificate['config']['ROLE']}",
            method="POST",
        ).respond_with_handler(make_handler(
                ca_key, tmp_path, token, renew_certificate,
                config))
        output = sp.run(
            renew_certificate['renew_scripts'][shell],
            capture_output=True,
            text=True,
            input=(
                f'{renew_certificate['username']}\n'
                f'{renew_certificate['password']}\n'))
        assert output.returncode == 0
        assert 'Logging into access control server...' in output.stdout

        output = sp.run(
            renew_certificate['renew_scripts'][shell],
            capture_output=True,
            text=True)

        assert output.returncode == 0
        assert 'Logging into access control server...' not in output.stdout
