import os
import os.path
import platform
import pytest
import subprocess as sp
from pytest_httpserver import HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from datalad_bao_ssh.setup_ssh import setup_ssh
from datalad.support.exceptions import IncompleteResultsError


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
        "SSH_HOSTS": [
            "ria3.com",
            "ria4.com"
        ]
    }
    vpn_connect = False
    fake_ui = SimpleNamespace(
        message=Mock(),
        yesno=Mock(return_value=False),
        question=Mock(side_effect=[
                user_response['ROLE'],
                user_response['PRINCIPAL'],
                user_response["CERTTYPE"],
                user_response["BAOHOST"],
                user_response["BAOPORT"],
                user_response["BAOAUTH"],
                user_response["SSH_HOSTS"][0],
                user_response["SSH_HOSTS"][1],
                ""
            ])
    )
    patches = {
        "Path.home": mocker.patch(
            "datalad_bao_ssh.setup_ssh.Path.home",
            return_value=Path(tmp_path)),
        "ui": mocker.patch(
            "datalad_bao_ssh.setup_ssh.ui",
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
    }


def test_setup_ssh(
        httpserver: HTTPServer, ssh_environment, mocker):
    shell = ssh_environment['shell']

    baosrv = "baoserver.com"
    server_response = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOPORT": "8200",
        "BAOAUTH": "ldap",
        "SSH_HOSTS": [
            "ria1.com",
            "ria2.com"
        ]
    }
    httpserver.expect_request(
        "/ssh_conf.json").respond_with_json(
            server_response)
    mocker.patch(
        "datalad_bao_ssh.setup_ssh.dlcfg.get",
        return_value=(
            f"{httpserver.url_for('/ssh_conf.json')}")
    )

    ssh_dir = ssh_environment['ssh_dir']

    cmd = setup_ssh()
    status = list(cmd.__call__(cmd))
    assert status == [{
        'action': 'setup_ssh',
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

Match host ria2.com exec "{exec_script}"
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
                        if f'**{k}**' in line:
                            line = line.replace(f'**{k}**', v)
                escript.write(line)
    assert os.path.exists(ssh_dir / f'{baosuffix}-renew.sh')
    with open(ssh_dir / f'{baosuffix}-renew.sh') as ascript:
        actual_script = ascript.read()
    with open(expected_script) as escript:
        required_script = escript.read()

    for k in server_response.keys():
        assert f'**{k}**' not in actual_script
        assert f'**{k}**' not in required_script
    assert actual_script == required_script

    for test_shell in ('/bin/bash', '/bin/zsh', ):
        mocker.patch(
            "datalad_bao_ssh.setup_ssh.setup_ssh.shell",
            return_value=test_shell)
        status = list(cmd.__call__(cmd))

        with open(mod_dir / 'openbao_certificate_renew.sh', 'r') as template:
            with open(expected_script, 'w') as escript:
                for line in template.readlines():
                    if line == '#!/bin/bash\n':
                        line = f'#!{test_shell}\n'
                    else:
                        for k, v in server_response.items():
                            if f'**{k}**' in line:
                                line = line.replace(f'**{k}**', v)
                    escript.write(line)

        assert os.path.exists(ssh_dir / f'{baosuffix}-renew.sh')
        with open(ssh_dir / f'{baosuffix}-renew.sh') as ascript:
            actual_script = ascript.read()
        with open(expected_script) as escript:
            required_script = escript.read()
        for k in server_response.keys():
            assert f'**{k}**' not in actual_script
            assert f'**{k}**' not in required_script
        assert actual_script == required_script


def test_setup_ssh_existing_config(
        httpserver: HTTPServer, ssh_environment, mocker):
    baosrv = "baoserver.com"
    server_response = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOPORT": "8200",
        "BAOAUTH": "ldap",
        "SSH_HOSTS": [
            "ria1.com",
            "ria2.com"
        ]
    }
    httpserver.expect_request(
        "/ssh_conf.json").respond_with_json(
            server_response)
    mocker.patch(
        "datalad_bao_ssh.setup_ssh.dlcfg.get",
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

    cmd = setup_ssh()
    status = list(cmd.__call__(cmd))
    assert status == [{
        'action': 'setup_ssh',
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
    cmd = setup_ssh()
    status = list(cmd.__call__(cmd))
    with open(ssh_config, 'r') as main_conf:
        content = main_conf.read()
    found = include_line in content
    assert found is True
    assert content.count(include_line) == 1
    assert content == f'{include_line}\n\n{existing_config}'


def test_setup_ssh_bad_dns(ssh_environment, mocker):
    shell = ssh_environment['shell']

    user_response = ssh_environment['user_response']
    baosrv = user_response['BAOHOST']
    mocker.patch(
        "datalad_bao_ssh.setup_ssh.dlcfg.get",
        return_value=(
            "http://test.invalid/ssh_conf.json')}")
    )
    ssh_dir = ssh_environment['ssh_dir']

    cmd = setup_ssh()
    status = list(cmd.__call__(cmd))
    assert status == [{
        'action': 'setup_ssh',
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

Match host ria4.com exec "{exec_script}"
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
                        if f'**{k}**' in line:
                            line = line.replace(f'**{k}**', v)
                escript.write(line)
    assert os.path.exists(ssh_dir / f'{baosuffix}-renew.sh')
    with open(ssh_dir / f'{baosuffix}-renew.sh') as ascript:
        actual_script = ascript.read()
    with open(expected_script) as escript:
        required_script = escript.read()

    for k in user_response.keys():
        assert f'**{k}**' not in actual_script
        assert f'**{k}**' not in required_script
    assert actual_script == required_script


def test_setup_ssh_user_exit(ssh_environment):
    ssh_environment['patches']['ui'].yesno.return_value = True

    cmd = setup_ssh()
    status = list(cmd.__call__(cmd))

    assert status == [{'action': 'setup_ssh', 'status': 'ok'}]


def test_setup_ssh_permissions_issue(ssh_environment):
    os.chmod(ssh_environment['ssh_dir'], 0o555)
    cmd = setup_ssh()
    with pytest.raises(IncompleteResultsError):
        status = list(cmd.__call__(cmd))
        assert status['status'] == 'error'
        assert status['error_message'] == "Failed at Installing renewal script"


def test_setup_ssh_shell_tcsh(monkeypatch, mocker):
    monkeypatch.setenv('SHELL', '/bin/tcsh')
    for system in (
            ('Darwin', '/bin/zsh', ),
            ('Linux', '/bin/bash', ),
            ('Another', '/bin/sh', ), ):
        mocker.patch(
            "datalad_bao_ssh.setup_ssh.platform.system",
            return_value=system[0])

        cmd = setup_ssh()
        shell = cmd.shell()
        assert shell == system[1]

# No tests of BASH script yet
@pytest.fixture
def renew_certificate(monkeypatch, tmp_path):
    mod_dir = Path(__file__).parent.parent
    home_dir = tmp_path
    sp.run([
        'ssh-keygen', '-t', 'ed25519',
        '-f', str(home_dir / 'ssh_ca')
    ])
    ssh_dir = Path.home() / '.ssh'
    os.mkdir(ssh_dir)
    os.chmod(ssh_dir, 0o700)

    baosrv = "baoserver.com"
    config = {
        "ROLE": "datalad-role",
        "PRINCIPAL": "dataladUsers",
        "CERTTYPE": "ed25519",
        "BAOHOST": baosrv,
        "BAOPORT": "8200",
        "BAOAUTH": "ldap",
        "SSH_HOSTS": [
            "ria1.com",
            "ria2.com"
        ]
    }
    renew_scripts ={
        'bash': ssh_dir / 'openbao_certificate_renew.bash',
        'zsh': ssh_dir / 'openbao_certificate_renew.zsh',
    }
    for shell in ('bash', 'zsh'):

        with open(mod_dir / f'openbao_certificate_renew.sh', 'r') as template:
            with open(renew_scripts[shell], 'w') as script:
                for line in template.readlines():
                    if line == '#!/bin/bash\n':
                        line = f'#!/bin/{shell}\n'
                    else:
                        for k, v in config.items():
                            if f'**{k}**' in line:
                                line = line.replace(f'**{k}**', v)
                    script.write(line)

    monkeypatch.setenv('HOME', tmp_path)

    return {
        'home_dir': home_dir,
        'ssh_dir': ssh_dir,
        'baosrv': baosrv,
        'config': config,
        'renew_scripts': renew_scripts,
    }


def test_openbao_certificate_renew(renew_certificate):
