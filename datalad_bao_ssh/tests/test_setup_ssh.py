import os
import os.path
import platform
from pytest_httpserver import HTTPServer
from pathlib import Path

from datalad_bao_ssh.setup_ssh import setup_ssh


def test_setup_ssh(httpserver: HTTPServer, tmp_path, mocker):
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

    mocker.patch(
        "datalad_bao_ssh.setup_ssh.Path.home",
        return_value=Path(tmp_path)
    )
    ssh_dir = tmp_path / '.ssh'
    os.mkdir(ssh_dir)
    with open(ssh_dir / 'config', 'w') as empty_conf:
        empty_conf.write('\n')

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
        f" {os.path.basename(ria_conf_file)}")
    with open(ssh_dir / 'config', 'r') as main_conf:
        found = include_line in main_conf.read()

    assert found is True

    expected_script = tmp_path / 'renewal_script'
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

# No tests of BASH script yet
