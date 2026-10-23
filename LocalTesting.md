# How to run tests locally

To run all tests (for your platform) use:

    python3 -m venv /tmp/bao-ssh-test
    source /tmp/bao-ssh-test/bin/activate
    python -m pip install -e '.[test]'
    python -m pytest
