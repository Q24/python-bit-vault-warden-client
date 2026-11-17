import re
from pathlib import Path

import bit_vault_warden_client

PYPROJECT = Path(__file__).resolve().parents[3] / "pyproject.toml"


def test_version_matches_pyproject():
    version = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.MULTILINE)
    assert version is not None
    assert bit_vault_warden_client.__version__ == version.group(1)


def test_public_api():
    for name in bit_vault_warden_client.__all__:
        assert hasattr(bit_vault_warden_client, name), name
    assert bit_vault_warden_client.WardenClient.__name__ == "WardenWebApi"
