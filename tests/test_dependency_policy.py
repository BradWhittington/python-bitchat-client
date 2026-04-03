import tomllib
from pathlib import Path

from python_bitchat_client import protocol as protocol_module


def test_protocol_library_is_vendored_not_runtime_dependency() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    deps = data["project"]["dependencies"]
    assert all(not dep.startswith("bitchat-protocol") for dep in deps)


def test_protocol_uses_vendored_module_namespace() -> None:
    assert protocol_module.decode_wire_packet.__module__.startswith(
        "python_bitchat_client._vendor.bitchat_protocol"
    )


def test_vendored_protocol_has_provenance_documentation() -> None:
    vendored_doc = (
        Path(__file__).resolve().parents[1]
        / "src/python_bitchat_client/_vendor/VENDORED.md"
    )
    assert vendored_doc.exists()
    content = vendored_doc.read_text()
    assert "bitchat-protocol" in content
    assert "0.1.1" in content
