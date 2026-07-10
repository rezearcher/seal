"""Interop test: verify all ports against the shared test-vector fixture.

Reads tests/vectors/vpe_vectors.json and verifies every vector using
the Python VPE implementation.  The same fixture is consumed by the
TypeScript, Go, and Rust ports.
"""

import json
from pathlib import Path

from seal.core import vpe_verify, vpe_verify_hmac

FIXTURE_DIR = Path(__file__).resolve().parent / "vectors"
FIXTURE_PATH = FIXTURE_DIR / "vpe_vectors.json"


def load_fixture() -> dict:
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def test_fixture_exists():
    assert FIXTURE_PATH.exists(), f"Fixture not found: {FIXTURE_PATH}"


def test_fixture_is_valid_json():
    data = load_fixture()
    assert data["version"] == 1
    assert len(data["vectors"]) >= 20


def _run_vector_test(vector: dict, fixture: dict):
    """Run a single vector against the Python verifier."""
    if vector["tampered_envelope_json"]:
        env_str = vector["tampered_envelope_json"]
    else:
        env_str = vector["signed_envelope_json"]

    if vector["signature_type"] == "ed25519":
        public_key = bytes.fromhex(fixture["ed25519_public_key_hex"])
        result = vpe_verify(env_str, public_key=public_key)
    else:
        shared_secret = bytes.fromhex(fixture["hmac_secret_hex"])
        result = vpe_verify_hmac(env_str, shared_secret=shared_secret)

    expected = vector["expected_verify"]
    assert result["valid"] == expected, (
        f"[{vector['id']}] expected valid={expected}, got valid={result['valid']} reason={result['reason']}"
    )
    assert result["reason"] == ("ok" if expected else result["reason"])


def test_all_vectors():
    """Verify every vector in the fixture."""
    fixture = load_fixture()
    for vec in fixture["vectors"]:
        _run_vector_test(vec, fixture)


# Generate individual test functions for every vector so pytest
# can report them separately.


def _make_vector_test(vec: dict, fixture: dict):
    def test_fn():
        _run_vector_test(vec, fixture)

    test_fn.__name__ = f"test_vector_{vec['id']}"
    test_fn.__doc__ = vec["description"]
    return test_fn


_fixture = load_fixture()
for _vec in _fixture["vectors"]:
    locals()[f"test_vector_{_vec['id']}"] = _make_vector_test(_vec, _fixture)
