from python_bitchat_client.keys import IdentityKeyPair


def test_generate_identity_creates_both_keys():
    identity = IdentityKeyPair.generate()
    assert identity.noise_private_key is not None
    assert identity.noise_public_key is not None
    assert identity.signing_private_key is not None
    assert identity.signing_public_key is not None
    assert len(identity.noise_private_key) == 32
    assert len(identity.noise_public_key) == 32
    assert len(identity.signing_private_key) == 32
    assert len(identity.signing_public_key) == 32


def test_peer_id_derived_from_noise_public_key():
    identity = IdentityKeyPair.generate()
    peer_id = identity.peer_id
    assert isinstance(peer_id, str)
    assert len(peer_id) == 64  # SHA-256 hex = 64 chars


def test_identity_from_seed_is_reproducible():
    seed = b"test-seed-123"
    id1 = IdentityKeyPair.from_seed(seed)
    id2 = IdentityKeyPair.from_seed(seed)
    assert id1.peer_id == id2.peer_id


def test_identity_accepts_external_keys():
    noise_private = bytes(range(32))
    signing_private = bytes(range(32, 64))
    identity = IdentityKeyPair(
        noise_private_key=noise_private,
        signing_private_key=signing_private,
    )
    assert identity.peer_id is not None
