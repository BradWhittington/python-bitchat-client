import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from python_bitchat_client.keys import IdentityKeyPair
from python_bitchat_client.noise_protocol import NoiseHandshakeState, NoiseRole
from python_bitchat_client.noise_session import NoiseSessionManager


def test_noise_session_manager_handshake_and_transport_roundtrip() -> None:
    alice = IdentityKeyPair.generate()
    bob = IdentityKeyPair.generate()

    alice_mgr = NoiseSessionManager(local_static_private_key=alice.noise_private_key)
    bob_mgr = NoiseSessionManager(local_static_private_key=bob.noise_private_key)

    m1 = alice_mgr.initiate_handshake("bob")
    m2 = bob_mgr.handle_incoming_handshake(peer_id="alice", message=m1)
    assert m2 is not None

    m3 = alice_mgr.handle_incoming_handshake(peer_id="bob", message=m2)
    assert m3 is not None

    m4 = bob_mgr.handle_incoming_handshake(peer_id="alice", message=m3)
    assert m4 is None

    assert alice_mgr.has_established_session("bob")
    assert bob_mgr.has_established_session("alice")

    ciphertext = alice_mgr.encrypt(peer_id="bob", plaintext=b"hello")
    plaintext = bob_mgr.decrypt(peer_id="alice", ciphertext=ciphertext)
    assert plaintext == b"hello"


def test_noise_session_manager_simultaneous_initiation_collision_recovers() -> None:
    alice = IdentityKeyPair.generate()
    bob = IdentityKeyPair.generate()

    alice_mgr = NoiseSessionManager(local_static_private_key=alice.noise_private_key)
    bob_mgr = NoiseSessionManager(local_static_private_key=bob.noise_private_key)

    alice_id = "alice"
    bob_id = "bob"

    # Both peers initiate at the same time.
    alice_init = alice_mgr.initiate_handshake(bob_id)
    bob_init = bob_mgr.initiate_handshake(alice_id)

    # Each side receives the other's initiator frame and should recover.
    alice_resp = alice_mgr.handle_incoming_handshake(peer_id=bob_id, message=bob_init)
    bob_resp = bob_mgr.handle_incoming_handshake(peer_id=alice_id, message=alice_init)

    # iOS-compatible behavior: either side may reset to responder and reply.
    assert alice_resp is not None
    assert bob_resp is not None


def test_noise_session_manager_responder_tolerates_duplicate_init() -> None:
    alice = IdentityKeyPair.generate()
    bob = IdentityKeyPair.generate()

    alice_mgr = NoiseSessionManager(local_static_private_key=alice.noise_private_key)
    bob_mgr = NoiseSessionManager(local_static_private_key=bob.noise_private_key)

    init = alice_mgr.initiate_handshake("bob")

    # Bob handles init and creates response.
    resp1 = bob_mgr.handle_incoming_handshake(peer_id="alice", message=init)
    assert resp1 is not None

    # Alice retransmits init before receiving response.
    resp2 = bob_mgr.handle_incoming_handshake(peer_id="alice", message=init)
    assert resp2 is not None


def test_noise_handshake_includes_empty_prologue_hash_mix() -> None:
    local_static = X25519PrivateKey.generate()
    handshake = NoiseHandshakeState(role=NoiseRole.INITIATOR, local_static=local_static)

    protocol_name = b"Noise_XX_25519_ChaChaPoly_SHA256"
    initial_h = protocol_name + b"\x00" * (32 - len(protocol_name))
    expected = hashlib.sha256(initial_h + b"").digest()

    assert handshake.handshake_hash() == expected
