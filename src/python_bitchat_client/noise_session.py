import threading
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .noise_protocol import NoiseCipherState, NoiseHandshakeState, NoiseRole


@dataclass
class NoiseSession:
    peer_id: str
    role: NoiseRole
    handshake: NoiseHandshakeState
    send_cipher: NoiseCipherState | None = None
    receive_cipher: NoiseCipherState | None = None

    @property
    def established(self) -> bool:
        return self.send_cipher is not None and self.receive_cipher is not None


class NoiseSessionManager:
    def __init__(self, *, local_static_private_key: bytes) -> None:
        self._local_static = X25519PrivateKey.from_private_bytes(
            local_static_private_key
        )
        self._sessions: dict[str, NoiseSession] = {}
        self._lock = threading.RLock()

    def has_session(self, peer_id: str) -> bool:
        with self._lock:
            return peer_id in self._sessions

    def has_established_session(self, peer_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(peer_id)
            return bool(session and session.established)

    def initiate_handshake(self, peer_id: str) -> bytes:
        with self._lock:
            if self.has_established_session(peer_id):
                raise ValueError("session already established")
            session = NoiseSession(
                peer_id=peer_id,
                role=NoiseRole.INITIATOR,
                handshake=NoiseHandshakeState(
                    role=NoiseRole.INITIATOR,
                    local_static=self._local_static,
                ),
            )
            self._sessions[peer_id] = session
            return session.handshake.write_message()

    def handle_incoming_handshake(
        self, *, peer_id: str, message: bytes
    ) -> bytes | None:
        with self._lock:
            session = self._sessions.get(peer_id)
            is_initiation = len(message) == 32
            if session is None:
                session = NoiseSession(
                    peer_id=peer_id,
                    role=NoiseRole.RESPONDER,
                    handshake=NoiseHandshakeState(
                        role=NoiseRole.RESPONDER,
                        local_static=self._local_static,
                    ),
                )
                self._sessions[peer_id] = session
            elif session.established and is_initiation:
                session = NoiseSession(
                    peer_id=peer_id,
                    role=NoiseRole.RESPONDER,
                    handshake=NoiseHandshakeState(
                        role=NoiseRole.RESPONDER,
                        local_static=self._local_static,
                    ),
                )
                self._sessions[peer_id] = session
            elif (
                not session.established
                and session.role == NoiseRole.INITIATOR
                and is_initiation
            ):
                # Mirror iOS behavior: if an initiation arrives while we are
                # handshaking as initiator, reset and accept as responder.
                session = NoiseSession(
                    peer_id=peer_id,
                    role=NoiseRole.RESPONDER,
                    handshake=NoiseHandshakeState(
                        role=NoiseRole.RESPONDER,
                        local_static=self._local_static,
                    ),
                )
                self._sessions[peer_id] = session
            elif (
                not session.established
                and session.role == NoiseRole.RESPONDER
                and is_initiation
            ):
                # Peer retransmitted handshake init before receiving our response.
                # Reset responder state and process fresh initiation.
                session = NoiseSession(
                    peer_id=peer_id,
                    role=NoiseRole.RESPONDER,
                    handshake=NoiseHandshakeState(
                        role=NoiseRole.RESPONDER,
                        local_static=self._local_static,
                    ),
                )
                self._sessions[peer_id] = session

            session.handshake.read_message(message)
            if session.handshake.is_complete():
                send_cipher, recv_cipher = session.handshake.get_transport_ciphers()
                session.send_cipher = send_cipher
                session.receive_cipher = recv_cipher
                return None

            response = session.handshake.write_message()
            if session.handshake.is_complete():
                send_cipher, recv_cipher = session.handshake.get_transport_ciphers()
                session.send_cipher = send_cipher
                session.receive_cipher = recv_cipher
            return response

    def encrypt(self, *, peer_id: str, plaintext: bytes) -> bytes:
        with self._lock:
            session = self._sessions.get(peer_id)
            if session is None or not session.established:
                raise ValueError("session not established")
            send_cipher = session.send_cipher
            if send_cipher is None:
                raise ValueError("session send cipher missing")
            return send_cipher.encrypt(plaintext)

    def decrypt(self, *, peer_id: str, ciphertext: bytes) -> bytes:
        with self._lock:
            session = self._sessions.get(peer_id)
            if session is None or not session.established:
                raise ValueError("session not established")
            receive_cipher = session.receive_cipher
            if receive_cipher is None:
                raise ValueError("session receive cipher missing")
            return receive_cipher.decrypt(ciphertext)

    def clear_session(self, peer_id: str) -> None:
        with self._lock:
            self._sessions.pop(peer_id, None)

    def clear_all_sessions(self) -> None:
        with self._lock:
            self._sessions.clear()

    def session_states(self) -> dict[str, str]:
        with self._lock:
            out: dict[str, str] = {}
            for peer_id, session in self._sessions.items():
                out[peer_id] = "established" if session.established else "handshaking"
            return out
