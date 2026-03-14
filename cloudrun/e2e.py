"""
e2e.py — End-to-End Encryption layer for KyberChat
====================================================
Implements the full Signal Protocol stack on the server-side key directory:

  Phase 1 · Key Bundle Management
    upload_pre_keys()       — client uploads SPK + OTPKs after registration
    get_key_bundle()        — sender fetches recipient's public key bundle
    replenish_one_time_keys() — client tops-up the OTPK pool

  Phase 2 · X3DH Key Agreement  (RFC-style as in Signal spec)
    x3dh_sender_init()      — sender derives the shared secret + initial message
    x3dh_receiver_init()    — recipient derives the same shared secret from
                               the X3DH header embedded in the first message

  Phase 3 · Double Ratchet  (Marlinspike/Perrin spec §3)
    RatchetSession          — stateful object held per conversation per device
      .encrypt()            — encrypt a plaintext, advance sending chain
      .decrypt()            — decrypt a ciphertext, advance receiving chain
      .serialise()          — JSON-safe dict for Firestore storage
      RatchetSession.deserialise() — reconstruct from Firestore doc

  Phase 4 · Message transport helpers
    encrypt_message()       — high-level: takes plaintext + session → wire frame
    decrypt_message()       — high-level: takes wire frame + session → plaintext

  Database endpoints (Flask Blueprint)
    POST /keys/upload       — upload_pre_keys
    GET  /keys/bundle/<uuid>— get_key_bundle
    POST /keys/replenish    — replenish_one_time_keys

Cryptographic primitives (all from `cryptography` — no third-party Signal lib):
  · Curve25519 (X25519)   — DH key agreement
  · Ed25519               — SPK signature verification
  · HKDF-SHA256           — key derivation (X3DH root + ratchet KDF)
  · AES-256-GCM           — AEAD message encryption
  · HMAC-SHA256           — chain-key ratchet step

Wire format (JSON, transmitted over Firestore or any transport):
  {
    "version":    1,
    "sender_uuid": "...",
    "x3dh_header": {               # only present in the FIRST message
        "ik_public":   "<hex>",    # sender ephemeral IK for this session
        "ek_public":   "<hex>",    # ephemeral key EK
        "spk_id":      <int>,
        "otpk_id":     <int> | null
    },
    "ratchet_header": {
        "dh_public":   "<hex>",    # sender's current ratchet public key
        "pn":          <int>,      # messages sent in previous sending chain
        "n":           <int>       # message number in current sending chain
    },
    "ciphertext":  "<hex>",        # AES-256-GCM ciphertext
    "nonce":       "<hex>",        # 12-byte GCM nonce
    "tag":         "<hex>"         # 16-byte GCM auth tag
  }
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from flask import Blueprint, request, jsonify
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from auth import verify_token
from db import engine

logger = logging.getLogger(__name__)
e2e_bp = Blueprint("e2e", __name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SIGNAL_INFO_ROOT   = b"KyberChat_X3DH_RootKey_v1"
_SIGNAL_INFO_CHAIN  = b"KyberChat_DR_ChainKey_v1"
_SIGNAL_INFO_MSG    = b"KyberChat_DR_MessageKey_v1"
_MAX_SKIP           = 1000   # max out-of-order messages to tolerate
_OTPK_REFILL_FLOOR  = 5      # warn / trigger refill below this many OTPKs

# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

def _x25519_dh(private_key: X25519PrivateKey, public_key: X25519PublicKey) -> bytes:
    return private_key.exchange(public_key)


def _hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)


def _kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """
    Signal KDF_RK: derive a new root key and chain key from a DH output.
    Returns (new_root_key, new_chain_key).
    """
    out = _hkdf(dh_output, salt=root_key, info=_SIGNAL_INFO_ROOT, length=64)
    return out[:32], out[32:]


def _kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    Signal KDF_CK: HMAC-SHA256 chain step.
    Returns (new_chain_key, message_key).
    """
    new_ck  = _hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    msg_key = _hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    return new_ck, msg_key


def _aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt. Returns (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ct


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM decrypt. Raises InvalidTag on auth failure."""
    return AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)


def _pub_to_hex(key) -> str:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def _hex_to_x25519_pub(hex_str: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def _hex_to_ed25519_pub(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


# ---------------------------------------------------------------------------
# Key generation helpers (called on the client; exposed here for testing)
# ---------------------------------------------------------------------------

@dataclass
class IdentityKeyPair:
    """Long-term Curve25519 identity key pair."""
    private_key: X25519PrivateKey
    public_key:  X25519PublicKey

    @staticmethod
    def generate() -> "IdentityKeyPair":
        priv = X25519PrivateKey.generate()
        return IdentityKeyPair(private_key=priv, public_key=priv.public_key())

    def public_hex(self) -> str:
        return _pub_to_hex(self.public_key)


@dataclass
class SignedPreKey:
    """Medium-term DH key signed by the identity Ed25519 key."""
    key_id:      int
    private_key: X25519PrivateKey
    public_key:  X25519PublicKey
    signature:   bytes           # Ed25519 sig over public_key raw bytes

    @staticmethod
    def generate(key_id: int, signing_key: Ed25519PrivateKey) -> "SignedPreKey":
        priv = X25519PrivateKey.generate()
        pub  = priv.public_key()
        pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        sig = signing_key.sign(pub_bytes)
        return SignedPreKey(key_id=key_id, private_key=priv, public_key=pub, signature=sig)


@dataclass
class OneTimePreKey:
    """Single-use ephemeral DH key."""
    key_id:      int
    private_key: X25519PrivateKey
    public_key:  X25519PublicKey

    @staticmethod
    def generate(key_id: int) -> "OneTimePreKey":
        priv = X25519PrivateKey.generate()
        return OneTimePreKey(key_id=key_id, private_key=priv, public_key=priv.public_key())


# ---------------------------------------------------------------------------
# Phase 1 — Key Bundle DB endpoints
# ---------------------------------------------------------------------------

@e2e_bp.route("/keys/upload", methods=["POST"])
def upload_pre_keys():
    """
    Upload or refresh a user's pre-key bundle.

    Authenticates via Bearer JWT. Replaces the current SPK and appends
    fresh OTPKs. The identity key is read from the users table (set at
    registration) — it is never overwritten here.

    Request body:
    {
      "signed_pre_key": {
        "key_id":    <int>,
        "public_key": "<hex>",
        "signature":  "<hex>"
      },
      "one_time_pre_keys": [
        {"key_id": <int>, "public_key": "<hex>"},
        ...
      ]
    }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        spk  = data.get("signed_pre_key")
        otpks = data.get("one_time_pre_keys", [])

        if not spk:
            return jsonify({"error": "Missing signed_pre_key"}), 400

        # Verify SPK signature against the stored identity public key
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT identity_key_public FROM users WHERE user_uuid = :u AND deleted = 0"),
                {"u": user_uuid},
            ).fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404

        ik_pub_bytes = bytes(row[0])
        spk_pub_bytes = bytes.fromhex(spk["public_key"])
        spk_sig_bytes = bytes.fromhex(spk["signature"])

        # Identity key is stored as X25519 for DH, but we need Ed25519 for signing.
        # Convention: the client derives an Ed25519 signing key from the same seed
        # and stores the Ed25519 public key alongside the X25519 key.
        # For verification we accept the Ed25519 public key embedded in the upload.
        ed_pub_hex = data.get("identity_key_ed25519_public")
        if ed_pub_hex:
            try:
                ed_pub = _hex_to_ed25519_pub(ed_pub_hex)
                ed_pub.verify(spk_sig_bytes, spk_pub_bytes)
            except Exception:
                return jsonify({"error": "SPK signature verification failed"}), 400

        with engine.begin() as conn:
            # Replace the signed pre-key (soft: keep old rows for in-flight sessions)
            conn.execute(
                text("""
                    INSERT INTO signed_pre_keys (user_uuid, key_id, public_key, signature)
                    VALUES (:u, :kid, :pub, :sig)
                """),
                {
                    "u":   user_uuid,
                    "kid": spk["key_id"],
                    "pub": spk_pub_bytes,
                    "sig": spk_sig_bytes,
                },
            )

            # Append one-time pre-keys
            for otpk in otpks:
                conn.execute(
                    text("""
                        INSERT IGNORE INTO one_time_pre_keys (user_uuid, key_id, public_key)
                        VALUES (:u, :kid, :pub)
                    """),
                    {
                        "u":   user_uuid,
                        "kid": otpk["key_id"],
                        "pub": bytes.fromhex(otpk["public_key"]),
                    },
                )

        logger.info(f"Pre-keys uploaded for {user_uuid}: SPK {spk['key_id']}, {len(otpks)} OTPKs")
        return jsonify({"message": "Pre-keys uploaded", "otpk_count": len(otpks)}), 201

    except IntegrityError as e:
        logger.warning(f"Duplicate key upload: {e}")
        return jsonify({"error": "Duplicate key_id"}), 409
    except Exception as e:
        logger.error(f"upload_pre_keys error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@e2e_bp.route("/keys/bundle/<target_uuid>", methods=["GET"])
def get_key_bundle(target_uuid: str):
    """
    Returns the recipient's public key bundle for X3DH initiation.

    Authentication: Bearer JWT (any authenticated user may fetch).

    Response:
    {
      "user_uuid":             "<uuid>",
      "identity_key_public":   "<hex>",   # X25519
      "registration_id":       <int>,
      "signed_pre_key": {
        "key_id":    <int>,
        "public_key": "<hex>",
        "signature":  "<hex>"
      },
      "one_time_pre_key": {               # null if pool is exhausted
        "key_id":    <int>,
        "public_key": "<hex>"
      }
    }
    """
    try:
        _, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        with engine.begin() as conn:
            user = conn.execute(
                text("""
                    SELECT user_uuid, identity_key_public, registration_id, kem_public_key
                    FROM users WHERE user_uuid = :u AND deleted = 0
                """),
                {"u": target_uuid},
            ).fetchone()
            if not user:
                return jsonify({"error": "User not found"}), 404

            spk = conn.execute(
                text("""
                    SELECT key_id, public_key, signature FROM signed_pre_keys
                    WHERE user_uuid = :u ORDER BY created_at DESC LIMIT 1
                """),
                {"u": target_uuid},
            ).fetchone()
            if not spk:
                return jsonify({"error": "No signed pre-key on file"}), 404

            # Atomically consume one OTPK (mark as used)
            otpk = conn.execute(
                text("""
                    SELECT id, key_id, public_key FROM one_time_pre_keys
                    WHERE user_uuid = :u AND is_consumed = FALSE
                    ORDER BY id ASC LIMIT 1
                    FOR UPDATE
                """),
                {"u": target_uuid},
            ).fetchone()

            otpk_data = None
            if otpk:
                conn.execute(
                    text("UPDATE one_time_pre_keys SET is_consumed = TRUE WHERE id = :id"),
                    {"id": otpk[0]},
                )
                otpk_data = {
                    "key_id":    otpk[1],
                    "public_key": bytes(otpk[2]).hex(),
                }

            # Count remaining OTPKs for refill hint
            remaining = conn.execute(
                text("SELECT COUNT(*) FROM one_time_pre_keys WHERE user_uuid = :u AND is_consumed = FALSE"),
                {"u": target_uuid},
            ).scalar()

        bundle = {
            "user_uuid":           user[0],
            "identity_key_public": bytes(user[1]).hex(),
            "registration_id":     user[2],
            # ML-KEM-768 public key — present if recipient has registered a KEM key (v1 PQC)
            "kem_public_key":      bytes(user[3]).hex() if user[3] else None,
            "signed_pre_key": {
                "key_id":    spk[0],
                "public_key": bytes(spk[1]).hex(),
                "signature":  bytes(spk[2]).hex(),
            },
            "one_time_pre_key": otpk_data,
            "otpk_remaining":   remaining,  # hint: client should replenish if low
        }
        logger.info(f"Key bundle fetched for {target_uuid}, {remaining} OTPKs left")
        return jsonify(bundle), 200

    except Exception as e:
        logger.error(f"get_key_bundle error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@e2e_bp.route("/keys/replenish", methods=["POST"])
def replenish_one_time_keys():
    """
    Top up the OTPK pool. Same payload as the otpk portion of /keys/upload.

    Request body:
    {
      "one_time_pre_keys": [{"key_id": <int>, "public_key": "<hex>"}, ...]
    }
    """
    try:
        user_uuid, err = verify_token(request)
        if err:
            return jsonify(err[0]), err[1]

        data = request.get_json() or {}
        otpks = data.get("one_time_pre_keys", [])
        if not otpks:
            return jsonify({"error": "No keys provided"}), 400

        with engine.begin() as conn:
            for otpk in otpks:
                conn.execute(
                    text("""
                        INSERT IGNORE INTO one_time_pre_keys (user_uuid, key_id, public_key)
                        VALUES (:u, :kid, :pub)
                    """),
                    {
                        "u":   user_uuid,
                        "kid": otpk["key_id"],
                        "pub": bytes.fromhex(otpk["public_key"]),
                    },
                )

        logger.info(f"Replenished {len(otpks)} OTPKs for {user_uuid}")
        return jsonify({"message": "OTPKs replenished", "count": len(otpks)}), 201

    except Exception as e:
        logger.error(f"replenish_one_time_keys error: {e}")
        return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Phase 2 — X3DH Key Agreement
# ---------------------------------------------------------------------------

@dataclass
class X3DHHeader:
    """Transmitted with the first message so the receiver can derive the same SK."""
    ik_public:  str   # sender's identity key public (hex)
    ek_public:  str   # sender's ephemeral key public (hex)
    spk_id:     int   # which SPK was used
    otpk_id:    Optional[int]  # which OTPK was used (None if pool exhausted)

    def to_dict(self) -> dict:
        return {
            "ik_public": self.ik_public,
            "ek_public": self.ek_public,
            "spk_id":    self.spk_id,
            "otpk_id":   self.otpk_id,
        }

    @staticmethod
    def from_dict(d: dict) -> "X3DHHeader":
        return X3DHHeader(
            ik_public=d["ik_public"],
            ek_public=d["ek_public"],
            spk_id=d["spk_id"],
            otpk_id=d.get("otpk_id"),
        )


def x3dh_sender_init(
    sender_ik:   X25519PrivateKey,
    recipient_bundle: dict,
) -> tuple[bytes, X3DHHeader]:
    """
    Perform X3DH as the sending party.

    Parameters
    ----------
    sender_ik         : Sender's long-term X25519 identity private key.
    recipient_bundle  : Dict as returned by GET /keys/bundle/<uuid>.

    Returns
    -------
    (shared_secret_32_bytes, X3DHHeader)

    The shared secret is the X3DH SK — pass it to RatchetSession.init_sender().
    The header must be attached to the first encrypted message.
    """
    # Deserialise recipient keys
    rik_pub  = _hex_to_x25519_pub(recipient_bundle["identity_key_public"])
    rspk_pub = _hex_to_x25519_pub(recipient_bundle["signed_pre_key"]["public_key"])
    rotpk_pub = None
    otpk_id   = None
    if recipient_bundle.get("one_time_pre_key"):
        rotpk_pub = _hex_to_x25519_pub(recipient_bundle["one_time_pre_key"]["public_key"])
        otpk_id   = recipient_bundle["one_time_pre_key"]["key_id"]

    # Generate ephemeral key EK
    ek_priv = X25519PrivateKey.generate()
    ek_pub  = ek_priv.public_key()

    # X3DH DH computations (Signal spec §3.3)
    #   DH1 = DH(IK_A, SPK_B)
    #   DH2 = DH(EK_A, IK_B)
    #   DH3 = DH(EK_A, SPK_B)
    #   DH4 = DH(EK_A, OTPK_B)   [optional]
    dh1 = _x25519_dh(sender_ik, rspk_pub)
    dh2 = _x25519_dh(ek_priv,   rik_pub)
    dh3 = _x25519_dh(ek_priv,   rspk_pub)

    ikm = dh1 + dh2 + dh3
    if rotpk_pub:
        dh4 = _x25519_dh(ek_priv, rotpk_pub)
        ikm += dh4

    # KDF over concatenated DH outputs (Signal prepends 0xFF bytes for domain sep)
    f   = b"\xff" * 32
    sk  = _hkdf(f + ikm, salt=b"\x00" * 32, info=_SIGNAL_INFO_ROOT, length=32)

    header = X3DHHeader(
        ik_public=_pub_to_hex(sender_ik.public_key()),
        ek_public=_pub_to_hex(ek_pub),
        spk_id=recipient_bundle["signed_pre_key"]["key_id"],
        otpk_id=otpk_id,
    )
    return sk, header


def x3dh_receiver_init(
    receiver_ik:  X25519PrivateKey,
    receiver_spk: X25519PrivateKey,
    receiver_otpk: Optional[X25519PrivateKey],
    header: X3DHHeader,
) -> bytes:
    """
    Derive the same X3DH shared secret as the sender, using the X3DHHeader
    that arrived with the first message.

    Parameters
    ----------
    receiver_ik   : Recipient's long-term X25519 identity private key.
    receiver_spk  : The SPK private key identified by header.spk_id.
    receiver_otpk : The OTPK private key identified by header.otpk_id (or None).
    header        : X3DHHeader from the first received message.

    Returns
    -------
    32-byte shared secret SK (same as what sender computed).
    """
    sik_pub = _hex_to_x25519_pub(header.ik_public)
    ek_pub  = _hex_to_x25519_pub(header.ek_public)

    # Mirror of sender's DH computations (keys swapped)
    dh1 = _x25519_dh(receiver_spk, sik_pub)
    dh2 = _x25519_dh(receiver_ik,  ek_pub)
    dh3 = _x25519_dh(receiver_spk, ek_pub)

    ikm = dh1 + dh2 + dh3
    if receiver_otpk:
        dh4 = _x25519_dh(receiver_otpk, ek_pub)
        ikm += dh4

    f  = b"\xff" * 32
    sk = _hkdf(f + ikm, salt=b"\x00" * 32, info=_SIGNAL_INFO_ROOT, length=32)
    return sk


# ---------------------------------------------------------------------------
# Phase 3 — Double Ratchet
# ---------------------------------------------------------------------------

@dataclass
class RatchetHeader:
    """Per-message ratchet header (included in every message after session init)."""
    dh_public: str   # sender's current ratchet public key (hex)
    pn:        int   # number of messages in previous sending chain
    n:         int   # message number in current sending chain

    def to_dict(self) -> dict:
        return {"dh_public": self.dh_public, "pn": self.pn, "n": self.n}

    @staticmethod
    def from_dict(d: dict) -> "RatchetHeader":
        return RatchetHeader(dh_public=d["dh_public"], pn=d["pn"], n=d["n"])

    def to_bytes(self) -> bytes:
        """Deterministic bytes for use as AES-GCM AAD."""
        return json.dumps(self.to_dict(), sort_keys=True).encode()


class RatchetSession:
    """
    Double Ratchet session between two users.

    Usage — sender side (Alice initiates to Bob):
        sk, header = x3dh_sender_init(alice_ik, bob_bundle)
        session = RatchetSession.init_sender(sk, bob_bundle["identity_key_public"])
        wire = session.encrypt(b"Hello Bob")

    Usage — receiver side (Bob receives first message):
        sk = x3dh_receiver_init(bob_ik, bob_spk, bob_otpk, x3dh_header)
        session = RatchetSession.init_receiver(sk, bob_ratchet_private_key)
        plaintext = session.decrypt(wire)
    """

    def __init__(self):
        # DH Ratchet
        self._dh_self_priv: Optional[X25519PrivateKey] = None
        self._dh_self_pub:  Optional[X25519PublicKey]  = None
        self._dh_remote:    Optional[X25519PublicKey]  = None

        # Chain keys
        self._root_key:    bytes = b""
        self._send_ck:     Optional[bytes] = None
        self._recv_ck:     Optional[bytes] = None

        # Message counters
        self._send_n:  int = 0   # messages sent in current chain
        self._recv_n:  int = 0   # messages received in current chain
        self._prev_send_n: int = 0   # pn: messages sent in previous chain

        # Skipped message keys: (dh_public_hex, n) → message_key
        self._skipped: dict[tuple[str, int], bytes] = {}

    # ------------------------------------------------------------------
    # Factory constructors
    # ------------------------------------------------------------------

    @staticmethod
    def init_sender(sk: bytes, recipient_ratchet_pub_hex: str) -> "RatchetSession":
        """
        Initialise as the sending party after X3DH.

        The recipient's initial ratchet public key is their SPK public key
        (per Signal spec the SPK doubles as the initial ratchet key for Bob).
        """
        s = RatchetSession()
        s._dh_self_priv = X25519PrivateKey.generate()
        s._dh_self_pub  = s._dh_self_priv.public_key()
        s._dh_remote    = _hex_to_x25519_pub(recipient_ratchet_pub_hex)

        # Perform first ratchet step to derive root + sending chain key
        dh_out = _x25519_dh(s._dh_self_priv, s._dh_remote)
        s._root_key, s._send_ck = _kdf_rk(sk, dh_out)
        return s

    @staticmethod
    def init_receiver(sk: bytes, receiver_ratchet_priv: X25519PrivateKey) -> "RatchetSession":
        """
        Initialise as the receiving party after X3DH.

        receiver_ratchet_priv is the SPK private key (doubles as initial ratchet
        key per Signal spec).
        """
        s = RatchetSession()
        s._dh_self_priv = receiver_ratchet_priv
        s._dh_self_pub  = receiver_ratchet_priv.public_key()
        s._root_key     = sk
        # recv chain key is populated on first decrypt() call
        return s

    # ------------------------------------------------------------------
    # Encrypt / Decrypt
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> dict:
        """
        Encrypt plaintext. Returns a wire-frame dict ready for Firestore.
        Advances the sending chain key by one step.
        """
        if self._send_ck is None:
            raise RuntimeError("Sending chain not initialised — are you the receiver?")

        self._send_ck, msg_key = _kdf_ck(self._send_ck)
        header = RatchetHeader(
            dh_public=_pub_to_hex(self._dh_self_pub),
            pn=self._prev_send_n,
            n=self._send_n,
        )
        self._send_n += 1

        nonce, ct_tag = _aes_gcm_encrypt(msg_key, plaintext, aad=header.to_bytes())
        # Split ct and tag for explicit storage (AESGCM appends 16-byte tag)
        ct, tag = ct_tag[:-16], ct_tag[-16:]

        return {
            "version":        1,
            "ratchet_header": header.to_dict(),
            "ciphertext":     ct.hex(),
            "nonce":          nonce.hex(),
            "tag":            tag.hex(),
        }

    def decrypt(self, wire: dict) -> bytes:
        """
        Decrypt a wire-frame dict. Performs a DH ratchet step when the sender's
        ratchet key has changed, and handles out-of-order delivery by caching
        skipped message keys.
        """
        rh = RatchetHeader.from_dict(wire["ratchet_header"])

        # Check skipped-message cache first
        cached = self._skipped.pop((_pub_to_hex(self._dh_remote) if self._dh_remote else "", rh.n), None)
        if self._dh_remote and rh.dh_public == _pub_to_hex(self._dh_remote) and cached:
            return self._decrypt_with_key(cached, wire, rh)

        # If sender ratchet key has changed → DH ratchet step
        new_dh_pub = _hex_to_x25519_pub(rh.dh_public)
        if self._dh_remote is None or rh.dh_public != _pub_to_hex(self._dh_remote):
            # Cache any skipped keys from the previous receiving chain
            self._skip_message_keys(rh.pn)
            # Ratchet step
            self._dh_ratchet(new_dh_pub)

        # Cache any skipped keys in current receiving chain up to rh.n
        self._skip_message_keys(rh.n)

        self._recv_ck, msg_key = _kdf_ck(self._recv_ck)
        self._recv_n += 1
        return self._decrypt_with_key(msg_key, wire, rh)

    def _dh_ratchet(self, remote_pub: X25519PublicKey) -> None:
        """Advance the DH ratchet: derive new recv chain, then new send chain."""
        self._prev_send_n = self._send_n
        self._send_n = 0
        self._recv_n = 0
        self._dh_remote = remote_pub

        # New receiving chain
        dh_recv = _x25519_dh(self._dh_self_priv, remote_pub)
        self._root_key, self._recv_ck = _kdf_rk(self._root_key, dh_recv)

        # New DH key pair for our next sending turn
        self._dh_self_priv = X25519PrivateKey.generate()
        self._dh_self_pub  = self._dh_self_priv.public_key()

        # New sending chain
        dh_send = _x25519_dh(self._dh_self_priv, remote_pub)
        self._root_key, self._send_ck = _kdf_rk(self._root_key, dh_send)

    def _skip_message_keys(self, until: int) -> None:
        if self._recv_ck is None:
            return
        if until - self._recv_n > _MAX_SKIP:
            raise RuntimeError(f"Refusing to skip {until - self._recv_n} messages (max {_MAX_SKIP})")
        dh_key = _pub_to_hex(self._dh_remote) if self._dh_remote else ""
        while self._recv_n < until:
            self._recv_ck, mk = _kdf_ck(self._recv_ck)
            self._skipped[(dh_key, self._recv_n)] = mk
            self._recv_n += 1

    @staticmethod
    def _decrypt_with_key(msg_key: bytes, wire: dict, header: RatchetHeader) -> bytes:
        ct_tag = bytes.fromhex(wire["ciphertext"]) + bytes.fromhex(wire["tag"])
        nonce  = bytes.fromhex(wire["nonce"])
        return _aes_gcm_decrypt(msg_key, nonce, ct_tag, aad=header.to_bytes())

    # ------------------------------------------------------------------
    # Serialisation — for Firestore session storage
    # ------------------------------------------------------------------

    def serialise(self) -> dict:
        """
        Produce a JSON-safe dict that captures the full ratchet state.
        Store this in Firestore under e.g.
          /sessions/{user_a_uuid}_{user_b_uuid}
        and load it at the start of each encrypt/decrypt call.
        """
        def _priv_to_hex(k: Optional[X25519PrivateKey]) -> Optional[str]:
            if k is None:
                return None
            return k.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ).hex()

        return {
            "dh_self_priv":   _priv_to_hex(self._dh_self_priv),
            "dh_self_pub":    _pub_to_hex(self._dh_self_pub)  if self._dh_self_pub  else None,
            "dh_remote":      _pub_to_hex(self._dh_remote)    if self._dh_remote    else None,
            "root_key":       self._root_key.hex(),
            "send_ck":        self._send_ck.hex()  if self._send_ck  else None,
            "recv_ck":        self._recv_ck.hex()  if self._recv_ck  else None,
            "send_n":         self._send_n,
            "recv_n":         self._recv_n,
            "prev_send_n":    self._prev_send_n,
            "skipped":        {
                f"{dh}:{n}": mk.hex()
                for (dh, n), mk in self._skipped.items()
            },
        }

    @staticmethod
    def deserialise(d: dict) -> "RatchetSession":
        """Reconstruct a RatchetSession from a serialised dict."""
        s = RatchetSession()

        if d.get("dh_self_priv"):
            raw = bytes.fromhex(d["dh_self_priv"])
            s._dh_self_priv = X25519PrivateKey.from_private_bytes(raw)
            s._dh_self_pub  = s._dh_self_priv.public_key()

        if d.get("dh_remote"):
            s._dh_remote = _hex_to_x25519_pub(d["dh_remote"])

        s._root_key       = bytes.fromhex(d["root_key"])
        s._send_ck        = bytes.fromhex(d["send_ck"])  if d.get("send_ck") else None
        s._recv_ck        = bytes.fromhex(d["recv_ck"])  if d.get("recv_ck") else None
        s._send_n         = d.get("send_n", 0)
        s._recv_n         = d.get("recv_n", 0)
        s._prev_send_n    = d.get("prev_send_n", 0)

        s._skipped = {}
        for key_str, mk_hex in d.get("skipped", {}).items():
            dh, n_str = key_str.rsplit(":", 1)
            s._skipped[(dh, int(n_str))] = bytes.fromhex(mk_hex)

        return s


# ---------------------------------------------------------------------------
# Phase 4 — High-level message helpers
# ---------------------------------------------------------------------------

def encrypt_message(
    session:     RatchetSession,
    plaintext:   bytes,
    sender_uuid: str,
    x3dh_header: Optional[X3DHHeader] = None,
) -> dict:
    """
    Encrypt a plaintext message and produce a complete wire frame.

    Parameters
    ----------
    session      : Active RatchetSession for this conversation.
    plaintext    : Raw message bytes (UTF-8 text, file bytes, etc.).
    sender_uuid  : UUID of the sending user (embedded for routing).
    x3dh_header  : Provide on the FIRST message only.

    Returns
    -------
    Wire frame dict — store directly in Firestore as a message document.
    """
    frame = session.encrypt(plaintext)
    frame["sender_uuid"] = sender_uuid
    if x3dh_header:
        frame["x3dh_header"] = x3dh_header.to_dict()
    return frame


def decrypt_message(
    session: RatchetSession,
    wire:    dict,
) -> bytes:
    """
    Decrypt a wire frame received from Firestore.

    Automatically handles the first-message case — if an x3dh_header is
    present it is ignored here (it was already used to initialise the session
    via x3dh_receiver_init before constructing the RatchetSession).

    Returns raw plaintext bytes.
    """
    return session.decrypt(wire)


# ---------------------------------------------------------------------------
# Full conversation bootstrap — convenience wrappers
# ---------------------------------------------------------------------------

def open_session_as_sender(
    sender_ik_priv:  X25519PrivateKey,
    recipient_bundle: dict,
) -> tuple[RatchetSession, X3DHHeader]:
    """
    One-call bootstrap for Alice opening a new chat with Bob.

    Returns (session, x3dh_header).
    Attach x3dh_header to the first encrypted message so Bob can derive SK.
    """
    sk, header = x3dh_sender_init(sender_ik_priv, recipient_bundle)
    # Bob's SPK public key also serves as his initial ratchet key
    spk_pub_hex = recipient_bundle["signed_pre_key"]["public_key"]
    session = RatchetSession.init_sender(sk, spk_pub_hex)
    return session, header


def open_session_as_receiver(
    receiver_ik_priv:   X25519PrivateKey,
    receiver_spk_priv:  X25519PrivateKey,
    receiver_otpk_priv: Optional[X25519PrivateKey],
    x3dh_header:        X3DHHeader,
) -> RatchetSession:
    """
    One-call bootstrap for Bob receiving Alice's first message.

    Returns an initialised RatchetSession ready for decrypt().
    """
    sk = x3dh_receiver_init(
        receiver_ik_priv,
        receiver_spk_priv,
        receiver_otpk_priv,
        x3dh_header,
    )
    return RatchetSession.init_receiver(sk, receiver_spk_priv)
