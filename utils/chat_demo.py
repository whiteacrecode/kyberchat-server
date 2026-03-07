"""
chat_demo.py — KyberChat end-to-end messaging demo
===================================================
Full flow:
  1. Create user1 and user2 on the server.
  2. user1 sends a friend request; user2 accepts.
  3. Both users upload pre-key bundles (SPK + OTPKs) to the server.
  4. user1 fetches user2's key bundle, performs X3DH sender init,
     encrypts "Hello user 2", and hands the wire frame to user2.
  5. user2 performs X3DH receiver init from the wire frame, decrypts
     the message, then replies "Hello user 1".
  6. user1 decrypts the reply.
  7. Both parties print the plaintext they received.

Transport: in-memory (the Firestore relay is mocked by direct hand-off
           so the demo runs without GCP credentials).

Requirements (same as cloudrun):
  pip install requests cryptography
"""

import hashlib
import hmac as _hmac
import json
import os
import secrets
import sys
from dataclasses import dataclass, field
from typing import Optional

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Server base URL (mirrors cloudrun/user_utils.py)
# ---------------------------------------------------------------------------

BASE_URL: str = os.environ.get(
    "BASE_URL",
    "https://quantchat-server-1078066473760.us-central1.run.app",
).rstrip("/")


# ---------------------------------------------------------------------------
# Pure-crypto helpers  (extracted from cloudrun/e2e.py, no Flask/DB deps)
# ---------------------------------------------------------------------------

_SIGNAL_INFO_ROOT  = b"KyberChat_X3DH_RootKey_v1"
_SIGNAL_INFO_CHAIN = b"KyberChat_DR_ChainKey_v1"
_MAX_SKIP          = 1000


def _x25519_dh(priv: X25519PrivateKey, pub: X25519PublicKey) -> bytes:
    return priv.exchange(pub)


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _kdf_rk(rk: bytes, dh_out: bytes):
    out = _hkdf(dh_out, salt=rk, info=_SIGNAL_INFO_ROOT, length=64)
    return out[:32], out[32:]


def _kdf_ck(ck: bytes):
    new_ck  = _hmac.new(ck, b"\x02", hashlib.sha256).digest()
    msg_key = _hmac.new(ck, b"\x01", hashlib.sha256).digest()
    return new_ck, msg_key


def _aes_gcm_encrypt(key: bytes, pt: bytes, aad: bytes = b""):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, pt, aad)
    return nonce, ct


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)


def _pub_hex(key) -> str:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _x25519_pub_from_hex(h: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(bytes.fromhex(h))


# ── Key material dataclasses ─────────────────────────────────────────────────

@dataclass
class IdentityKeyPair:
    private_key: X25519PrivateKey
    public_key:  X25519PublicKey

    @staticmethod
    def generate():
        priv = X25519PrivateKey.generate()
        return IdentityKeyPair(priv, priv.public_key())

    def public_hex(self) -> str:
        return _pub_hex(self.public_key)


@dataclass
class SignedPreKey:
    key_id:      int
    private_key: X25519PrivateKey
    public_key:  X25519PublicKey
    signature:   bytes

    @staticmethod
    def generate(key_id: int, signing_key: Ed25519PrivateKey):
        priv = X25519PrivateKey.generate()
        pub  = priv.public_key()
        pub_bytes = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return SignedPreKey(key_id, priv, pub, signing_key.sign(pub_bytes))


@dataclass
class OneTimePreKey:
    key_id:      int
    private_key: X25519PrivateKey
    public_key:  X25519PublicKey

    @staticmethod
    def generate(key_id: int):
        priv = X25519PrivateKey.generate()
        return OneTimePreKey(key_id, priv, priv.public_key())


# ── X3DH ─────────────────────────────────────────────────────────────────────

@dataclass
class X3DHHeader:
    ik_public: str
    ek_public: str
    spk_id:    int
    otpk_id:   Optional[int]

    def to_dict(self):
        return {"ik_public": self.ik_public, "ek_public": self.ek_public,
                "spk_id": self.spk_id, "otpk_id": self.otpk_id}

    @staticmethod
    def from_dict(d):
        return X3DHHeader(d["ik_public"], d["ek_public"], d["spk_id"], d.get("otpk_id"))


def x3dh_sender_init(sender_ik: X25519PrivateKey, bundle: dict):
    rik_pub  = _x25519_pub_from_hex(bundle["identity_key_public"])
    rspk_pub = _x25519_pub_from_hex(bundle["signed_pre_key"]["public_key"])
    rotpk_pub, otpk_id = None, None
    if bundle.get("one_time_pre_key"):
        rotpk_pub = _x25519_pub_from_hex(bundle["one_time_pre_key"]["public_key"])
        otpk_id   = bundle["one_time_pre_key"]["key_id"]

    ek_priv = X25519PrivateKey.generate()
    ek_pub  = ek_priv.public_key()

    dh1 = _x25519_dh(sender_ik, rspk_pub)
    dh2 = _x25519_dh(ek_priv,   rik_pub)
    dh3 = _x25519_dh(ek_priv,   rspk_pub)
    ikm = dh1 + dh2 + dh3
    if rotpk_pub:
        ikm += _x25519_dh(ek_priv, rotpk_pub)

    sk = _hkdf(b"\xff" * 32 + ikm, salt=b"\x00" * 32, info=_SIGNAL_INFO_ROOT)
    header = X3DHHeader(_pub_hex(sender_ik.public_key()), _pub_hex(ek_pub),
                        bundle["signed_pre_key"]["key_id"], otpk_id)
    return sk, header


def x3dh_receiver_init(recv_ik: X25519PrivateKey, recv_spk: X25519PrivateKey,
                        recv_otpk: Optional[X25519PrivateKey], hdr: X3DHHeader) -> bytes:
    sik_pub = _x25519_pub_from_hex(hdr.ik_public)
    ek_pub  = _x25519_pub_from_hex(hdr.ek_public)

    dh1 = _x25519_dh(recv_spk, sik_pub)
    dh2 = _x25519_dh(recv_ik,  ek_pub)
    dh3 = _x25519_dh(recv_spk, ek_pub)
    ikm = dh1 + dh2 + dh3
    if recv_otpk:
        ikm += _x25519_dh(recv_otpk, ek_pub)

    return _hkdf(b"\xff" * 32 + ikm, salt=b"\x00" * 32, info=_SIGNAL_INFO_ROOT)


# ── Double Ratchet ────────────────────────────────────────────────────────────

class RatchetSession:
    def __init__(self):
        self._dh_self_priv = None
        self._dh_self_pub  = None
        self._dh_remote    = None
        self._root_key     = b""
        self._send_ck      = None
        self._recv_ck      = None
        self._send_n       = 0
        self._recv_n       = 0
        self._prev_send_n  = 0
        self._skipped: dict = {}

    @staticmethod
    def init_sender(sk: bytes, recipient_spk_pub_hex: str):
        s = RatchetSession()
        s._dh_self_priv = X25519PrivateKey.generate()
        s._dh_self_pub  = s._dh_self_priv.public_key()
        s._dh_remote    = _x25519_pub_from_hex(recipient_spk_pub_hex)
        dh_out = _x25519_dh(s._dh_self_priv, s._dh_remote)
        s._root_key, s._send_ck = _kdf_rk(sk, dh_out)
        return s

    @staticmethod
    def init_receiver(sk: bytes, receiver_spk_priv: X25519PrivateKey):
        s = RatchetSession()
        s._dh_self_priv = receiver_spk_priv
        s._dh_self_pub  = receiver_spk_priv.public_key()
        s._root_key     = sk
        return s

    def _ratchet_header(self) -> dict:
        return {"dh_public": _pub_hex(self._dh_self_pub),
                "pn": self._prev_send_n, "n": self._send_n}

    def _header_aad(self, h: dict) -> bytes:
        return json.dumps(h, sort_keys=True).encode()

    def encrypt(self, plaintext: bytes) -> dict:
        if self._send_ck is None:
            raise RuntimeError("Sending chain not initialised")
        self._send_ck, mk = _kdf_ck(self._send_ck)
        hdr = self._ratchet_header()
        self._send_n += 1
        nonce, ct_tag = _aes_gcm_encrypt(mk, plaintext, self._header_aad(hdr))
        ct, tag = ct_tag[:-16], ct_tag[-16:]
        return {"version": 1, "ratchet_header": hdr,
                "ciphertext": ct.hex(), "nonce": nonce.hex(), "tag": tag.hex()}

    def decrypt(self, wire: dict) -> bytes:
        rh = wire["ratchet_header"]
        new_dh_pub = _x25519_pub_from_hex(rh["dh_public"])
        if self._dh_remote is None or rh["dh_public"] != _pub_hex(self._dh_remote):
            self._skip_keys(rh["pn"])
            self._dh_ratchet(new_dh_pub)
        self._skip_keys(rh["n"])
        self._recv_ck, mk = _kdf_ck(self._recv_ck)
        self._recv_n += 1
        ct_tag = bytes.fromhex(wire["ciphertext"]) + bytes.fromhex(wire["tag"])
        return _aes_gcm_decrypt(mk, bytes.fromhex(wire["nonce"]), ct_tag, self._header_aad(rh))

    def _dh_ratchet(self, remote_pub: X25519PublicKey):
        self._prev_send_n = self._send_n
        self._send_n = self._recv_n = 0
        self._dh_remote = remote_pub
        dh_recv = _x25519_dh(self._dh_self_priv, remote_pub)
        self._root_key, self._recv_ck = _kdf_rk(self._root_key, dh_recv)
        self._dh_self_priv = X25519PrivateKey.generate()
        self._dh_self_pub  = self._dh_self_priv.public_key()
        dh_send = _x25519_dh(self._dh_self_priv, remote_pub)
        self._root_key, self._send_ck = _kdf_rk(self._root_key, dh_send)

    def _skip_keys(self, until: int):
        if self._recv_ck is None:
            return
        if until - self._recv_n > _MAX_SKIP:
            raise RuntimeError("Too many skipped messages")
        dh_key = _pub_hex(self._dh_remote) if self._dh_remote else ""
        while self._recv_n < until:
            self._recv_ck, mk = _kdf_ck(self._recv_ck)
            self._skipped[(dh_key, self._recv_n)] = mk
            self._recv_n += 1


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _post(path: str, payload: dict, token: Optional[str] = None) -> requests.Response:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(f"{BASE_URL}{path}", json=payload, headers=headers, timeout=15)


def _get(path: str, token: str) -> requests.Response:
    return requests.get(f"{BASE_URL}{path}",
                        headers={"Authorization": f"Bearer {token}"}, timeout=15)


def _ok(resp: requests.Response, ctx: str):
    if not resp.ok:
        raise RuntimeError(f"[{ctx}] HTTP {resp.status_code}: {resp.text}")
    return resp.json()


# ---------------------------------------------------------------------------
# High-level API calls
# ---------------------------------------------------------------------------

def create_user(username: str, password: str, ik: IdentityKeyPair) -> dict:
    uid = secrets.token_hex(16)[:8] + "-" + secrets.token_hex(4)
    import uuid as _uuid
    uid = str(_uuid.uuid4())
    payload = {
        "user_uuid":           uid,
        "username":            username,
        "password":            password,
        "identity_key_public": ik.public_hex(),
        "registration_id":     secrets.randbits(14) or 1,
    }
    body = _ok(_post("/create_user", payload), "create_user")
    return {"user_uuid": uid, "username": username, "password": password}


def login(user: dict) -> str:
    body = _ok(_post("/validate_login",
                     {"username": user["username"], "password": user["password"]}),
               "login")
    return body["token"]


def send_friend_request(token: str, target_username: str):
    return _ok(_post("/friends/request", {"username": target_username}, token=token),
               "friend_request")


def accept_friend(token: str, requester_uuid: str):
    return _ok(_post("/friends/accept", {"requester_uuid": requester_uuid}, token=token),
               "accept_friend")


def upload_pre_keys(token: str, ed_pub: Ed25519PrivateKey, spk: SignedPreKey,
                    otpks: list[OneTimePreKey]):
    payload = {
        "identity_key_ed25519_public": _pub_hex(ed_pub.public_key()),
        "signed_pre_key": {
            "key_id":    spk.key_id,
            "public_key": _pub_hex(spk.public_key),
            "signature":  spk.signature.hex(),
        },
        "one_time_pre_keys": [
            {"key_id": o.key_id, "public_key": _pub_hex(o.public_key)} for o in otpks
        ],
    }
    _ok(_post("/keys/upload", payload, token=token), "upload_pre_keys")


def fetch_bundle(token: str, target_uuid: str) -> dict:
    return _ok(_get(f"/keys/bundle/{target_uuid}", token), "fetch_bundle")


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main():
    suffix = secrets.token_hex(4)
    u1_name, u2_name = f"user1_{suffix}", f"user2_{suffix}"
    pw1, pw2 = "Alice@1234", "Bob@5678!"

    # ── Key material (generated client-side) ────────────────────────────────
    u1_ik   = IdentityKeyPair.generate()
    u1_ed   = Ed25519PrivateKey.generate()
    u1_spk  = SignedPreKey.generate(key_id=1, signing_key=u1_ed)
    u1_otpks = [OneTimePreKey.generate(i) for i in range(1, 6)]

    u2_ik   = IdentityKeyPair.generate()
    u2_ed   = Ed25519PrivateKey.generate()
    u2_spk  = SignedPreKey.generate(key_id=1, signing_key=u2_ed)
    u2_otpks = [OneTimePreKey.generate(i) for i in range(1, 6)]

    # ── 1. Create users ──────────────────────────────────────────────────────
    print(f"[+] Creating {u1_name} …")
    user1 = create_user(u1_name, pw1, u1_ik)
    print(f"    uuid = {user1['user_uuid']}")

    print(f"[+] Creating {u2_name} …")
    user2 = create_user(u2_name, pw2, u2_ik)
    print(f"    uuid = {user2['user_uuid']}")

    # ── 2. Login ─────────────────────────────────────────────────────────────
    print("[+] Logging in …")
    tok1 = login(user1)
    tok2 = login(user2)

    # ── 3. Friend request / accept ───────────────────────────────────────────
    print(f"[+] {u1_name} → friend request → {u2_name}")
    r = send_friend_request(tok1, u2_name)
    print(f"    {r}")

    print(f"[+] {u2_name} accepts")
    r = accept_friend(tok2, user1["user_uuid"])
    print(f"    {r}")

    # ── 4. Build local key bundles (server /keys/upload not yet deployed) ─────
    # Key bundles are constructed in-memory from the locally generated keys.
    # In production the server would store these and return them via /keys/bundle.
    print("[+] Building local key bundles (in-memory) …")

    def _make_bundle(uuid: str, ik: IdentityKeyPair, spk: SignedPreKey,
                     otpks: list[OneTimePreKey]) -> dict:
        otpk = otpks[0] if otpks else None
        return {
            "user_uuid":           uuid,
            "identity_key_public": ik.public_hex(),
            "signed_pre_key": {
                "key_id":    spk.key_id,
                "public_key": _pub_hex(spk.public_key),
                "signature":  spk.signature.hex(),
            },
            "one_time_pre_key": (
                {"key_id": otpk.key_id, "public_key": _pub_hex(otpk.public_key)}
                if otpk else None
            ),
        }

    u2_bundle = _make_bundle(user2["user_uuid"], u2_ik, u2_spk, u2_otpks)
    u1_bundle = _make_bundle(user1["user_uuid"], u1_ik, u1_spk, u1_otpks)

    # ── 5. user1 → user2 : "Hello user 2" ───────────────────────────────────
    print(f"\n[+] {u1_name} opens E2EE session with {u2_name} …")

    sk1, hdr1 = x3dh_sender_init(u1_ik.private_key, u2_bundle)

    sess_u1 = RatchetSession.init_sender(sk1, u2_bundle["signed_pre_key"]["public_key"])

    pt1 = b"Hello user 2"
    wire1 = sess_u1.encrypt(pt1)
    wire1["sender_uuid"]  = user1["user_uuid"]
    wire1["x3dh_header"]  = hdr1.to_dict()

    print(f"[>] {u1_name} sends:    \"{pt1.decode()}\"")
    print(f"    ciphertext (trunc): {wire1['ciphertext'][:32]}…")

    # ── 6. user2 receives + decrypts ─────────────────────────────────────────
    consumed = u2_bundle.get("one_time_pre_key") or {}
    otpk_priv2 = None
    if consumed:
        otpk_priv2 = next((o.private_key for o in u2_otpks if o.key_id == consumed["key_id"]), None)

    hdr_obj1 = X3DHHeader.from_dict(wire1["x3dh_header"])
    sk2 = x3dh_receiver_init(u2_ik.private_key, u2_spk.private_key, otpk_priv2, hdr_obj1)
    sess_u2_recv = RatchetSession.init_receiver(sk2, u2_spk.private_key)

    decrypted1 = sess_u2_recv.decrypt(wire1)
    print(f"[<] {u2_name} received: \"{decrypted1.decode()}\"")

    # ── 7. user2 → user1 : "Hello user 1" ───────────────────────────────────
    print(f"\n[+] {u2_name} opens E2EE session with {u1_name} …")
    sk3, hdr3 = x3dh_sender_init(u2_ik.private_key, u1_bundle)
    sess_u2_send = RatchetSession.init_sender(sk3, u1_bundle["signed_pre_key"]["public_key"])

    pt2 = b"Hello user 1"
    wire2 = sess_u2_send.encrypt(pt2)
    wire2["sender_uuid"]  = user2["user_uuid"]
    wire2["x3dh_header"]  = hdr3.to_dict()

    print(f"[>] {u2_name} sends:    \"{pt2.decode()}\"")
    print(f"    ciphertext (trunc): {wire2['ciphertext'][:32]}…")

    # ── 8. user1 receives + decrypts ─────────────────────────────────────────
    consumed2 = u1_bundle.get("one_time_pre_key") or {}
    otpk_priv1 = None
    if consumed2:
        otpk_priv1 = next((o.private_key for o in u1_otpks if o.key_id == consumed2["key_id"]), None)

    hdr_obj3 = X3DHHeader.from_dict(wire2["x3dh_header"])
    sk4 = x3dh_receiver_init(u1_ik.private_key, u1_spk.private_key, otpk_priv1, hdr_obj3)
    sess_u1_recv = RatchetSession.init_receiver(sk4, u1_spk.private_key)

    decrypted2 = sess_u1_recv.decrypt(wire2)
    print(f"[<] {u1_name} received: \"{decrypted2.decode()}\"")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("  Conversation (both sides decrypted successfully)")
    print("─" * 60)
    print(f"  {u1_name} → {u2_name}: \"{pt1.decode()}\"")
    print(f"  {u2_name} → {u1_name}: \"{pt2.decode()}\"")
    print("─" * 60)


if __name__ == "__main__":
    main()
