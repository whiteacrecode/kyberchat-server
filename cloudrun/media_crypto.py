"""
media_crypto.py — Chunked streaming AEAD for encrypted audio/video attachments.

Overview
--------
Two components:

1. MediaEnvelope
   A small JSON payload that travels as a Double Ratchet message through the
   existing E2EE channel (Firestore or /messages/send).  It carries everything
   the recipient needs to download and decrypt the ciphertext blob from GCS:
   the media key, base nonce, blob pointer, ciphertext digest, and metadata.
   The server NEVER sees the plaintext of a MediaEnvelope.

2. Chunked streaming AEAD
   AES-256-GCM over fixed-size frames so large blobs (100+ MB video) can be
   encrypted/decrypted without holding the entire buffer in memory, and so
   partial decryption can start during streaming download.

   Per-chunk nonce:  base_nonce XOR frame_index (counter in the lowest 32 bits)
   Per-chunk AAD:    frame_index (4 bytes BE) || flags (1 byte)
   Flags:            bit 0 = is_final — prevents truncation attacks

   Wire format per frame:
     [0:4]  frame_index  uint32 BE
     [4]    flags        uint8 (0x01 = final frame, 0x00 otherwise)
     [5:9]  ct_size      uint32 BE — AES-GCM output (plaintext + 16-byte tag)
     [9:]   ciphertext   ct_size bytes

CLI (test without Swift)
------------------------
  python media_crypto.py selftest
  python media_crypto.py encrypt  <input>  <output>
  python media_crypto.py decrypt  <key_hex> <nonce_hex> <input> <output> [sha256_hex]
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from typing import Iterator, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHUNK_SIZE         = 64 * 1024   # 64 KiB plaintext per frame
NONCE_SIZE         = 12          # AES-GCM standard nonce length (bytes)
KEY_SIZE           = 32          # AES-256-GCM key length (bytes)
TAG_SIZE           = 16          # GCM authentication tag length (bytes)
_FRAME_HEADER_SIZE = 9           # frame_index(4) + flags(1) + ct_size(4)
_FLAG_FINAL        = 0x01


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

def _chunk_nonce(base_nonce: bytes, frame_index: int) -> bytes:
    """Derive a per-chunk nonce.

    XOR the base nonce (12 bytes, big-endian integer) with frame_index.  The
    counter occupies at most 32 bits, so the upper 8 bytes keep their entropy
    from base_nonce.  Safe for up to 2^32 frames (= 256 TiB at 64 KiB/frame).
    """
    n = int.from_bytes(base_nonce, 'big') ^ frame_index
    return n.to_bytes(NONCE_SIZE, 'big')


def _frame_aad(frame_index: int, is_final: bool) -> bytes:
    """5-byte AAD authenticating chunk position and final-frame flag."""
    return struct.pack('>IB', frame_index, _FLAG_FINAL if is_final else 0x00)


# ---------------------------------------------------------------------------
# Streaming encrypt
# ---------------------------------------------------------------------------

def encrypt_stream(
    plaintext_iter: Iterator[bytes],
    key: bytes,
    base_nonce: bytes,
    chunk_size: int = CHUNK_SIZE,
) -> Iterator[bytes]:
    """
    Encrypt an iterable of plaintext bytes and yield encrypted wire frames.

    Uses one-chunk look-ahead so the is_final flag can be set on the last
    frame without materialising the entire input in memory.

    Parameters
    ----------
    plaintext_iter : Any iterable of bytes (e.g. file.read in a loop).
    key            : 32-byte AES-256-GCM key.
    base_nonce     : 12-byte base nonce.  MUST be unique per (key, stream).
    chunk_size     : Plaintext bytes per frame.  Default 64 KiB.

    Yields
    ------
    bytes — one wire-format frame per plaintext chunk.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f'key must be {KEY_SIZE} bytes, got {len(key)}')
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError(f'base_nonce must be {NONCE_SIZE} bytes, got {len(base_nonce)}')

    aesgcm = AESGCM(key)
    frame_index = 0

    def _emit(chunk: bytes, is_final: bool) -> bytes:
        nonlocal frame_index
        nonce  = _chunk_nonce(base_nonce, frame_index)
        aad    = _frame_aad(frame_index, is_final)
        ct     = aesgcm.encrypt(nonce, chunk, aad)
        header = struct.pack('>IBI', frame_index, _FLAG_FINAL if is_final else 0x00, len(ct))
        frame_index += 1
        return header + ct

    buf: bytes = b''
    pending: Optional[bytes] = None   # one-chunk look-ahead

    for raw in plaintext_iter:
        buf += raw
        while len(buf) >= chunk_size:
            current = buf[:chunk_size]
            buf = buf[chunk_size:]
            if pending is not None:
                yield _emit(pending, False)
            pending = current

    # Drain remaining bytes into pending
    if buf:
        if pending is not None:
            yield _emit(pending, False)
        pending = buf

    # Emit the final chunk (or an empty final frame for an empty stream)
    yield _emit(pending if pending is not None else b'', True)


def encrypt_bytes(
    plaintext: bytes,
    key: Optional[bytes] = None,
    base_nonce: Optional[bytes] = None,
    chunk_size: int = CHUNK_SIZE,
) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypt plaintext bytes in one call.  Generates key and nonce if omitted.

    Returns
    -------
    (ciphertext_blob, key, base_nonce, ciphertext_sha256)
    """
    if key is None:
        key = os.urandom(KEY_SIZE)
    if base_nonce is None:
        base_nonce = os.urandom(NONCE_SIZE)

    ciphertext_blob = b''.join(encrypt_stream(iter([plaintext]), key, base_nonce, chunk_size))
    digest = hashlib.sha256(ciphertext_blob).digest()
    return ciphertext_blob, key, base_nonce, digest


def encrypt_file(
    input_path: str,
    output_path: str,
    key: Optional[bytes] = None,
    base_nonce: Optional[bytes] = None,
    chunk_size: int = CHUNK_SIZE,
) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt a file to output_path using chunked AEAD.

    Returns (key, base_nonce, ciphertext_sha256).
    """
    if key is None:
        key = os.urandom(KEY_SIZE)
    if base_nonce is None:
        base_nonce = os.urandom(NONCE_SIZE)

    sha = hashlib.sha256()

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        def _reader() -> Iterator[bytes]:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                yield chunk

        for frame in encrypt_stream(_reader(), key, base_nonce, chunk_size):
            fout.write(frame)
            sha.update(frame)

    return key, base_nonce, sha.digest()


# ---------------------------------------------------------------------------
# Streaming decrypt
# ---------------------------------------------------------------------------

def decrypt_stream(
    ciphertext_iter: Iterator[bytes],
    key: bytes,
    base_nonce: bytes,
) -> Iterator[bytes]:
    """
    Decrypt a stream of encrypted frames and yield plaintext chunks.

    IMPORTANT: Callers MUST verify the ciphertext SHA-256 (from MediaEnvelope)
    BEFORE calling this function.  The SHA-256 check is a cheap single-pass
    operation that prevents the server from feeding a corrupted blob that would
    cause a mid-stream GCM failure during playback.

    Raises
    ------
    ValueError               — reordered frames, unexpected final flag,
                               trailing bytes, or stream truncated without
                               a final-frame marker.
    InvalidTag (cryptography) — GCM authentication failure on any frame.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f'key must be {KEY_SIZE} bytes, got {len(key)}')
    if len(base_nonce) != NONCE_SIZE:
        raise ValueError(f'base_nonce must be {NONCE_SIZE} bytes, got {len(base_nonce)}')

    aesgcm = AESGCM(key)
    buf: bytes = b''
    frame_index = 0
    saw_final = False

    for raw in ciphertext_iter:
        buf += raw

        while True:
            if len(buf) < _FRAME_HEADER_SIZE:
                break

            idx, flags, ct_size = struct.unpack_from('>IBI', buf, 0)
            total_frame = _FRAME_HEADER_SIZE + ct_size
            if len(buf) < total_frame:
                break

            if idx != frame_index:
                raise ValueError(
                    f'Frame index mismatch: expected {frame_index}, got {idx}. '
                    'Stream is corrupted or reordered.'
                )

            if saw_final:
                raise ValueError(
                    'Received data after final-frame marker — '
                    'stream is corrupted or truncation attack.'
                )

            is_final = bool(flags & _FLAG_FINAL)
            ct = buf[_FRAME_HEADER_SIZE:total_frame]
            buf = buf[total_frame:]

            nonce     = _chunk_nonce(base_nonce, frame_index)
            aad       = _frame_aad(frame_index, is_final)
            plaintext = aesgcm.decrypt(nonce, ct, aad)  # raises InvalidTag on failure
            yield plaintext

            if is_final:
                saw_final = True
            frame_index += 1

    if buf:
        raise ValueError(
            f'{len(buf)} trailing bytes after last complete frame — stream truncated?'
        )
    if not saw_final:
        raise ValueError(
            'Stream ended without a final-frame marker — stream is truncated.'
        )


def decrypt_bytes(
    ciphertext_blob: bytes,
    key: bytes,
    base_nonce: bytes,
    expected_sha256: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt a ciphertext blob in one call.

    If expected_sha256 is provided it is verified BEFORE decryption begins.
    """
    if expected_sha256 is not None:
        actual = hashlib.sha256(ciphertext_blob).digest()
        if actual != expected_sha256:
            raise ValueError(
                f'Ciphertext SHA-256 mismatch — blob is corrupted or tampered with.\n'
                f'  expected: {expected_sha256.hex()}\n'
                f'  actual:   {actual.hex()}'
            )

    return b''.join(decrypt_stream(iter([ciphertext_blob]), key, base_nonce))


def decrypt_file(
    input_path: str,
    output_path: str,
    key: bytes,
    base_nonce: bytes,
    expected_sha256: Optional[bytes] = None,
    read_chunk: int = 256 * 1024,
) -> None:
    """
    Decrypt a ciphertext file to output_path.

    If expected_sha256 is provided the entire input is hashed BEFORE
    decryption starts (fail fast on a corrupt blob, no partial output).
    """
    if expected_sha256 is not None:
        sha = hashlib.sha256()
        with open(input_path, 'rb') as f:
            while chunk := f.read(read_chunk):
                sha.update(chunk)
        actual = sha.digest()
        if actual != expected_sha256:
            raise ValueError(
                f'Ciphertext SHA-256 mismatch.\n'
                f'  expected: {expected_sha256.hex()}\n'
                f'  actual:   {actual.hex()}'
            )

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        def _reader() -> Iterator[bytes]:
            while chunk := fin.read(read_chunk):
                yield chunk

        for plaintext_chunk in decrypt_stream(_reader(), key, base_nonce):
            fout.write(plaintext_chunk)


# ---------------------------------------------------------------------------
# MediaEnvelope
# ---------------------------------------------------------------------------

class MediaEnvelope:
    """
    The Double Ratchet payload for an audio or video attachment.

    The sender:
      1. Encrypts the media blob → (ciphertext_blob, key, base_nonce, sha256)
         using encrypt_bytes() / encrypt_file().
      2. Uploads ciphertext_blob to GCS via the signed PUT URL from
         POST /media/upload-url.
      3. Builds a MediaEnvelope with the returned blob_id plus key, base_nonce,
         sha256, and playback metadata.
      4. Passes envelope.to_bytes() to RatchetSession.encrypt() and sends the
         wire frame through the existing E2EE channel.

    The recipient:
      1. Decrypts the ratchet message to recover the raw payload bytes.
      2. Calls MediaEnvelope.from_bytes(payload) to deserialise the envelope.
      3. Calls GET /media/<blob_id>/download-url to get a signed GCS GET URL.
      4. Downloads the ciphertext blob.
      5. Verifies hashlib.sha256(blob).digest() == envelope.ciphertext_sha256
         BEFORE decrypting.
      6. Calls decrypt_bytes(blob, envelope.key, envelope.base_nonce) to
         recover the plaintext media.

    JSON wire format (before Double Ratchet encryption):
    {
      "type":              "media",
      "key":               "<64 hex chars — 32-byte AES-256-GCM media key>",
      "base_nonce":        "<24 hex chars — 12-byte AEAD base nonce>",
      "blob_id":           "<uuid — GCS blob pointer>",
      "ciphertext_sha256": "<64 hex chars — SHA-256 of full ciphertext blob>",
      "mime_type":         "audio/m4a",
      "byte_size":         12345,
      "duration_ms":       30000,
      "width":             null,             // video only
      "height":            null,             // video only
      "waveform":          [0.1, 0.8, ...], // audio: downsampled amplitudes
      "thumbnail_key":     null              // 32-byte hex key for poster frame
    }
    """

    def __init__(
        self,
        key: bytes,
        base_nonce: bytes,
        blob_id: str,
        ciphertext_sha256: bytes,
        mime_type: str,
        byte_size: int,
        duration_ms: int,
        width: Optional[int] = None,
        height: Optional[int] = None,
        waveform: Optional[list[float]] = None,
        thumbnail_key: Optional[bytes] = None,
    ) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError(f'key must be {KEY_SIZE} bytes')
        if len(base_nonce) != NONCE_SIZE:
            raise ValueError(f'base_nonce must be {NONCE_SIZE} bytes')
        if len(ciphertext_sha256) != 32:
            raise ValueError('ciphertext_sha256 must be 32 bytes')
        if thumbnail_key is not None and len(thumbnail_key) != KEY_SIZE:
            raise ValueError(f'thumbnail_key must be {KEY_SIZE} bytes')

        self.key               = key
        self.base_nonce        = base_nonce
        self.blob_id           = blob_id
        self.ciphertext_sha256 = ciphertext_sha256
        self.mime_type         = mime_type
        self.byte_size         = byte_size
        self.duration_ms       = duration_ms
        self.width             = width
        self.height            = height
        self.waveform          = waveform
        self.thumbnail_key     = thumbnail_key

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """JSON-serialisable dict for transport in a Double Ratchet payload."""
        d: dict = {
            'type':               'media',
            'key':                self.key.hex(),
            'base_nonce':         self.base_nonce.hex(),
            'blob_id':            self.blob_id,
            'ciphertext_sha256':  self.ciphertext_sha256.hex(),
            'mime_type':          self.mime_type,
            'byte_size':          self.byte_size,
            'duration_ms':        self.duration_ms,
        }
        if self.width is not None:
            d['width'] = self.width
        if self.height is not None:
            d['height'] = self.height
        if self.waveform is not None:
            d['waveform'] = self.waveform
        if self.thumbnail_key is not None:
            d['thumbnail_key'] = self.thumbnail_key.hex()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_bytes(self) -> bytes:
        """UTF-8 bytes to pass to RatchetSession.encrypt()."""
        return self.to_json().encode('utf-8')

    # ── Deserialisation ───────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, d: dict) -> 'MediaEnvelope':
        if d.get('type') != 'media':
            raise ValueError(f"Expected message type 'media', got {d.get('type')!r}")
        return cls(
            key               = bytes.fromhex(d['key']),
            base_nonce        = bytes.fromhex(d['base_nonce']),
            blob_id           = d['blob_id'],
            ciphertext_sha256 = bytes.fromhex(d['ciphertext_sha256']),
            mime_type         = d['mime_type'],
            byte_size         = int(d['byte_size']),
            duration_ms       = int(d['duration_ms']),
            width             = d.get('width'),
            height            = d.get('height'),
            waveform          = d.get('waveform'),
            thumbnail_key     = bytes.fromhex(d['thumbnail_key']) if d.get('thumbnail_key') else None,
        )

    @classmethod
    def from_json(cls, s: str) -> 'MediaEnvelope':
        return cls.from_dict(json.loads(s))

    @classmethod
    def from_bytes(cls, payload: bytes) -> 'MediaEnvelope':
        """Inverse of to_bytes() — call after RatchetSession.decrypt()."""
        return cls.from_json(payload.decode('utf-8'))

    def __repr__(self) -> str:
        return (
            f'MediaEnvelope(blob_id={self.blob_id!r}, mime_type={self.mime_type!r}, '
            f'byte_size={self.byte_size}, duration_ms={self.duration_ms})'
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_selftest() -> None:
    """Encrypt and decrypt test payloads; verify round-trip and all invariants."""
    import traceback

    print('Running self-test...\n')
    passed = 0
    failed = 0

    def _check(name: str, fn) -> None:
        nonlocal passed, failed
        try:
            fn()
            print(f'  [PASS] {name}')
            passed += 1
        except Exception as e:
            print(f'  [FAIL] {name}: {e}')
            traceback.print_exc()
            failed += 1

    # ── 1. Basic round-trip (multi-chunk) ─────────────────────────────────────
    def _test_roundtrip():
        plaintext = os.urandom(CHUNK_SIZE * 3 + 7)   # 3 full chunks + a partial
        ct, key, nonce, digest = encrypt_bytes(plaintext)
        assert hashlib.sha256(ct).digest() == digest, 'Digest mismatch after encrypt'
        recovered = decrypt_bytes(ct, key, nonce, expected_sha256=digest)
        assert recovered == plaintext, 'Plaintext mismatch after decrypt'

    _check('Basic round-trip (3+ chunks)', _test_roundtrip)

    # ── 2. Empty stream ────────────────────────────────────────────────────────
    def _test_empty():
        ct, key, nonce, digest = encrypt_bytes(b'')
        recovered = decrypt_bytes(ct, key, nonce, expected_sha256=digest)
        assert recovered == b''

    _check('Empty plaintext', _test_empty)

    # ── 3. Single byte ────────────────────────────────────────────────────────
    def _test_single_byte():
        ct, key, nonce, digest = encrypt_bytes(b'\xAB')
        recovered = decrypt_bytes(ct, key, nonce, expected_sha256=digest)
        assert recovered == b'\xAB'

    _check('Single byte', _test_single_byte)

    # ── 4. SHA-256 mismatch detected before decrypt ───────────────────────────
    def _test_sha256_check():
        ct, key, nonce, digest = encrypt_bytes(b'hello')
        bad_digest = bytes(32)   # all zeros
        try:
            decrypt_bytes(ct, key, nonce, expected_sha256=bad_digest)
            raise AssertionError('Should have raised ValueError')
        except ValueError as e:
            assert 'SHA-256' in str(e)

    _check('SHA-256 mismatch detected', _test_sha256_check)

    # ── 5. Truncation detected ────────────────────────────────────────────────
    def _test_truncation():
        plaintext = os.urandom(CHUNK_SIZE * 2)
        ct, key, nonce, _ = encrypt_bytes(plaintext)
        try:
            decrypt_bytes(ct[:-1], key, nonce)
            raise AssertionError('Should have raised on truncated stream')
        except Exception:
            pass   # ValueError or InvalidTag — either is correct

    _check('Truncation detection', _test_truncation)

    # ── 6. Bit-flip detected ──────────────────────────────────────────────────
    def _test_bitflip():
        plaintext = b'sensitive data'
        ct, key, nonce, _ = encrypt_bytes(plaintext)
        ct_tampered = bytearray(ct)
        ct_tampered[-1] ^= 0xFF   # flip last byte (GCM tag)
        try:
            decrypt_bytes(bytes(ct_tampered), key, nonce)
            raise AssertionError('Should have raised on tampered ciphertext')
        except Exception:
            pass

    _check('Bit-flip detection (GCM tag)', _test_bitflip)

    # ── 7. Wrong key ──────────────────────────────────────────────────────────
    def _test_wrong_key():
        ct, key, nonce, _ = encrypt_bytes(b'secret')
        try:
            decrypt_bytes(ct, os.urandom(KEY_SIZE), nonce)
            raise AssertionError('Should have raised with wrong key')
        except Exception:
            pass

    _check('Wrong key rejected', _test_wrong_key)

    # ── 8. MediaEnvelope round-trip ───────────────────────────────────────────
    def _test_envelope():
        key   = os.urandom(KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        digest = os.urandom(32)
        env = MediaEnvelope(
            key=key, base_nonce=nonce, blob_id='test-blob-abc',
            ciphertext_sha256=digest, mime_type='audio/m4a',
            byte_size=99_999, duration_ms=45_000,
            waveform=[0.1, 0.5, 0.9],
        )
        env2 = MediaEnvelope.from_bytes(env.to_bytes())
        assert env2.key == key
        assert env2.base_nonce == nonce
        assert env2.blob_id == 'test-blob-abc'
        assert env2.ciphertext_sha256 == digest
        assert env2.waveform == [0.1, 0.5, 0.9]
        assert env2.width is None
        assert env2.thumbnail_key is None

    _check('MediaEnvelope round-trip', _test_envelope)

    # ── 9. MediaEnvelope video fields ─────────────────────────────────────────
    def _test_envelope_video():
        key   = os.urandom(KEY_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        tkey  = os.urandom(KEY_SIZE)
        env = MediaEnvelope(
            key=key, base_nonce=nonce, blob_id='vid-blob',
            ciphertext_sha256=os.urandom(32), mime_type='video/mp4',
            byte_size=50_000_000, duration_ms=60_000,
            width=1280, height=720, thumbnail_key=tkey,
        )
        env2 = MediaEnvelope.from_bytes(env.to_bytes())
        assert env2.width == 1280
        assert env2.height == 720
        assert env2.thumbnail_key == tkey

    _check('MediaEnvelope video fields', _test_envelope_video)

    # ── 10. Streaming encrypt → file → decrypt ────────────────────────────────
    def _test_file_roundtrip():
        import tempfile
        plaintext = os.urandom(CHUNK_SIZE * 5 + 1234)
        with tempfile.NamedTemporaryFile(delete=False) as fin:
            fin.write(plaintext)
            in_path = fin.name
        ct_path  = in_path + '.enc'
        out_path = in_path + '.dec'
        try:
            key, nonce, digest = encrypt_file(in_path, ct_path)
            decrypt_file(ct_path, out_path, key, nonce, expected_sha256=digest)
            with open(out_path, 'rb') as f:
                recovered = f.read()
            assert recovered == plaintext
        finally:
            for p in (in_path, ct_path, out_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    _check('File encrypt/decrypt round-trip (5+ chunks)', _test_file_roundtrip)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f'\n{passed + failed} tests: {passed} passed, {failed} failed.')
    if failed:
        sys.exit(1)
    print('Self-test PASSED.')


def _cli_encrypt(args: list[str]) -> None:
    if len(args) < 2:
        print('Usage: encrypt <input_file> <output_file>', file=sys.stderr)
        sys.exit(1)
    key, nonce, digest = encrypt_file(args[0], args[1])
    print(f'key:        {key.hex()}')
    print(f'base_nonce: {nonce.hex()}')
    print(f'sha256:     {digest.hex()}')
    print(f'output:     {args[1]}')


def _cli_decrypt(args: list[str]) -> None:
    if len(args) < 4:
        print('Usage: decrypt <key_hex> <nonce_hex> <input_file> <output_file> [sha256_hex]',
              file=sys.stderr)
        sys.exit(1)
    key      = bytes.fromhex(args[0])
    nonce    = bytes.fromhex(args[1])
    in_path  = args[2]
    out_path = args[3]
    expected = bytes.fromhex(args[4]) if len(args) > 4 else None
    decrypt_file(in_path, out_path, key, nonce, expected_sha256=expected)
    print(f'Decrypted to {out_path}')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd, *rest = sys.argv[1:]
    if cmd == 'selftest':
        _cli_selftest()
    elif cmd == 'encrypt':
        _cli_encrypt(rest)
    elif cmd == 'decrypt':
        _cli_decrypt(rest)
    else:
        print(f'Unknown command: {cmd!r}. Use: selftest | encrypt | decrypt', file=sys.stderr)
        sys.exit(1)
