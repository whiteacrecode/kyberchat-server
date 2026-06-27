# CLAUDE.md — kyberchat-ios

Context and working notes for Claude Code operating in the KyberChat iOS client.

## Project overview

KyberChat is a Signal-Protocol-based end-to-end encrypted messaging app.

- **Client:** SwiftUI (iOS 16+), this repo (`kyberchat-ios`).
- **Server:** `kyberchat-server` — Python on Google Cloud Run, Firestore for persistence.
- **Crypto stack:** X3DH key agreement + Double Ratchet messaging, AES-256-GCM,
  Firestore-compatible serialization (see `e2e.py` in the server repo).
- **Org:** `whiteacrellc` on GitHub.

### Conventions / constraints

- The Double Ratchet path is for **small payloads only**. Never route bulk media
  bytes through a ratchet message.
- Firestore must only ever hold **ciphertext** and non-sensitive metadata. Plaintext
  and media keys never touch the server.
- The Cloud Run container has restricted egress; prefer client → GCS direct transfers
  over signed URLs rather than proxying large bytes through the backend.

---

## Planned feature: Audio & Video Messaging (async clips)

Scope: **asynchronous A/V clips** — record, encrypt, send, recipient plays later.
(Live real-time A/V calls are a separate, larger effort — see "Out of scope" below.)

### Core design: separate the key from the blob

Mirror Signal's attachment model. Do **not** stuff media into the ratchet.

1. Generate a fresh random **media key** (AES-256-GCM) per attachment, client-side.
2. Encrypt the media blob locally with that key.
3. Upload only **ciphertext** to blob storage (GCS). Server never sees plaintext or key.
4. Send a **MediaEnvelope** (media key + IV + blob pointer + ciphertext digest +
   metadata) as a normal Double Ratchet message through the existing E2EE channel.
5. Recipient decrypts the envelope, downloads ciphertext from GCS, verifies the
   digest, decrypts, and plays.

Result: the X3DH / Double Ratchet text path is unchanged. The small key envelope
rides the ratchet (inheriting forward secrecy); bulk bytes go out-of-band.

### MediaEnvelope (travels as a ratchet message)

```
MediaEnvelope {
  key:              [u8; 32]   // AES-256-GCM media key
  iv:               [u8]       // base nonce
  blobId:           String     // GCS object pointer
  ciphertextSHA256: [u8; 32]   // verify BEFORE decrypting (cheap DoS guard)
  mime:             String
  byteSize:         Int
  durationMs:       Int
  width, height:    Int?       // video only
  waveform:         [Float]?   // audio UI
  thumbnailKey:     [u8; 32]?  // encrypted poster frame
}
```

- AES-256-GCM tag provides authenticity; the whole-ciphertext SHA-256 lets the
  recipient verify integrity before spending effort on decryption.
- Keep serialization Firestore-compatible with the existing `e2e.py` envelope
  discipline — this is a new message subtype, not a new format.

### Large media: chunked streaming AEAD

Do not single-shot GCM a 100MB buffer in memory. Use fixed-size frames with
per-chunk nonces (base nonce + counter) and a final-chunk flag to prevent
truncation attacks. This enables resumable uploads and streaming playback.

---

## Implementation phases

### Phase 1 — Server: encrypted blob transport (`kyberchat-server`)
- GCS bucket for ciphertext blobs.
- `POST /media/upload-url` → signed PUT + `blobId`.
- `GET /media/{blobId}/download-url` → signed GET. Authorize via existing session/auth.
- Firestore message doc gains: type (`audio` | `video`), `blobId`, ciphertext size,
  pre-download metadata. Media key stays in the ratchet payload, never here.
- Lifecycle: size caps, blob TTL/expiry, orphaned-blob sweeper, per-user rate limits.
  Wire blob deletion to message expiry if disappearing messages exist.

### Phase 2 — Crypto envelope (shared)
- Define `MediaEnvelope` and chunked streaming AEAD framing.
- Pin ciphertext SHA-256; verify before decrypt.
- Testable from a CLI before any Swift is written.

### Phase 3 — iOS capture & encode
- **Audio:** `AVAudioRecorder` → AAC/Opus `.m4a`; generate downsampled waveform at
  record time.
- **Video:** `PHPickerViewController` (pick) or `AVCaptureSession` (in-app record) →
  transcode/downscale via `AVAssetExportSession` (H.264/HEVC); extract encrypted
  poster-frame thumbnail.
- Encrypt with CryptoKit `AES.GCM` (chunked) → upload ciphertext to signed URL →
  send `MediaEnvelope` through the ratchet.
- `Info.plist`: `NSMicrophoneUsageDescription`, `NSCameraUsageDescription`,
  photo-library usage keys.

### Phase 4 — iOS playback (keep plaintext off disk)
- Receive envelope → download ciphertext → verify digest → decrypt.
- Preferred: stream-decrypt via `AVAssetResourceLoaderDelegate` so AVPlayer pulls
  decrypted frames on demand; plaintext never persists.
- v1 fallback: decrypt to a temp file in a protected app-group container; shred on
  dismiss.
- UI: audio bubble with waveform + scrubber; video bubble with thumbnail → tap-to-play.

### Phase 5 — Hardening
- Push notifications must not leak content — send content-available nudge, fetch and
  render the envelope locally.
- Background upload/download via `URLSession` background config; resumable retries.
- Max durations/sizes, cancel mid-record, interrupted-upload recovery.
- Clear failed-decrypt state; accessibility considerations.

### Suggested order
Phase 1 + 2 unlock everything and are CLI-testable before touching Swift. Ship
**audio before video** (smaller, exercises the full pipeline end-to-end); video
reuses the identical envelope + transport.

---

## Out of scope (separate effort)

**Live real-time A/V calls.** This is WebRTC with DTLS-SRTP. True E2EE there —
especially group/SFU — requires frame-level encryption with keys derived from the
Signal session via insertable streams. Different and much larger battle; not covered
by the plan above.

## Security reminders
- Rotate the previously-exposed GitHub PAT.
- Never log media keys, plaintext, or decrypted buffers.
- Treat every blob pointer and signed URL as capability-bearing; scope and expire them.
