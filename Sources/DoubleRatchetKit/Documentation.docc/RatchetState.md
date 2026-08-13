# RatchetState

Internal Codable snapshot of a Double Ratchet lane. Nested in `SessionIdentity.UnwrappedProps` under coding key `"h"`. Hosts should use `RatchetSessionStatus` instead of reading this type.

## Overview

`RatchetState` encapsulates all the cryptographic state needed for the Double Ratchet algorithm: PQXDH identity key material, the root key, sending/receiving chain keys, header keys, message counters, skipped message keys, and the per-turn hybrid ratchet keys. The struct is immutable — every mutation returns a new value — ensuring thread safety and preventing accidental state corruption.

In 4.0 the type is **internal**. It remains `Codable` because it is the persisted heart of a session, but hosts never construct, read, or mutate it directly. The engine loads it from the encrypted identity blob, advances it, and persists it back at authenticated success points.

## Declaration

```swift
struct RatchetState: Sendable, Codable  // internal in 4.0; hosts use RatchetSessionStatus
```

## What It Contains

Conceptually, a snapshot holds:

- **Identity key material** — local private and remote public keys for the PQXDH handshake (long-term, optional one-time, ML-KEM)
- **Root key** — advanced by two KDF steps on every DH ratchet (epoch)
- **Chain keys** — separate sending and receiving chains, advanced per message
- **Header keys** — current and next keys for encrypted headers
- **Counters** — sent, received, and previous-chain message counts
- **Skipped message keys** — a bounded list for out-of-order delivery, each entry tagged with the ratchet chain it was derived from
- **Per-turn hybrid ratchet keys** — Curve25519 and ML-KEM-1024 ratchet key pairs plus the KEM ciphertext for the current sending chain
- **Suite marker** — records the v4 KDF suite (HKDF-SHA512 root, HMAC-SHA256 chain/message, HKDF-SHA256 header)

## Persistence Contract (must not break)

The snapshot is what makes existing databases work across releases:

- Encoded with single-character coding keys `"a"`–`"z"`, `"A"`–`"G"`, plus the optional suite marker `"H"`. These keys are **frozen**; renaming a Swift property never changes its coding key.
- Stored inside the AES-GCM-encrypted `UnwrappedProps` blob (coding key `"h"`), which lives in the SQLite `SessionIdentity` row.
- Decoding is lenient toward pre-4.0 blobs:
  - a missing initiator flag (`"E"`) defaults to `false`
  - skipped-key entries without the chain tag (`"f"`) are pruned on load — they cannot match a v4 frame
  - a missing suite marker (`"H"`) is treated as the current suite
- An **unknown** suite marker fails the load loudly instead of silently mis-deriving keys.
- Blobs written by 4.0 remain readable by 3.0 binaries: the decoder ignores unknown keys, so the added `"H"` entry is skipped on rollback.

This is why 3.0.0 conformers upgrade to 4.0 with **no database migration**.

## What Hosts Use Instead

Read-only session progress is exposed through `RatchetSessionStatus`:

```swift
public struct RatchetSessionStatus: Sendable, Equatable {
    public let sentMessagesCount: Int
    public let receivedMessagesCount: Int
    public let sendingHandshakeFinished: Bool
    public let receivingHandshakeFinished: Bool
}

let status = try await ratchetManager.sessionStatus(sessionId: sessionId)
if status.sendingHandshakeFinished, status.receivedMessagesCount == 0 {
    // The peer has never answered on this lane.
}
```

For persistence, implement `SessionIdentityDelegate.updateSessionIdentity(_:)` and store the opaque `SessionIdentity.data` blob; the ratchet state rides inside it untouched.

## Design Notes

- **Immutability**: every update produces a new snapshot, so a failed decrypt can simply discard its working copy — durable state advances only after authenticated success.
- **Bounded caches**: skipped message keys are capped by `maxSkippedMessageKeys`, and already-decrypted message numbers are tracked to reject replays without unbounded growth.
- **Chain-tagged skipped keys**: each skipped key remembers which ratchet chain produced it, so late arrivals from an old chain cannot be confused with the current one.

## Related Documentation

- <doc:UsingMessageRatchet> for the main actor managing ratchet state
- <doc:UsingSessionIdentity> for session identity management
- <doc:KeyManagement> for key management operations
