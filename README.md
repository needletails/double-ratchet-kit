# DoubleRatchetKit

A Swift implementation of the **Double Ratchet Algorithm** with **Post-Quantum X3DH (PQXDH)** integration, providing asynchronous forward secrecy and post-compromise security for secure messaging applications.

[![Swift](https://img.shields.io/badge/Swift-6.3+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-iOS%2018%2B%20%7C%20macOS%2015%2B%20%7C%20Linux%20%7C%20Android-blue.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-4.0.0-green.svg)](https://github.com/needletails/double-ratchet-kit/releases)

## 🎉 Version 4.0.0

DoubleRatchetKit 4.0.0 is a Swift API clean break with **the same ratchet
behavior, the same wire format, and the same identity blob**. On-disk coding
keys, SQLite columns, and `SessionIdentity.UnwrappedProps` fields `a`–`n` are
unchanged. App fields such as `deviceName` and `verifiedIdentity` stay on
`UnwrappedProps` until a later Post-Quantum Solace store migration.

The break is names, dead code, and accidental public surface — not crypto.

### What's New

- **🧭 Two façades**: `MessageRatchet` (`encrypt` / `decrypt`) and `KeyRatchet`
  (`nextSendKey` / `receiveKey(for:)`). Same engine, no runtime mode switch.
- **📦 Same identity blob**: `SessionIdentity(id:data:)` still reconstructs
  table `g`. Nested `RatchetState` remains Codable under props key `"h"`.
- **🔒 Tighter surface**: `RatchetState` is internal. Hosts and tests use
  `RatchetSessionStatus`. `_SessionIdentity` and `makeDecryptedModel` are gone.
- **🧪 Hash generic removed**: v4 KDFs stay hardcoded. A future hash change is
  a persisted suite marker (`Int`), not a generic. Missing marker → current
  suite; unknown marker → load failure.
- **🧹 Lifecycle**: idempotent `flushAndClose()`, no `deinit` crashes, `setDelegate`
  only, never-thrown `RatchetError` cases deleted.

> **Upgrading from 3.x?** This is a compile-time Swift break. Existing SQLite
> rows and nested encrypted blobs must still decode. See
> [4.0.0 Migration Guide](#-400-migration-guide). For 3.0 behavioral changes,
> see [3.0.0 Migration Guide](#-300-migration-guide). For the 1.x → 2.0 API
> break, see the [2.0.0 Migration Guide](#-200-migration-guide).

### What's New in 3.0.0 (previous major)

- **🔐 Payload AEAD binding**: `associatedData` is authenticated as AES-GCM AAD
  together with the encoded encrypted header.
- **🛡️ Deferred state persistence**: durable commits happen only after
  authenticated decrypt succeeds.
- **🔑 Safer one-time key consumption** and out-of-order hardening.

### What's New in 2.0.0 (previous major)

- **✨ Enhanced API Design**: Session-explicit APIs with `sessionId` parameters for multi-session support
- **🔧 Improved Error Handling**: Comprehensive error types with detailed documentation
- **📚 Complete Documentation**: Full DocC documentation with examples and best practices
- **🔐 Advanced Key Derivation**: `KeyRatchet` with `nextSendKey` and `receiveKey(for:)` for external encryption workflows
- **⚙️ Configuration Access**: `RatchetConfiguration` fields are now public for inspection
- **🛡️ OTK Consistency**: Optional strict one-time key validation with `enforceOTKConsistency`
- **🔄 Alternative Initialization**: New `respondToSession` overload in `KeyRatchet` for external key derivation workflows
- **📖 Lifecycle Documentation**: Clear documentation on initialization semantics and state management

## 🌟 Features

- **🔐 Double Ratchet Protocol**: Double Ratchet secure messaging with PQXDH key agreement
- **⚡ Post-Quantum Security**: Hybrid PQXDH with MLKEM1024 and Curve25519
- **🔄 Forward Secrecy**: Message keys change with every message
- **🛡️ Post-Compromise Security**: Recovery from key compromise
- **📦 Header Encryption**: Protects metadata against traffic analysis
- **⏱️ Out-of-Order Support**: Handles skipped messages with key caching
- **🎯 Concurrency Safe**: Built with Swift actors for thread safety
- **📱 Cross-Platform**: Supports macOS 15+, iOS 18+, Android, and Linux

## 📋 Requirements

- **Swift**: 6.3 or later
- **Platforms**: 
  - macOS 15.0+
  - iOS 18.0+
  - Android (via Swift for Android)
  - Linux (Ubuntu 20.04+, or other distributions with Swift 6.3+)
- **Dependencies**: 
  - `needletail-crypto` (1.3.0+)
  - `needletail-logger` (3.1.5+)
  - `binary-codable` (1.0.3+)

## 🚀 Installation

### Swift Package Manager

Add DoubleRatchetKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "4.0.0")
]
```

For version 3.x (previous major):
```swift
dependencies: [
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", "3.0.0"..<"4.0.0")
]
```

Or add it directly in Xcode:
1. File → Add Package Dependencies
2. Enter the repository URL
3. Select the version you want to use

## 📖 Quick Start

### 1. Initialize the Ratchet State Managers

```swift
import DoubleRatchetKit
import NeedleTailLogger

// Any SerialExecutor works (e.g. a DispatchQueue-backed executor).
// Each party (device) owns one manager; a manager serves many sessions.
let logger = NeedleTailLogger()
let aliceManager = MessageRatchet(executor: executor, logger: logger)
let bobManager = MessageRatchet(executor: executor, logger: logger)
```

### 2. Set Up Session Identities

A `SessionIdentity` describes the **peer lane**: its props hold the remote party's public keys, and its `id` is the `sessionId` used for `encrypt`/`decrypt`.

```swift
// On Alice's side: an identity describing Bob
let bobProps = SessionIdentity.UnwrappedProps(
    secretName: "bob_session",
    deviceId: UUID(),
    sessionContextId: 1,
    longTermPublicKey: bobLongTermPublicKey,
    signingPublicKey: bobSigningPublicKey,
    mlKEMPublicKey: bobMLKEMPublicKey,
    oneTimePublicKey: bobOneTimePublicKey,
    deviceName: "Bob's iPhone",
    isMasterDevice: true
)

let bobSessionIdentity = try SessionIdentity(
    id: UUID(),
    props: bobProps,
    symmetricKey: sessionKey
)

// On Bob's side: an identity describing Alice (same structure)
let aliceSessionIdentity = try SessionIdentity(
    id: UUID(),
    props: aliceProps,
    symmetricKey: sessionKey
)
```

### 3. Initialize Sending Session (Alice)

```swift
// Alice prepares to send messages to Bob
try await aliceManager.initiateSession(
    sessionIdentity: bobSessionIdentity,   // describes the peer (Bob)
    sessionSymmetricKey: sessionKey,
    remoteKeys: RemoteKeys(
        longTerm: bobLongTermPublicKey,
        oneTime: bobOneTimePublicKey,
        mlKEM: bobMLKEMPublicKey
    ),
    localKeys: LocalKeys(
        longTerm: aliceLongTermPrivateKey,
        oneTime: aliceOneTimePrivateKey,
        mlKEM: aliceMLKEMPrivateKey
    )
)
```

### 4. Send First Message (Alice) and Initialize Receiver (Bob)

```swift
// Alice encrypts the first message to Bob. The header bootstraps Bob's receiving ratchet.
let plaintext = "Hello, Bob!".data(using: .utf8)!
let firstMessage = try await aliceManager.encrypt(
    plainText: plaintext,
    sessionId: bobSessionIdentity.id
)

// Bob initializes his receiving state using the first header from Alice
try await bobManager.respondToSession(
    sessionIdentity: aliceSessionIdentity, // describes the peer (Alice)
    sessionSymmetricKey: sessionKey,
    header: firstMessage.header,
    localKeys: LocalKeys(
        longTerm: bobLongTermPrivateKey,
        oneTime: bobOneTimePrivateKey,
        mlKEM: bobMLKEMPrivateKey
    )
)

// Bob decrypts the first message
let decryptedMessage = try await bobManager.decrypt(
    firstMessage,
    sessionId: aliceSessionIdentity.id
)
let message = String(data: decryptedMessage, encoding: .utf8)!
print("Received: \(message)") // "Hello, Bob!"
```

### 5. Clean Up

```swift
// Always flush and close when done
try await aliceManager.flushAndClose()
try await bobManager.flushAndClose()
```

## 🔧 Advanced Usage

### Custom Configuration

```swift
// Create custom ratchet configuration
let customConfig = RatchetConfiguration(
    messageKeyData: Data([0x00]),
    chainKeyData: Data([0x01]),
    rootKeyData: Data([0x02, 0x03]),
    associatedData: "MyApp".data(using: .ascii)!,
    maxSkippedMessageKeys: 1000  // Reduce for memory-constrained environments
)

let ratchetManager = MessageRatchet(
    executor: executor,
    logger: logger,
    ratchetConfiguration: customConfig
)

// Inspect configuration
print("Max skipped keys: \(customConfig.maxSkippedMessageKeys)")
print("Associated data: \(customConfig.associatedData)")
```

`associatedData` is authenticated as AES-GCM associated data for payload
encryption, together with the encoded ratchet header.

### External Key Derivation

For advanced use cases where you need to handle encryption/decryption externally:

```swift
// Use KeyRatchet for external key derivation
let externalManager = KeyRatchet(executor: executor, logger: logger)
await externalManager.setDelegate(sessionDelegate)

// Derive message key for external encryption (sending)
let (messageKey, messageNumber) = try await externalManager.nextSendKey(sessionId: sessionId)
let encryptedData = try customEncrypt(plaintext, key: messageKey)

// Derive message key for external decryption (receiving)
let (messageKey, messageNumber) = try await externalManager.receiveKey(
    for: sessionId,
    cipherText: ciphertext
)
let plaintext = try customDecrypt(encryptedData, key: messageKey)
```

**⚠️ Warning:** These methods (`nextSendKey`, `receiveKey(for:)`, `sessionStatus`, `getCipherText`) are available in `KeyRatchet`, not `MessageRatchet`. They should **only be used when NOT encrypting/decrypting messages via `encrypt`/`decrypt`**. They are designed for external key derivation workflows. Do not mix the two façades on one session, as this may cause state inconsistencies and security issues.

### Alternative Recipient Initialization

For external key derivation workflows using `KeyRatchet`:

```swift
// Use KeyRatchet for external key derivation
let keyManager = KeyRatchet(executor: executor, logger: logger)

// Initialize receiver with keys and ciphertext (without full message)
try await keyManager.respondToSession(
    sessionIdentity: sessionIdentity,
    sessionSymmetricKey: sessionKey,
    localKeys: localKeys,
    remoteKeys: remoteKeys,
    ciphertext: mlKEMCiphertext
)
```

### OTK Consistency Enforcement

Enable strict one-time key validation:

```swift
// Enable strict validation in production
await ratchetManager.setEnforceOTKConsistency(true)

// This will fail fast if OTK is missing when header signals it
try await ratchetManager.decrypt(message, sessionId: sessionId)
```

### Session Identity Delegate

```swift
class MySessionDelegate: SessionIdentityDelegate {
    func updateSessionIdentity(_ identity: SessionIdentity) async throws {
        // Persist session identity to storage
        try await storage.save(identity)
    }
    
    func fetchOneTimePrivateKey(_ id: UUID?) async throws -> X25519PrivateKey? {
        // Retrieve one-time key from storage
        return try await storage.fetchOneTimeKey(id: id)
    }
    
    func updateOneTimeKey(remove id: UUID) async {
        // Remove used one-time key and generate new one
        await storage.removeOneTimeKey(id: id)
        await generateNewOneTimeKey()
    }
}

// Set the delegate
await ratchetManager.setDelegate(MySessionDelegate())
```

### Key Management

Key Wrappers are used to Identify keys that the recipient needs to reference from it's own key store. For instance Alice uses Bob's one time key that is fetched from a remote server, Bob needs to know what key was used so Alice sends the identifier for Bob to look up in his own local key store.

```swift
// Wrapper for Curve25519 keys
let curvePrivateKey = try X25519PrivateKey(id: UUID(), curve25519PrivateKey.rawRepresentation)
let curvePublicKey = try X25519PublicKey(id: UUID(), curve25519PublicKey.rawRepresentation)

// Wrapper for MLKEM1024 keys
let kemPrivateKey = try MLKEMPrivateKey(id: UUID(), mlKEM1024PrivateKey.encode())
let kemPublicKey = try MLKEMPublicKey(id: UUID(), mlKEM1024PublicKey.rawRepresentation)
```

## 🏗️ Architecture

### Core Components

- **`MessageRatchet`**: Main actor managing the Double Ratchet protocol for standard encryption/decryption workflows
- **`KeyRatchet`**: Actor for advanced external key derivation workflows (separate from standard API)
- **`RatchetState`**: Immutable state container for session data
- **`SessionIdentity`**: Encrypted session identity with cryptographic keys
- **`RemoteKeys`/`LocalKeys`**: Containers for public/private key pairs
- **`RatchetMessage`**: Encrypted message with header metadata

### Protocol Flow

1. **Initial Handshake (PQXDH)**:
   - Hybrid key exchange using Curve25519 + MLKEM1024
   - Derives root key and initial chain keys
   - Establishes header encryption keys

2. **Message Exchange**:
   - Symmetric key ratchet for each message
   - Header encryption protects metadata
   - Automatic key rotation and state management

3. **Key Rotation**:
   - Diffie-Hellman ratchet on key changes
   - Skipped message key management
   - Forward secrecy maintenance

## 🔒 Security Features

### Post-Quantum Security
- **Hybrid PQXDH**: Combines classical (Curve25519) and post-quantum (MLKEM1024) key exchange
- **MLKEM1024**: NIST ML-KEM (Kyber-1024) key encapsulation
- **Forward Secrecy**: Each message uses unique keys

### Metadata Protection
- **Header Encryption**: Encrypts message counters and key IDs
- **Traffic Analysis Resistance**: Hides message patterns
- **Skipped Message Support**: Handles out-of-order delivery

### Key Management
- **One-Time Keys**: Ephemeral keys for enhanced security
- **Automatic Rotation**: Keys change with every message
- **Compromise Recovery**: Post-compromise security guarantees

## 📚 Documentation

### DocC Documentation

Comprehensive documentation is available through DocC:

- **Getting Started**: Quick setup and basic usage
- **Key Concepts**: Understanding the Double Ratchet algorithm
- **Security Model**: Security properties and threat model
- **API Reference**: Complete API documentation
- **Best Practices**: Implementation guidelines
- **Performance**: Optimization strategies
- **Error Handling**: Error management patterns

To view the documentation:
1. Open the project in Xcode
2. Go to Product → Build Documentation
3. View the documentation in the Documentation Navigator

### API Reference

For detailed API documentation, see the [API Reference](https://github.com/needletails/double-ratchet-kit/blob/main/Sources/DoubleRatchetKit/Documentation.docc/APIReference.md) or build the DocC documentation in Xcode.

## 🧭 4.0.0 Migration Guide

Version 4.0.0 is a **Swift API clean break** with the same ratchet behavior,
the same wire format, and the same identity blob. Existing SQLite rows and
nested encrypted blobs must still decode. Compiling hosts must update names.

### Swift API

| 3.x | 4.0 |
|---|---|
| `DoubleRatchetStateManager` | `MessageRatchet` |
| `RatchetKeyStateManager` | `KeyRatchet` |
| `ratchetEncrypt` / `ratchetDecrypt` | `encrypt` / `decrypt` |
| `senderInitialization` / `recipientInitialization` | `initiateSession` / `respondToSession` |
| `deriveMessageKey` / `deriveReceivedMessageKey` | `nextSendKey` / `receiveKey(for:)` |
| `evictSessionConfiguration` | `discardCachedLane` |
| `shutdown()` | `flushAndClose()` |
| `getSentMessageNumber` / `getReceivedMessageNumber` | `sessionStatus(sessionId:)` |
| `CurvePublicKey` / `X25519PrivateKey` | `X25519PublicKey` / `X25519PrivateKey` |
| `KeyErrors` | `KeyError` |
| `RatchetMessage.encryptedData` | `RatchetMessage.ciphertext` (coding key `"b"` unchanged) |
| `updateIdentityProps` | `update(_:symmetricKey:)` |
| `props.state != nil` | `props.hasRatchetState` |

`RatchetState` is internal. Use `hasRatchetState` / `sessionStatus(sessionId:)`.
Do not reach into `UnwrappedProps.state` from a host module. Mutate `deviceName`
and `sessionContextId` on decoded props and `update` them — the snapshot rides
along. App fields on `UnwrappedProps` remain until a PQS store migration.

The `Hash` generic is gone. Header HKDF is hardcoded SHA-256 (production
today). A future hash change is a persisted suite marker, not a type parameter.

`@_exported` imports of `Crypto`, `NeedleTailCrypto`, `BinaryCodable`, and
`NeedleTailLogger` are removed. Import those modules yourself.

### Persistence (must not break)

- Table `g`: `id` TEXT PK, blob `a`. Reconstruct via `SessionIdentity(id:data:)`.
- Blob is AES-GCM of `UnwrappedProps` keys `a`–`n`. Nested `RatchetState` keys
  `a`–`z`, `A`–`G` (plus optional suite marker `"H"`).
- Pre-4.0 blobs without `"E"` / skipped-key `"f"` / suite `"H"` still load:
  initiator defaults `false`, untagged skipped keys are pruned, suite defaults
  to current. An unknown suite marker fails load.

### 📝 Migration Steps

```swift
dependencies: [
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "4.0.0")
]
```

PQS sources compile against this API; the PQS 4.0 rewrite is a separate change.

## 🧭 3.0.0 Migration Guide

Version 3.0.0 changes **persistence semantics** and **payload AEAD semantics**,
not public Swift signatures. Integrators upgrading from 2.x should retest
decrypt-failure, out-of-order recovery, and any queued ciphertext paths rather
than expecting a compile-time break.

### ⚠️ Behavioral Changes

1. **Failed decrypt no longer persists state**
   - **2.x**: Receiving keys, header indices, or skipped-key caches could advance
     (and be written via `updateSessionIdentity`) even when AEAD authentication failed.
   - **3.0.0**: State advances are held in memory until decrypt succeeds; the delegate
     is not called for failed attempts.

2. **One-time keys consumed only after success**
   - **2.x**: An initial-handshake decrypt failure could still remove the local OTK.
   - **3.0.0**: OTK removal happens only after authenticated decrypt.

3. **Corrupt out-of-order messages are dropped safely**
   - **2.x**: A bad gap-fill attempt could consume a stored skipped key.
   - **3.0.0**: The skipped key is retained; counters do not advance.

4. **Payload associated data is now cryptographically enforced**
   - **2.x**: `associatedData` was documented as AEAD context, but payload
     AES-GCM did not authenticate it (or the encoded header) in the tag.
   - **3.0.0**: Payload decrypt requires the exact `associatedData + encoded header`
     AAD. Pre-3.0.0 ciphertext may fail decrypt until sessions are reestablished.

### 🎯 Why These Changes?

- **Security**: A single corrupted or replayed frame must not brick a session or
  burn keys the peer still needs.
- **Layered recovery**: Lets upper layers (e.g. Post-Quantum Solace) retry,
  request resend, or reestablish without ratchet state having already moved on.
- **Deterministic persistence**: `SessionIdentityDelegate` callbacks now mean
  "durable state changed after a verified message," not "decrypt was attempted."

### 📝 Migration Steps

#### Step 1: Pin DoubleRatchetKit 3.0.0

```swift
dependencies: [
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "3.0.0")
]
```

Post-Quantum Solace 3.0.0 requires this release. Do not mix PQS 3.x with DRK 2.x.

#### Step 2: Retest failure and replay paths

Re-run integration tests where you previously observed:
- decrypt failures followed by successful resend of the same `sharedMessageId`
- out-of-order delivery with corrupt middle frames
- session reestablishment after `maxSkippedHeadersExceeded` or OTK mismatch

No source changes are required if you only call the public
`encrypt` / `decrypt` APIs (named `ratchetEncrypt` / `ratchetDecrypt` in 3.x).

#### Step 3: Audit custom delegate assumptions (if any)

If your `SessionIdentityDelegate` implementation assumed
`updateSessionIdentity` fires on every decrypt **attempt**, update that logic.
In 3.0.0 it fires only when durable ratchet state actually changes after success.

```swift
// ✅ Still correct — persist whatever identity the delegate receives
func updateSessionIdentity(_ identity: SessionIdentity) async throws {
    try await store.save(identity)
}
```

### ✅ Post-upgrade checklist

- [ ] `Package.swift` pins `from: "3.0.0"`
- [ ] If using Post-Quantum Solace, upgrade it to 3.0.0 in the same release
- [ ] Decrypt-failure → resend of the same `sharedMessageId` still succeeds
- [ ] Out-of-order delivery with a corrupt middle frame does not brick the session
- [ ] OTK mismatch / `maxSkippedHeadersExceeded` recovery paths retested
- [ ] `SessionIdentityDelegate` logic does not assume a callback per decrypt attempt

### 📌 Migration Notes

- ✅ **No** changes to encrypt / decrypt signatures in 3.0 (renamed in 4.0)
- ✅ **No** wire-format changes to `RatchetMessage` or `EncryptedHeader`
- ✅ **No** changes to `initiateSession` / `respondToSession` signatures
- ⚠️ On-disk ratchet snapshots taken under 2.x semantics may differ from 3.0.0
  evolution for sessions that were mid-recovery during upgrade — plan a clean
  reestablishment or retest active sessions after upgrading

## 🧭 2.0.0 Migration Guide

Version 2.0.0 introduces session‑explicit APIs and a header‑driven receive initialization. These are **source‑breaking changes** that require code updates.

### ⚠️ Breaking Changes

1. **Receiving initialization is now header-based:**
   - **1.x**: `respondToSession(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)`
   - **2.0**: `respondToSession(sessionIdentity:sessionSymmetricKey:header:localKeys:)`

2. **Encrypt/Decrypt require explicit `sessionId`:**
   - **1.x**: `ratchetEncrypt(plainText:)`, `ratchetDecrypt(_:)`
   - **2.0**: `ratchetEncrypt(plainText:sessionId:)`, `ratchetDecrypt(_:sessionId:)`

3. **Error handling updates:**
   - New error: `RatchetError.missingConfiguration` when `sessionId` is unknown
   - Enhanced error documentation and types

### 🎯 Why These Changes?

- **Header-based initialization**: The receiver must bind state to the actual first header it sees, supporting out‑of‑order delivery and key rotation correctly
- **Explicit `sessionId`**: Avoids ambiguity when multiple sessions are active and enables proper session management
- **Better error handling**: More specific errors help diagnose issues faster

### 📝 Migration Steps

#### Step 1: Update Receiving Initialization

```swift
// ❌ Before (1.x)
try await bobManager.respondToSession(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: bobRemoteKeysFromAlice,
    localKeys: bobLocalKeys
)

// ✅ After (2.0) - Standard approach
// First, receive the initial message from Alice
let firstMessage = // ... receive from network

try await bobManager.respondToSession(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    header: firstMessage.header,  // Use the actual header
    localKeys: bobLocalKeys
)

// ✅ Alternative (2.0) - For external key derivation (requires KeyRatchet)
let keyManager = KeyRatchet(executor: executor, logger: logger)
try await keyManager.respondToSession(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    localKeys: bobLocalKeys,
    remoteKeys: bobRemoteKeysFromAlice,
    ciphertext: mlKEMCiphertext
)
```

#### Step 2: Add `sessionId` to Encrypt/Decrypt

```swift
// ❌ Before (1.x)
let msg = try await aliceManager.encrypt(plainText: data)
let pt  = try await bobManager.decrypt(msg)

// ✅ After (2.0)
let msg = try await aliceManager.encrypt(
    plainText: data,
    sessionId: bobSessionIdentity.id  // Explicit session ID
)
let pt  = try await bobManager.decrypt(
    msg,
    sessionId: aliceSessionIdentity.id  // Explicit session ID
)
```

#### Step 3: Update Error Handling

```swift
// ✅ Enhanced error handling in 2.0
do {
    let message = try await ratchetManager.encrypt(
        plainText: data,
        sessionId: sessionId
    )
} catch RatchetError.missingConfiguration {
    // New error: Session not found
    // Ensure session is initialized first
} catch RatchetError.stateUninitialized {
    // Session exists but not initialized
} catch RatchetError.encryptionFailed {
    // Encryption operation failed
} catch {
    // Other errors
}
```

### ✨ New Features in 2.0.0

- **Advanced Key Derivation**: `KeyRatchet` for external encryption workflows
- **Alternative Initialization**: New `respondToSession` overload in `KeyRatchet` for external key derivation
- **OTK Consistency**: `setEnforceOTKConsistency(_:)` for strict one-time key validation
- **Configuration Access**: `RatchetConfiguration` fields are now public for inspection
- **Enhanced Logging**: `setLogLevel(_:)` for adjustable verbosity
- **Better Documentation**: Complete DocC documentation with examples

### 📌 Migration Notes

- ✅ No changes required to `initiateSession` signatures
- ✅ If managing multiple sessions, ensure correct `sessionId` routing
- ✅ Review error handling to catch new `missingConfiguration` error
- ✅ Consider using new advanced APIs for custom encryption workflows
- ✅ Update delegate implementations if using one-time key management

## 🧪 Testing

```bash
# Run tests
swift test

# Run with verbose output
swift test --verbose

# Run with code coverage (generates .build/coverage data for inspection)
swift test --enable-code-coverage
```

Test coverage is not enforced at 100%. To check coverage, run `swift test --enable-code-coverage` and inspect the generated coverage data (e.g. with `xcrun llvm-cov report` or Xcode). The suite includes re-synchronization scenarios: out-of-order delivery followed by subsequent sends to ensure both sides stay in sync (see `testResynchronizationAfterOutOfOrderSubsequentSends`, `testOutOfOrderThenBidirectionalFlowContinues`, `testLargeGapOutOfOrderThenResyncAndContinue`).

## 📚 API Reference

### Main Classes

#### `MessageRatchet`

**Initialization:**
- `init(executor:logger:ratchetConfiguration:)` - Create manager with optional custom configuration

**Session Management:**
- `initiateSession(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)` - Initialize sending session
- `respondToSession(sessionIdentity:sessionSymmetricKey:header:localKeys:)` - Initialize receiving session

**Message Operations:**
- `encrypt(plainText:sessionId:)` - Encrypt message
- `decrypt(_:sessionId:)` - Decrypt message
- `sessionStatus(sessionId:)` - Read-only sent/received counts and handshake phase
- `discardCachedLane(_:)` - Drop a cached in-memory lane after a rolled-back persist

**Configuration:**
- `setDelegate(_:)` - Set session identity delegate
- `setEnforceOTKConsistency(_:)` - Enable/disable strict OTK validation
- `setLogLevel(_:)` - Set logging verbosity
- `flushAndClose()` - Persist and close (idempotent)

**Properties:**
- `unownedExecutor: UnownedSerialExecutor` - Access to actor's executor

#### `KeyRatchet`

**Initialization:**
- `init(executor:logger:ratchetConfiguration:)` - Create manager with optional custom configuration

**Session Management:**
- `initiateSession(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)` - Initialize sending session
- `respondToSession(sessionIdentity:sessionSymmetricKey:localKeys:remoteKeys:ciphertext:)` - Initialize receiving session (for external key derivation)

**Advanced Key Derivation:**
- `nextSendKey(sessionId:)` - Derive key for external encryption (returns `(SymmetricKey, Int)`)
- `receiveKey(for:cipherText:)` - Derive key for external decryption (returns `(SymmetricKey, Int)`)
- `sessionStatus(sessionId:)` - Read-only sent/received counts and handshake phase
- `getCipherText(sessionId:)` - Get the PQXDH handshake ciphertext from session state

**⚠️ Warning:** These methods should **only be used when NOT encrypting/decrypting messages via `encrypt`/`decrypt`**. They are designed for external key derivation workflows. Do not mix these methods with the standard encryption/decryption API, as this may cause state inconsistencies and security issues.

**Configuration:**
- `setDelegate(_:)` - Set session identity delegate
- `setEnforceOTKConsistency(_:)` - Enable/disable strict OTK validation
- `setLogLevel(_:)` - Set logging verbosity
- `flushAndClose()` - Persist and close (idempotent)

**Properties:**
- `unownedExecutor: UnownedSerialExecutor` - Access to actor's executor

#### `SessionIdentity`
- `init(id:props:symmetricKey:)` - Create with properties
- `init(id:data:)` - Create from encrypted data
- `props(symmetricKey:)` - Get decrypted properties
- `decryptProps(symmetricKey:)` - Decrypt properties (throws)
- `update(_:symmetricKey:)` - Re-encrypt and store `UnwrappedProps` (keys `a`–`n`)

#### `RatchetMessage`
- `header: EncryptedHeader` - Encrypted metadata
- `ciphertext: Data` - Encrypted message content (coding key `"b"`)

#### `RatchetConfiguration`
- `messageKeyData: Data` - Data for message key derivation
- `chainKeyData: Data` - Data for chain key derivation
- `rootKeyData: Data` - Data for root key derivation
- `associatedData: Data` - Protocol context authenticated as payload AEAD associated data
- `maxSkippedMessageKeys: Int` - Maximum skipped keys to retain

### Error Handling

```swift
do {
    let message = try await ratchetManager.encrypt(
        plainText: data,
        sessionId: sessionId
    )
} catch RatchetError.missingConfiguration {
    // Session not found - check session ID
} catch RatchetError.stateUninitialized {
    // Session not initialized - call initialization methods
} catch RatchetError.encryptionFailed {
    // Encryption operation failed
} catch RatchetError.missingOneTimeKey {
    // One-time key missing (if OTK consistency is enforced)
} catch RatchetError.decryptionFailed {
    // Decryption operation failed
} catch RatchetError.headerDecryptFailed {
    // Header decryption failed
} catch RatchetError.expiredKey {
    // Message uses an expired key
} catch RatchetError.maxSkippedHeadersExceeded {
    // Too many messages were skipped
} catch {
    // Handle other errors
}
```

### Logging

```swift
// Set log level for debugging
await ratchetManager.setLogLevel(.debug)

// Available levels: .trace, .debug, .info, .warning, .error
// Default is .trace for maximum verbosity
```

### Version History

- **4.0.0** (Current): Swift API clean break — `MessageRatchet` / `KeyRatchet`
  facades, renamed methods (`encrypt` / `decrypt`, `initiateSession` /
  `respondToSession`, `nextSendKey` / `receiveKey(for:)`, `flushAndClose()`),
  `RatchetState` made internal (`RatchetSessionStatus` for hosts), dead error
  cases removed, `@_exported` imports removed. Same ratchet behavior, wire
  format, and identity blob as 3.0.0 — no database migration.
- **3.0.0**: Payload AEAD now authenticates `associatedData` and the
  encoded header; deferred ratchet state persistence until authenticated decrypt
  succeeds; OTK consumption and skipped-key handling hardened. Requires
  `needletail-crypto` 1.3.0+.
- **2.0.0**: Session-explicit `sessionId` APIs, header-driven receive
  initialization, external key derivation manager (now `KeyRatchet`),
  OTK consistency enforcement, and expanded DocC documentation.
- **1.x**: Initial Double Ratchet + PQXDH implementation.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Double Ratchet**: Public Double Ratchet algorithm specification
- **ML‑KEM (Kyber)**: Post-quantum cryptography standard
- **Swift Crypto**: Apple's cryptographic primitives
- **NeedleTail Organization**: Supporting libraries and tools

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/needletails/double-ratchet-kit/issues)
- **Documentation**: [DocC Documentation](Sources/DoubleRatchetKit/Documentation.docc/Documentation.md)

---

**DoubleRatchetKit** - Secure messaging with post-quantum cryptography for the modern Swift ecosystem.
