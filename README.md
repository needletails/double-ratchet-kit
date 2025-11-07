# DoubleRatchetKit

A Swift implementation of the **Double Ratchet Algorithm** with **Post-Quantum X3DH (PQXDH)** integration, providing asynchronous forward secrecy and post-compromise security for secure messaging applications.

[![Swift](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-macOS%2015%2B%20%7C%20iOS%2018%2B-blue.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

## 🌟 Features

- **🔐 Double Ratchet Protocol**: Implements the Signal protocol specification for secure messaging
- **⚡ Post-Quantum Security**: Hybrid PQXDH with MLKEM1024 and Curve25519
- **🔄 Forward Secrecy**: Message keys change with every message
- **🛡️ Post-Compromise Security**: Recovery from key compromise
- **📦 Header Encryption**: Protects metadata against traffic analysis
- **⏱️ Out-of-Order Support**: Handles skipped messages with key caching
- **🎯 Concurrency Safe**: Built with Swift actors for thread safety
- **📱 Modern Swift**: Requires Swift 6.1+ and supports macOS 15+ and iOS 18+

## 📋 Requirements

- **Swift**: 6.1 or later
- **Platforms**: macOS 15.0+, iOS 18.0+
- **Dependencies**: 
  - `swift-crypto` (3.12.3+)
  - `needletail-crypto` (1.1.1+)
  - `needletail-algorithms` (2.0.1+)
  - `needletail-logger` (3.0.0+)

## 🚀 Installation

### Swift Package Manager

Add DoubleRatchetKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "2.0.0")
]
```

Or add it directly in Xcode:
1. File → Add Package Dependencies
2. Enter the repository URL
3. Select the version you want to use

## 📖 Quick Start

### 1. Initialize the Ratchet State Manager

```swift
import DoubleRatchetKit
import NeedleTailLogger

// Create a serial executor for the actor
let executor = //Some Executor
let logger = NeedleTailLogger()

// Initialize the ratchet state manager
let ratchetManager = RatchetStateManager<SHA256>(
    executor: executor,
    logger: logger
)
```

### 2. Set Up Session Identities

```swift
// Create session identity for Alice
let aliceSessionId = UUID()
let aliceProps = SessionIdentity.UnwrappedProps(
    secretName: "alice_session",
    deviceId: UUID(),
    sessionContextId: 1,
    longTermPublicKey: aliceLongTermPublicKey,
    signingPublicKey: aliceSigningPublicKey,
    mlKEMPublicKey: aliceMLKEMPublicKey,
    oneTimePublicKey: aliceOneTimePublicKey,
    deviceName: "Alice's iPhone",
    isMasterDevice: true
)

let aliceSessionIdentity = try SessionIdentity(
    id: aliceSessionId,
    props: aliceProps,
    symmetricKey: sessionKey
)

// Create session identity for Bob (similar structure)
let bobSessionIdentity = try SessionIdentity(
    id: UUID(),
    props: bobProps,
    symmetricKey: sessionKey
)
```

### 3. Initialize Sending Session (Alice)

```swift
// Alice prepares to send messages to Bob
try await ratchetManager.senderInitialization(
    sessionIdentity: aliceSessionIdentity,
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
let firstMessage = try await ratchetManager.ratchetEncrypt(
    plainText: plaintext,
    sessionId: bobSessionIdentity.id
)

// Bob initializes his receiving state using the first header from Alice
try await ratchetManager.recipientInitialization(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    header: firstMessage.header,
    localKeys: LocalKeys(
        longTerm: bobLongTermPrivateKey,
        oneTime: bobOneTimePrivateKey,
        mlKEM: bobMLKEMPrivateKey
    )
)

// Bob decrypts the first message
let decryptedMessage = try await ratchetManager.ratchetDecrypt(
    firstMessage,
    sessionId: aliceSessionIdentity.id
)
let message = String(data: decryptedMessage, encoding: .utf8)!
print("Received: \(message)") // "Hello, Bob!"
```

### 6. Clean Up

```swift
// Always call shutdown when done
try await ratchetManager.shutdown()
```

## 🔧 Advanced Usage

### Session Identity Delegate

```swift
class MySessionDelegate: SessionIdentityDelegate {
    func updateSessionIdentity(_ identity: SessionIdentity) async throws {
        // Persist session identity to storage
        try await storage.save(identity)
    }
    
    func fetchOneTimePrivateKey(_ id: UUID?) async throws -> CurvePrivateKey? {
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
ratchetManager.setDelegate(MySessionDelegate())
```

### Key Management

Key Wrappers are used to Identify keys that the recipient needs to reference from it's own key store. For instance Alice uses Bob's one time key that is fetched from a remote server, Bob needs to know what key was used so Alice sends the identifier for Bob to look up in his own local key store.

```swift
// Wrapper for Curve25519 keys
let curvePrivateKey = try CurvePrivateKey(id: UUID(), curve25519PrivateKey.rawRepresentation)
let curvePublicKey = try CurvePublicKey(id: UUID(), curve25519PublicKey.rawRepresentation)

// Wrapper for MLKEM1024 keys
let kyberPrivateKey = try MLKEMPrivateKey(id: UUID(), MLKEM1024PrivateKey.rawRepresentation)
let kyberPublicKey = try MLKEMPublicKey(id: UUID(), MLKEM1024PublicKey.rawRepresentation)
```

## 🏗️ Architecture

### Core Components

- **`RatchetStateManager`**: Main actor managing the Double Ratchet protocol
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

## 🧭 2.0.0 Migration Guide

Version 2.0.0 introduces session‑explicit APIs and a header‑driven receive initialization. These are source‑breaking changes.

### What changed

- Receiving init is header‑based:
  - 1.x: `recipientInitialization(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)`
  - 2.0: `recipientInitialization(sessionIdentity:sessionSymmetricKey:header:localKeys:)`
- Encrypt/Decrypt require a `sessionId`:
  - 1.x: `ratchetEncrypt(plainText:)`, `ratchetDecrypt(_:)`
  - 2.0: `ratchetEncrypt(plainText:sessionId:)`, `ratchetDecrypt(_:sessionId:)`

### Why

- The receiver must bind state to the actual first header it sees (supports out‑of‑order and key rotation correctly).
- Explicit `sessionId` avoids ambiguity when multiple sessions are active.

### How to migrate

1) Replace receiving initialization to use the first message header:

```swift
// Before (1.x)
try await bobManager.recipientInitialization(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: bobRemoteKeysFromAlice,
    localKeys: bobLocalKeys
)

// After (2.0)
try await bobManager.recipientInitialization(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    header: firstMessageFromAlice.header,
    localKeys: bobLocalKeys
)
```

2) Pass `sessionId` to encrypt/decrypt:

```swift
// Before (1.x)
let msg = try await aliceManager.ratchetEncrypt(plainText: data)
let pt  = try await bobManager.ratchetDecrypt(msg)

// After (2.0)
let msg = try await aliceManager.ratchetEncrypt(plainText: data, sessionId: bobSessionIdentity.id)
let pt  = try await bobManager.ratchetDecrypt(msg, sessionId: aliceSessionIdentity.id)
```

3) Review error handling

- You may now encounter `RatchetError.missingConfiguration` if a `sessionId` is unknown.
- Decryption failures for corrupted payloads can surface as `CryptoKitError`.

### Notes

- No changes are required to `senderInitialization` signatures.
- If you manage multiple sessions, ensure you route the correct `sessionId` consistently.

## 🧪 Testing

```bash
# Run tests
swift test

# Run with verbose output
swift test --verbose
```

## 📚 API Reference

### Main Classes

#### `RatchetStateManager<Hash>`
- `senderInitialization(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)`
- `recipientInitialization(sessionIdentity:sessionSymmetricKey:header:localKeys:)`
- `ratchetEncrypt(plainText:sessionId:)`
- `ratchetDecrypt(_:sessionId:)`
- `shutdown()`

#### `SessionIdentity`
- `init(id:props:symmetricKey:)`
- `props(symmetricKey:)`
- `updateIdentityProps(symmetricKey:props:)`

#### `RatchetMessage`
- `header`: Encrypted metadata
- `encryptedData`: Encrypted message content

### Error Handling

```swift
do {
    let message = try await ratchetManager.ratchetEncrypt(plainText: data)
} catch RatchetError.stateUninitialized {
    // Handle uninitialized state
} catch RatchetError.encryptionFailed {
    // Handle encryption failure
} catch {
    // Handle other errors
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Signal Protocol**: Based on the Signal specification
- **ML‑KEM (Kyber)**: Post-quantum cryptography standard
- **Swift Crypto**: Apple's cryptographic primitives
- **NeedleTail Organization**: Supporting libraries and tools

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/needletails/double-ratchet-kit/issues)
- **Documentation**: [DocC Documentation](Sources/DoubleRatchetKit/Documentation.docc/Documentation.md)

---

**DoubleRatchetKit** - Secure messaging with post-quantum cryptography for the modern Swift ecosystem.
