
# DoubleRatchetKit

A Swift implementation of the **Double Ratchet Algorithm** with **Post-Quantum X3DH (PQXDH)** integration, providing asynchronous forward secrecy and post-compromise security for secure messaging applications.

[![Swift](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-macOS%2015%2B%20%7C%20iOS%2018%2B-blue.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

## 🌟 Features

- **🔐 Double Ratchet Protocol**: Implements the Signal protocol specification for secure messaging
- **⚡ Post-Quantum Security**: Hybrid PQXDH with Kyber1024 and Curve25519
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
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "1.0.0")
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
    pqKemPublicKey: alicePQKemPublicKey,
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
        pqKem: bobPQKemPublicKey
    ),
    localKeys: LocalKeys(
        longTerm: aliceLongTermPrivateKey,
        oneTime: aliceOneTimePrivateKey,
        pqKem: alicePQKemPrivateKey
    )
)
```

### 4. Initialize Receiving Session (Bob)

```swift
// Bob prepares to receive messages from Alice
try await ratchetManager.recipientInitialization(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: RemoteKeys(
        longTerm: aliceLongTermPublicKey,
        oneTime: aliceOneTimePublicKey,
        pqKem: alicePQKemPublicKey
    ),
    localKeys: LocalKeys(
        longTerm: bobLongTermPrivateKey,
        oneTime: bobOneTimePrivateKey,
        pqKem: bobPQKemPrivateKey
    )
)
```

### 5. Send and Receive Messages

```swift
// Alice encrypts a message
let plaintext = "Hello, Bob!".data(using: .utf8)!
let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: plaintext)

// Bob decrypts the message
let decryptedMessage = try await ratchetManager.ratchetDecrypt(encryptedMessage)
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

// Wrapper for Kyber1024 keys
let kyberPrivateKey = try PQKemPrivateKey(id: UUID(), kyber1024PrivateKey.rawRepresentation)
let kyberPublicKey = try PQKemPublicKey(id: UUID(), kyber1024PublicKey.rawRepresentation)
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
   - Hybrid key exchange using Curve25519 + Kyber1024
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
- **Hybrid PQXDH**: Combines classical (Curve25519) and post-quantum (Kyber1024) key exchange
- **Kyber1024**: OQS Kyber 1024 key encapsulation
- **Forward Secrecy**: Each message uses unique keys

### Metadata Protection
- **Header Encryption**: Encrypts message counters and key IDs
- **Traffic Analysis Resistance**: Hides message patterns
- **Skipped Message Support**: Handles out-of-order delivery

### Key Management
- **One-Time Keys**: Ephemeral keys for enhanced security
- **Automatic Rotation**: Keys change with every message
- **Compromise Recovery**: Post-compromise security guarantees

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
- `recipientInitialization(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)`
- `ratchetEncrypt(plainText:)`
- `ratchetDecrypt(_:)`
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
- **OQS Kyber**: Post-quantum cryptography standards
- **Swift Crypto**: Apple's cryptographic primitives
- **NeedleTail Organization**: Supporting libraries and tools

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/needletails/double-ratchet-kit/issues)
- **Documentation**: [API Reference](https://github.com/needletails/double-ratchet-kit)

---

**DoubleRatchetKit** - Secure messaging with post-quantum cryptography for the modern Swift ecosystem.
