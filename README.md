# DoubleRatchetKit

A Swift implementation of the **Double Ratchet Algorithm** with **Post-Quantum X3DH (PQXDH)** integration, providing asynchronous forward secrecy and post-compromise security for secure messaging applications.

[![Swift](https://img.shields.io/badge/Swift-6.1+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/Platform-iOS%2018%2B%20%7C%20macOS%2015%2B%20%7C%20Linux%20%7C%20Android-blue.svg)](https://developer.apple.com)
[![License](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0.0-green.svg)](https://github.com/needletails/double-ratchet-kit/releases)

## 🎉 Version 2.0.0

DoubleRatchetKit 2.0.0 is a major release with significant API improvements, enhanced documentation, and better error handling.

### What's New

- **✨ Enhanced API Design**: Session-explicit APIs with `sessionId` parameters for multi-session support
- **🔧 Improved Error Handling**: Comprehensive error types with detailed documentation
- **📚 Complete Documentation**: Full DocC documentation with examples and best practices
- **🔐 Advanced Key Derivation**: New `RatchetKeyStateManager` with `deriveMessageKey` and `deriveReceivedMessageKey` methods for external encryption workflows
- **⚙️ Configuration Access**: `RatchetConfiguration` fields are now public for inspection
- **🛡️ OTK Consistency**: Optional strict one-time key validation with `enforceOTKConsistency`
- **🔄 Alternative Initialization**: New `recipientInitialization` overload in `RatchetKeyStateManager` for external key derivation workflows
- **📖 Lifecycle Documentation**: Clear documentation on initialization semantics and state management

## 🌟 Features

- **🔐 Double Ratchet Protocol**: Implements the Signal protocol specification for secure messaging
- **⚡ Post-Quantum Security**: Hybrid PQXDH with MLKEM1024 and Curve25519
- **🔄 Forward Secrecy**: Message keys change with every message
- **🛡️ Post-Compromise Security**: Recovery from key compromise
- **📦 Header Encryption**: Protects metadata against traffic analysis
- **⏱️ Out-of-Order Support**: Handles skipped messages with key caching
- **🎯 Concurrency Safe**: Built with Swift actors for thread safety
- **📱 Cross-Platform**: Supports macOS 15+, iOS 18+, Android, and Linux

## 📋 Requirements

- **Swift**: 6.1 or later
- **Platforms**: 
  - macOS 15.0+
  - iOS 18.0+
  - Android (via Swift for Android)
  - Linux (Ubuntu 20.04+, or other distributions with Swift 6.1+)
- **Dependencies**: 
  - `needletail-crypto` (1.2.1+)
  - `needletail-logger` (3.1.1+)
  - `binary-codable` (1.0.3+)

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
let ratchetManager = DoubleRatchetStateManager<SHA256>(
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

let ratchetManager = DoubleRatchetStateManager<SHA256>(
    executor: executor,
    logger: logger,
    ratchetConfiguration: customConfig
)

// Inspect configuration
print("Max skipped keys: \(customConfig.maxSkippedMessageKeys)")
print("Associated data: \(customConfig.associatedData)")
```

### External Key Derivation

For advanced use cases where you need to handle encryption/decryption externally:

```swift
// Use RatchetKeyStateManager for external key derivation
let externalManager = RatchetKeyStateManager<SHA256>(executor: executor, logger: logger)
await externalManager.setDelegate(sessionDelegate)

// Derive message key for external encryption (sending)
let (messageKey, messageNumber) = try await externalManager.deriveMessageKey(sessionId: sessionId)
let encryptedData = try customEncrypt(plaintext, key: messageKey)

// Derive message key for external decryption (receiving)
let (messageKey, messageNumber) = try await externalManager.deriveReceivedMessageKey(
    sessionId: sessionId,
    cipherText: ciphertext
)
let plaintext = try customDecrypt(encryptedData, key: messageKey)
```

**⚠️ Warning:** These methods (`deriveMessageKey`, `deriveReceivedMessageKey`, `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are available in `RatchetKeyStateManager`, not `DoubleRatchetStateManager`. They should **only be used when NOT encrypting/decrypting messages via `ratchetEncrypt`/`ratchetDecrypt`**. They are designed for external key derivation workflows. Do not mix these methods with the standard encryption/decryption API, as this may cause state inconsistencies and security issues.

### Alternative Recipient Initialization

For external key derivation workflows using `RatchetKeyStateManager`:

```swift
// Use RatchetKeyStateManager for external key derivation
let keyManager = RatchetKeyStateManager<SHA256>(executor: executor, logger: logger)

// Initialize receiver with keys and ciphertext (without full message)
try await keyManager.recipientInitialization(
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
try await ratchetManager.ratchetDecrypt(message, sessionId: sessionId)
```

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
await ratchetManager.setDelegate(MySessionDelegate())
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

- **`DoubleRatchetStateManager`**: Main actor managing the Double Ratchet protocol for standard encryption/decryption workflows
- **`RatchetKeyStateManager`**: Actor for advanced external key derivation workflows (separate from standard API)
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

Version 2.0.0 introduces session‑explicit APIs and a header‑driven receive initialization. These are **source‑breaking changes** that require code updates.

### ⚠️ Breaking Changes

1. **Receiving initialization is now header-based:**
   - **1.x**: `recipientInitialization(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)`
   - **2.0**: `recipientInitialization(sessionIdentity:sessionSymmetricKey:header:localKeys:)`

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
try await bobManager.recipientInitialization(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: bobRemoteKeysFromAlice,
    localKeys: bobLocalKeys
)

// ✅ After (2.0) - Standard approach
// First, receive the initial message from Alice
let firstMessage = // ... receive from network

try await bobManager.recipientInitialization(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    header: firstMessage.header,  // Use the actual header
    localKeys: bobLocalKeys
)

// ✅ Alternative (2.0) - For external key derivation (requires RatchetKeyStateManager)
let keyManager = RatchetKeyStateManager<SHA256>(executor: executor, logger: logger)
try await keyManager.recipientInitialization(
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
let msg = try await aliceManager.ratchetEncrypt(plainText: data)
let pt  = try await bobManager.ratchetDecrypt(msg)

// ✅ After (2.0)
let msg = try await aliceManager.ratchetEncrypt(
    plainText: data,
    sessionId: bobSessionIdentity.id  // Explicit session ID
)
let pt  = try await bobManager.ratchetDecrypt(
    msg,
    sessionId: aliceSessionIdentity.id  // Explicit session ID
)
```

#### Step 3: Update Error Handling

```swift
// ✅ Enhanced error handling in 2.0
do {
    let message = try await ratchetManager.ratchetEncrypt(
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

- **Advanced Key Derivation**: `RatchetKeyStateManager` with `deriveMessageKey` and `deriveReceivedMessageKey` for external encryption workflows
- **Alternative Initialization**: New `recipientInitialization` overload in `RatchetKeyStateManager` for external key derivation
- **OTK Consistency**: `setEnforceOTKConsistency(_:)` for strict one-time key validation
- **Configuration Access**: `RatchetConfiguration` fields are now public for inspection
- **Enhanced Logging**: `setLogLevel(_:)` for adjustable verbosity
- **Better Documentation**: Complete DocC documentation with examples

### 📌 Migration Notes

- ✅ No changes required to `senderInitialization` signatures
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
```

## 📚 API Reference

### Main Classes

#### `DoubleRatchetStateManager<Hash>`

**Initialization:**
- `init(executor:logger:ratchetConfiguration:)` - Create manager with optional custom configuration

**Session Management:**
- `senderInitialization(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)` - Initialize sending session
- `recipientInitialization(sessionIdentity:sessionSymmetricKey:header:localKeys:)` - Initialize receiving session

**Message Operations:**
- `ratchetEncrypt(plainText:sessionId:)` - Encrypt message
- `ratchetDecrypt(_:sessionId:)` - Decrypt message

**Configuration:**
- `setDelegate(_:)` - Set session identity delegate
- `setEnforceOTKConsistency(_:)` - Enable/disable strict OTK validation
- `setLogLevel(_:)` - Set logging verbosity
- `shutdown()` - Clean up and persist state

**Properties:**
- `unownedExecutor: UnownedSerialExecutor` - Access to actor's executor

#### `RatchetKeyStateManager<Hash>`

**Initialization:**
- `init(executor:logger:ratchetConfiguration:)` - Create manager with optional custom configuration

**Session Management:**
- `senderInitialization(sessionIdentity:sessionSymmetricKey:remoteKeys:localKeys:)` - Initialize sending session
- `recipientInitialization(sessionIdentity:sessionSymmetricKey:localKeys:remoteKeys:ciphertext:)` - Initialize receiving session (for external key derivation)

**Advanced Key Derivation:**
- `deriveMessageKey(sessionId:)` - Derive key for external encryption (returns `(SymmetricKey, Int)`)
- `deriveReceivedMessageKey(sessionId:cipherText:)` - Derive key for external decryption (returns `(SymmetricKey, Int)`)
- `getSentMessageNumber(sessionId:)` - Get current sent message number (0-based)
- `getReceivedMessageNumber(sessionId:)` - Get current received message number (0-based)
- `setCipherText(sessionId:cipherText:)` - Set MLKEM ciphertext in session state
- `getCipherText(sessionId:)` - Get MLKEM ciphertext from session state

**⚠️ Warning:** These methods should **only be used when NOT encrypting/decrypting messages via `ratchetEncrypt`/`ratchetDecrypt`**. They are designed for external key derivation workflows. Do not mix these methods with the standard encryption/decryption API, as this may cause state inconsistencies and security issues.

**Configuration:**
- `setDelegate(_:)` - Set session identity delegate
- `setEnforceOTKConsistency(_:)` - Enable/disable strict OTK validation
- `setLogLevel(_:)` - Set logging verbosity
- `shutdown()` - Clean up and persist state

**Properties:**
- `unownedExecutor: UnownedSerialExecutor` - Access to actor's executor

#### `SessionIdentity`
- `init(id:props:symmetricKey:)` - Create with properties
- `init(id:data:)` - Create from encrypted data
- `props(symmetricKey:)` - Get decrypted properties
- `decryptProps(symmetricKey:)` - Decrypt properties (throws)
- `updateIdentityProps(symmetricKey:props:)` - Update properties

#### `RatchetMessage`
- `header: EncryptedHeader` - Encrypted metadata
- `encryptedData: Data` - Encrypted message content

#### `RatchetConfiguration`
- `messageKeyData: Data` - Data for message key derivation
- `chainKeyData: Data` - Data for chain key derivation
- `rootKeyData: Data` - Data for root key derivation
- `associatedData: Data` - Associated data for messages
- `maxSkippedMessageKeys: Int` - Maximum skipped keys to retain

### Error Handling

```swift
do {
    let message = try await ratchetManager.ratchetEncrypt(
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
} catch RatchetError.skippedKeysDrained {
    // Skipped message keys have been exhausted
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
