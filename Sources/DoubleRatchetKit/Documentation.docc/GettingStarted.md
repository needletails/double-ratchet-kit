# Getting Started

Learn how to integrate DoubleRatchetKit into your secure messaging application.

## Overview

This guide walks you through setting up DoubleRatchetKit for secure messaging with post-quantum cryptography. You'll learn how to initialize sessions, send and receive encrypted messages, and manage cryptographic keys.

## Prerequisites

- **Swift**: 6.1 or later
- **Platforms**: macOS 15.0+, iOS 18.0+
- **Dependencies**: 
  - `swift-crypto` (3.12.3+)
  - `needletail-crypto` (1.1.1+)
  - `needletail-algorithms` (2.0.1+)
  - `needletail-logger` (3.0.0+)

## Installation

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

## Basic Setup

### 1. Import the Module

```swift
import DoubleRatchetKit
import NeedleTailLogger
```

### 2. Initialize the Ratchet State Manager

```swift
// Create a serial executor for the actor
let executor = // Some Executor
let logger = NeedleTailLogger()

// Initialize the ratchet state manager
let ratchetManager = RatchetStateManager<SHA256>(
    executor: executor,
    logger: logger
)
```

### 3. Set Up Session Identities

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

## Session Initialization

### Sender Initialization (Alice)

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

### Recipient Initialization (Bob)

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

## Sending and Receiving Messages

### Encrypting a Message

```swift
// Alice encrypts a message
let plaintext = "Hello, Bob!".data(using: .utf8)!
let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: plaintext)
```

### Decrypting a Message

```swift
// Bob decrypts the message
let decryptedMessage = try await ratchetManager.ratchetDecrypt(encryptedMessage)
let message = String(data: decryptedMessage, encoding: .utf8)!
print("Received: \(message)") // "Hello, Bob!"
```

## Key Management

### Key Wrappers

Key wrappers are used to identify keys that the recipient needs to reference from their own key store. For instance, Alice uses Bob's one-time key that is fetched from a remote server, and Bob needs to know what key was used so Alice sends the identifier for Bob to look up in his own local key store.

```swift
// Wrapper for Curve25519 keys
let curvePrivateKey = try CurvePrivateKey(id: UUID(), curve25519PrivateKey.rawRepresentation)
let curvePublicKey = try CurvePublicKey(id: UUID(), curve25519PublicKey.rawRepresentation)

// Wrapper for Kyber1024 keys
let kyberPrivateKey = try PQKemPrivateKey(id: UUID(), kyber1024PrivateKey.rawRepresentation)
let kyberPublicKey = try PQKemPublicKey(id: UUID(), kyber1024PublicKey.rawRepresentation)
```

## Session Identity Delegate

### Implementing the Delegate

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
```

### Setting the Delegate

```swift
// Set the delegate
ratchetManager.setDelegate(MySessionDelegate())
```

## Error Handling

### Common Error Patterns

```swift
do {
    let message = try await ratchetManager.ratchetEncrypt(plainText: data)
} catch RatchetError.stateUninitialized {
    // Handle uninitialized state
    print("Session not initialized")
} catch RatchetError.encryptionFailed {
    // Handle encryption failure
    print("Encryption failed")
} catch {
    // Handle other errors
    print("Unexpected error: \(error)")
}
```

## Cleanup

### Shutdown

Always call shutdown when you're done with the ratchet manager:

```swift
// Always call shutdown when done
try await ratchetManager.shutdown()
```

## Next Steps

- Learn about the <doc:KeyConcepts> behind the Double Ratchet algorithm
- Understand the <doc:SecurityModel> and threat model
- Explore <doc:BestPractices> for secure implementation
- Review the <doc:APIReference> for detailed method documentation 