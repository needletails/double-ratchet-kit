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
let executor = //Some Executor
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
        mlKEM: bobMLKEMPublicKey
    ),
    localKeys: LocalKeys(
        longTerm: aliceLongTermPrivateKey,
        oneTime: aliceOneTimePrivateKey,
        mlKEM: aliceMLKEMPrivateKey
    )
)
```

### Recipient Initialization (Bob)

**Using Encrypted Header (Standard):**

```swift
// Bob receives the first message from Alice with an encrypted header
let encryptedHeader = // ... received from Alice
try await ratchetManager.recipientInitialization(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    header: encryptedHeader,
    localKeys: LocalKeys(
        longTerm: bobLongTermPrivateKey,
        oneTime: bobOneTimePrivateKey,
        mlKEM: bobMLKEMPrivateKey
    )
)
```

**Alternative Initialization (Advanced):**

```swift
// For external key derivation workflows
try await ratchetManager.recipientInitialization(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    localKeys: LocalKeys(
        longTerm: bobLongTermPrivateKey,
        oneTime: bobOneTimePrivateKey,
        mlKEM: bobMLKEMPrivateKey
    ),
    remoteKeys: RemoteKeys(
        longTerm: aliceLongTermPublicKey,
        oneTime: aliceOneTimePublicKey,
        mlKEM: aliceMLKEMPublicKey
    ),
    ciphertext: mlKEMCiphertext
)
```

## Sending and Receiving Messages

### Encrypting a Message

```swift
// Alice encrypts a message
let plaintext = "Hello, Bob!".data(using: .utf8)!
let encryptedMessage = try await ratchetManager.ratchetEncrypt(
    plainText: plaintext,
    sessionId: aliceSessionIdentity.id
)
```

### Decrypting a Message

```swift
// Bob decrypts the message
let decryptedMessage = try await ratchetManager.ratchetDecrypt(
    encryptedMessage,
    sessionId: bobSessionIdentity.id
)
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

// Wrapper for MLKEM1024 keys
let kyberPrivateKey = try MLKEMPrivateKey(id: UUID(), MLKEM1024PrivateKey.rawRepresentation)
let kyberPublicKey = try MLKEMPublicKey(id: UUID(), MLKEM1024PublicKey.rawRepresentation)
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

## Swift Concurrency Best Practices

### Actor Isolation

The `RatchetStateManager` is implemented as a Swift actor, providing automatic thread safety:

```swift
// All state mutations are automatically serialized
let ratchetManager = RatchetStateManager<SHA256>(executor: executor, logger: logger)

Task {
    let message1 = try await ratchetManager.ratchetEncrypt(plainText: data1)
    let message2 = try await ratchetManager.ratchetEncrypt(plainText: data2)
}
```

### Proper Resource Management

Always call `shutdown()` when done with the ratchet manager:

```swift
// Always call shutdown when done
try await ratchetManager.shutdown()
```

### Error Handling

```swift
do {
    let message = try await ratchetManager.ratchetEncrypt(
        plainText: data,
        sessionId: sessionId
    )
} catch RatchetError.missingConfiguration {
    // Handle missing session
    print("Session not found")
} catch RatchetError.stateUninitialized {
    // Handle uninitialized state
    print("Session not initialized")
} catch RatchetError.encryptionFailed {
    // Handle encryption failure
    print("Encryption failed")
} catch RatchetError.missingOneTimeKey {
    // Handle missing one-time key (if OTK consistency is enforced)
    print("One-time key missing")
} catch {
    // Handle other errors
    print("Unexpected error: \(error)")
}
```

### Concurrent Session Management

For managing multiple sessions, create separate manager instances:

```swift
// Each session should have its own manager instance
let aliceManager = RatchetStateManager<SHA256>(executor: executor, logger: logger)
let bobManager = RatchetStateManager<SHA256>(executor: executor, logger: logger)

// Each manager can operate concurrently
await withTaskGroup(of: Void.self) { group in
    group.addTask {
        try await aliceManager.senderInitialization(/* ... */)
    }
    group.addTask {
        try await bobManager.recipientInitialization(/* ... */)
    }
}
```

## Next Steps

- Learn about the <doc:KeyConcepts> behind the Double Ratchet algorithm
- Understand the <doc:SecurityModel> and threat model
- Review the <doc:APIReference> for detailed method documentation 
