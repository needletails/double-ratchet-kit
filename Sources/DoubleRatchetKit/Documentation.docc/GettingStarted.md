# Getting Started

Learn how to integrate DoubleRatchetKit into your secure messaging application.

## Overview

This guide walks you through setting up DoubleRatchetKit for secure messaging with post-quantum cryptography. You'll learn how to initialize sessions, send and receive encrypted messages, and manage cryptographic keys.

## Prerequisites

- **Swift**: 6.3 or later
- **Platforms**: macOS 15.0+, iOS 18.0+
- **Dependencies** (resolved automatically):
  - `needletail-crypto` (1.3.0+)
  - `needletail-logger` (3.1.5+)
  - `binary-codable` (1.0.3+)

## Installation

### Swift Package Manager

Add DoubleRatchetKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/needletails/double-ratchet-kit.git", from: "4.0.0")
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

`MessageRatchet` is an actor driven by a `SerialExecutor` you supply. A minimal queue-backed executor looks like this:

```swift
final class RatchetExecutor: SerialExecutor {
    private let queue = DispatchQueue(label: "ratchet-executor")

    func enqueue(_ job: consuming ExecutorJob) {
        let job = UnownedJob(job)
        queue.async { [weak self] in
            guard let self else { return }
            job.runSynchronously(on: asUnownedSerialExecutor())
        }
    }

    func asUnownedSerialExecutor() -> UnownedSerialExecutor {
        UnownedSerialExecutor(ordinary: self)
    }
}

let executor = RatchetExecutor()
let logger = NeedleTailLogger()

// Initialize the ratchet state manager
let ratchetManager = MessageRatchet(
    executor: executor,
    logger: logger
)
```

### 3. Set Up Session Identities

A `SessionIdentity` describes the **peer lane**: its props hold the remote party's public keys, and its `id` is the `sessionId` you pass to `encrypt`/`decrypt`. Alice stores an identity describing Bob, and Bob stores one describing Alice:

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

## Session Initialization

### Sender Initialization (Alice)

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

### Recipient Initialization (Bob)

```swift
// Bob receives the first message from Alice and binds to its encrypted header
try await bobManager.respondToSession(
    sessionIdentity: aliceSessionIdentity, // describes the peer (Alice)
    sessionSymmetricKey: sessionKey,
    header: encryptedMessage.header,
    localKeys: LocalKeys(
        longTerm: bobLongTermPrivateKey,
        oneTime: bobOneTimePrivateKey,
        mlKEM: bobMLKEMPrivateKey
    )
)
```

**External key derivation (Advanced):** `KeyRatchet` offers a recipient path that bootstraps from PQXDH ciphertext instead of a header — see <doc:UsingKeyRatchet>:

```swift
let keyRatchet = KeyRatchet(executor: executor, logger: logger)
try await keyRatchet.respondToSession(
    sessionIdentity: aliceSessionIdentity,
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
let encryptedMessage = try await aliceManager.encrypt(
    plainText: plaintext,
    sessionId: bobSessionIdentity.id
)
```

### Decrypting a Message

```swift
// Bob decrypts the message
let decryptedMessage = try await bobManager.decrypt(
    encryptedMessage,
    sessionId: aliceSessionIdentity.id
)
let message = String(data: decryptedMessage, encoding: .utf8)!
print("Received: \(message)") // "Hello, Bob!"
```

## Key Management

### Key Wrappers

Key wrappers are used to identify keys that the recipient needs to reference from their own key store. For instance, Alice uses Bob's one-time key that is fetched from a remote server, and Bob needs to know what key was used so Alice sends the identifier for Bob to look up in his own local key store.

```swift
// Wrapper for Curve25519 keys
let curvePrivateKey = try X25519PrivateKey(id: UUID(), curve25519PrivateKey.rawRepresentation)
let curvePublicKey = try X25519PublicKey(id: UUID(), curve25519PublicKey.rawRepresentation)

// Wrapper for MLKEM1024 keys (private wraps encode(), public wraps rawRepresentation)
let kemPrivateKey = try MLKEMPrivateKey(id: UUID(), mlKEM1024PrivateKey.encode())
let kemPublicKey = try MLKEMPublicKey(id: UUID(), mlKEM1024PublicKey.rawRepresentation)
```

## Session Identity Delegate

### Implementing the Delegate

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
```

### Setting the Delegate

```swift
// Set the delegate
await ratchetManager.setDelegate(MySessionDelegate())
```

## Swift Concurrency Best Practices

### Actor Isolation

The `MessageRatchet` is implemented as a Swift actor, providing automatic thread safety:

```swift
// All state mutations are automatically serialized
let ratchetManager = MessageRatchet(executor: executor, logger: logger)

Task {
    let message1 = try await ratchetManager.encrypt(plainText: data1, sessionId: sessionId)
    let message2 = try await ratchetManager.encrypt(plainText: data2, sessionId: sessionId)
}
```

### Proper Resource Management

Always call `flushAndClose()` when done with the ratchet manager:

```swift
// Always call flushAndClose when done
try await ratchetManager.flushAndClose()
```

### Error Handling

```swift
do {
    let message = try await ratchetManager.encrypt(
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

A single manager handles many sessions concurrently, keyed by session identity UUID. Each party (device) typically owns one manager:

```swift
// One manager per party
let aliceManager = MessageRatchet(executor: executor, logger: logger)
let bobManager = MessageRatchet(executor: executor, logger: logger)

// Managers can operate concurrently
try await withThrowingTaskGroup(of: Void.self) { group in
    group.addTask {
        try await aliceManager.initiateSession(/* ... */)
    }
    group.addTask {
        try await bobManager.respondToSession(/* ... */)
    }
    try await group.waitForAll()
}
```

## Next Steps

- Learn about the <doc:KeyConcepts> behind the Double Ratchet algorithm
- Understand the <doc:SecurityModel> and threat model
- Review the <doc:APIReference> for detailed method documentation 
