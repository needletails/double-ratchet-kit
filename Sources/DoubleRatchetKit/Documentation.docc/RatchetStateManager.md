# RatchetStateManager

The main actor that manages the cryptographic state for secure messaging using the Double Ratchet algorithm.

## Overview

`RatchetStateManager` is the primary interface for implementing secure messaging with the Double Ratchet protocol. It manages session state, handles key rotation, and provides encryption/decryption operations for messages.

## Declaration

```swift
public actor RatchetStateManager<Hash: HashFunction & Sendable>
```

## Generic Parameters

- `Hash`: The hash function used for key derivation (e.g., `SHA256`, `SHA512`)

## Initialization

### Creating a Ratchet State Manager

```swift
let ratchetManager = RatchetStateManager<SHA256>(
    executor: executor,
    logger: logger
)
```

**Parameters:**
- `executor`: A `SerialExecutor` used to coordinate concurrent operations
- `logger`: A `NeedleTailLogger` instance for logging (optional)

## Core Functionality

### Session Initialization

#### Sender Initialization

Initialize a session for sending messages:

```swift
try await ratchetManager.senderInitialization(
    sessionIdentity: sessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: remoteKeys,
    localKeys: localKeys
)
```

**Parameters:**
- `sessionIdentity`: The session identity for this communication
- `sessionSymmetricKey`: Symmetric key for encrypting session metadata
- `remoteKeys`: Recipient's public keys
- `localKeys`: Sender's private keys

#### Recipient Initialization

Initialize a session for receiving messages:

```swift
try await ratchetManager.recipientInitialization(
    sessionIdentity: sessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: remoteKeys,
    localKeys: localKeys
)
```

**Parameters:**
- `sessionIdentity`: The session identity for this communication
- `sessionSymmetricKey`: Symmetric key for decrypting session metadata
- `remoteKeys`: Sender's public keys
- `localKeys`: Recipient's private keys

### Message Operations

#### Encrypting Messages

Encrypt a plaintext message:

```swift
let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: plaintext)
```

**Parameters:**
- `plainText`: The plaintext data to encrypt

**Returns:** A `RatchetMessage` containing the encrypted payload and header

**Throws:**
- `RatchetError.stateUninitialized`: If the session is not initialized
- `RatchetError.sendingKeyIsNil`: If the sending key is missing
- `RatchetError.encryptionFailed`: If encryption fails
- `RatchetError.headerEncryptionFailed`: If header encryption fails

#### Decrypting Messages

Decrypt a received message:

```swift
let decryptedMessage = try await ratchetManager.ratchetDecrypt(encryptedMessage)
```

**Parameters:**
- `encryptedMessage`: The `RatchetMessage` to decrypt

**Returns:** The decrypted plaintext data

**Throws:**
- `RatchetError.stateUninitialized`: If the session is not initialized
- `RatchetError.decryptionFailed`: If decryption fails
- `RatchetError.headerDecryptFailed`: If header decryption fails
- `RatchetError.expiredKey`: If the message uses an expired key

### Session Management

#### Setting the Delegate

Set a delegate for session identity management:

```swift
ratchetManager.setDelegate(sessionDelegate)
```

**Parameters:**
- `sessionDelegate`: An object conforming to `SessionIdentityDelegate`

#### Shutting Down

Clean up resources when done:

```swift
try await ratchetManager.shutdown()
```

**Important:** Always call `shutdown()` when the manager is no longer needed to ensure proper cleanup.

## Delegate Protocol

### SessionIdentityDelegate

The delegate protocol for managing session identities and keys:

```swift
public protocol SessionIdentityDelegate: AnyObject, Sendable {
    func updateSessionIdentity(_ identity: SessionIdentity) async throws
    func fetchOneTimePrivateKey(_ id: UUID?) async throws -> CurvePrivateKey?
    func updateOneTimeKey(remove id: UUID) async
}
```

#### Required Methods

**updateSessionIdentity(_:)**
Updates the stored session identity.

**fetchOneTimePrivateKey(_:)**
Fetches a previously stored private one-time Curve25519 key by its unique identifier.

**updateOneTimeKey(remove:)**
Notifies that a new one-time key should be generated and made available.

## Swift Concurrency Best Practices

### Actor Isolation

`RatchetStateManager` is implemented as a Swift actor, providing automatic thread safety:

- **Isolated State**: All state mutations are isolated to the actor
- **Concurrent Access**: Multiple threads can safely call methods concurrently
- **Serial Execution**: Operations are executed serially within the actor

### Proper Resource Management

The manager automatically handles memory management for cryptographic state:

- **Key Cleanup**: Used keys are automatically cleaned up
- **State Persistence**: Session state is persisted through the delegate
- **Resource Cleanup**: Call `shutdown()` to ensure proper cleanup

### Concurrent Usage Patterns

```swift
// Safe concurrent access
let ratchetManager = RatchetStateManager<SHA256>(executor: executor, logger: logger)

// Multiple tasks can safely access the same manager
await withTaskGroup(of: RatchetMessage.self) { group in
    group.addTask {
        return try await ratchetManager.ratchetEncrypt(plainText: data1)
    }
    group.addTask {
        return try await ratchetManager.ratchetEncrypt(plainText: data2)
    }
}
```

### Multiple Session Management

For managing multiple sessions, create separate manager instances:

```swift
// Each session should have its own manager instance
let session1Manager = RatchetStateManager<SHA256>(executor: executor, logger: logger)
let session2Manager = RatchetStateManager<SHA256>(executor: executor, logger: logger)

// Each manager can operate independently and concurrently
```

## Error Handling

### Common Errors

```swift
do {
    let message = try await ratchetManager.ratchetEncrypt(plainText: data)
} catch RatchetError.stateUninitialized {
    // Session not initialized - call senderInitialization or recipientInitialization
} catch RatchetError.sendingKeyIsNil {
    // Sending key missing - check session state
} catch RatchetError.encryptionFailed {
    // Encryption operation failed
} catch RatchetError.headerEncryptionFailed {
    // Header encryption failed
} catch RatchetError.decryptionFailed {
    // Decryption operation failed
} catch RatchetError.headerDecryptFailed {
    // Header decryption failed
} catch RatchetError.expiredKey {
    // Message uses an expired key
} catch RatchetError.missingOneTimeKey {
    // Required one-time key is missing
} catch {
    // Handle other errors
}
```

## Example Usage

### Complete Example

```swift
import DoubleRatchetKit
import NeedleTailLogger

// Create manager
let executor = MainActor.shared
let logger = NeedleTailLogger()
let ratchetManager = RatchetStateManager<SHA256>(executor: executor, logger: logger)

// Set delegate
ratchetManager.setDelegate(MySessionDelegate())

// Initialize sending session
try await ratchetManager.senderInitialization(
    sessionIdentity: aliceSessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: bobRemoteKeys,
    localKeys: aliceLocalKeys
)

// Send message
let plaintext = "Hello, Bob!".data(using: .utf8)!
let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: plaintext)

// Receive message (on Bob's side)
let decryptedMessage = try await ratchetManager.ratchetDecrypt(encryptedMessage)

// Clean up
try await ratchetManager.shutdown()
```

## Related Documentation

- <doc:SessionIdentity> - Session identity management
- <doc:RatchetState> - Session state structure
- <doc:KeyManagement> - Cryptographic key management 