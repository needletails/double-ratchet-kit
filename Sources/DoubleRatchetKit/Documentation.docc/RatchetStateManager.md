# DoubleRatchetStateManager

The main actor that manages the cryptographic state for secure messaging using the Double Ratchet algorithm.

## Overview

`DoubleRatchetStateManager` is the primary interface for implementing secure messaging with the Double Ratchet protocol. It manages session state, handles key rotation, and provides encryption/decryption operations for messages.

## Declaration

```swift
public actor DoubleRatchetStateManager<Hash: HashFunction & Sendable>
```

## Generic Parameters

- `Hash`: The hash function used for key derivation (e.g., `SHA256`, `SHA512`)

## Initialization

### Creating a Ratchet State Manager

**Default Configuration:**

```swift
let ratchetManager = DoubleRatchetStateManager<SHA256>(
    executor: executor,
    logger: logger
)
```

**Custom Configuration:**

```swift
let customConfig = RatchetConfiguration(
    messageKeyData: Data([0x00]),
    chainKeyData: Data([0x01]),
    rootKeyData: Data([0x02, 0x03]),
    associatedData: "MyApp".data(using: .ascii)!,
    maxSkippedMessageKeys: 1000
)

let ratchetManager = DoubleRatchetStateManager<SHA256>(
    executor: executor,
    logger: logger,
    ratchetConfiguration: customConfig
)
```

**Parameters:**
- `executor`: A `SerialExecutor` used to coordinate concurrent operations within the actor
- `logger`: A `NeedleTailLogger` instance for logging (optional, defaults to new instance)
- `ratchetConfiguration`: Optional custom configuration. If `nil`, uses default configuration with `maxSkippedMessageKeys: 100`

**Note:** Use a custom configuration only if you need to modify protocol parameters. The default configuration is suitable for most use cases.

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

Initialize a session for receiving messages using an encrypted header:

```swift
try await ratchetManager.recipientInitialization(
    sessionIdentity: sessionIdentity,
    sessionSymmetricKey: sessionKey,
    header: encryptedHeader,
    localKeys: localKeys
)
```

**Parameters:**
- `sessionIdentity`: The session identity for this communication
- `sessionSymmetricKey`: Symmetric key for decrypting session metadata
- `header`: The `EncryptedHeader` received from the sender
- `localKeys`: Recipient's private keys

**Alternative Initialization (Advanced):**

For external key derivation workflows, you can use:

```swift
try await ratchetManager.recipientInitialization(
    sessionIdentity: sessionIdentity,
    sessionSymmetricKey: sessionKey,
    localKeys: localKeys,
    remoteKeys: remoteKeys,
    ciphertext: ciphertext
)
```

**Parameters:**
- `sessionIdentity`: The session identity for this communication
- `sessionSymmetricKey`: Symmetric key for decrypting session metadata
- `localKeys`: Recipient's private keys
- `remoteKeys`: Sender's public keys (oneTime is optional)
- `ciphertext`: The MLKEM ciphertext from the sender's initial handshake

**Note:** This alternative method is designed for advanced use cases where you need to bootstrap a session without calling `ratchetEncrypt` first.

### Message Operations

#### Encrypting Messages

Encrypt a plaintext message:

```swift
let encryptedMessage = try await ratchetManager.ratchetEncrypt(
    plainText: plaintext,
    sessionId: sessionId
)
```

**Parameters:**
- `plainText`: The plaintext data to encrypt
- `sessionId`: The UUID of the session to encrypt for

**Returns:** A `RatchetMessage` containing the encrypted payload and header

**Throws:**
- `RatchetError.missingConfiguration`: If the session is not found
- `RatchetError.stateUninitialized`: If the session state is not initialized
- `RatchetError.sendingKeyIsNil`: If the sending key is missing
- `RatchetError.encryptionFailed`: If encryption fails
- `RatchetError.headerEncryptionFailed`: If header encryption fails
- `RatchetError.missingOneTimeKey`: If OTK consistency is enforced and the key is missing

#### Decrypting Messages

Decrypt a received message:

```swift
let decryptedMessage = try await ratchetManager.ratchetDecrypt(
    encryptedMessage,
    sessionId: sessionId
)
```

**Parameters:**
- `encryptedMessage`: The `RatchetMessage` to decrypt
- `sessionId`: The UUID of the session to decrypt for

**Returns:** The decrypted plaintext data

**Throws:**
- `RatchetError.missingConfiguration`: If the session is not found
- `RatchetError.stateUninitialized`: If the session state is not initialized
- `RatchetError.decryptionFailed`: If decryption fails
- `RatchetError.headerDecryptFailed`: If header decryption fails
- `RatchetError.expiredKey`: If the message uses an expired key
- `RatchetError.missingOneTimeKey`: If OTK consistency is enforced and the key is missing
- `RatchetError.maxSkippedHeadersExceeded`: If too many messages were skipped
- `RatchetError.skippedKeysDrained`: If skipped message keys have been exhausted

#### Advanced Key Derivation

For advanced use cases where you want to handle encryption/decryption externally, use `RatchetKeyStateManager` instead of `DoubleRatchetStateManager`. See the `RatchetKeyStateManager` documentation for details on external key derivation workflows.

**Important:** Do not mix external key derivation methods with the standard `ratchetEncrypt`/`ratchetDecrypt` API. Use separate manager instances for each workflow to avoid state inconsistencies and security issues.

### Session Management

#### Setting the Delegate

Set a delegate for session identity management:

```swift
await ratchetManager.setDelegate(sessionDelegate)
```

**Parameters:**
- `sessionDelegate`: An object conforming to `SessionIdentityDelegate`. Pass `nil` to remove the current delegate.

**Delegate Responsibilities:**
- Persisting session identities to storage
- Fetching one-time private keys by ID
- Managing one-time key rotation

**Important:** The delegate should be set before calling initialization methods if you want session state to be persisted automatically. Without a delegate, session state will only exist in memory.

#### OTK Consistency Enforcement

Enable or disable strict one-time-prekey (OTK) consistency enforcement:

```swift
await ratchetManager.setEnforceOTKConsistency(true)
```

**When enabled:** If the header signals an OTK but the corresponding local private OTK cannot be loaded, decryption will fail fast with `RatchetError.missingOneTimeKey`.

**When disabled:** Decryption proceeds even if the OTK is missing, potentially failing later during the actual decryption operation.

**Note:** This should be enabled when using a delegate that manages one-time keys to ensure keys are properly fetched and validated before use.

#### Setting Log Level

Set the logging level for the ratchet state manager:

```swift
// Development: maximum verbosity
await ratchetManager.setLogLevel(.trace)

// Production: minimal logging
await ratchetManager.setLogLevel(.warning)
```

**Parameters:**
- `level`: The desired log level. Available levels (from most to least verbose):
  - `.trace`: Most verbose, includes all debug information
  - `.debug`: Debug information including operations
  - `.info`: Informational messages
  - `.warning`: Warning messages
  - `.error`: Only error messages

**Note:** The default log level is `.trace`. Adjust this in production to reduce logging overhead.

#### Shutting Down

Clean up resources when done:

```swift
try await ratchetManager.shutdown()
```

**Lifecycle:**
- Persists all session states to storage via the delegate
- Clears in-memory session configurations
- Marks the manager as shut down

**Important:**
- Always call `shutdown()` when the manager is no longer needed to ensure proper cleanup
- The manager cannot be used after `shutdown()` is called
- If `shutdown()` is not called, the `deinit` will crash with a precondition failure
- This method is safe to call multiple times (idempotent after first call)

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

`DoubleRatchetStateManager` is implemented as a Swift actor, providing automatic thread safety:

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
let ratchetManager = DoubleRatchetStateManager<SHA256>(executor: executor, logger: logger)

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
let session1Manager = DoubleRatchetStateManager<SHA256>(executor: executor, logger: logger)
let session2Manager = DoubleRatchetStateManager<SHA256>(executor: executor, logger: logger)

// Each manager can operate independently and concurrently
```

## Error Handling

### Common Errors

```swift
do {
    let message = try await ratchetManager.ratchetEncrypt(plainText: data, sessionId: sessionId)
} catch RatchetError.missingConfiguration {
    // Session not found - check session ID
} catch RatchetError.stateUninitialized {
    // Session not initialized - call senderInitialization or recipientInitialization
} catch RatchetError.sendingKeyIsNil {
    // Sending key missing - check session state
} catch RatchetError.encryptionFailed {
    // Encryption operation failed
} catch RatchetError.headerEncryptionFailed {
    // Header encryption failed
} catch RatchetError.missingOneTimeKey {
    // Required one-time key is missing (if OTK consistency is enforced)
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

## Example Usage

### Complete Example

```swift
import DoubleRatchetKit
import NeedleTailLogger

// Create manager
let executor = MainActor.shared
let logger = NeedleTailLogger()
let ratchetManager = DoubleRatchetStateManager<SHA256>(executor: executor, logger: logger)

// Set delegate
await ratchetManager.setDelegate(MySessionDelegate())

// Initialize sending session
try await ratchetManager.senderInitialization(
    sessionIdentity: aliceSessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: bobRemoteKeys,
    localKeys: aliceLocalKeys
)

// Send message
let plaintext = "Hello, Bob!".data(using: .utf8)!
let encryptedMessage = try await ratchetManager.ratchetEncrypt(
    plainText: plaintext,
    sessionId: aliceSessionIdentity.id
)

// Receive message (on Bob's side)
let decryptedMessage = try await ratchetManager.ratchetDecrypt(
    encryptedMessage,
    sessionId: bobSessionIdentity.id
)

// Clean up
try await ratchetManager.shutdown()
```

## Related Documentation

- <doc:SessionIdentity> - Session identity management
- <doc:RatchetState> - Session state structure
- <doc:KeyManagement> - Cryptographic key management 
