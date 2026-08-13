# Using MessageRatchet

The main actor that manages the cryptographic state for secure messaging using the Double Ratchet algorithm.

## Overview

`MessageRatchet` is the primary interface for implementing secure messaging with the Double Ratchet protocol. It manages session state, handles key rotation, and provides encryption/decryption operations for messages.

## Declaration

```swift
public actor MessageRatchet
```

## Initialization

### Creating a Ratchet State Manager

**Default Configuration:**

```swift
let ratchetManager = MessageRatchet(
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

let ratchetManager = MessageRatchet(
    executor: executor,
    logger: logger,
    ratchetConfiguration: customConfig
)
```

`associatedData` is authenticated as AES-GCM associated data for payload
encryption, together with the encoded ratchet header.

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
try await ratchetManager.openAsSender(
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
try await ratchetManager.openAsRecipient(
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

### Message Operations

#### Encrypting Messages

Encrypt a plaintext message:

```swift
let encryptedMessage = try await ratchetManager.encrypt(
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
let decryptedMessage = try await ratchetManager.decrypt(
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

#### Advanced Key Derivation

For advanced use cases where you want to handle encryption/decryption externally, use `KeyRatchet` instead of `MessageRatchet`. See the `KeyRatchet` documentation for details on external key derivation workflows.

**Important:** Do not mix external key derivation methods with the standard `encrypt`/`decrypt` API. Use separate manager instances for each workflow to avoid state inconsistencies and security issues.

### Session Management

#### Setting the Delegate

Set a delegate for session identity management:

```swift
await ratchetManager.setDelegate(sessionDelegate)
```

**Parameters:**
- `sessionDelegate`: An object conforming to `SessionIdentityDelegate`

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
try await ratchetManager.flushAndClose()
```

**Lifecycle:**
- Persists all session states to storage via the delegate
- Clears in-memory session configurations
- Marks the manager as shut down

**Important:**
- Always call `flushAndClose()` when the manager is no longer needed to ensure proper cleanup
- The manager cannot be used after `flushAndClose()` is called
- `flushAndClose()` is idempotent; further session operations after close are unsupported
- This method is safe to call multiple times (idempotent after first call)

## Delegate Protocol

### SessionIdentityDelegate

The delegate protocol for managing session identities and keys:

```swift
public protocol SessionIdentityDelegate: AnyObject, Sendable {
    func updateSessionIdentity(_ identity: SessionIdentity) async throws
    func fetchOneTimePrivateKey(_ id: UUID?) async throws -> X25519PrivateKey?
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

`MessageRatchet` is implemented as a Swift actor, providing automatic thread safety:

- **Isolated State**: All state mutations are isolated to the actor
- **Concurrent Access**: Multiple threads can safely call methods concurrently
- **Serial Execution**: Operations are executed serially within the actor

### Proper Resource Management

The manager automatically handles memory management for cryptographic state:

- **Key Cleanup**: Used keys are automatically cleaned up
- **State Persistence**: Session state is persisted through the delegate
- **Resource Cleanup**: Call `flushAndClose()` to ensure proper cleanup

### Concurrent Usage Patterns

```swift
// Safe concurrent access
let ratchetManager = MessageRatchet(executor: executor, logger: logger)

// Multiple tasks can safely access the same manager
try await withThrowingTaskGroup(of: RatchetMessage.self) { group in
    group.addTask {
        try await ratchetManager.encrypt(plainText: data1, sessionId: sessionId)
    }
    group.addTask {
        try await ratchetManager.encrypt(plainText: data2, sessionId: sessionId)
    }
    for try await message in group {
        // handle each encrypted message
    }
}
```

### Multiple Session Management

A single manager handles many sessions concurrently, keyed by session identity UUID. Each party (device) typically owns one manager:

```swift
// One manager per party; each manager serves all of that party's sessions
let aliceManager = MessageRatchet(executor: executor, logger: logger)
let bobManager = MessageRatchet(executor: executor, logger: logger)

// Alice can talk to many peers through the same manager,
// addressing each conversation by its sessionId.
```

## Error Handling

### Common Errors

```swift
do {
    let message = try await ratchetManager.encrypt(plainText: data, sessionId: sessionId)
} catch RatchetError.missingConfiguration {
    // Session not found - check session ID
} catch RatchetError.stateUninitialized {
    // Session not initialized - call openAsSender or openAsRecipient
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
} catch {
    // Handle other errors
}
```

## Example Usage

### Complete Example

```swift
import DoubleRatchetKit
import NeedleTailLogger

// Create managers — any SerialExecutor works (see <doc:GettingStarted>)
let logger = NeedleTailLogger()
let aliceManager = MessageRatchet(executor: executor, logger: logger)
let bobManager = MessageRatchet(executor: executor, logger: logger)

// Set delegates
await aliceManager.setDelegate(aliceSessionDelegate)
await bobManager.setDelegate(bobSessionDelegate)

// Alice initializes a sending session to Bob
try await aliceManager.openAsSender(
    sessionIdentity: bobSessionIdentity,   // identity describing the peer lane
    sessionSymmetricKey: sessionKey,
    remoteKeys: bobRemoteKeys,
    localKeys: aliceLocalKeys
)

// Alice sends a message
let plaintext = "Hello, Bob!".data(using: .utf8)!
let encryptedMessage = try await aliceManager.encrypt(
    plainText: plaintext,
    sessionId: bobSessionIdentity.id
)

// Bob initializes from the received header, then decrypts
try await bobManager.openAsRecipient(
    sessionIdentity: aliceSessionIdentity,
    sessionSymmetricKey: sessionKey,
    header: encryptedMessage.header,
    localKeys: bobLocalKeys
)
let decryptedMessage = try await bobManager.decrypt(
    encryptedMessage,
    sessionId: aliceSessionIdentity.id
)

// Clean up
try await aliceManager.flushAndClose()
try await bobManager.flushAndClose()
```

## Related Documentation

- <doc:UsingSessionIdentity> - Session identity management
- <doc:RatchetState> - Session state structure
- <doc:KeyManagement> - Cryptographic key management 
