# API Reference

Complete API reference for DoubleRatchetKit.

## Overview

This document provides a comprehensive reference for all public APIs in DoubleRatchetKit, including classes, protocols, structs, and functions.

## Core Classes

### DoubleRatchetStateManager

The main actor that manages the cryptographic state for secure messaging.

```swift
public actor DoubleRatchetStateManager<Hash: HashFunction & Sendable>
```

#### Initialization

```swift
public init(
    executor: any SerialExecutor,
    logger: NeedleTailLogger = NeedleTailLogger(),
    ratchetConfiguration: RatchetConfiguration? = nil
)
```

**Parameters:**
- `executor`: A `SerialExecutor` used to coordinate concurrent operations within the actor
- `logger`: A `NeedleTailLogger` instance for logging (optional, defaults to new instance)
- `ratchetConfiguration`: Optional custom configuration for the Double Ratchet protocol. If `nil`, uses default configuration with `maxSkippedMessageKeys: 100` and standard key derivation parameters.

**Default Configuration:**
- `maxSkippedMessageKeys: 100`
- Standard key derivation data
- Associated data: "DoubleRatchetKit"

**Note:** Use a custom `ratchetConfiguration` only if you need to modify protocol parameters for compatibility or security requirements. The default configuration is suitable for most use cases.

#### Core Methods

##### Session Initialization

```swift
public func senderInitialization(
    sessionIdentity: SessionIdentity,
    sessionSymmetricKey: SymmetricKey,
    remoteKeys: RemoteKeys,
    localKeys: LocalKeys
) async throws
```

Initialize a session for sending messages.

**Parameters:**
- `sessionIdentity`: A unique identity used to bind the session cryptographically
- `sessionSymmetricKey`: A symmetric key used to encrypt metadata or protect session state
- `remoteKeys`: The recipient's public keys
- `localKeys`: The sender's private keys

**Throws:**
- `RatchetError.missingConfiguration`: If session configuration cannot be loaded
- `RatchetError.missingProps`: If session properties are missing

**Note:** This method can be called multiple times for the same session to support key rotation scenarios.

```swift
public func recipientInitialization(
    sessionIdentity: SessionIdentity,
    sessionSymmetricKey: SymmetricKey,
    header: EncryptedHeader,
    localKeys: LocalKeys
) async throws
```

Initialize a session for receiving messages using an encrypted header.

**Parameters:**
- `sessionIdentity`: A unique identity used to bind the session cryptographically
- `sessionSymmetricKey`: A symmetric key used to decrypt or authenticate session metadata
- `header`: The `EncryptedHeader` received from the sender
- `localKeys`: The recipient's private keys

**Throws:**
- `RatchetError.missingConfiguration`: If session configuration cannot be loaded
- `RatchetError.headerDecryptFailed`: If header decryption fails
- `RatchetError.missingOneTimeKey`: If OTK consistency is enforced and the key is missing

**Note:** This method can be called multiple times with different headers to handle out-of-order message delivery.

```swift
public func recipientInitialization(
    sessionIdentity: SessionIdentity,
    sessionSymmetricKey: SymmetricKey,
    localKeys: LocalKeys,
    remoteKeys: RemoteKeys,
    ciphertext: Data
) async throws
```

Alternative initialization method for external key derivation workflows. This method creates a synthetic header from the provided keys and ciphertext.

**Parameters:**
- `sessionIdentity`: A unique identity used to bind the session cryptographically
- `sessionSymmetricKey`: A symmetric key used to decrypt or authenticate session metadata
- `localKeys`: The recipient's private keys
- `remoteKeys`: The sender's public keys (oneTime is optional)
- `ciphertext`: The MLKEM ciphertext from the sender's initial handshake

**Throws:**
- `RatchetError.missingConfiguration`: If session configuration cannot be loaded

**See Also:** `deriveReceivedMessageKey(sessionId:cipherText:)` for external key derivation workflows.

##### Message Operations

```swift
public func ratchetEncrypt(plainText: Data, sessionId: UUID) async throws -> RatchetMessage
```

Encrypt a plaintext message.

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

```swift
public func ratchetDecrypt(_ message: RatchetMessage, sessionId: UUID) async throws -> Data
```

Decrypt a received message.

**Parameters:**
- `message`: The `RatchetMessage` to decrypt
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

##### Advanced Key Derivation

```swift
public func deriveMessageKey(sessionId: UUID) async throws -> (SymmetricKey, Int)
```

Derives the next message key for sending without performing full message encryption. This method is designed for advanced use cases where you want to handle encryption externally while the SDK manages ratchet key derivation.

**Parameters:**
- `sessionId`: The UUID of the session to derive the key for

**Returns:** A tuple containing:
  - The derived symmetric key for encrypting the next message
  - The message number (0-based index) for this message

**Throws:**
- `RatchetError.missingConfiguration`: If the session is not found
- `RatchetError.stateUninitialized`: If the session state is not initialized
- `RatchetError.sendingKeyIsNil`: If the sending key is missing
- `RatchetError.missingOneTimeKey`: If OTK consistency is enforced and the key is missing

**Important:** This method advances the ratchet state. Each call derives a new key and increments the message counter. Do not call this method multiple times for the same message.

**Warning:** This method is available in `RatchetKeyStateManager`, not `DoubleRatchetStateManager`. It should **only be used when NOT encrypting/decrypting messages via `ratchetEncrypt`/`ratchetDecrypt`**. These methods (`deriveMessageKey`, `deriveReceivedMessageKey`, `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are designed for external key derivation workflows. Do not mix these methods with the standard encryption/decryption API, as this may cause state inconsistencies and security issues.

**See Also:** `deriveReceivedMessageKey(sessionId:cipherText:)` for the receiving side equivalent.

```swift
public func deriveReceivedMessageKey(sessionId: UUID, cipherText: Data) async throws -> (SymmetricKey, Int)
```

Derives the next message key for receiving without performing full message decryption. This method is designed for advanced use cases where you want to handle decryption externally while the SDK manages ratchet key derivation.

**Parameters:**
- `sessionId`: The UUID of the session to derive the key for
- `cipherText`: The MLKEM ciphertext. Used during handshake to derive root key if needed. After handshake, this parameter is not used but required for signature consistency.

**Returns:** A tuple containing:
  - The derived symmetric key for decrypting the next message
  - The message number (0-based index) for this message

**Throws:**
- `RatchetError.missingConfiguration`: If the session is not found
- `RatchetError.stateUninitialized`: If the session state is not initialized
- `RatchetError.receivingKeyIsNil`: If the receiving key is missing
- `RatchetError.rootKeyIsNil`: If the root key is missing when needed

**Important:** This method advances the ratchet state. Each call derives a new key. Do not call this method multiple times for the same message.

**Warning:** This method is available in `RatchetKeyStateManager`, not `DoubleRatchetStateManager`. It should **only be used when NOT encrypting/decrypting messages via `ratchetEncrypt`/`ratchetDecrypt`**. These methods (`deriveMessageKey`, `deriveReceivedMessageKey`, `getSentMessageNumber`, `getReceivedMessageNumber`, `setCipherText`, `getCipherText`) are designed for external key derivation workflows. Do not mix these methods with the standard encryption/decryption API, as this may cause state inconsistencies and security issues.

**See Also:** `deriveMessageKey(sessionId:)` for the sending side equivalent.

##### Session Management

```swift
public func setDelegate(_ delegate: SessionIdentityDelegate) async
```

Set a delegate for session identity management.

**Parameters:**
- `delegate`: An object conforming to `SessionIdentityDelegate`. Pass `nil` to remove the current delegate.

**Delegate Responsibilities:**
- Persisting session identities to storage via `updateSessionIdentity(_:)`
- Fetching one-time private keys by ID via `fetchOneTimePrivateKey(_:)`
- Managing one-time key rotation via `updateOneTimeKey(remove:)`

**Important:** The delegate should be set before calling initialization methods if you want session state to be persisted automatically.

**Parameters:**
- `delegate`: An object conforming to `SessionIdentityDelegate`

```swift
public func setEnforceOTKConsistency(_ value: Bool)
```

Enable or disable strict one-time-prekey (OTK) consistency enforcement.

**Parameters:**
- `value`: `true` to enable strict validation, `false` to disable

**Behavior:**
- **When enabled**: If the header signals an OTK but the corresponding local private OTK cannot be loaded, decryption will fail fast with `RatchetError.missingOneTimeKey`.
- **When disabled**: Decryption proceeds even if the OTK is missing, potentially failing later during the actual decryption operation.

**Note:** This should be enabled when using a delegate that manages one-time keys to ensure keys are properly fetched and validated before use.

```swift
public func setLogLevel(_ level: Level) async
```

Set the logging level for the ratchet state manager.

**Parameters:**
- `level`: The desired log level. Available levels (from most to least verbose):
  - `.trace`: Most verbose, includes all debug information
  - `.debug`: Debug information including operations
  - `.info`: Informational messages
  - `.warning`: Warning messages
  - `.error`: Only error messages

**Note:** The default log level is `.trace`. Adjust this in production to reduce logging overhead.

```swift
public func shutdown() async throws
```

Shuts down the ratchet state manager and persists all session states.

**Lifecycle:**
- Persists all session states to storage via the delegate
- Clears in-memory session configurations
- Marks the manager as shut down

**Important:**
- The manager cannot be used after `shutdown()` is called
- If `shutdown()` is not called, the `deinit` will crash with a precondition failure
- This method is safe to call multiple times (idempotent after first call)

**Throws:** An error if session state persistence fails through the delegate.

#### Properties

```swift
public nonisolated var unownedExecutor: UnownedSerialExecutor
```

Returns the executor used for non-isolated tasks. Provides access to the underlying `SerialExecutor` for coordination with the actor's executor.

```swift
public private(set) var sessionConfigurations: [UUID: SessionConfiguration]
```

All known session configurations keyed by session identity UUID. Read-only property containing all active session configurations managed by this ratchet state manager.

**Note:** The `SessionConfiguration` struct is public for type inspection only. Its properties are intentionally internal to prevent direct mutation, which could break the internal state management of the ratchet state manager. Use the public API methods to manage sessions rather than modifying configurations directly.

```swift
public weak var delegate: SessionIdentityDelegate?
```

The delegate for session identity management. Handles persistence of session identities and one-time key management. Set using `setDelegate(_:)` method.

```swift
public var enforceOTKConsistency: Bool
```

When enabled, enforces that one-time prekeys (OTK) are used exactly as indicated by the incoming header during the initial handshake. See `setEnforceOTKConsistency(_:)` for details.

## Protocols

### SessionIdentityDelegate

Protocol for managing session identities and keys.

```swift
public protocol SessionIdentityDelegate: AnyObject, Sendable
```

#### Required Methods

```swift
func updateSessionIdentity(_ identity: SessionIdentity) async throws
```

Updates the stored session identity.

```swift
func fetchOneTimePrivateKey(_ id: UUID?) async throws -> CurvePrivateKey?
```

Fetches a previously stored private one-time Curve25519 key by its unique identifier.

```swift
func updateOneTimeKey(remove id: UUID) async
```

Notifies that a new one-time key should be generated and made available.

## Key Types

### CurvePrivateKey

Wraps Curve25519 private keys with identification.

```swift
public struct CurvePrivateKey: Codable, Sendable, Equatable
```

#### Properties

```swift
public let id: UUID
public let rawRepresentation: Data
```

#### Initialization

```swift
public init(id: UUID = UUID(), _ rawRepresentation: Data) throws
```

**Parameters:**
- `id`: An optional UUID to tag this key
- `rawRepresentation`: The raw 32-byte Curve private key data

**Throws:** `KeyErrors.invalidKeySize` if the key size is not 32 bytes

### CurvePublicKey

Wraps Curve25519 public keys with identification.

```swift
public struct CurvePublicKey: Codable, Sendable, Hashable
```

#### Properties

```swift
public let id: UUID
public let rawRepresentation: Data
```

#### Initialization

```swift
public init(id: UUID = UUID(), _ rawRepresentation: Data) throws
```

**Parameters:**
- `id`: An optional UUID to tag this key
- `rawRepresentation`: The raw 32-byte Curve public key data

**Throws:** `KeyErrors.invalidKeySize` if the key size is not 32 bytes

### MLKEMPrivateKey

Wraps MLKEM1024 private keys with identification.

```swift
public struct MLKEMPrivateKey: Codable, Sendable, Equatable
```

#### Properties

```swift
public let id: UUID
public let rawRepresentation: Data
```

#### Initialization

```swift
public init(id: UUID = UUID(), _ rawRepresentation: Data) throws
```

**Parameters:**
- `id`: An optional UUID to tag this key
- `rawRepresentation`: The raw MLKEM private key bytes

**Throws:** `KeyErrors.invalidKeySize` if the key size is incorrect

### MLKEMPublicKey

Wraps MLKEM1024 public keys with identification.

```swift
public struct MLKEMPublicKey: Codable, Sendable, Equatable, Hashable
```

#### Properties

```swift
public let id: UUID
public let rawRepresentation: Data
```

#### Initialization

```swift
public init(id: UUID = UUID(), _ rawRepresentation: Data) throws
```

**Parameters:**
- `id`: An optional UUID to tag this key
- `rawRepresentation`: The raw MLKEM public key bytes

**Throws:** `KeyErrors.invalidKeySize` if the key size is incorrect

## Key Containers

### RemoteKeys

Container for all remote public keys.

```swift
public struct RemoteKeys
```

#### Properties

```swift
let longTerm: CurvePublicKey
let oneTime: CurvePublicKey?
let mlKEM: MLKEMPublicKey
```

#### Initialization

```swift
public init(
    longTerm: CurvePublicKey,
    oneTime: CurvePublicKey?,
    mlKEM: MLKEMPublicKey
)
```

### LocalKeys

Container for all local private keys.

```swift
public struct LocalKeys
```

#### Properties

```swift
let longTerm: CurvePrivateKey
let oneTime: CurvePrivateKey?
let mlKEM: MLKEMPrivateKey
```

#### Initialization

```swift
public init(
    longTerm: CurvePrivateKey,
    oneTime: CurvePrivateKey?,
    mlKEM: MLKEMPrivateKey
)
```

## Session Identity

### SessionIdentity

A secure model for managing encrypted session identities.

```swift
public final class SessionIdentity: SecureModelProtocol, @unchecked Sendable
```

#### Properties

```swift
public let id: UUID
public var data: Data
```

#### Initialization

```swift
public init(
    id: UUID,
    props: UnwrappedProps,
    symmetricKey: SymmetricKey
) throws
```

Create a new session identity with encrypted properties.

```swift
public init(id: UUID, data: Data)
```

Create a session identity from existing encrypted data.

#### Methods

```swift
public func props(symmetricKey: SymmetricKey) async -> UnwrappedProps?
```

Asynchronously retrieves the decrypted properties.

```swift
public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps
```

Decrypts the stored properties using the provided symmetric key.

```swift
public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps?
```

Updates the properties and returns the updated decrypted properties.

```swift
public func updateIdentityProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws
```

Updates the properties without returning the decrypted result.

### UnwrappedProps

The decrypted session properties structure.

```swift
public struct UnwrappedProps: Codable & Sendable
```

#### Properties

```swift
public let secretName: String
public let deviceId: UUID
public let sessionContextId: Int
public var longTermPublicKey: Data
public let signingPublicKey: Data
public let oneTimePublicKey: CurvePublicKey?
public var mlKEMPublicKey: MLKEMPublicKey
public var state: RatchetState?
public let deviceName: String
public var serverTrusted: Bool?
public var previousRekey: Date?
public var isMasterDevice: Bool
public var verifiedIdentity: Bool
public var verificationCode: String?
```

## Message Types

### RatchetMessage

Represents an encrypted message along with its header.

```swift
public struct RatchetMessage: Codable, Sendable, Hashable
```

#### Properties

```swift
public let header: EncryptedHeader
let encryptedData: Data
```

#### Initialization

```swift
public init(header: EncryptedHeader, encryptedData: Data)
```

### EncryptedHeader

Represents the header of an encrypted message.

```swift
public struct EncryptedHeader: Sendable, Codable, Hashable
```

#### Properties

```swift
public let remoteLongTermPublicKey: RemoteLongTermPublicKey
public let remoteOneTimePublicKey: RemoteOneTimePublicKey?
public let remoteMLKEMPublicKey: RemoteMLKEMPublicKey
public let headerCiphertext: Data
public let messageCiphertext: Data
public let oneTimeKeyId: UUID?
public let mlKEMOneTimeKeyId: UUID?
public let encrypted: Data
public private(set) var decrypted: MessageHeader?
```

#### Methods

```swift
public mutating func setDecrypted(_ decrypted: MessageHeader)
```

Sets the decrypted message header.

### MessageHeader

Represents the header of a message.

```swift
public struct MessageHeader: Sendable, Codable
```

#### Properties

```swift
public let previousChainLength: Int
public let messageNumber: Int
```

#### Initialization

```swift
public init(previousChainLength: Int, messageNumber: Int)
```

## Configuration

### RatchetConfiguration

Configuration for the Double Ratchet protocol.

```swift
public struct RatchetConfiguration: Sendable, Codable
```

#### Properties

```swift
public let messageKeyData: Data
public let chainKeyData: Data
public let rootKeyData: Data
public let associatedData: Data
public let maxSkippedMessageKeys: Int
```

#### Initialization

```swift
public init(
    messageKeyData: Data,
    chainKeyData: Data,
    rootKeyData: Data,
    associatedData: Data,
    maxSkippedMessageKeys: Int
)
```

### Default Configuration

```swift
let defaultRatchetConfiguration = RatchetConfiguration(
    messageKeyData: Data([0x00]),
    chainKeyData: Data([0x01]),
    rootKeyData: Data([0x02, 0x03]),
    associatedData: "DoubleRatchetKit".data(using: .ascii)!,
    maxSkippedMessageKeys: 100
)
```

## State Management

### RatchetState

Represents the state of the Double Ratchet protocol.

```swift
public struct RatchetState: Sendable, Codable
```

#### Key Properties

```swift
private(set) public var localLongTermPrivateKey: LocalLongTermPrivateKey
private(set) public var localOneTimePrivateKey: LocalOneTimePrivateKey?
private(set) public var localMLKEMPrivateKey: LocalMLKEMPrivateKey
private(set) public var remoteLongTermPublicKey: RemoteLongTermPublicKey
private(set) public var remoteOneTimePublicKey: RemoteOneTimePublicKey?
private(set) public var remoteMLKEMPublicKey: RemoteMLKEMPublicKey
private(set) var rootKey: SymmetricKey?
private(set) var sendingKey: SymmetricKey?
private(set) var receivingKey: SymmetricKey?
private(set) var sentMessagesCount: Int
private(set) var receivedMessagesCount: Int
private(set) var sendingHandshakeFinished: Bool
private(set) var receivingHandshakeFinished: Bool
```

#### State Update Methods

```swift
func updateRootKey(_ rootKey: SymmetricKey) async -> Self
func updateSendingKey(_ sendingKey: SymmetricKey) async -> Self
func updateReceivingKey(_ receivingKey: SymmetricKey) async -> Self
func incrementSentMessagesCount() async -> Self
func incrementReceivedMessagesCount() async -> Self
func updateSendingHandshakeFinished(_ finished: Bool) async -> Self
func updateReceivingHandshakeFinished(_ finished: Bool) async -> Self
```

## Error Types

### RatchetError

Enum representing possible errors in the Double Ratchet protocol.

```swift
public enum RatchetError: Error
```

#### Error Cases

```swift
case missingConfiguration        // Session configuration is missing
case missingProps                 // Session properties are missing
case sendingKeyIsNil             // Sending key is missing
case receivingKeyIsNil           // Receiving key is missing
case headerDataIsNil             // Header data is missing
case invalidNonceLength          // Nonce length is invalid
case encryptionFailed            // Encryption operation failed
case decryptionFailed            // Decryption operation failed
case expiredKey                  // Message uses an expired key
case stateUninitialized          // Session state is not initialized
case missingCipherText          // Ciphertext is missing
case headerKeysNil               // Header keys are missing
case headerEncryptionFailed      // Header encryption failed
case headerDecryptFailed         // Header decryption failed
case missingNextHeaderKey        // Next header key is missing
case missingOneTimeKey          // One-time prekey is missing or unavailable
case delegateNotSet             // Session identity delegate is not set
case receivingHeaderKeyIsNil    // Receiving header key is missing
case maxSkippedHeadersExceeded  // Maximum number of skipped headers exceeded
case rootKeyIsNil                // Root key is missing
case initialMessageNotReceived  // Initial message has not been received
case skippedKeysDrained         // Skipped message keys have been exhausted
```

### KeyErrors

Errors that can occur during key validation and initialization.

```swift
public enum KeyErrors: Error
```

#### Error Cases

```swift
case invalidKeySize  // The key size is invalid for the expected key type
```

### CryptoError

Custom error type for encryption-related errors.

```swift
public enum CryptoError: Error
```

#### Error Cases

```swift
case encryptionFailed    // Encryption operation failed
case decryptionFailed    // Decryption operation failed
case propsError          // Error accessing session properties
case messageOutOfOrder   // Message received out of order
```

## Type Aliases

```swift
public typealias RemoteLongTermPublicKey = Data
public typealias RemoteOneTimePublicKey = CurvePublicKey
public typealias RemoteMLKEMPublicKey = MLKEMPublicKey
public typealias LocalLongTermPrivateKey = Data
public typealias LocalOneTimePrivateKey = CurvePrivateKey
public typealias LocalMLKEMPrivateKey = MLKEMPrivateKey
```

## Extensions

### SecureModelProtocol

Protocol defining the base model functionality.

```swift
public protocol SecureModelProtocol: Codable, Sendable
```

#### Associated Types

```swift
associatedtype Props: Codable & Sendable
```

#### Required Methods

```swift
func decryptProps(symmetricKey: SymmetricKey) async throws -> Props
func updateProps(symmetricKey: SymmetricKey, props: Props) async throws -> Props?
func makeDecryptedModel<T: Sendable & Codable>(of: T.Type, symmetricKey: SymmetricKey) async throws -> T
```

## Internal Types

### SessionConfiguration

Represents session identity and associated symmetric key for key derivation. This is an internal implementation detail exposed for inspection only.

```swift
public struct SessionConfiguration: Sendable
```

**Note:** This struct is public for type inspection only. Its properties are intentionally internal to prevent direct mutation, which could break the internal state management of the ratchet state manager. Use the public API methods to manage sessions rather than modifying configurations directly.

**Access:** Available through the `sessionConfigurations` property on `DoubleRatchetStateManager`.

## Related Documentation

- <doc:DoubleRatchetStateManager> - Main protocol interface
- <doc:SessionIdentity> - Session identity management
- <doc:KeyManagement> - Cryptographic key handling 
