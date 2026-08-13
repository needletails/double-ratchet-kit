# API Reference

Complete API reference for DoubleRatchetKit.

## Overview

This document provides a comprehensive reference for all public APIs in DoubleRatchetKit, including classes, protocols, structs, and functions.

## Core Classes

### MessageRatchet

The main actor that manages the cryptographic state for secure messaging.

```swift
public actor MessageRatchet
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
- Protocol context data: "DoubleRatchetKit"

**Note:** Use a custom `ratchetConfiguration` only if you need to modify protocol parameters for compatibility or security requirements. The default configuration is suitable for most use cases.

#### Core Methods

##### Session Initialization

```swift
public func openAsSender(
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
public func openAsRecipient(
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

The KeyRatchet recipient path takes `localKeys`, `remoteKeys`, and `ciphertext` instead of `header`. See <doc:UsingKeyRatchet>.

##### Message Operations

```swift
public func encrypt(plainText: Data, sessionId: UUID) async throws -> RatchetMessage
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
public func decrypt(_ message: RatchetMessage, sessionId: UUID) async throws -> Data
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

##### Session Management

```swift
public func setDelegate(_ delegate: SessionIdentityDelegate) async
```

Set a delegate for session identity management.

**Parameters:**
- `delegate`: An object conforming to `SessionIdentityDelegate`

**Delegate Responsibilities:**
- Persisting session identities to storage via `updateSessionIdentity(_:)`
- Fetching one-time private keys by ID via `fetchOneTimePrivateKey(_:)`
- Managing one-time key rotation via `updateOneTimeKey(remove:)`

**Important:** The delegate should be set before calling initialization methods if you want session state to be persisted automatically.

```swift
public func setEnforceOTKConsistency(_ value: Bool) async
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
public func sessionStatus(sessionId: UUID) async throws -> RatchetSessionStatus
```

Read-only sent/received counts and handshake phase. Replaces the deleted counter getters. Hosts should not reach into `RatchetState`.

```swift
public func discardCachedLane(_ id: UUID) async
```

Drops the in-memory cached lane after the caller rolls back a persisted `SessionIdentity`.

```swift
public func flushAndClose() async throws
```

Shuts down the ratchet state manager and persists all session states.

**Lifecycle:**
- Persists all session states to storage via the delegate
- Clears in-memory session configurations
- Marks the manager as shut down

**Important:**
- The manager cannot be used after `flushAndClose()` is called
- `flushAndClose()` is idempotent; further session operations after close are unsupported
- This method is safe to call multiple times (idempotent after first call)

**Throws:** An error if session state persistence fails through the delegate.

#### Properties

```swift
public nonisolated var unownedExecutor: UnownedSerialExecutor
```

Returns the executor used for non-isolated tasks. Provides access to the underlying `SerialExecutor` for coordination with the actor's executor.

**Note:** Session configurations, the delegate, and the OTK consistency flag are intentionally not exposed as public properties. Use `setDelegate(_:)`, `setEnforceOTKConsistency(_:)`, and `sessionStatus(sessionId:)` instead.

### KeyRatchet

The façade for external key derivation. Same engine and lifecycle methods as `MessageRatchet` (`setDelegate`, `setEnforceOTKConsistency`, `setLogLevel`, `sessionStatus`, `flushAndClose`), but it derives keys instead of producing `RatchetMessage` frames. Do not mix the two façades on one session. See <doc:UsingKeyRatchet> for usage.

```swift
public actor KeyRatchet
```

#### Session Initialization

`openAsSender` matches `MessageRatchet`. The recipient path bootstraps from PQXDH ciphertext instead of an encrypted header:

```swift
public func openAsRecipient(
    sessionIdentity: SessionIdentity,
    sessionSymmetricKey: SymmetricKey,
    localKeys: LocalKeys,
    remoteKeys: RemoteKeys,
    ciphertext: Data
) async throws
```

#### Key Derivation

```swift
public func nextSendKey(sessionId: UUID) async throws -> (SymmetricKey, Int)
```

Derives the next message key for sending without performing message encryption. The host encrypts with its own AEAD while the SDK manages ratchet key derivation.

**Returns:** A tuple containing:
  - The derived symmetric key for encrypting the next message
  - The message number (0-based index) for this message

**Throws:**
- `RatchetError.missingConfiguration`: If the session is not found
- `RatchetError.stateUninitialized`: If the session state is not initialized
- `RatchetError.sendingKeyIsNil`: If the sending key is missing
- `RatchetError.missingOneTimeKey`: If OTK consistency is enforced and the key is missing

**Important:** This method advances the ratchet state. Each call derives a new key and increments the message counter. Do not call this method multiple times for the same message.

```swift
public func receiveKey(for sessionId: UUID, cipherText: Data) async throws -> (SymmetricKey, Int)
```

Derives the next message key for receiving without performing message decryption.

**Parameters:**
- `sessionId`: The UUID of the session to derive the key for
- `cipherText`: The MLKEM ciphertext. Used during handshake to derive the root key if needed. After handshake, this parameter is not used but required for signature consistency.

**Returns:** A tuple containing:
  - The derived symmetric key for decrypting the next message
  - The message number (0-based index) for this message

**Throws:**
- `RatchetError.missingConfiguration`: If the session is not found
- `RatchetError.stateUninitialized`: If the session state is not initialized
- `RatchetError.receivingKeyIsNil`: If the receiving key is missing
- `RatchetError.rootKeyIsNil`: If the root key is missing when needed

**Important:** This method advances the ratchet state. Each call derives a new key. Do not call this method multiple times for the same message.

```swift
public func getCipherText(sessionId: UUID) async throws -> Data
```

Returns the PQXDH handshake ciphertext from the sender's persisted state, for transport to the recipient's `openAsRecipient(ciphertext:)`.

**Warning:** `KeyRatchet` methods should **only be used when NOT encrypting/decrypting via `MessageRatchet.encrypt`/`decrypt`**. Mixing the two façades on the same session causes state inconsistencies and security issues.

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
func fetchOneTimePrivateKey(_ id: UUID?) async throws -> X25519PrivateKey?
```

Fetches a previously stored private one-time Curve25519 key by its unique identifier.

```swift
func updateOneTimeKey(remove id: UUID) async
```

Notifies that a new one-time key should be generated and made available.

## Key Types

### X25519PrivateKey

Wraps Curve25519 private keys with identification.

```swift
public struct X25519PrivateKey: Codable, Sendable, Equatable
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

**Throws:** `KeyError.invalidKeySize` if the key size is not 32 bytes

### X25519PublicKey

Wraps Curve25519 public keys with identification.

```swift
public struct X25519PublicKey: Codable, Sendable, Hashable
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

**Throws:** `KeyError.invalidKeySize` if the key size is not 32 bytes

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

**Throws:** `KeyError.invalidKeySize` if the key size is incorrect

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

**Throws:** `KeyError.invalidKeySize` if the key size is incorrect

## Key Containers

### RemoteKeys

Container for all remote public keys.

```swift
public struct RemoteKeys
```

#### Properties

```swift
public let longTerm: X25519PublicKey
public let oneTime: X25519PublicKey?
public let mlKEM: MLKEMPublicKey
```

#### Initialization

```swift
public init(
    longTerm: X25519PublicKey,
    oneTime: X25519PublicKey?,
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
public let longTerm: X25519PrivateKey
public let oneTime: X25519PrivateKey?
public let mlKEM: MLKEMPrivateKey
```

#### Initialization

```swift
public init(
    longTerm: X25519PrivateKey,
    oneTime: X25519PrivateKey?,
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
public func update(_ props: UnwrappedProps, symmetricKey: SymmetricKey) async throws
```

Re-encrypts and stores `props`. Encoding is still `UnwrappedProps` with keys `a`–`n`.

### UnwrappedProps

The decrypted session properties structure.

```swift
public struct UnwrappedProps: Codable & Sendable
```

#### Properties

```swift
public let secretName: String
public let deviceId: UUID
public var sessionContextId: Int
public var longTermPublicKey: Data
public var signingPublicKey: Data
public var oneTimePublicKey: X25519PublicKey?
public var mlKEMPublicKey: MLKEMPublicKey
public var deviceName: String
public var serverTrusted: Bool?
public var previousRekey: Date?
public var isMasterDevice: Bool
public var verifiedIdentity: Bool
public var verificationCode: String?
public var hasRatchetState: Bool
public var ratchetOneTimePrivateKey: X25519PrivateKey?
public var ratchetMLKEMPrivateKey: MLKEMPrivateKey?
public var ratchetReceivedMessagesCount: Int
public mutating func clearRatchetState()
```

The nested ratchet snapshot (coding key `"h"`) is internal. Mutate `deviceName` / `sessionContextId` on a decoded props value and `update` it to archive a lane — the snapshot rides along. Use `sessionStatus(sessionId:)` for live session progress.

## Message Types

### RatchetMessage

Represents an encrypted message along with its header.

```swift
public struct RatchetMessage: Codable, Sendable, Hashable
```

#### Properties

```swift
public let header: EncryptedHeader
public let ciphertext: Data
```

#### Initialization

```swift
public init(header: EncryptedHeader, ciphertext: Data)
```

### EncryptedHeader

Represents the header of an encrypted message.

```swift
public struct EncryptedHeader: Sendable, Codable, Hashable
```

#### Properties

```swift
public let remoteLongTermPublicKey: Data
public let remoteOneTimePublicKey: X25519PublicKey?
public let remoteMLKEMPublicKey: MLKEMPublicKey
public let headerCiphertext: Data
public let messageCiphertext: Data
public let oneTimeKeyId: UUID?
public let mlKEMOneTimeKeyId: UUID?
public let encrypted: Data
public private(set) var decrypted: MessageHeader?
```

`decrypted` only exists at runtime after decryption; it is set internally by the decrypt path and never serialized.

### MessageHeader

Represents the plaintext header of a message. The per-turn hybrid ratchet fields ride inside the *encrypted* header body, preserving metadata protection.

```swift
public struct MessageHeader: Sendable, Codable
```

#### Properties

```swift
public let previousChainLength: Int
public let messageNumber: Int
public let ratchetPublicKey: Data          // per-turn Curve25519 ratchet public key
public let ratchetKEMPublicKey: Data       // per-turn ML-KEM-1024 ratchet public key
public let ratchetKEMCiphertext: Data?     // nil on the initiator's PQXDH bootstrap chain
```

#### Initialization

```swift
public init(
    previousChainLength: Int,
    messageNumber: Int,
    ratchetPublicKey: Data,
    ratchetKEMPublicKey: Data,
    ratchetKEMCiphertext: Data? = nil
)
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

`associatedData` is authenticated as AES-GCM associated data for payload
encryption, together with the encoded ratchet header.

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

Internal Codable snapshot nested in `UnwrappedProps.state` (coding key `"h"`). Hosts should not reach into it; use `RatchetSessionStatus`. See <doc:RatchetState> for the persistence invariants.

```swift
struct RatchetState: Sendable, Codable  // internal in 4.0
```

### RatchetSessionStatus

The public, read-only view of a session's progress, returned by `sessionStatus(sessionId:)` on both façades.

```swift
public struct RatchetSessionStatus: Sendable, Equatable
```

#### Properties

```swift
public let sentMessagesCount: Int
public let receivedMessagesCount: Int
public let sendingHandshakeFinished: Bool
public let receivingHandshakeFinished: Bool
```

## Error Types

### RatchetError

Enum representing possible errors in the Double Ratchet protocol.

```swift
public enum RatchetError: Error, Equatable
```

#### Error Cases

```swift
case missingConfiguration        // Session configuration is missing
case missingProps                // Session properties are missing
case sendingKeyIsNil             // Sending key is missing
case receivingKeyIsNil           // Receiving key is missing
case encryptionFailed            // Encryption operation failed
case decryptionFailed            // Decryption operation failed
case expiredKey                  // Message uses an expired key
case stateUninitialized          // Session state is not initialized
case missingCipherText           // Ciphertext is missing
case headerKeysNil               // Header keys are missing
case headerEncryptionFailed      // Header encryption failed
case headerDecryptFailed         // Header decryption failed
case missingOneTimeKey           // One-time prekey is missing or unavailable
case receivingHeaderKeyIsNil     // Receiving header key is missing
case maxSkippedHeadersExceeded   // Maximum number of skipped headers exceeded
case rootKeyIsNil                // Root key is missing
```

Cases that could never be thrown (`missingNextHeaderKey`, `delegateNotSet`, `initialMessageNotReceived`, `skippedKeysDrained`) were deleted in 4.0.

### KeyError

Errors that can occur during key validation and initialization.

```swift
public enum KeyError: Error
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
```

## Related Documentation

- <doc:UsingMessageRatchet> - Integrated encrypt/decrypt façade
- <doc:UsingKeyRatchet> - External key derivation façade
- <doc:UsingSessionIdentity> - Session identity management
- <doc:KeyManagement> - Cryptographic key handling 
