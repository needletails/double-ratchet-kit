# API Reference

Complete API reference for DoubleRatchetKit.

## Overview

This document provides a comprehensive reference for all public APIs in DoubleRatchetKit, including classes, protocols, structs, and functions.

## Core Classes

### RatchetStateManager

The main actor that manages the cryptographic state for secure messaging.

```swift
public actor RatchetStateManager<Hash: HashFunction & Sendable>
```

#### Initialization

```swift
public init(executor: any SerialExecutor, logger: NeedleTailLogger = NeedleTailLogger())
```

**Parameters:**
- `executor`: A `SerialExecutor` used to coordinate concurrent operations
- `logger`: A `NeedleTailLogger` instance for logging (optional)

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

```swift
public func recipientInitialization(
    sessionIdentity: SessionIdentity,
    sessionSymmetricKey: SymmetricKey,
    remoteKeys: RemoteKeys,
    localKeys: LocalKeys
) async throws
```

Initialize a session for receiving messages.

##### Message Operations

```swift
public func ratchetEncrypt(plainText: Data) async throws -> RatchetMessage
```

Encrypt a plaintext message.

**Parameters:**
- `plainText`: The plaintext data to encrypt

**Returns:** A `RatchetMessage` containing the encrypted payload and header

**Throws:**
- `RatchetError.stateUninitialized`: If the session is not initialized
- `RatchetError.sendingKeyIsNil`: If the sending key is missing
- `RatchetError.encryptionFailed`: If encryption fails
- `RatchetError.headerEncryptionFailed`: If header encryption fails

```swift
public func ratchetDecrypt(_ message: RatchetMessage) async throws -> Data
```

Decrypt a received message.

**Parameters:**
- `message`: The `RatchetMessage` to decrypt

**Returns:** The decrypted plaintext data

**Throws:**
- `RatchetError.stateUninitialized`: If the session is not initialized
- `RatchetError.decryptionFailed`: If decryption fails
- `RatchetError.headerDecryptFailed`: If header decryption fails
- `RatchetError.expiredKey`: If the message uses an expired key

##### Session Management

```swift
public func setDelegate(_ delegate: SessionIdentityDelegate)
```

Set a delegate for session identity management.

```swift
public func shutdown() async throws
```

Clean up resources when done.

#### Properties

```swift
public nonisolated var unownedExecutor: UnownedSerialExecutor
```

Returns the executor used for non-isolated tasks.

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

**Throws:** `KyberError.invalidKeySize` if the key size is not 32 bytes

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

**Throws:** `KyberError.invalidKeySize` if the key size is not 32 bytes

### PQKemPrivateKey

Wraps Kyber1024 private keys with identification.

```swift
public struct PQKemPrivateKey: Codable, Sendable, Equatable
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
- `rawRepresentation`: The raw PQKem private key bytes

**Throws:** `KyberError.invalidKeySize` if the key size is incorrect

### PQKemPublicKey

Wraps Kyber1024 public keys with identification.

```swift
public struct PQKemPublicKey: Codable, Sendable, Equatable, Hashable
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
- `rawRepresentation`: The raw PQKem public key bytes

**Throws:** `KyberError.invalidKeySize` if the key size is incorrect

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
let pqKem: PQKemPublicKey
```

#### Initialization

```swift
public init(
    longTerm: CurvePublicKey,
    oneTime: CurvePublicKey?,
    pqKem: PQKemPublicKey
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
let pqKem: PQKemPrivateKey
```

#### Initialization

```swift
public init(
    longTerm: CurvePrivateKey,
    oneTime: CurvePrivateKey?,
    pqKem: PQKemPrivateKey
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
public var pqKemPublicKey: PQKemPublicKey
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
public let remotePQKemPublicKey: RemotePQKemPublicKey
public let headerCiphertext: Data
public let messageCiphertext: Data
public let oneTimeKeyId: UUID?
public let pqKemOneTimeKeyId: UUID?
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
let messageKeyData: Data
let chainKeyData: Data
let rootKeyData: Data
let associatedData: Data
let maxSkippedMessageKeys: Int
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
    maxSkippedMessageKeys: 80
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
private(set) public var localPQKemPrivateKey: LocalPQKemPrivateKey
private(set) public var remoteLongTermPublicKey: RemoteLongTermPublicKey
private(set) public var remoteOneTimePublicKey: RemoteOneTimePublicKey?
private(set) public var remotePQKemPublicKey: RemotePQKemPublicKey
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
case missingConfiguration
case missingProps
case sendingKeyIsNil
case receivingKeyIsNil
case headerDataIsNil
case invalidNonceLength
case encryptionFailed
case decryptionFailed
case expiredKey
case stateUninitialized
case missingCipherText
case headerKeysNil
case headerEncryptionFailed
case headerDecryptFailed
case missingNextHeaderKey
case missingOneTimeKey
case delegateNotSet
case receivingHeaderKeyIsNil
case maxSkippedHeadersExceeded
case rootKeyIsNil
case initialMessageNotReceived
case skippedKeysDrained
```

### CryptoError

Custom error type for encryption-related errors.

```swift
public enum CryptoError: Error
```

#### Error Cases

```swift
case encryptionFailed
case decryptionFailed
case propsError
case messageOutOfOrder
```

## Type Aliases

```swift
public typealias RemoteLongTermPublicKey = Data
public typealias RemoteOneTimePublicKey = CurvePublicKey
public typealias RemotePQKemPublicKey = PQKemPublicKey
public typealias LocalLongTermPrivateKey = Data
public typealias LocalOneTimePrivateKey = CurvePrivateKey
public typealias LocalPQKemPrivateKey = PQKemPrivateKey
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

## Related Documentation

- <doc:RatchetStateManager> - Main protocol interface
- <doc:SessionIdentity> - Session identity management
- <doc:KeyManagement> - Cryptographic key handling 