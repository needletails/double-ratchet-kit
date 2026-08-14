# Using SessionIdentity

A secure model for managing encrypted session identities and cryptographic keys.

## Overview

`SessionIdentity` provides encrypted storage for session metadata and cryptographic keys. It implements the `SecureModelProtocol` to ensure all sensitive data is encrypted at rest and only accessible through secure interfaces.

## Declaration

```swift
public final class SessionIdentity: SecureModelProtocol, @unchecked Sendable
```

## Core Functionality

### Creating Session Identities

#### Initialization with Properties

Create a new session identity with encrypted properties:

```swift
let sessionIdentity = try SessionIdentity(
    id: sessionId,
    props: props,
    symmetricKey: sessionKey
)
```

**Parameters:**
- `id`: Unique identifier for the session
- `props`: Unwrapped properties containing session data
- `symmetricKey`: Symmetric key for encrypting the properties

#### Initialization with Data

Create a session identity from existing encrypted data:

```swift
let sessionIdentity = SessionIdentity(id: sessionId, data: encryptedData)
```

**Parameters:**
- `id`: Unique identifier for the session
- `data`: Pre-encrypted session data

### Accessing Properties

#### Retrieving Decrypted Properties

Access the decrypted session properties:

```swift
if let props = await sessionIdentity.props(symmetricKey: sessionKey) {
    // Use the decrypted properties
    print("Device: \(props.deviceName)")
    print("Long-term key: \(props.longTermPublicKey)")
}
```

**Parameters:**
- `symmetricKey`: The symmetric key used for decryption

**Returns:** Optional `UnwrappedProps` if decryption succeeds

#### Updating Properties

Update the session properties (immutable fields like `deviceName` are fixed at creation; mutable fields include `serverTrusted`, `previousRekey`, `verifiedIdentity`, and the key setters):

```swift
guard var updatedProps = await sessionIdentity.props(symmetricKey: sessionKey) else { return }
updatedProps.serverTrusted = true
updatedProps.previousRekey = Date()

try await sessionIdentity.update(
    updatedProps,
    symmetricKey: sessionKey
)
```

**Parameters:**
- `props`: The new properties to store
- `symmetricKey`: The symmetric key for encryption

## UnwrappedProps Structure

The `UnwrappedProps` struct contains all session metadata and cryptographic keys:

```swift
public struct UnwrappedProps: Codable & Sendable {
    public let secretName: String
    public let deviceId: UUID
    public var sessionContextId: Int
    
    // Cryptographic keys
    public var longTermPublicKey: Data
    public var signingPublicKey: Data
    public var oneTimePublicKey: X25519PublicKey?
    public var mlKEMPublicKey: MLKEMPublicKey
    
    // Session state is internal. Hosts use:
    // hasRatchetState, ratchetOneTimePrivateKey, ratchetMLKEMPrivateKey,
    // ratchetReceivedMessagesCount, clearRatchetState()
    
    // Device information
    public var deviceName: String
    public var serverTrusted: Bool?
    public var previousRekey: Date?
    public var isMasterDevice: Bool
    public var verifiedIdentity: Bool
    public var verificationCode: String?
}
```

### Key Properties

#### Identity Keys

- **`longTermPublicKey`**: Long-term Curve25519 public key (IKB)
- **`signingPublicKey`**: Signed pre-key Curve25519 public key (SPKB)
- **`oneTimePublicKey`**: Optional one-time Curve25519 public key (OPKBₙ)
- **`mlKEMPublicKey`**: Post-quantum MLKEM1024 public key (PQSPKB)

#### Session Information

- **`secretName`**: Human-readable name for the session
- **`deviceId`**: Unique device identifier
- **`sessionContextId`**: Context identifier for the session
- **`deviceName`**: Human-readable device name
- **`isMasterDevice`**: Whether this is the master device
- **`verifiedIdentity`**: Whether the identity has been verified

#### State Management

- **`state`**: Current ratchet state for the session
- **`serverTrusted`**: Whether the server is trusted
- **`previousRekey`**: Timestamp of last rekey operation
- **`verificationCode`**: Optional verification code

## SecureModelProtocol Implementation

`SessionIdentity` implements the `SecureModelProtocol` for secure data handling:

### Decryption

```swift
public func decryptProps(symmetricKey: SymmetricKey) async throws -> UnwrappedProps
```

Decrypts the stored properties using the provided symmetric key.

### Update Operations

```swift
public func updateProps(symmetricKey: SymmetricKey, props: UnwrappedProps) async throws -> UnwrappedProps?
```

Updates the properties and returns the updated decrypted properties.

```swift
public func update(_ props: UnwrappedProps, symmetricKey: SymmetricKey) async throws
```

Re-encrypts and stores `props`. Encoding is still `UnwrappedProps` with keys `a`–`n`.

## Key Management

### Creating Key Wrappers

Session identities work with key wrapper types for secure key management:

```swift
// Curve25519 keys
let curvePrivateKey = try X25519PrivateKey(id: UUID(), curve25519PrivateKey.rawRepresentation)
let curvePublicKey = try X25519PublicKey(id: UUID(), curve25519PublicKey.rawRepresentation)

// MLKEM1024 keys (private wraps encode(), public wraps rawRepresentation)
let kemPrivateKey = try MLKEMPrivateKey(id: UUID(), mlKEM1024PrivateKey.encode())
let kemPublicKey = try MLKEMPublicKey(id: UUID(), mlKEM1024PublicKey.rawRepresentation)
```

### Key Validation

Key wrappers automatically validate key sizes:

```swift
// Curve25519 keys must be 32 bytes
guard rawRepresentation.count == 32 else {
    throw KeyError.invalidKeySize
}

// MLKEM1024 public keys must be the correct size
guard rawRepresentation.count == Int(MLKEM1024PublicKeyLength) else {
    throw KeyError.invalidKeySize
}
```

## Error Handling

### Common Errors

```swift
do {
    let props = try await sessionIdentity.decryptProps(symmetricKey: sessionKey)
} catch CryptoError.decryptionFailed {
    // Decryption failed - check symmetric key
} catch CryptoError.encryptionFailed {
    // Encryption failed during update
} catch CryptoError.propsError {
    // Properties error
} catch {
    // Handle other errors
}
```

## Security Considerations

### Encryption at Rest

All session data is encrypted using the provided symmetric key:

```swift
// Data is encrypted before storage
let data = try BinaryEncoder().encode(props)
guard let encryptedData = try crypto.encrypt(data: data, symmetricKey: symmetricKey) else {
    throw CryptoError.encryptionFailed
}
```

### Key Management

- **Symmetric Key**: Must be kept secure and not shared
- **Key Derivation**: Use strong key derivation functions
- **Key Rotation**: Rotate keys periodically
- **Secure Storage**: Store keys in secure enclaves when possible

### Memory Safety

- **Encrypted at rest**: Plaintext props exist only transiently during `decryptProps`/`update`
- **Synchronized storage**: The encrypted payload is guarded by a `Mutex`, so instances can safely cross actor boundaries
- **Access Control**: Only accessible through secure interfaces

## Example Usage

### Complete Example

```swift
import DoubleRatchetKit
import Crypto

// Create session properties
let props = SessionIdentity.UnwrappedProps(
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

// Create session identity
let sessionIdentity = try SessionIdentity(
    id: UUID(),
    props: props,
    symmetricKey: sessionKey
)

// Access properties
if let decryptedProps = await sessionIdentity.props(symmetricKey: sessionKey) {
    print("Device: \(decryptedProps.deviceName)")
    print("Verified: \(decryptedProps.verifiedIdentity)")
}

// Update properties
if var updatedProps = await sessionIdentity.props(symmetricKey: sessionKey) {
    updatedProps.verifiedIdentity = true
    try await sessionIdentity.update(
        updatedProps,
        symmetricKey: sessionKey
    )
}
```

## Performance Considerations

### Optimization Tips

1. **Reuse Instances**: Reuse session identities when possible
2. **Efficient Encryption**: Use efficient symmetric encryption algorithms
3. **Caching**: Cache decrypted properties when appropriate
4. **Memory Usage**: Monitor memory usage for large key sets

### Scalability

- **Multiple Sessions**: Each session should have its own identity
- **Key Rotation**: Plan for efficient key rotation
- **Storage**: Consider storage requirements for many sessions

## Related Documentation

- <doc:UsingMessageRatchet> - Main protocol interface
- <doc:RatchetState> - Session state management
- <doc:KeyManagement> - Cryptographic key handling
- <doc:SecurityModel> - Security considerations 
