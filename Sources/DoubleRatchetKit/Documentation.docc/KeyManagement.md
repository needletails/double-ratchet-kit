# Key Management

Comprehensive guide to managing cryptographic keys in DoubleRatchetKit.

## Overview

DoubleRatchetKit uses a sophisticated key management system that combines classical (Curve25519) and post-quantum (Kyber1024) cryptography. This system provides forward secrecy, post-compromise security, and protection against quantum attacks.

## Key Types

### Classical Keys (Curve25519)

#### CurvePrivateKey

Wraps Curve25519 private keys with identification:

```swift
public struct CurvePrivateKey: Codable, Sendable, Equatable {
    public let id: UUID
    public let rawRepresentation: Data
}
```

**Usage:**
```swift
let curvePrivateKey = try CurvePrivateKey(
    id: UUID(), 
    curve25519PrivateKey.rawRepresentation
)
```

**Validation:**
- Must be exactly 32 bytes
- Throws `KyberError.invalidKeySize` if invalid

#### CurvePublicKey

Wraps Curve25519 public keys with identification:

```swift
public struct CurvePublicKey: Codable, Sendable, Hashable {
    public let id: UUID
    public let rawRepresentation: Data
}
```

**Usage:**
```swift
let curvePublicKey = try CurvePublicKey(
    id: UUID(), 
    curve25519PublicKey.rawRepresentation
)
```

**Validation:**
- Must be exactly 32 bytes
- Throws `KyberError.invalidKeySize` if invalid

### Post-Quantum Keys (Kyber1024)

#### PQKemPrivateKey

Wraps Kyber1024 private keys with identification:

```swift
public struct PQKemPrivateKey: Codable, Sendable, Equatable {
    public let id: UUID
    public let rawRepresentation: Data
}
```

**Usage:**
```swift
let kyberPrivateKey = try PQKemPrivateKey(
    id: UUID(), 
    kyber1024PrivateKey.rawRepresentation
)
```

**Validation:**
- Must be exactly `kyber1024PrivateKeyLength` bytes
- Throws `KyberError.invalidKeySize` if invalid

#### PQKemPublicKey

Wraps Kyber1024 public keys with identification:

```swift
public struct PQKemPublicKey: Codable, Sendable, Equatable, Hashable {
    public let id: UUID
    public let rawRepresentation: Data
}
```

**Usage:**
```swift
let kyberPublicKey = try PQKemPublicKey(
    id: UUID(), 
    kyber1024PublicKey.rawRepresentation
)
```

**Validation:**
- Must be exactly `kyber1024PublicKeyLength` bytes
- Throws `KyberError.invalidKeySize` if invalid

## Key Containers

### RemoteKeys

Container for all remote public keys:

```swift
public struct RemoteKeys {
    let longTerm: CurvePublicKey
    let oneTime: CurvePublicKey?
    let pqKem: PQKemPublicKey
}
```

**Usage:**
```swift
let remoteKeys = RemoteKeys(
    longTerm: bobLongTermPublicKey,
    oneTime: bobOneTimePublicKey,
    pqKem: bobPQKemPublicKey
)
```

### LocalKeys

Container for all local private keys:

```swift
public struct LocalKeys {
    let longTerm: CurvePrivateKey
    let oneTime: CurvePrivateKey?
    let pqKem: PQKemPrivateKey
}
```

**Usage:**
```swift
let localKeys = LocalKeys(
    longTerm: aliceLongTermPrivateKey,
    oneTime: aliceOneTimePrivateKey,
    pqKem: alicePQKemPrivateKey
)
```

## Key Lifecycle

### Key Generation

#### Curve25519 Keys

```swift
import Crypto

// Generate Curve25519 key pair
let privateKey = Curve25519.KeyAgreement.PrivateKey()
let publicKey = privateKey.publicKey

// Wrap keys
let curvePrivateKey = try CurvePrivateKey(
    id: UUID(), 
    privateKey.rawRepresentation
)
let curvePublicKey = try CurvePublicKey(
    id: UUID(), 
    publicKey.rawRepresentation
)
```

#### Kyber1024 Keys

```swift
import SwiftKyber

// Generate Kyber1024 key pair
let privateKey = Kyber1024.KeyAgreement.PrivateKey()
let publicKey = privateKey.publicKey

// Wrap keys
let kyberPrivateKey = try PQKemPrivateKey(
    id: UUID(), 
    privateKey.rawRepresentation
)
let kyberPublicKey = try PQKemPublicKey(
    id: UUID(), 
    publicKey.rawRepresentation
)
```

### Key Storage

#### Secure Storage

Store keys securely using the session identity:

```swift
// Create session identity with keys
let props = SessionIdentity.UnwrappedProps(
    secretName: "alice_session",
    deviceId: UUID(),
    sessionContextId: 1,
    longTermPublicKey: curvePublicKey.rawRepresentation,
    signingPublicKey: signingPublicKey.rawRepresentation,
    pqKemPublicKey: kyberPublicKey,
    oneTimePublicKey: oneTimePublicKey,
    deviceName: "Alice's iPhone",
    isMasterDevice: true
)

let sessionIdentity = try SessionIdentity(
    id: UUID(),
    props: props,
    symmetricKey: sessionKey
)
```

#### Delegate Implementation

Implement the delegate for key management:

```swift
class SecureKeyManager: SessionIdentityDelegate {
    func updateSessionIdentity(_ identity: SessionIdentity) async throws {
        // Store encrypted session identity
        try await storage.save(identity)
    }
    
    func fetchOneTimePrivateKey(_ id: UUID?) async throws -> CurvePrivateKey? {
        // Retrieve one-time key from secure storage
        guard let id = id else { return nil }
        return try await storage.fetchOneTimeKey(id: id)
    }
    
    func updateOneTimeKey(remove id: UUID) async {
        // Remove used one-time key and generate replacement
        await storage.removeOneTimeKey(id: id)
        await generateNewOneTimeKey()
    }
}
```

### Key Rotation

#### One-Time Key Rotation

One-time keys are automatically rotated after use:

```swift
// After using a one-time key, it's automatically removed
func updateOneTimeKey(remove id: UUID) async {
    // Remove from storage
    await storage.removeOneTimeKey(id: id)
    
    // Generate new one-time key
    let newPrivateKey = Curve25519.KeyAgreement.PrivateKey()
    let newPublicKey = newPrivateKey.publicKey
    
    let newOneTimeKey = try CurvePrivateKey(
        id: UUID(), 
        newPrivateKey.rawRepresentation
    )
    
    // Store new key
    await storage.storeOneTimeKey(newOneTimeKey)
    
    // Publish new public key
    await publishOneTimePublicKey(newPublicKey.rawRepresentation)
}
```

#### Long-Term Key Rotation

Long-term keys should be rotated periodically:

```swift
// Rotate long-term keys
func rotateLongTermKeys() async throws {
    // Generate new key pair
    let newPrivateKey = Curve25519.KeyAgreement.PrivateKey()
    let newPublicKey = newPrivateKey.publicKey
    
    // Update session identity
    var props = try await sessionIdentity.props(symmetricKey: sessionKey)
    props?.longTermPublicKey = newPublicKey.rawRepresentation
    
    try await sessionIdentity.updateIdentityProps(
        symmetricKey: sessionKey,
        props: props!
    )
    
    // Publish new public key
    await publishLongTermPublicKey(newPublicKey.rawRepresentation)
    
    // Update local keys
    let newLocalKeys = LocalKeys(
        longTerm: try CurvePrivateKey(id: UUID(), newPrivateKey.rawRepresentation),
        oneTime: localKeys.oneTime,
        pqKem: localKeys.pqKem
    )
    
    // Reinitialize session with new keys
    try await ratchetManager.senderInitialization(
        sessionIdentity: sessionIdentity,
        sessionSymmetricKey: sessionKey,
        remoteKeys: remoteKeys,
        localKeys: newLocalKeys
    )
}
```

## Key Exchange

### PQXDH Key Exchange

The protocol uses hybrid PQXDH for key exchange:

#### Sender Side

```swift
// Derive shared secret using PQXDH
let cipher = try await derivePQXDHFinalKey(
    localLongTermPrivateKey: localLongTermPrivateKey,
    remotePublicLongTermKey: remotePublicLongTermKey,
    localOneTimePrivateKey: localOneTimePrivateKey,
    remoteOneTimePublicKey: remoteOneTimePublicKey,
    remotePQKemPublicKey: remotePQKemPublicKey
)

// Use derived symmetric key
let symmetricKey = cipher.symmetricKey
let ciphertext = cipher.ciphertext
```

#### Receiver Side

```swift
// Derive shared secret from received ciphertext
let symmetricKey = try await derivePQXDHFinalKeyReceiver(
    remoteLongTermPublicKey: remoteLongTermPublicKey,
    remoteOneTimePublicKey: remoteOneTimePublicKey,
    localLongTermPrivateKey: localLongTermPrivateKey,
    localOneTimePrivateKey: localOneTimePrivateKey,
    localPQKemPrivateKey: localPQKemPrivateKey,
    receivedCiphertext: receivedCiphertext
)
```

## Key Validation

### Size Validation

All keys are automatically validated for correct size:

```swift
// Curve25519 keys must be 32 bytes
guard rawRepresentation.count == 32 else {
    throw KyberError.invalidKeySize
}

// Kyber1024 keys must be correct size
guard rawRepresentation.count == Int(kyber1024PublicKeyLength) else {
    throw KyberError.invalidKeySize
}
```

### Format Validation

Keys should be validated for correct format:

```swift
// Validate Curve25519 public key
func validateCurve25519PublicKey(_ data: Data) throws -> Bool {
    guard data.count == 32 else { return false }
    
    // Check if point is on curve (simplified)
    let firstByte = data[0]
    return (firstByte & 0x80) == 0
}
```

## Security Considerations

### Key Storage

- **Encryption**: All keys should be encrypted at rest
- **Access Control**: Implement proper access controls
- **Secure Deletion**: Ensure secure deletion of old keys
- **Backup Security**: Secure backup of cryptographic material

### Key Generation

- **Entropy**: Use cryptographically secure random number generators
- **Key Size**: Use appropriate key sizes for security level
- **Algorithm Selection**: Use standardized, well-vetted algorithms

### Key Distribution

- **Authenticity**: Verify key authenticity through secure channels
- **Integrity**: Protect keys during transmission
- **Freshness**: Ensure keys are fresh and not reused

### Key Compromise

- **Detection**: Monitor for signs of key compromise
- **Response**: Immediately rotate compromised keys
- **Recovery**: Implement recovery procedures
- **Audit**: Log all key operations for audit

## Performance Considerations

### Key Generation

- **Batch Generation**: Generate keys in batches when possible
- **Background Generation**: Generate keys in background threads
- **Caching**: Cache frequently used keys
- **Memory Usage**: Monitor memory usage for large key sets

### Key Storage

- **Efficient Storage**: Use efficient storage formats
- **Indexing**: Index keys for fast retrieval
- **Compression**: Consider compression for large key sets
- **Cleanup**: Regular cleanup of unused keys

## Example Usage

### Complete Key Management

```swift
import DoubleRatchetKit
import Crypto
import SwiftKyber

// Generate all required keys
let curvePrivateKey = Curve25519.KeyAgreement.PrivateKey()
let curvePublicKey = curvePrivateKey.publicKey

let kyberPrivateKey = Kyber1024.KeyAgreement.PrivateKey()
let kyberPublicKey = kyberPrivateKey.publicKey

let oneTimePrivateKey = Curve25519.KeyAgreement.PrivateKey()
let oneTimePublicKey = oneTimePrivateKey.publicKey

// Wrap keys
let localKeys = LocalKeys(
    longTerm: try CurvePrivateKey(id: UUID(), curvePrivateKey.rawRepresentation),
    oneTime: try CurvePrivateKey(id: UUID(), oneTimePrivateKey.rawRepresentation),
    pqKem: try PQKemPrivateKey(id: UUID(), kyberPrivateKey.rawRepresentation)
)

let remoteKeys = RemoteKeys(
    longTerm: try CurvePublicKey(id: UUID(), bobCurvePublicKey.rawRepresentation),
    oneTime: try CurvePublicKey(id: UUID(), bobOneTimePublicKey.rawRepresentation),
    pqKem: try PQKemPublicKey(id: UUID(), bobKyberPublicKey.rawRepresentation)
)

// Initialize session
try await ratchetManager.senderInitialization(
    sessionIdentity: sessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: remoteKeys,
    localKeys: localKeys
)
```

## Related Documentation

- <doc:RatchetStateManager> - Main protocol interface
- <doc:SessionIdentity> - Session identity management
- <doc:RatchetState> - Session state management
- <doc:SecurityModel> - Security considerations 