# Key Management

Comprehensive guide to managing cryptographic keys in DoubleRatchetKit.

## Overview

DoubleRatchetKit uses a sophisticated key management system that combines classical (Curve25519) and post-quantum (MLKEM1024) cryptography. This system provides forward secrecy, post-compromise security, and protection against quantum attacks.

## Key Types

### Classical Keys (Curve25519)

#### X25519PrivateKey

Wraps Curve25519 private keys with identification:

```swift
public struct X25519PrivateKey: Codable, Sendable, Equatable {
    public let id: UUID
    public let rawRepresentation: Data
}
```

**Usage:**
```swift
let curvePrivateKey = try X25519PrivateKey(
    id: UUID(), 
    curve25519PrivateKey.rawRepresentation
)
```

**Validation:**
- Must be exactly 32 bytes
- Throws `KeyError.invalidKeySize` if invalid

#### X25519PublicKey

Wraps Curve25519 public keys with identification:

```swift
public struct X25519PublicKey: Codable, Sendable, Hashable {
    public let id: UUID
    public let rawRepresentation: Data
}
```

**Usage:**
```swift
let curvePublicKey = try X25519PublicKey(
    id: UUID(), 
    curve25519PublicKey.rawRepresentation
)
```

**Validation:**
- Must be exactly 32 bytes
- Throws `KeyError.invalidKeySize` if invalid

### Post-Quantum Keys (MLKEM1024)

#### MLKEMPrivateKey

Wraps MLKEM1024 private keys with identification:

```swift
public struct MLKEMPrivateKey: Codable, Sendable, Equatable {
    public let id: UUID
    public let rawRepresentation: Data
}
```

**Usage:**
```swift
let kemPrivateKey = try MLKEMPrivateKey(
    id: UUID(), 
    mlKEM1024PrivateKey.encode()
)
```

**Validation:**
- Must be exactly `MLKEM1024PrivateKeyLength` bytes
- Throws `KeyError.invalidKeySize` if invalid

#### MLKEMPublicKey

Wraps MLKEM1024 public keys with identification:

```swift
public struct MLKEMPublicKey: Codable, Sendable, Equatable, Hashable {
    public let id: UUID
    public let rawRepresentation: Data
}
```

**Usage:**
```swift
let kemPublicKey = try MLKEMPublicKey(
    id: UUID(), 
    mlKEM1024PublicKey.rawRepresentation
)
```

**Validation:**
- Must be exactly `MLKEM1024PublicKeyLength` bytes
- Throws `KeyError.invalidKeySize` if invalid

## Key Containers

### RemoteKeys

Container for all remote public keys:

```swift
public struct RemoteKeys: Sendable {
    public let longTerm: X25519PublicKey
    public let oneTime: X25519PublicKey?
    public let mlKEM: MLKEMPublicKey
}
```

**Usage:**
```swift
let remoteKeys = RemoteKeys(
    longTerm: bobLongTermPublicKey,
    oneTime: bobOneTimePublicKey,
    mlKEM: bobMLKEMPublicKey
)
```

### LocalKeys

Container for all local private keys:

```swift
public struct LocalKeys: Sendable {
    public let longTerm: X25519PrivateKey
    public let oneTime: X25519PrivateKey?
    public let mlKEM: MLKEMPrivateKey
}
```

**Usage:**
```swift
let localKeys = LocalKeys(
    longTerm: aliceLongTermPrivateKey,
    oneTime: aliceOneTimePrivateKey,
    mlKEM: aliceMLKEMPrivateKey
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
let curvePrivateKey = try X25519PrivateKey(
    id: UUID(), 
    privateKey.rawRepresentation
)
let curvePublicKey = try X25519PublicKey(
    id: UUID(), 
    publicKey.rawRepresentation
)
```

#### MLKEM1024 Keys

```swift
import Crypto

// Generate MLKEM1024 key pair
let privateKey = try MLKEM1024.PrivateKey()
let publicKey = privateKey.publicKey

// Wrap keys — the private key wraps its encoded form,
// the public key wraps its raw representation
let keyId = UUID()
let kemPrivateKey = try MLKEMPrivateKey(id: keyId, privateKey.encode())
let kemPublicKey = try MLKEMPublicKey(id: keyId, publicKey.rawRepresentation)
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
    mlKEMPublicKey: kyberPublicKey,
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
    
    func fetchOneTimePrivateKey(_ id: UUID?) async throws -> X25519PrivateKey? {
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

### Skipped Message Keys

DoubleRatchetKit follows the Double Ratchet specification’s recommendation to store per-message keys (messageKey) for out-of-order messages. When a message with number n arrives and the receiver’s next expected counter is Ns < n, the receiver will:

- Derive and store messageKey for each missing index i in [Ns, n).
- Derive messageKey for the current message n and prepare the next receiving chain key CK(n+1) transactionally.
- Attempt decryption using the prepared messageKey for n. If decryption fails, no state is committed; if it succeeds, the prepared state is committed.

This ensures correct decryption of out-of-order messages without advancing the live chain head prematurely.

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
    
    let newOneTimeKey = try X25519PrivateKey(
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
    
    // Publish new public key
    await publishLongTermPublicKey(newPublicKey.rawRepresentation)
    
    // Update local keys
    let newLocalKeys = LocalKeys(
        longTerm: try X25519PrivateKey(id: UUID(), newPrivateKey.rawRepresentation),
        oneTime: localKeys.oneTime,
        mlKEM: localKeys.mlKEM
    )
    
    // Re-open the session with new keys — the engine detects the key change,
    // performs a PQXDH epoch step, and updates the identity props itself.
    try await ratchetManager.initiateSession(
        sessionIdentity: sessionIdentity,
        sessionSymmetricKey: sessionKey,
        remoteKeys: remoteKeys,
        localKeys: newLocalKeys
    )
}
```

## Key Exchange

### PQXDH Key Exchange

The protocol uses hybrid PQXDH for key exchange. The derivation is internal to the engine — hosts never call it directly. It runs automatically inside `initiateSession` / `respondToSession` and epoch (re-key) steps:

- **Sender side**: X25519 agreements against the recipient's long-term (and optional one-time) public keys are combined with an ML-KEM-1024 encapsulation to the recipient's KEM public key. The secrets are joined through HKDF into the initial root key; the KEM ciphertext rides to the recipient in the first encrypted header.
- **Receiver side**: the recipient runs the matching X25519 agreements and decapsulates the received ciphertext with its ML-KEM private key, arriving at the same root key.

The only host-visible artifact is the ciphertext: `MessageRatchet` carries it inside `EncryptedHeader.messageCiphertext`, and `KeyRatchet` exposes it via `getCipherText(sessionId:)` for transport to `respondToSession(ciphertext:)`.

## Key Validation

### Size Validation

All keys are automatically validated for correct size:

```swift
// Curve25519 keys must be 32 bytes
guard rawRepresentation.count == 32 else {
    throw KeyError.invalidKeySize
}

// MLKEM1024 keys must be correct size
guard rawRepresentation.count == Int(MLKEM1024PublicKeyLength) else {
    throw KeyError.invalidKeySize
}
```

### Format Validation

Beyond size, X25519 accepts any 32-byte string as a public key by design; invalid or low-order points surface as key-agreement failures rather than needing up-front point validation. ML-KEM public keys are structurally validated when the underlying `MLKEM1024.PublicKey` is constructed from the raw representation.

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

// Generate all required keys
let curvePrivateKey = Curve25519.KeyAgreement.PrivateKey()
let curvePublicKey = curvePrivateKey.publicKey

let kemPrivateKey = try MLKEM1024.PrivateKey()
let kemPublicKey = kemPrivateKey.publicKey

let oneTimePrivateKey = Curve25519.KeyAgreement.PrivateKey()
let oneTimePublicKey = oneTimePrivateKey.publicKey

// Wrap keys
let localKeys = LocalKeys(
    longTerm: try X25519PrivateKey(id: UUID(), curvePrivateKey.rawRepresentation),
    oneTime: try X25519PrivateKey(id: UUID(), oneTimePrivateKey.rawRepresentation),
    mlKEM: try MLKEMPrivateKey(id: UUID(), kemPrivateKey.encode())
)

let remoteKeys = RemoteKeys(
    longTerm: try X25519PublicKey(id: UUID(), bobX25519PublicKey.rawRepresentation),
    oneTime: try X25519PublicKey(id: UUID(), bobOneTimePublicKey.rawRepresentation),
    mlKEM: try MLKEMPublicKey(id: UUID(), bobKEMPublicKey.rawRepresentation)
)

// Initialize session (the identity describes the peer lane)
try await ratchetManager.initiateSession(
    sessionIdentity: bobSessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: remoteKeys,
    localKeys: localKeys
)
```

## Related Documentation

- <doc:UsingMessageRatchet> - Main protocol interface
- <doc:UsingSessionIdentity> - Session identity management
- <doc:RatchetState> - Session state management
- <doc:SecurityModel> - Security considerations 
