# Key Concepts

Understand the fundamental concepts behind the Double Ratchet algorithm and its implementation in DoubleRatchetKit.

## Overview

The Double Ratchet algorithm is a cryptographic protocol that provides forward secrecy and post-compromise security for secure messaging. It combines two types of ratchets: a **Diffie-Hellman ratchet** and **symmetric-key ratchets**.

## Double Ratchet Algorithm

### Core Principles

The Double Ratchet algorithm ensures that:

1. **Forward Secrecy**: Compromise of current keys doesn't reveal past messages
2. **Post-Compromise Security**: Compromise of keys doesn't affect future messages once the ratchet advances
3. **Asynchronous Operation**: Messages can be sent and received out of order

### Two Types of Ratchets

#### Diffie-Hellman Ratchet
- Triggered when a new Diffie-Hellman key exchange occurs
- Updates the root key and chain keys
- Provides forward secrecy across key exchanges

#### Symmetric-Key Ratchet
- Triggered for every message
- Derives new message keys from chain keys
- Provides forward secrecy for individual messages

## PQXDH Hybrid Key Exchange

### Post-Quantum X3DH

DoubleRatchetKit uses **PQXDH (Post-Quantum X3DH)** for initial key agreement, which combines:

- **Curve25519**: Classical elliptic curve cryptography
- **MLKEM1024**: Post-quantum key encapsulation mechanism

This hybrid approach ensures security against both classical and quantum attacks.

### Key Exchange Flow

1. **Initial Handshake**: PQXDH establishes the initial shared secret
2. **Root Key Derivation**: The shared secret becomes the root key
3. **Chain Key Creation**: Chain keys are derived from the root key
4. **Message Key Generation**: Each message gets a unique key

## Key Types and Management

### Cryptographic Keys

#### Curve25519 Keys
- **Long-term Keys**: Persistent identity keys
- **One-time Keys**: Ephemeral keys for enhanced security
- **Signed Prekeys**: Pre-computed keys for faster handshakes

#### MLKEM1024 Keys
- **MLKEM Keys**: Post-quantum key encapsulation keys
- **Hybrid Security**: Combined with Curve25519 for quantum resistance

### Key Containers

```swift
// Remote keys (public keys from the other party)
struct RemoteKeys {
    let longTerm: RemoteLongTermPublicKey
    let oneTime: RemoteOneTimePublicKey?
    let mlKEM: RemoteMLKEMPublicKey
}

// Local keys (private keys for this party)
struct LocalKeys {
    let longTerm: LocalLongTermPrivateKey
    let oneTime: LocalOneTimePrivateKey?
    let mlKEM: LocalMLKEMPrivateKey
}
```

## Header Encryption

### Purpose

Header encryption protects metadata from traffic analysis by encrypting:
- Message counters
- Key identifiers
- Protocol version information

### Implementation

```swift
// Header keys are derived from chain keys
let headerKey = deriveHeaderKey(from: chainKey)
let encryptedHeader = encrypt(header, with: headerKey)
```

## Message Flow

### Initial Message (Handshake)

1. **PQXDH Key Exchange**: Establishes shared secret
2. **Root Key Derivation**: Creates initial root key
3. **Chain Key Creation**: Derives sending/receiving chain keys
4. **Header Key Setup**: Establishes header encryption keys
5. **Message Encryption**: Encrypts first message

### Subsequent Messages

1. **Symmetric Ratchet**: Derives new message key
2. **Header Encryption**: Encrypts message metadata
3. **Payload Encryption**: Encrypts message content
4. **State Update**: Advances message counters

### Key Rotation

1. **DH Ratchet Trigger**: New DH key exchange occurs
2. **Root Key Update**: New root key derived
3. **Chain Key Reset**: New chain keys created
4. **Header Key Update**: Header keys refreshed

## Security Properties

### Forward Secrecy

- **Message-level**: Each message uses a unique key
- **Session-level**: Compromise of session keys doesn't reveal past messages
- **Long-term**: Compromise of long-term keys doesn't affect past sessions

### Post-Compromise Security

- **Immediate**: New messages are secure once ratchet advances
- **Recovery**: System can recover from key compromise
- **Isolation**: Compromise is limited to specific time periods

### Post-Quantum Security

- **Hybrid Approach**: Combines classical and quantum-resistant cryptography
- **MLKEM1024**: Provides quantum resistance for key exchange
- **Future-Proof**: Secure against both current and future quantum attacks

## Concurrency Model

### Actor-Based Design

DoubleRatchetKit uses Swift actors for thread safety:

```swift
public actor RatchetStateManager<Hash: HashFunction & Sendable> {
    // All state mutations are serialized through the actor
}
```

### Benefits

- **Thread Safety**: Automatic synchronization of state access
- **Performance**: Efficient concurrent message processing
- **Simplicity**: No manual locking required

## State Management

### Ratchet State

The `RatchetState` struct contains all session information:

```swift
struct RatchetState {
    let rootKey: SymmetricKey
    let chainKeys: ChainKeys
    let headerKeys: HeaderKeys
    let messageCounters: MessageCounters
    let skippedMessageKeys: [Int: SymmetricKey]
}
```

### State Transitions

1. **Initialization**: State created from PQXDH handshake
2. **Message Processing**: State updated for each message
3. **Key Rotation**: State refreshed during DH ratchet
4. **Cleanup**: State cleared on session termination

## Skipped Message Handling

### Out-of-Order Delivery

The protocol handles messages that arrive out of order:

1. **Key Storage**: Per-message keys (messageKey) for skipped messages are cached
2. **Decryption**: Messages are decrypted directly using the stored messageKey
3. **Cleanup**: Old keys are purged to prevent DoS attacks

### Implementation

```swift
// Store per-message keys for skipped messages
var skippedMessageKeys: [Int: SymmetricKey] = [:]

// Retrieve key for specific message number
if let messageKey = skippedMessageKeys[messageNumber] {
    // Decrypt message with stored messageKey
}
```

## Next Steps

- Explore the <doc:SecurityModel> for detailed security analysis
- Check the <doc:APIReference> for complete API documentation 
