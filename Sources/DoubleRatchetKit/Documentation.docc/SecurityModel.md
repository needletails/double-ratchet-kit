# Security Model

Understand the security properties, threat model, and cryptographic assumptions of DoubleRatchetKit.

## Overview

DoubleRatchetKit provides a comprehensive security model based on the Signal protocol with post-quantum enhancements. This document outlines the security guarantees, threat model, and implementation security considerations.

## Security Properties

### Forward Secrecy

**Definition**: Compromise of current keys does not reveal past messages.

**Implementation**:
- **Message-level**: Each message uses a unique key derived from chain keys
- **Session-level**: Compromise of session keys doesn't reveal past sessions
- **Long-term**: Compromise of long-term keys doesn't affect past sessions

**Guarantees**:
```swift
// Even if current keys are compromised
let compromisedKeys = getCurrentKeys()
// Past messages remain secure
let pastMessages = getPastMessages() // Still encrypted
```

### Post-Compromise Security

**Definition**: After a compromise, new messages remain secure once the ratchet advances.

**Implementation**:
- **Immediate Recovery**: New messages are secure after key rotation
- **Isolation**: Compromise is limited to specific time periods
- **Automatic Rotation**: Keys change with every message

**Guarantees**:
```swift
// After compromise
let compromisedState = getCompromisedState()
// New messages are still secure
let newMessage = try await ratchetManager.ratchetEncrypt(plainText: data)
```

### Post-Quantum Security

**Definition**: Security against both classical and quantum computational attacks.

**Implementation**:
- **Hybrid PQXDH**: Combines Curve25519 and MLKEM1024
- **MLKEM1024**: Post-quantum key encapsulation mechanism
- **Future-Proof**: Secure against quantum computers

**Guarantees**:
```swift
// Classical security (Curve25519)
let classicalSecret = Curve25519.KeyAgreement.sharedSecret(...)
// Quantum resistance (MLKEM1024)
let quantumSecret = MLKEM1024.KeyAgreement.sharedSecret(...)
// Combined security
let finalSecret = classicalSecret + quantumSecret
```

### Metadata Protection

**Definition**: Message metadata is protected against traffic analysis.

**Implementation**:
- **Header Encryption**: Message counters and key IDs are encrypted
- **Traffic Analysis Resistance**: Message patterns are hidden
- **Skipped Message Support**: Out-of-order delivery doesn't reveal patterns

## Threat Model

### Adversarial Capabilities

#### Passive Adversaries
- **Network Eavesdropping**: Can observe encrypted traffic
- **Traffic Analysis**: Can analyze message patterns and timing
- **Metadata Collection**: Can gather message metadata

#### Active Adversaries
- **Message Injection**: Can inject fake messages
- **Message Modification**: Can modify encrypted messages
- **Replay Attacks**: Can replay old messages
- **Man-in-the-Middle**: Can intercept and modify traffic

#### Compromise Scenarios
- **Key Compromise**: Access to cryptographic keys
- **Device Compromise**: Full access to device
- **Session Compromise**: Access to session state
- **Long-term Key Compromise**: Access to identity keys

### Attack Vectors

#### Cryptographic Attacks
- **Brute Force**: Exhaustive key search
- **Quantum Attacks**: Shor's algorithm on discrete logarithms
- **Side-Channel Attacks**: Timing, power, or cache attacks
- **Implementation Attacks**: Bugs in cryptographic code

#### Protocol Attacks
- **Replay Attacks**: Reusing old messages
- **Key Reuse**: Using the same key multiple times
- **State Manipulation**: Modifying ratchet state
- **DoS Attacks**: Exhausting resources

#### System Attacks
- **Memory Dumps**: Extracting keys from memory
- **Storage Compromise**: Accessing stored keys
- **Network Attacks**: Intercepting network traffic
- **Social Engineering**: Manipulating users

## Cryptographic Assumptions

### Classical Cryptography

#### Curve25519
- **Security**: 128-bit security level
- **Assumption**: Discrete logarithm problem in elliptic curve groups
- **Attack**: Requires solving ECDLP in Curve25519

#### AES-256
- **Security**: 256-bit security level
- **Assumption**: Block cipher security
- **Attack**: Requires breaking AES-256

#### SHA-256
- **Security**: 128-bit collision resistance
- **Assumption**: Hash function security
- **Attack**: Requires finding SHA-256 collisions

### Post-Quantum Cryptography

#### MLKEM1024
- **Security**: 256-bit post-quantum security
- **Assumption**: Learning with Errors (LWE) problem
- **Attack**: Requires solving LWE in quantum polynomial time

#### Hybrid Security
- **Security**: Maximum of classical and quantum security
- **Assumption**: Both classical and quantum assumptions hold
- **Attack**: Requires breaking both classical and quantum primitives

## Key Management Security

### Key Generation
- **Cryptographic Randomness**: Uses secure random number generation
- **Key Validation**: Validates key properties and parameters
- **Key Derivation**: Uses secure key derivation functions

### Key Storage
- **Encrypted Storage**: Keys are encrypted at rest
- **Memory Protection**: Keys are protected in memory
- **Secure Deletion**: Keys are securely wiped when no longer needed

### Key Rotation
- **Automatic Rotation**: Keys change with every message
- **Forward Secrecy**: Old keys are immediately invalidated
- **Compromise Recovery**: New keys provide post-compromise security

## Implementation Security

### Memory Safety
- **Swift Safety**: Leverages Swift's memory safety features
- **Zeroing**: Sensitive data is zeroed after use
- **Bounds Checking**: Array and buffer bounds are checked

### Concurrency Safety
- **Actor Isolation**: State mutations are serialized
- **Thread Safety**: No race conditions in state access
- **Atomic Operations**: State updates are atomic

### Error Handling
- **Secure Failures**: Failures don't leak sensitive information
- **Graceful Degradation**: System continues operating after errors
- **Error Recovery**: Automatic recovery from transient errors

## Security Recommendations

### Deployment Security

#### Key Management
- **Secure Key Generation**: Use cryptographically secure random number generators
- **Key Backup**: Implement secure key backup and recovery
- **Key Rotation**: Implement automatic key rotation policies

#### Network Security
- **Transport Security**: Use TLS for network transport
- **Certificate Validation**: Validate TLS certificates properly
- **Network Isolation**: Isolate sensitive network traffic

#### System Security
- **Secure Boot**: Ensure system integrity during boot
- **Memory Protection**: Protect memory from unauthorized access
- **Secure Storage**: Use secure storage for sensitive data

### Operational Security

#### Monitoring
- **Security Logging**: Log security-relevant events
- **Anomaly Detection**: Monitor for unusual patterns
- **Incident Response**: Have procedures for security incidents

#### Updates
- **Regular Updates**: Keep software and dependencies updated
- **Security Patches**: Apply security patches promptly
- **Vulnerability Management**: Monitor for vulnerabilities

#### Access Control
- **Principle of Least Privilege**: Minimize access to sensitive data
- **Authentication**: Implement strong authentication
- **Authorization**: Control access to cryptographic operations

## Security Considerations

### Quantum Resistance
- **Hybrid Approach**: Combines classical and quantum-resistant cryptography
- **Migration Path**: Provides path to full quantum resistance
- **Standards Compliance**: Follows post-quantum standards

### Performance Impact
- **Optimization**: Cryptographic operations are optimized
- **Caching**: Efficient key caching for performance
- **Resource Management**: Careful resource usage

### Compatibility
- **Interoperability**: Compatible with existing protocols
- **Backward Compatibility**: Supports legacy systems
- **Standards Compliance**: Follows relevant standards

## Security Testing

### Cryptographic Testing
- **Known Answer Tests**: Verify cryptographic operations
- **Randomness Testing**: Test random number generation
- **Key Validation**: Test key generation and validation

### Protocol Testing
- **State Machine Testing**: Test protocol state transitions
- **Error Handling**: Test error conditions and recovery
- **Concurrency Testing**: Test concurrent operations

### Penetration Testing
- **Vulnerability Assessment**: Regular security assessments
- **Red Team Testing**: Simulate real-world attacks
- **Code Review**: Regular security code reviews

## Next Steps

- Explore the <doc:APIReference> for complete documentation 
