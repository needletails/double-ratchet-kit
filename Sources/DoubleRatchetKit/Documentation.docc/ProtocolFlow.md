# Protocol Flow

Detailed explanation of the Double Ratchet protocol flow, including handshake, message exchange, and key rotation phases.

## Overview

The Double Ratchet protocol consists of three main phases:

1. **Initial Handshake (PQXDH)**: Establishes the initial session
2. **Message Exchange**: Ongoing encrypted communication
3. **Key Rotation**: Periodic key updates for forward secrecy

## Initial Handshake (PQXDH)

### Phase 1: Key Exchange

The initial handshake uses Post-Quantum X3DH (PQXDH) to establish the root key:

```swift
// Alice initiates handshake with Bob
func performPQXDHHandshake(
    aliceKeys: LocalKeys,
    bobKeys: RemoteKeys
) throws -> HandshakeResult {
    // 1. Classical key exchange (Curve25519)
    let classicalSecret = try performX3DH(
        aliceLongTerm: aliceKeys.longTerm,
        aliceOneTime: aliceKeys.oneTime,
        bobLongTerm: bobKeys.longTerm,
        bobOneTime: bobKeys.oneTime
    )
    
    // 2. Post-quantum key exchange (Kyber1024)
    let quantumSecret = try performKyberExchange(
        alicePQKem: aliceKeys.pqKem,
        bobPQKem: bobKeys.pqKem
    )
    
    // 3. Combine secrets
    let rootKey = combineSecrets(classical: classicalSecret, quantum: quantumSecret)
    
    return HandshakeResult(rootKey: rootKey)
}
```

### Phase 2: Key Derivation

After establishing the root key, derive initial chain keys and header keys:

```swift
func deriveInitialKeys(rootKey: SymmetricKey) throws -> InitialKeys {
    // Derive chain key
    let chainKey = try deriveChainKey(from: rootKey)
    
    // Derive header keys
    let sendingHeaderKey = try deriveHeaderKey(from: rootKey, purpose: .sending)
    let receivingHeaderKey = try deriveHeaderKey(from: rootKey, purpose: .receiving)
    
    return InitialKeys(
        chainKey: chainKey,
        sendingHeaderKey: sendingHeaderKey,
        receivingHeaderKey: receivingHeaderKey
    )
}
```

### Phase 3: First Message

Send the first encrypted message with handshake completion:

```swift
func sendInitialMessage(
    plaintext: Data,
    state: RatchetState
) async throws -> RatchetMessage {
    // 1. Derive message key
    let messageKey = try deriveMessageKey(from: state.chainKey)
    
    // 2. Encrypt message
    let encryptedData = try encrypt(data: plaintext, with: messageKey)
    
    // 3. Create header
    let header = try createHeader(
        messageNumber: 0,
        headerKey: state.sendingHeaderKey
    )
    
    // 4. Update state
    let newState = state
        .updateMessageNumber(1)
        .updateChainKey(deriveNewChainKey(from: state.chainKey))
        .updateSendingHandshakeFinished(true)
    
    return RatchetMessage(header: header, encryptedData: encryptedData)
}
```

## Message Exchange

### Sending Messages

Each message follows a symmetric key ratchet:

```swift
func sendMessage(
    plaintext: Data,
    state: RatchetState
) async throws -> (RatchetMessage, RatchetState) {
    // 1. Ratchet sending header key
    let newSendingHeaderKey = try ratchetHeaderKey(state.sendingHeaderKey)
    
    // 2. Ratchet chain key
    let (messageKey, newChainKey) = try ratchetChainKey(state.chainKey)
    
    // 3. Encrypt message
    let encryptedData = try encrypt(data: plaintext, with: messageKey)
    
    // 4. Create header
    let header = try createHeader(
        messageNumber: state.messageNumber,
        headerKey: newSendingHeaderKey
    )
    
    // 5. Update state
    let newState = state
        .updateMessageNumber(state.messageNumber + 1)
        .updateChainKey(newChainKey)
        .updateSendingHeaderKey(newSendingHeaderKey)
    
    return (RatchetMessage(header: header, encryptedData: encryptedData), newState)
}
```

### Receiving Messages

Message reception may trigger DH ratchet steps:

```swift
func receiveMessage(
    message: RatchetMessage,
    state: RatchetState
) async throws -> (Data, RatchetState) {
    // 1. Decrypt header
    let header = try decryptHeader(
        encryptedHeader: message.header,
        headerKey: state.receivingHeaderKey
    )
    
    // 2. Check if DH ratchet is needed
    if needsDHRatchet(header: header, state: state) {
        let newState = try await performDHRatchet(header: header, state: state)
        return try await receiveMessage(message: message, state: newState)
    }
    
    // 3. Handle skipped messages
    if header.messageNumber > state.messageNumber + 1 {
        let newState = try await handleSkippedMessages(
            from: state.messageNumber + 1,
            to: header.messageNumber - 1,
            state: state
        )
        return try await receiveMessage(message: message, state: newState)
    }
    
    // 4. Decrypt message
    let messageKey = try deriveMessageKey(from: state.chainKey)
    let plaintext = try decrypt(data: message.encryptedData, with: messageKey)
    
    // 5. Update state
    let newState = state
        .updateMessageNumber(header.messageNumber)
        .updateChainKey(deriveNewChainKey(from: state.chainKey))
        .updateReceivingHeaderKey(ratchetHeaderKey(state.receivingHeaderKey))
        .setAlreadyDecryptedMessageNumbers(
            state.alreadyDecryptedMessageNumbers.union([header.messageNumber])
        )
    
    return (plaintext, newState)
}
```

## Key Rotation

### DH Ratchet Trigger

DH ratchet steps occur when new DH keys are available:

```swift
func needsDHRatchet(header: MessageHeader, state: RatchetState) -> Bool {
    // Check if remote party has new DH keys
    return header.remoteLongTermPublicKey != state.remoteLongTermPublicKey ||
           header.remoteOneTimePublicKey != state.remoteOneTimePublicKey ||
           header.remotePQKemPublicKey != state.remotePQKemPublicKey
}
```

### DH Ratchet Execution

```swift
func performDHRatchet(
    header: MessageHeader,
    state: RatchetState
) async throws -> RatchetState {
    // 1. Perform new DH exchange
    let newRootKey = try performDHExchange(
        remoteKeys: RemoteKeys(
            longTerm: header.remoteLongTermPublicKey,
            oneTime: header.remoteOneTimePublicKey,
            pqKem: header.remotePQKemPublicKey
        ),
        localKeys: LocalKeys(
            longTerm: state.localLongTermPrivateKey,
            oneTime: state.localOneTimePrivateKey,
            pqKem: state.localPQKemPrivateKey
        )
    )
    
    // 2. Derive new chain keys
    let newChainKey = try deriveChainKey(from: newRootKey)
    
    // 3. Update state
    return state
        .updateRootKey(newRootKey)
        .updateChainKey(newChainKey)
        .updateRemoteLongTermPublicKey(header.remoteLongTermPublicKey)
        .updateRemoteOneTimePublicKey(header.remoteOneTimePublicKey)
        .updateRemotePQKemPublicKey(header.remotePQKemPublicKey)
}
```

## Skipped Message Handling

### Storing Skipped Keys

```swift
func handleSkippedMessages(
    from: Int,
    to: Int,
    state: RatchetState
) async throws -> RatchetState {
    var currentState = state
    var skippedKeys: [SkippedMessageKey] = []
    
    for messageNumber in from...to {
        // Derive key for skipped message
        let messageKey = try deriveMessageKey(from: currentState.chainKey)
        
        // Store skipped key
        let skippedKey = SkippedMessageKey(
            remoteLongTermPublicKey: currentState.remoteLongTermPublicKey,
            remoteOneTimePublicKey: currentState.remoteOneTimePublicKey?.rawRepresentation,
            remotePQKemPublicKey: currentState.remotePQKemPublicKey.rawRepresentation,
            messageIndex: messageNumber,
            chainKey: messageKey
        )
        skippedKeys.append(skippedKey)
        
        // Advance chain key
        currentState = currentState.updateChainKey(
            deriveNewChainKey(from: currentState.chainKey)
        )
    }
    
    // Update state with skipped keys
    return currentState.updateSkippedMessageKeys(skippedKeys)
}
```

### Using Skipped Keys

```swift
func decryptSkippedMessage(
    message: RatchetMessage,
    skippedKeys: [SkippedMessageKey]
) throws -> Data? {
    let header = try decryptHeader(
        encryptedHeader: message.header,
        headerKey: currentHeaderKey
    )
    
    // Find matching skipped key
    guard let skippedKey = skippedKeys.first(where: { 
        $0.messageIndex == header.messageNumber 
    }) else {
        return nil
    }
    
    // Decrypt message
    return try decrypt(data: message.encryptedData, with: skippedKey.chainKey)
}
```

## Header Encryption Flow

### Header Creation

```swift
func createHeader(
    messageNumber: Int,
    headerKey: SymmetricKey
) throws -> EncryptedHeader {
    // 1. Create header data
    let headerData = MessageHeader(
        messageNumber: messageNumber,
        timestamp: Date(),
        keyIds: currentKeyIds
    )
    
    // 2. Serialize header
    let serializedHeader = try JSONEncoder().encode(headerData)
    
    // 3. Encrypt header
    let encryptedHeader = try encrypt(data: serializedHeader, with: headerKey)
    
    // 4. Create header ciphertext
    let headerCiphertext = try createHeaderCiphertext(encryptedHeader)
    
    return EncryptedHeader(
        remoteLongTermPublicKey: currentRemoteLongTermKey,
        remoteOneTimePublicKey: currentRemoteOneTimeKey,
        remotePQKemPublicKey: currentRemotePQKemKey,
        headerCiphertext: headerCiphertext,
        messageCiphertext: messageCiphertext,
        oneTimeKeyId: currentOneTimeKeyId,
        pqKemOneTimeKeyId: currentPQKemOneTimeKeyId,
        encrypted: encryptedHeader
    )
}
```

### Header Decryption

```swift
func decryptHeader(
    encryptedHeader: EncryptedHeader,
    headerKey: SymmetricKey
) throws -> MessageHeader {
    // 1. Decrypt header data
    let decryptedHeader = try decrypt(
        data: encryptedHeader.encrypted,
        with: headerKey
    )
    
    // 2. Deserialize header
    let header = try JSONDecoder().decode(MessageHeader.self, from: decryptedHeader)
    
    return header
}
```

## State Transitions

### State Machine

The protocol follows a state machine with these states:

```swift
enum RatchetState {
    case uninitialized
    case handshakeInProgress
    case active
    case error
}

enum HandshakeState {
    case notStarted
    case pqxdhComplete
    case keysDerived
    case firstMessageSent
    case handshakeComplete
}
```

### State Transitions

```swift
func transitionState(
    from currentState: RatchetState,
    event: RatchetEvent
) -> RatchetState {
    switch (currentState, event) {
    case (.uninitialized, .initialize):
        return .handshakeInProgress
        
    case (.handshakeInProgress, .pqxdhComplete):
        return .handshakeInProgress
        
    case (.handshakeInProgress, .firstMessageSent):
        return .active
        
    case (.active, .messageSent):
        return .active
        
    case (.active, .messageReceived):
        return .active
        
    case (.active, .dhRatchet):
        return .active
        
    case (_, .error):
        return .error
        
    default:
        return .error
    }
}
```

## Security Properties

### Forward Secrecy

Each message uses a unique key derived from the current chain key:

```swift
// Message 1: Uses key K1
let message1Key = deriveMessageKey(from: chainKey1)

// Message 2: Uses key K2 (derived from K1)
let message2Key = deriveMessageKey(from: chainKey2)

// Compromise of K2 cannot reveal K1
```

### Post-Compromise Security

DH ratchet steps introduce new randomness:

```swift
// After compromise, new DH exchange creates new root key
let newRootKey = performDHExchange(remoteKeys, localKeys)
let newChainKey = deriveChainKey(from: newRootKey)

// New messages use keys derived from new root
let newMessageKey = deriveMessageKey(from: newChainKey)
```

### Metadata Protection

Header encryption prevents traffic analysis:

```swift
// Header contains sensitive metadata
let header = MessageHeader(
    messageNumber: currentMessageNumber,
    keyIds: currentKeyIds,
    timestamp: Date()
)

// Encrypt header to protect metadata
let encryptedHeader = encrypt(header, with: headerKey)
```

## Performance Considerations

### Key Derivation Optimization

```swift
// Cache derived keys for efficiency
class KeyCache {
    private var cache: [String: SymmetricKey] = [:]
    
    func getDerivedKey(from baseKey: SymmetricKey, purpose: String) -> SymmetricKey {
        let key = "\(baseKey.hashValue)_\(purpose)"
        
        if let cached = cache[key] {
            return cached
        }
        
        let derived = deriveKey(from: baseKey, purpose: purpose)
        cache[key] = derived
        return derived
    }
}
```

### Batch Processing

```swift
// Process multiple messages efficiently
func processMessageBatch(
    messages: [RatchetMessage],
    state: RatchetState
) async throws -> ([Data], RatchetState) {
    var currentState = state
    var results: [Data] = []
    
    for message in messages.sorted(by: { $0.header.messageNumber < $1.header.messageNumber }) {
        let (plaintext, newState) = try await receiveMessage(message: message, state: currentState)
        results.append(plaintext)
        currentState = newState
    }
    
    return (results, currentState)
}
```

## Error Handling

### Protocol Errors

```swift
enum ProtocolError: Error {
    case invalidMessageNumber
    case duplicateMessage
    case missingSkippedKey
    case invalidHeader
    case keyDerivationFailed
    case handshakeIncomplete
}

func handleProtocolError(_ error: ProtocolError, state: RatchetState) -> RatchetState {
    switch error {
    case .duplicateMessage:
        // Ignore duplicate messages
        return state
        
    case .missingSkippedKey:
        // Request message resend
        return state
        
    case .invalidHeader:
        // Reset to last known good state
        return state.rollbackToLastGoodState()
        
    default:
        // Transition to error state
        return state.transitionToError()
    }
}
```

### Recovery Mechanisms

```swift
func recoverFromError(state: RatchetState) async throws -> RatchetState {
    // 1. Check if we can recover automatically
    if state.canAutoRecover {
        return state.autoRecover()
    }
    
    // 2. Request new handshake if needed
    if state.needsNewHandshake {
        return try await performNewHandshake()
    }
    
    // 3. Reset to initial state as last resort
    return RatchetState.initial()
}
```

## Example Implementation

Complete example showing protocol flow:

```swift
class DoubleRatchetProtocol {
    private var state: RatchetState = .uninitialized
    private let keyManager: KeyManager
    private let crypto: CryptoProvider
    
    func initializeSession(
        remoteKeys: RemoteKeys,
        localKeys: LocalKeys
    ) async throws {
        // 1. Perform PQXDH handshake
        let handshakeResult = try await performPQXDHHandshake(
            remoteKeys: remoteKeys,
            localKeys: localKeys
        )
        
        // 2. Derive initial keys
        let initialKeys = try deriveInitialKeys(rootKey: handshakeResult.rootKey)
        
        // 3. Initialize state
        state = RatchetState(
            rootKey: handshakeResult.rootKey,
            chainKey: initialKeys.chainKey,
            sendingHeaderKey: initialKeys.sendingHeaderKey,
            receivingHeaderKey: initialKeys.receivingHeaderKey,
            remoteKeys: remoteKeys,
            localKeys: localKeys
        )
    }
    
    func sendMessage(_ plaintext: Data) async throws -> RatchetMessage {
        guard case .active = state else {
            throw ProtocolError.handshakeIncomplete
        }
        
        // 1. Ratchet keys
        let (messageKey, newChainKey) = try ratchetChainKey(state.chainKey)
        let newHeaderKey = try ratchetHeaderKey(state.sendingHeaderKey)
        
        // 2. Encrypt message
        let encryptedData = try crypto.encrypt(data: plaintext, with: messageKey)
        
        // 3. Create header
        let header = try createHeader(
            messageNumber: state.messageNumber,
            headerKey: newHeaderKey
        )
        
        // 4. Update state
        state = state
            .updateMessageNumber(state.messageNumber + 1)
            .updateChainKey(newChainKey)
            .updateSendingHeaderKey(newHeaderKey)
        
        return RatchetMessage(header: header, encryptedData: encryptedData)
    }
    
    func receiveMessage(_ message: RatchetMessage) async throws -> Data {
        guard case .active = state else {
            throw ProtocolError.handshakeIncomplete
        }
        
        // 1. Decrypt header
        let header = try decryptHeader(
            encryptedHeader: message.header,
            headerKey: state.receivingHeaderKey
        )
        
        // 2. Handle DH ratchet if needed
        if needsDHRatchet(header: header) {
            state = try await performDHRatchet(header: header)
        }
        
        // 3. Handle skipped messages
        if header.messageNumber > state.messageNumber + 1 {
            state = try await handleSkippedMessages(
                from: state.messageNumber + 1,
                to: header.messageNumber - 1
            )
        }
        
        // 4. Decrypt message
        let messageKey = try deriveMessageKey(from: state.chainKey)
        let plaintext = try crypto.decrypt(data: message.encryptedData, with: messageKey)
        
        // 5. Update state
        state = state
            .updateMessageNumber(header.messageNumber)
            .updateChainKey(deriveNewChainKey(from: state.chainKey))
            .updateReceivingHeaderKey(ratchetHeaderKey(state.receivingHeaderKey))
        
        return plaintext
    }
}
```

## Related Documentation

- <doc:RatchetStateManager> - Main ratchet state management
- <doc:RatchetState> - Immutable ratchet state
- <doc:KeyManagement> - Cryptographic key management
- <doc:SecurityModel> - Security properties and guarantees 