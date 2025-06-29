# RatchetState

An immutable struct that represents the current state of the Double Ratchet protocol.

## Overview

`RatchetState` encapsulates all the cryptographic state needed for the Double Ratchet algorithm, including root keys, chain keys, header keys, message counters, and skipped message keys. The struct is immutable, ensuring thread safety and preventing accidental state corruption.

## Declaration

```swift
public struct RatchetState: Codable, Hashable, Sendable
```

## Core Properties

### Root Key

The master key derived from the initial PQXDH handshake:

```swift
let rootKey: SymmetricKey
```

- **Purpose**: Master key for deriving chain keys
- **Source**: Initial PQXDH key exchange
- **Updates**: Changed during DH ratchet operations

### Chain Keys

Keys used for deriving message keys:

```swift
let chainKeys: ChainKeys
```

The `ChainKeys` struct contains:
- **`sendingChainKey`**: Key for deriving sending message keys
- **`receivingChainKey`**: Key for deriving receiving message keys

### Header Keys

Keys used for encrypting and decrypting message headers:

```swift
let headerKeys: HeaderKeys
```

The `HeaderKeys` struct contains:
- **`sendingHeaderKey`**: Key for encrypting outgoing message headers
- **`receivingHeaderKey`**: Key for decrypting incoming message headers

### Message Counters

Track the number of messages sent and received:

```swift
let messageCounters: MessageCounters
```

The `MessageCounters` struct contains:
- **`sendingMessageNumber`**: Number of messages sent
- **`receivingMessageNumber`**: Number of messages received

### Skipped Message Keys

Cache for handling out-of-order message delivery:

```swift
let skippedMessageKeys: [Int: SymmetricKey]
```

- **Key**: Message number
- **Value**: Symmetric key for decrypting the message
- **Purpose**: Handle messages that arrive out of order

## State Updates

### Immutable Updates

All state updates return a new `RatchetState` instance:

```swift
// Update sending message number
let newState = state.updateSendingMessageNumber(state.sendingMessageNumber + 1)

// Update receiving message number
let newState = state.updateReceivingMessageNumber(state.receivingMessageNumber + 1)

// Add skipped message key
let newState = state.addSkippedMessageKey(messageNumber: 5, key: messageKey)

// Remove skipped message key
let newState = state.removeSkippedMessageKey(messageNumber: 5)
```

### Chain Key Updates

Update chain keys during symmetric ratchet operations:

```swift
// Update sending chain key
let newState = state.updateSendingChainKey(newChainKey)

// Update receiving chain key
let newState = state.updateReceivingChainKey(newChainKey)
```

### Header Key Updates

Update header keys during key rotation:

```swift
// Update sending header key
let newState = state.updateSendingHeaderKey(newHeaderKey)

// Update receiving header key
let newState = state.updateReceivingHeaderKey(newHeaderKey)
```

### Root Key Updates

Update root key during DH ratchet operations:

```swift
// Update root key
let newState = state.updateRootKey(newRootKey)
```

## State Transitions

### Initial State

Created from PQXDH handshake:

```swift
let initialState = RatchetState(
    rootKey: derivedRootKey,
    chainKeys: initialChainKeys,
    headerKeys: initialHeaderKeys,
    messageCounters: MessageCounters(sending: 0, receiving: 0),
    skippedMessageKeys: [:]
)
```

### Message Processing

State updates during message encryption/decryption:

```swift
// For sending a message
let newState = state
    .updateSendingMessageNumber(state.sendingMessageNumber + 1)
    .updateSendingChainKey(derivedChainKey)

// For receiving a message
let newState = state
    .updateReceivingMessageNumber(state.receivingMessageNumber + 1)
    .updateReceivingChainKey(derivedChainKey)
```

### Key Rotation

State updates during DH ratchet:

```swift
// During DH ratchet
let newState = state
    .updateRootKey(newRootKey)
    .updateSendingChainKey(newSendingChainKey)
    .updateReceivingChainKey(newReceivingChainKey)
    .updateSendingHeaderKey(newSendingHeaderKey)
    .updateReceivingHeaderKey(newReceivingHeaderKey)
```

## Skipped Message Handling

### Adding Skipped Keys

When a message arrives out of order:

```swift
// Store key for later decryption
let newState = state.addSkippedMessageKey(
    messageNumber: receivedMessageNumber,
    key: derivedMessageKey
)
```

### Using Skipped Keys

When the missing message arrives:

```swift
// Check if we have a key for this message
if let skippedKey = state.skippedMessageKeys[messageNumber] {
    // Decrypt the message
    let decrypted = try decrypt(message, with: skippedKey)
    
    // Remove the used key
    let newState = state.removeSkippedMessageKey(messageNumber: messageNumber)
}
```

### Key Cleanup

Periodically clean up old skipped keys:

```swift
// Remove keys older than threshold
let threshold = state.receivingMessageNumber - 1000
let newState = state.removeSkippedMessageKeysOlderThan(threshold)
```

## Performance Considerations

### Immutability Benefits

- **Thread Safety**: No race conditions during state access
- **Memory Safety**: Prevents accidental state corruption
- **Debugging**: Easier to track state changes
- **Testing**: Simpler to test state transitions

### Memory Usage

- **Efficient Updates**: Only changed fields create new instances
- **Key Caching**: Skipped message keys are cached for performance
- **Automatic Cleanup**: Old keys are automatically removed

### Optimization

- **Copy-on-Write**: Swift optimizes immutable struct copying
- **Minimal Allocations**: Only necessary fields are copied
- **Efficient Storage**: Keys are stored in optimized data structures

## Example Usage

### Creating Initial State

```swift
// Create initial state from PQXDH handshake
let rootKey = deriveRootKey(from: pqxdhSecret)
let chainKeys = deriveChainKeys(from: rootKey)
let headerKeys = deriveHeaderKeys(from: rootKey)

let initialState = RatchetState(
    rootKey: rootKey,
    chainKeys: chainKeys,
    headerKeys: headerKeys,
    messageCounters: MessageCounters(sending: 0, receiving: 0),
    skippedMessageKeys: [:]
)
```

### Processing Messages

```swift
// Send a message
func sendMessage(_ data: Data, state: RatchetState) -> (RatchetMessage, RatchetState) {
    let messageKey = deriveMessageKey(from: state.chainKeys.sendingChainKey)
    let encryptedMessage = try encrypt(data, with: messageKey)
    
    let newState = state
        .updateSendingMessageNumber(state.sendingMessageNumber + 1)
        .updateSendingChainKey(deriveNextChainKey(from: state.chainKeys.sendingChainKey))
    
    return (encryptedMessage, newState)
}

// Receive a message
func receiveMessage(_ message: RatchetMessage, state: RatchetState) -> (Data, RatchetState) {
    let messageKey = deriveMessageKey(from: state.chainKeys.receivingChainKey)
    let decryptedData = try decrypt(message, with: messageKey)
    
    let newState = state
        .updateReceivingMessageNumber(state.receivingMessageNumber + 1)
        .updateReceivingChainKey(deriveNextChainKey(from: state.chainKeys.receivingChainKey))
    
    return (decryptedData, newState)
}
```

### Handling Out-of-Order Messages

```swift
func handleOutOfOrderMessage(_ message: RatchetMessage, state: RatchetState) -> (Data?, RatchetState) {
    let messageNumber = extractMessageNumber(from: message)
    
    // Check if we have a key for this message
    if let skippedKey = state.skippedMessageKeys[messageNumber] {
        let decryptedData = try decrypt(message, with: skippedKey)
        let newState = state.removeSkippedMessageKey(messageNumber: messageNumber)
        return (decryptedData, newState)
    }
    
    // Store key for later use
    let messageKey = deriveMessageKey(from: state.chainKeys.receivingChainKey)
    let newState = state.addSkippedMessageKey(messageNumber: messageNumber, key: messageKey)
    return (nil, newState)
}
```

## Related Documentation

- <doc:RatchetStateManager> for the main actor managing ratchet state
- <doc:SessionIdentity> for session identity management
- <doc:KeyManagement> for key management operations
- <doc:ProtocolFlow> for protocol implementation details
- <doc:BestPractices> for implementation guidelines 