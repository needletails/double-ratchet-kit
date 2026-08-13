# Using KeyRatchet

The façade for external key derivation. Same engine as `MessageRatchet`; do not mix the two on one session.

## Overview

`KeyRatchet` derives message keys so a host can encrypt and decrypt with its own AEAD. It does not produce `RatchetMessage` frames. Use a separate manager instance from any `MessageRatchet` that talks on the same lane.

## Declaration

```swift
public actor KeyRatchet
```

## Initialization

```swift
let keyRatchet = KeyRatchet(
    executor: executor,
    logger: logger
)
await keyRatchet.setDelegate(sessionDelegate)
```

## Session setup

```swift
try await keyRatchet.initiateSession(
    sessionIdentity: sessionIdentity,
    sessionSymmetricKey: sessionKey,
    remoteKeys: remoteKeys,
    localKeys: localKeys
)

try await keyRatchet.respondToSession(
    sessionIdentity: sessionIdentity,
    sessionSymmetricKey: sessionKey,
    localKeys: localKeys,
    remoteKeys: remoteKeys,
    ciphertext: mlKEMCiphertext
)
```

The recipient path bootstraps from PQXDH ciphertext without a full encrypted header. That is the KeyRatchet-only `respondToSession` overload — `MessageRatchet` still takes `header:`.

## Key derivation

```swift
let (sendKey, sendNumber) = try await keyRatchet.nextSendKey(sessionId: sessionId)
let ciphertext = try customEncrypt(plaintext, key: sendKey)

let (receiveKey, receiveNumber) = try await keyRatchet.receiveKey(
    for: sessionId,
    cipherText: mlKEMCiphertext
)
let plaintext = try customDecrypt(ciphertext, key: receiveKey)

let status = try await keyRatchet.sessionStatus(sessionId: sessionId)
```

Do not mix these methods with `MessageRatchet.encrypt` / `decrypt` on the same session.

## Lifecycle

```swift
try await keyRatchet.flushAndClose()
```

`flushAndClose()` is idempotent. Further session operations after close are unsupported.

## Related Documentation

- <doc:UsingMessageRatchet>
- <doc:APIReference>
- <doc:GettingStarted>
