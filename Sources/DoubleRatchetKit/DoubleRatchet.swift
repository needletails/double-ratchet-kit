//
//  DoubleRatchet.swift
//  double-ratchet-kit
//
//  Created by Cole M on 6/16/25.
//
//  Copyright (c) 2025 NeedleTails Organization.
//
//  This project is licensed under the AGPL-3.0 License.
//
//  See the LICENSE file for more information.
//
//  This file is part of the Double Ratchet Kit SDK, which provides
//  post-quantum secure messaging with Double Ratchet Algorithm and PQXDH integration.
//

/*
 # Double Ratchet API Overview
 
 This module implements the **Double Ratchet Algorithm**, which provides *asynchronous forward secrecy* and *post-compromise security* for secure messaging. It is based on the Signal protocol specification:
 
 📄 Specification: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf
 
 The Double Ratchet combines a **Diffie-Hellman (DH) ratchet** and **symmetric-key ratchets** to derive message keys that change with every message. It ensures that compromise of current or past keys does not reveal other session messages.
 
 ## Core Features
 
 1. **Header Encryption (HE) Variant**
 This implementation includes *header encryption*, which encrypts message headers (e.g., message counters, key IDs) under the current sending header key (`HKs`). This protects metadata against passive traffic analysis. See the `encryptHeader` and `decryptHeader` methods for details.
 
 2. **Skipped Message Key Management**
 To support out-of-order message receipt, skipped message keys are temporarily stored. To mitigate denial-of-service (DoS) and compromise risks:
 - A cap is placed on the number of stored skipped keys per session (e.g., 100).
 - Keys are purged after timeouts or event-based thresholds (e.g., number of received messages).
 
 3. **Deferred DH Ratchet Key Generation**
 As an optimization, the generation of new DH ratchet keys can be deferred until a message is actually sent. This slightly increases security by reducing the window in which private keys exist.
 
 4. **Post-Compromise Recovery**
 Even if a party is compromised (e.g., key leak or device breach), the Double Ratchet ensures that new messages are still secure once the ratchet advances. However, active attacks can persist unless new identity keys and devices are re-established.
 
 5. **Post-Quantum X3DH (PQXDH) Integration**
 This Double Ratchet is designed to work with **PQXDH**, a post-quantum secure version of X3DH for initial key agreement:
 - `SK` from PQXDH is used as the initial root key.
 - `AD` (associated data) from PQXDH is passed to message encryption/decryption.
 - Bob's signed prekey (SPKB) becomes the initial DH ratchet public key.
 - Alice's first Double Ratchet message includes the PQXDH initial ciphertext.
 
 🔒 PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
 
 ## Key Components
 
 - `RatchetStateManager`: Core ratchet state machine. Handles key rotation, message counters, and skipped key pruning.
 - `encryptHeader`: Serializes and encrypts the message header under the current header key (HKs).
 - `decryptHeader`: Decrypts the header using current, next, or skipped header keys. May trigger a DH ratchet step.
 
 ## Operational & Security Considerations
 
 - Bounded header-gap scanning: `decryptHeader` tries skipped header keys, then the current header key, and then advances the header key iteratively up to `maxSkippedMessageKeys`. This supports large out-of-order gaps while keeping per-message work bounded.
 - Error surface: Internal crypto failures surface as `CryptoKitError` or specific `RatchetError` values (e.g., `missingConfiguration`, `receivingHeaderKeyIsNil`, `maxSkippedHeadersExceeded`). Callers should avoid exposing detailed crypto errors to untrusted clients.
 - Logging: Do not log key material or ciphertext in production. Any prints in this file are intended for debugging and must be disabled in production builds.
 
 ## References
 
 - Double Ratchet Specification: https://signal.org/docs/specifications/doubleratchet/
 - PQXDH Specification: https://signal.org/docs/specifications/pqxdh/
 - X3DH (original): https://signal.org/docs/specifications/x3dh/
 */

/* INITIAL MESSAGE (Handshake Phase)
 ------------------------------
 Sender Side:                            Receiver Side:
 
 1. PQXDH (hybrid DH) derives            1. PQXDH (hybrid DH) derives
 root key + initial sending key          root key + initial receiving key
 (derivePQXDHFinalKey)                   (derivePQXDHFinalKeyReceiver)
 
 2. Update sending header key            2. Update receiving header key
 (state.sendingHeaderKey)                (state.receivingHeaderKey)
 
 3. Derive chain key from root key      3. Derive chain key from root key
 (deriveChainKey)                       (deriveChainKey)
 
 4. Ratchet sending key (symmetric      4. Ratchet receiving key (symmetric
 KDF step)                             KDF step)
 
 5. Encrypt message header and payload  5. Decrypt message header and payload
 
 6. Mark handshake finished             6. Mark handshake finished
 
 ---
 
 SUBSEQUENT MESSAGES (Post-handshake)
 ----------------------------------
 
 Sender Side:                            Receiver Side:
 
 1. Ratchet sending header key          1. Ratchet receiving header key
 (symmetricKeyRatchet)                  (symmetricKeyRatchet)
 
 2. Ratchet sending key (chain key)    2. Ratchet receiving key (chain key)
 
 3. Update root key (optional, if       3. Update root key (optional, if
 new DH or PQXDH done)                  new DH or PQXDH done)
 
 4. Encrypt message header and payload  4. Decrypt message header and payload
 
 5. Increment message count             5. Increment message count
 
 6. Handle skipped/out-of-order msgs   6. Handle skipped/out-of-order msgs
 
 ---
 
 KEY FLOW SUMMARY:
 
 Root Key (PQXDH DH secret) ──► deriveChainKey ──► Chain Key ──► symmetricKeyRatchet (per message)
 
 Header Keys ratcheted similarly to maintain header encryption/decryption keys.
 */

typealias DoubleRatchetStateManager = RatchetStateManager
