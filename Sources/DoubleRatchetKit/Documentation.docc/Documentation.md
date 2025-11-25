# DoubleRatchetKit

A Swift implementation of the **Double Ratchet Algorithm** with **Post-Quantum X3DH (PQXDH)** integration, providing asynchronous forward secrecy and post-compromise security for secure messaging applications.

## Overview

DoubleRatchetKit implements the Signal protocol's Double Ratchet algorithm with post-quantum security enhancements. It provides:

- **Forward Secrecy**: Message keys change with every message
- **Post-Compromise Security**: Recovery from key compromise
- **Post-Quantum Security**: Hybrid PQXDH with MLKEM1024 and Curve25519
- **Header Encryption**: Protects metadata against traffic analysis
- **Out-of-Order Support**: Handles skipped messages with key caching
- **Concurrency Safety**: Built with Swift actors for thread safety

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:KeyConcepts>
- <doc:SecurityModel>

### Core Components

- <doc:DoubleRatchetStateManager>
- <doc:SessionIdentity>
- <doc:RatchetState>
- <doc:KeyManagement>

### API Reference

- <doc:APIReference> 
