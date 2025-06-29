# Best Practices

Comprehensive guidelines for secure and efficient implementation of DoubleRatchetKit.

## Overview

This document provides best practices for implementing secure messaging with DoubleRatchetKit, covering security, performance, and deployment considerations.

## Security Best Practices

### Key Management

#### Secure Key Generation

```swift
class SecureKeyManager {
    private let keychain = KeychainWrapper.standard
    
    func generateSecureKeys() throws -> (CurvePrivateKey, PQKemPrivateKey) {
        // Use CryptoKit for secure key generation
        let curvePrivateKey = try Curve25519.KeyAgreement.PrivateKey()
        let kyberPrivateKey = try Kyber1024.KeyAgreement.PrivateKey()
        
        // Wrap keys with UUIDs for identification
        let wrappedCurveKey = try CurvePrivateKey(
            id: UUID(),
            curvePrivateKey.rawRepresentation
        )
        let wrappedKyberKey = try PQKemPrivateKey(
            id: UUID(),
            kyberPrivateKey.rawRepresentation
        )
        
        return (wrappedCurveKey, wrappedKyberKey)
    }
    
    func storeKeysSecurely(_ keys: (CurvePrivateKey, PQKemPrivateKey)) throws {
        // Store in Keychain with appropriate access control
        try keychain.set(
            keys.0.rawRepresentation,
            forKey: "curve_private_key_\(keys.0.id)",
            withAccessibility: .whenUnlockedThisDeviceOnly
        )
        
        try keychain.set(
            keys.1.rawRepresentation,
            forKey: "kyber_private_key_\(keys.1.id)",
            withAccessibility: .whenUnlockedThisDeviceOnly
        )
    }
}
```

#### Key Rotation

```swift
class KeyRotationManager {
    private let keyManager: SecureKeyManager
    private let rotationInterval: TimeInterval = 24 * 60 * 60 // 24 hours
    
    func scheduleKeyRotation() {
        Timer.scheduledTimer(withTimeInterval: rotationInterval, repeats: true) { _ in
            Task {
                try await self.rotateKeys()
            }
        }
    }
    
    func rotateKeys() async throws {
        // Generate new keys
        let newKeys = try keyManager.generateSecureKeys()
        
        // Update session with new keys
        try await updateSessionKeys(newKeys)
        
        // Securely delete old keys
        try await deleteOldKeys()
        
        // Notify delegate of key rotation
        await delegate?.keysRotated(newKeys)
    }
    
    private func deleteOldKeys() async throws {
        // Securely wipe old key material
        try await secureWipe(oldKeys)
    }
}
```

### Session Management

#### Secure Session Initialization

```swift
class SecureSessionManager {
    private let ratchetManager: RatchetStateManager<SHA256>
    private let keyManager: SecureKeyManager
    
    func initializeSecureSession(
        for peerId: UUID,
        with keys: (CurvePrivateKey, PQKemPrivateKey)
    ) async throws -> SessionIdentity {
        
        // Validate keys before use
        try validateKeys(keys)
        
        // Generate session-specific symmetric key
        let sessionKey = SymmetricKey(size: .bits256)
        
        // Create session identity with proper metadata
        let sessionProps = SessionIdentity.UnwrappedProps(
            secretName: "session_\(peerId.uuidString)",
            deviceId: getCurrentDeviceId(),
            sessionContextId: generateSessionContextId(),
            longTermPublicKey: keys.0.rawRepresentation,
            signingPublicKey: generateSigningKey(),
            pqKemPublicKey: keys.1,
            oneTimePublicKey: generateOneTimeKey(),
            deviceName: getDeviceName(),
            isMasterDevice: isMasterDevice(),
            verifiedIdentity: false // Will be verified through out-of-band process
        )
        
        let sessionIdentity = try SessionIdentity(
            id: UUID(),
            props: sessionProps,
            symmetricKey: sessionKey
        )
        
        // Initialize ratchet manager
        try await ratchetManager.senderInitialization(
            sessionIdentity: sessionIdentity,
            sessionSymmetricKey: sessionKey,
            remoteKeys: await fetchRemoteKeys(for: peerId),
            localKeys: LocalKeys(
                longTerm: keys.0,
                oneTime: generateOneTimeKey(),
                pqKem: keys.1
            )
        )
        
        return sessionIdentity
    }
}
```

#### Session Validation

```swift
class SessionValidator {
    func validateSession(_ session: SessionIdentity) throws {
        // Check session integrity
        guard session.id != UUID.init(uuidString: "00000000-0000-0000-0000-000000000000") else {
            throw SecurityError.invalidSessionId
        }
        
        // Validate session properties
        let props = try session.decryptProps(symmetricKey: sessionKey)
        
        guard !props.deviceName.isEmpty else {
            throw SecurityError.invalidDeviceName
        }
        
        guard props.sessionContextId > 0 else {
            throw SecurityError.invalidSessionContext
        }
        
        // Check for session expiration
        if let lastActivity = props.previousRekey {
            let sessionAge = Date().timeIntervalSince(lastActivity)
            if sessionAge > maxSessionAge {
                throw SecurityError.sessionExpired
            }
        }
    }
}
```

### Message Security

#### Input Validation

```swift
class MessageValidator {
    private let maxMessageSize = 1024 * 1024 // 1MB
    private let allowedContentTypes = ["text/plain", "application/json", "image/jpeg"]
    
    func validateMessage(_ data: Data, contentType: String) throws {
        // Check message size
        guard data.count <= maxMessageSize else {
            throw SecurityError.messageTooLarge
        }
        
        // Check content type
        guard allowedContentTypes.contains(contentType) else {
            throw SecurityError.invalidContentType
        }
        
        // Check for null bytes or other dangerous content
        guard !data.contains(0) else {
            throw SecurityError.invalidMessageContent
        }
        
        // Validate message format
        try validateMessageFormat(data)
    }
    
    private func validateMessageFormat(_ data: Data) throws {
        // Implement format-specific validation
        // For example, check JSON structure, image headers, etc.
    }
}
```

#### Secure Message Handling

```swift
class SecureMessageHandler {
    private let ratchetManager: RatchetStateManager<SHA256>
    private let validator: MessageValidator
    
    func sendSecureMessage(_ content: String, to peerId: UUID) async throws -> RatchetMessage {
        // Validate input
        guard let data = content.data(using: .utf8) else {
            throw SecurityError.invalidMessageContent
        }
        
        try validator.validateMessage(data, contentType: "text/plain")
        
        // Add message metadata
        let messageWithMetadata = addMessageMetadata(data)
        
        // Encrypt message
        let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: messageWithMetadata)
        
        // Log message for audit (without content)
        await logMessageSent(to: peerId, messageId: encryptedMessage.header.hashValue)
        
        return encryptedMessage
    }
    
    func receiveSecureMessage(_ message: RatchetMessage, from peerId: UUID) async throws -> String {
        // Validate message structure
        try validateMessageStructure(message)
        
        // Decrypt message
        let decryptedData = try await ratchetManager.ratchetDecrypt(message)
        
        // Validate decrypted content
        try validator.validateMessage(decryptedData, contentType: "text/plain")
        
        // Extract and validate metadata
        let (content, metadata) = extractMessageMetadata(decryptedData)
        try validateMessageMetadata(metadata, from: peerId)
        
        // Log message for audit
        await logMessageReceived(from: peerId, messageId: message.header.hashValue)
        
        return content
    }
}
```

## Implementation Best Practices

### Error Handling

#### Comprehensive Error Management

```swift
class RobustErrorHandler {
    private let logger: Logger
    private let metrics: MetricsCollector
    
    func handleRatchetError(_ error: Error, context: ErrorContext) async {
        // Log error with context
        logger.error("""
            Ratchet error: \(error)
            Context: \(context)
            Stack trace: \(Thread.callStackSymbols)
            """)
        
        // Collect metrics
        await metrics.incrementCounter("ratchet.error.\(errorType)")
        
        // Handle specific error types
        switch error {
        case RatchetError.stateUninitialized:
            await handleUninitializedState(context)
        case RatchetError.encryptionFailed:
            await handleEncryptionFailure(context)
        case RatchetError.missingOneTimeKey:
            await handleMissingOneTimeKey(context)
        default:
            await handleUnexpectedError(error, context)
        }
    }
    
    private func handleUninitializedState(_ context: ErrorContext) async {
        // Attempt to reinitialize session
        do {
            try await reinitializeSession(context.sessionId)
        } catch {
            await escalateError(error, context)
        }
    }
    
    private func handleEncryptionFailure(_ context: ErrorContext) async {
        // Refresh keys and retry
        do {
            try await refreshKeys(context.sessionId)
        } catch {
            await escalateError(error, context)
        }
    }
}
```

#### Graceful Degradation

```swift
class GracefulDegradationManager {
    private var fallbackMode = false
    private let fallbackEncryption: FallbackEncryption
    
    func sendMessageWithFallback(_ content: String) async throws -> MessageResult {
        do {
            let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: content.data(using: .utf8)!)
            return .success(encryptedMessage)
        } catch RatchetError.stateUninitialized {
            // Fall back to basic encryption
            fallbackMode = true
            let fallbackMessage = try await fallbackEncryption.encrypt(content)
            return .fallback(fallbackMessage)
        } catch {
            return .failure(error)
        }
    }
    
    func receiveMessageWithFallback(_ message: MessageData) async throws -> String {
        if fallbackMode {
            return try await fallbackEncryption.decrypt(message)
        } else {
            let decryptedData = try await ratchetManager.ratchetDecrypt(message.ratchetMessage)
            return String(data: decryptedData, encoding: .utf8)!
        }
    }
}
```

### Performance Optimization

#### Efficient Resource Management

```swift
class ResourceManager {
    private let sessionPool = NSCache<NSString, RatchetStateManager<SHA256>>()
    private let keyCache = NSCache<NSString, SymmetricKey>()
    
    init() {
        // Configure cache limits
        sessionPool.countLimit = 100
        sessionPool.totalCostLimit = 50 * 1024 * 1024 // 50MB
        
        keyCache.countLimit = 1000
        keyCache.totalCostLimit = 10 * 1024 * 1024 // 10MB
    }
    
    func getSession(for sessionId: UUID) -> RatchetStateManager<SHA256>? {
        return sessionPool.object(forKey: sessionId.uuidString as NSString)
    }
    
    func cacheSession(_ session: RatchetStateManager<SHA256>, for sessionId: UUID) {
        sessionPool.setObject(session, forKey: sessionId.uuidString as NSString)
    }
    
    func cleanupUnusedResources() {
        // Remove sessions inactive for more than 1 hour
        let cutoff = Date().addingTimeInterval(-3600)
        // Implementation depends on session tracking
    }
}
```

#### Batch Processing

```swift
class BatchProcessor {
    private let processingQueue = DispatchQueue(
        label: "batch-processing",
        qos: .userInitiated,
        attributes: .concurrent
    )
    
    func processMessageBatch(_ messages: [RatchetMessage]) async throws -> [Data] {
        return try await withThrowingTaskGroup(of: (Int, Data).self) { group in
            for (index, message) in messages.enumerated() {
                group.addTask {
                    let decrypted = try await self.decryptMessage(message)
                    return (index, decrypted)
                }
            }
            
            var results: [(Int, Data)] = []
            for try await result in group {
                results.append(result)
            }
            
            return results.sorted { $0.0 < $1.0 }.map { $0.1 }
        }
    }
}
```

## Deployment Best Practices

### Configuration Management

#### Environment-Specific Configuration

```swift
struct RatchetConfiguration {
    let maxSkippedMessageKeys: Int
    let sessionTimeout: TimeInterval
    let keyRotationInterval: TimeInterval
    let enableHardwareAcceleration: Bool
    let logLevel: LogLevel
    
    static let development = RatchetConfiguration(
        maxSkippedMessageKeys: 100,
        sessionTimeout: 300, // 5 minutes
        keyRotationInterval: 3600, // 1 hour
        enableHardwareAcceleration: true,
        logLevel: .debug
    )
    
    static let production = RatchetConfiguration(
        maxSkippedMessageKeys: 1000,
        sessionTimeout: 3600, // 1 hour
        keyRotationInterval: 86400, // 24 hours
        enableHardwareAcceleration: true,
        logLevel: .error
    )
    
    static let testing = RatchetConfiguration(
        maxSkippedMessageKeys: 10,
        sessionTimeout: 60, // 1 minute
        keyRotationInterval: 300, // 5 minutes
        enableHardwareAcceleration: false,
        logLevel: .trace
    )
}
```

#### Secure Configuration

```swift
class SecureConfigurationManager {
    private let keychain = KeychainWrapper.standard
    
    func loadSecureConfiguration() throws -> RatchetConfiguration {
        // Load configuration from secure storage
        guard let configData = keychain.data(forKey: "ratchet_config") else {
            throw ConfigurationError.missingConfiguration
        }
        
        let config = try JSONDecoder().decode(RatchetConfiguration.self, from: configData)
        
        // Validate configuration
        try validateConfiguration(config)
        
        return config
    }
    
    func saveSecureConfiguration(_ config: RatchetConfiguration) throws {
        // Validate before saving
        try validateConfiguration(config)
        
        let configData = try JSONEncoder().encode(config)
        
        // Store in Keychain
        try keychain.set(configData, forKey: "ratchet_config")
    }
    
    private func validateConfiguration(_ config: RatchetConfiguration) throws {
        guard config.maxSkippedMessageKeys > 0 else {
            throw ConfigurationError.invalidMaxSkippedKeys
        }
        
        guard config.sessionTimeout > 0 else {
            throw ConfigurationError.invalidSessionTimeout
        }
        
        guard config.keyRotationInterval > 0 else {
            throw ConfigurationError.invalidKeyRotationInterval
        }
    }
}
```

### Logging and Monitoring

#### Secure Logging

```swift
class SecureLogger {
    private let logger: Logger
    private let sensitiveFields = ["privateKey", "symmetricKey", "sessionKey"]
    
    func logSecureEvent(_ event: String, metadata: [String: Any]) {
        // Sanitize sensitive data
        let sanitizedMetadata = sanitizeMetadata(metadata)
        
        logger.info("""
            Event: \(event)
            Metadata: \(sanitizedMetadata)
            Timestamp: \(Date())
            """)
    }
    
    private func sanitizeMetadata(_ metadata: [String: Any]) -> [String: Any] {
        var sanitized = metadata
        
        for field in sensitiveFields {
            if sanitized[field] != nil {
                sanitized[field] = "[REDACTED]"
            }
        }
        
        return sanitized
    }
    
    func logSecurityEvent(_ event: SecurityEvent) {
        logger.warning("""
            Security Event: \(event.type)
            Severity: \(event.severity)
            Details: \(event.details)
            Timestamp: \(Date())
            """)
        
        // Alert security team for high-severity events
        if event.severity == .high {
            alertSecurityTeam(event)
        }
    }
}
```

#### Performance Monitoring

```swift
class PerformanceMonitor {
    private let metrics: MetricsCollector
    
    func monitorRatchetOperation<T>(_ operation: String, block: () async throws -> T) async throws -> T {
        let startTime = CFAbsoluteTimeGetCurrent()
        
        do {
            let result = try await block()
            
            let duration = CFAbsoluteTimeGetCurrent() - startTime
            await metrics.recordTiming("ratchet.\(operation)", duration: duration)
            await metrics.incrementCounter("ratchet.\(operation).success")
            
            return result
        } catch {
            await metrics.incrementCounter("ratchet.\(operation).failure")
            throw error
        }
    }
    
    func monitorMemoryUsage() {
        let usage = getMemoryUsage()
        
        if usage.residentSizeMB > 100 {
            // Alert on high memory usage
            alertHighMemoryUsage(usage)
        }
        
        // Record memory metrics
        Task {
            await metrics.recordGauge("memory.resident", value: usage.residentSizeMB)
            await metrics.recordGauge("memory.virtual", value: usage.virtualSizeMB)
        }
    }
}
```

## Testing Best Practices

### Unit Testing

```swift
class RatchetUnitTests: XCTestCase {
    var ratchetManager: RatchetStateManager<SHA256>!
    var mockDelegate: MockSessionDelegate!
    
    override func setUp() {
        super.setUp()
        ratchetManager = RatchetStateManager<SHA256>(
            executor: TestExecutor(),
            logger: TestLogger()
        )
        mockDelegate = MockSessionDelegate()
        ratchetManager.setDelegate(mockDelegate)
    }
    
    func testSecureKeyGeneration() throws {
        let keys = try generateSecureKeys()
        
        // Verify key sizes
        XCTAssertEqual(keys.0.rawRepresentation.count, 32)
        XCTAssertEqual(keys.1.rawRepresentation.count, Int(kyber1024PrivateKeyLength))
        
        // Verify key uniqueness
        XCTAssertNotEqual(keys.0.id, keys.1.id)
    }
    
    func testMessageEncryptionDecryption() async throws {
        let plaintext = "Hello, World!"
        let data = plaintext.data(using: .utf8)!
        
        // Encrypt
        let encrypted = try await ratchetManager.ratchetEncrypt(plainText: data)
        
        // Verify encryption
        XCTAssertNotEqual(encrypted.encryptedData, data)
        
        // Decrypt
        let decrypted = try await ratchetManager.ratchetDecrypt(encrypted)
        
        // Verify decryption
        XCTAssertEqual(decrypted, data)
        XCTAssertEqual(String(data: decrypted, encoding: .utf8), plaintext)
    }
    
    func testForwardSecrecy() async throws {
        let message1 = "Message 1"
        let message2 = "Message 2"
        
        // Encrypt two messages
        let encrypted1 = try await ratchetManager.ratchetEncrypt(plainText: message1.data(using: .utf8)!)
        let encrypted2 = try await ratchetManager.ratchetEncrypt(plainText: message2.data(using: .utf8)!)
        
        // Verify different ciphertexts
        XCTAssertNotEqual(encrypted1.encryptedData, encrypted2.encryptedData)
    }
}
```

### Integration Testing

```swift
class RatchetIntegrationTests: XCTestCase {
    func testEndToEndCommunication() async throws {
        // Setup Alice and Bob
        let alice = try await createSecureSession(name: "Alice")
        let bob = try await createSecureSession(name: "Bob")
        
        // Exchange keys
        try await exchangeKeys(alice: alice, bob: bob)
        
        // Alice sends message to Bob
        let message = "Hello from Alice!"
        let encrypted = try await alice.sendMessage(message)
        
        // Bob receives and decrypts message
        let decrypted = try await bob.receiveMessage(encrypted)
        
        // Verify message integrity
        XCTAssertEqual(decrypted, message)
    }
    
    func testSessionRecovery() async throws {
        let session = try await createSecureSession(name: "TestUser")
        
        // Simulate session corruption
        try await corruptSession(session)
        
        // Attempt recovery
        try await session.recover()
        
        // Verify session works after recovery
        let message = "Test message"
        let encrypted = try await session.sendMessage(message)
        let decrypted = try await session.receiveMessage(encrypted)
        
        XCTAssertEqual(decrypted, message)
    }
}
```

### Security Testing

```swift
class SecurityTests: XCTestCase {
    func testKeyCompromiseRecovery() async throws {
        let session = try await createSecureSession(name: "TestUser")
        
        // Simulate key compromise
        try await compromiseKeys(session)
        
        // Verify post-compromise security
        let message = "Secret message"
        let encrypted = try await session.sendMessage(message)
        
        // Attempt decryption with compromised keys should fail
        XCTAssertThrowsError(try await decryptWithCompromisedKeys(encrypted))
    }
    
    func testReplayAttackProtection() async throws {
        let session = try await createSecureSession(name: "TestUser")
        
        let message = "Original message"
        let encrypted = try await session.sendMessage(message)
        
        // Attempt replay attack
        XCTAssertThrowsError(try await session.receiveMessage(encrypted))
    }
    
    func testManInTheMiddleProtection() async throws {
        let alice = try await createSecureSession(name: "Alice")
        let bob = try await createSecureSession(name: "Bob")
        let eve = try await createSecureSession(name: "Eve")
        
        // Setup secure communication between Alice and Bob
        try await establishSecureChannel(alice: alice, bob: bob)
        
        // Eve attempts to intercept
        let message = "Secret message"
        let encrypted = try await alice.sendMessage(message)
        
        // Eve should not be able to decrypt
        XCTAssertThrowsError(try await eve.receiveMessage(encrypted))
    }
}
```

## Security Considerations

### Threat Model

1. **Passive Adversaries**: Eavesdropping on encrypted messages
2. **Active Adversaries**: Modifying or injecting messages
3. **Key Compromise**: Access to private keys
4. **Side-Channel Attacks**: Timing, power, or cache attacks
5. **Implementation Vulnerabilities**: Bugs in cryptographic code

### Security Recommendations

1. **Regular Updates**: Keep dependencies updated
2. **Key Rotation**: Implement automatic key rotation
3. **Audit Logging**: Log security-relevant events
4. **Input Validation**: Validate all inputs
5. **Secure Storage**: Use Keychain for sensitive data
6. **Memory Protection**: Securely wipe sensitive data
7. **Transport Security**: Use TLS for network communication
8. **Code Review**: Regular security code reviews

## Related Documentation

- <doc:RatchetStateManager> - Main ratchet state management
- <doc:SecurityModel> - Security properties and guarantees
- <doc:ErrorHandling> - Error handling patterns
- <doc:Performance> - Performance optimization 