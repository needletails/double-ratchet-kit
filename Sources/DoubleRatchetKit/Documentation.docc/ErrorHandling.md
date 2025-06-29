# Error Handling

Comprehensive guide to error handling in DoubleRatchetKit, including error types, recovery patterns, and best practices.

## Error Types

### RatchetError

The main error type for Double Ratchet operations:

```swift
enum RatchetError: Error {
    case stateUninitialized
    case encryptionFailed
    case decryptionFailed
    case missingOneTimeKey
    case invalidKeySize
    case keyDerivationFailed
    case headerDecryptionFailed
    case messageOutOfOrder
    case duplicateMessage
    case missingConfiguration
    case missingProps
    case rootKeyIsNil
    case invalidMessageNumber
    case handshakeIncomplete
    case delegateError
    case shutdownError
}
```

### CryptoError

Errors related to cryptographic operations:

```swift
enum CryptoError: Error {
    case encryptionFailed
    case decryptionFailed
    case propsError
    case messageOutOfOrder
    case invalidKeyData
    case keyValidationFailed
}
```

### KeyError

Errors related to key management:

```swift
enum KeyError: Error {
    case invalidKeySize
    case keyNotFound
    case keyExpired
    case keyCompromised
    case invalidKeyFormat
    case keyGenerationFailed
}
```

## Common Error Scenarios

### Initialization Errors

```swift
do {
    try await ratchetManager.senderInitialization(
        sessionIdentity: sessionIdentity,
        sessionSymmetricKey: sessionKey,
        remoteKeys: remoteKeys,
        localKeys: localKeys
    )
} catch RatchetError.stateUninitialized {
    // Handle uninitialized state
    print("Ratchet state not properly initialized")
} catch RatchetError.missingConfiguration {
    // Handle missing configuration
    print("Session configuration is missing")
} catch RatchetError.missingProps {
    // Handle missing session properties
    print("Session properties are missing or corrupted")
} catch {
    // Handle other initialization errors
    print("Initialization failed: \(error)")
}
```

### Encryption Errors

```swift
do {
    let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: data)
} catch RatchetError.encryptionFailed {
    // Handle encryption failure
    print("Message encryption failed")
} catch RatchetError.stateUninitialized {
    // Handle uninitialized state
    print("Cannot encrypt: ratchet not initialized")
} catch RatchetError.missingOneTimeKey {
    // Handle missing one-time key
    print("One-time key not available")
} catch {
    // Handle other encryption errors
    print("Encryption error: \(error)")
}
```

### Decryption Errors

```swift
do {
    let decryptedData = try await ratchetManager.ratchetDecrypt(message)
} catch RatchetError.decryptionFailed {
    // Handle decryption failure
    print("Message decryption failed")
} catch RatchetError.messageOutOfOrder {
    // Handle out-of-order message
    print("Message received out of order")
} catch RatchetError.duplicateMessage {
    // Handle duplicate message
    print("Duplicate message received")
} catch RatchetError.headerDecryptionFailed {
    // Handle header decryption failure
    print("Header decryption failed")
} catch {
    // Handle other decryption errors
    print("Decryption error: \(error)")
}
```

### Key Management Errors

```swift
do {
    let key = try CurvePrivateKey(id: UUID(), keyData)
} catch KeyError.invalidKeySize {
    // Handle invalid key size
    print("Key size is invalid")
} catch KeyError.invalidKeyFormat {
    // Handle invalid key format
    print("Key format is invalid")
} catch {
    // Handle other key errors
    print("Key error: \(error)")
}
```

## Recovery Patterns

### Graceful Degradation

```swift
class SecureMessagingClient {
    private let ratchetManager: RatchetStateManager<SHA256>
    private var fallbackMode = false
    
    func sendMessage(_ text: String) async throws -> MessageResult {
        do {
            let data = text.data(using: .utf8)!
            let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: data)
            return .success(encryptedMessage)
        } catch RatchetError.stateUninitialized {
            // Fall back to unencrypted mode
            fallbackMode = true
            return .fallback(text)
        } catch RatchetError.encryptionFailed {
            // Retry with fresh keys
            try await refreshKeys()
            return try await sendMessage(text)
        } catch {
            // Log error and return failure
            logger.error("Send failed: \(error)")
            return .failure(error)
        }
    }
    
    func receiveMessage(_ message: RatchetMessage) async throws -> String {
        do {
            let decryptedData = try await ratchetManager.ratchetDecrypt(message)
            return String(data: decryptedData, encoding: .utf8)!
        } catch RatchetError.messageOutOfOrder {
            // Store message for later processing
            await storeForLaterProcessing(message)
            throw error
        } catch RatchetError.duplicateMessage {
            // Ignore duplicate
            return ""
        } catch {
            // Handle other errors
            throw error
        }
    }
}
```

### Automatic Recovery

```swift
class AutoRecoveryManager {
    private let ratchetManager: RatchetStateManager<SHA256>
    private let keyManager: KeyManager
    
    func handleEncryptionError(_ error: Error) async throws {
        switch error {
        case RatchetError.missingOneTimeKey:
            // Generate new one-time keys
            try await keyManager.generateNewOneTimeKeys()
            
        case RatchetError.stateUninitialized:
            // Reinitialize session
            try await reinitializeSession()
            
        case RatchetError.encryptionFailed:
            // Refresh session keys
            try await refreshSessionKeys()
            
        default:
            throw error
        }
    }
    
    func handleDecryptionError(_ error: Error) async throws {
        switch error {
        case RatchetError.messageOutOfOrder:
            // Wait for missing messages
            await waitForMissingMessages()
            
        case RatchetError.headerDecryptionFailed:
            // Request key refresh
            try await requestKeyRefresh()
            
        case RatchetError.duplicateMessage:
            // Ignore duplicate
            return
            
        default:
            throw error
        }
    }
}
```

### Session Recovery

```swift
class SessionRecoveryManager {
    private let ratchetManager: RatchetStateManager<SHA256>
    private let storage: SessionStorage
    
    func recoverSession(for sessionId: UUID) async throws {
        // 1. Load session from storage
        guard let sessionData = try await storage.loadSession(id: sessionId) else {
            throw RatchetError.missingConfiguration
        }
        
        // 2. Validate session data
        guard sessionData.isValid else {
            throw RatchetError.missingProps
        }
        
        // 3. Reinitialize ratchet manager
        try await ratchetManager.senderInitialization(
            sessionIdentity: sessionData.identity,
            sessionSymmetricKey: sessionData.symmetricKey,
            remoteKeys: sessionData.remoteKeys,
            localKeys: sessionData.localKeys
        )
        
        // 4. Verify session is working
        try await verifySession()
    }
    
    func verifySession() async throws {
        // Send a test message to verify session is working
        let testData = "test".data(using: .utf8)!
        let encrypted = try await ratchetManager.ratchetEncrypt(plainText: testData)
        let decrypted = try await ratchetManager.ratchetDecrypt(encrypted)
        
        guard decrypted == testData else {
            throw RatchetError.decryptionFailed
        }
    }
}
```

## Error Handling Best Practices

### Comprehensive Error Handling

```swift
class RobustMessagingClient {
    private let ratchetManager: RatchetStateManager<SHA256>
    private let errorHandler: ErrorHandler
    private let logger: Logger
    
    func sendMessage(_ text: String) async -> SendResult {
        do {
            let data = text.data(using: .utf8)!
            let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: data)
            return .success(encryptedMessage)
            
        } catch RatchetError.stateUninitialized {
            logger.warning("Session not initialized, attempting recovery")
            return await handleUninitializedState()
            
        } catch RatchetError.encryptionFailed {
            logger.error("Encryption failed: \(error)")
            return await handleEncryptionFailure()
            
        } catch RatchetError.missingOneTimeKey {
            logger.info("One-time key missing, generating new keys")
            return await handleMissingOneTimeKey()
            
        } catch {
            logger.error("Unexpected error: \(error)")
            return .failure(error)
        }
    }
    
    private func handleUninitializedState() async -> SendResult {
        do {
            try await reinitializeSession()
            return try await sendMessage(text)
        } catch {
            return .failure(error)
        }
    }
    
    private func handleEncryptionFailure() async -> SendResult {
        do {
            try await refreshKeys()
            return try await sendMessage(text)
        } catch {
            return .failure(error)
        }
    }
    
    private func handleMissingOneTimeKey() async -> SendResult {
        do {
            try await generateNewOneTimeKeys()
            return try await sendMessage(text)
        } catch {
            return .failure(error)
        }
    }
}
```

### Error Logging and Monitoring

```swift
class ErrorMonitor {
    private let logger: Logger
    private let metrics: MetricsCollector
    
    func logError(_ error: Error, context: ErrorContext) {
        // Log error with context
        logger.error("""
            Error: \(error)
            Context: \(context)
            Stack trace: \(Thread.callStackSymbols)
            """)
        
        // Collect metrics
        metrics.incrementCounter("ratchet.error.\(errorType)")
        metrics.recordGauge("ratchet.error.rate", value: errorRate)
        
        // Alert on critical errors
        if isCriticalError(error) {
            alertCriticalError(error, context: context)
        }
    }
    
    func isCriticalError(_ error: Error) -> Bool {
        switch error {
        case RatchetError.stateUninitialized:
            return false // Can be recovered
        case RatchetError.encryptionFailed:
            return true // Critical
        case RatchetError.decryptionFailed:
            return true // Critical
        default:
            return false
        }
    }
}
```

### Retry Logic

```swift
class RetryManager {
    private let maxRetries: Int
    private let backoffStrategy: BackoffStrategy
    
    func withRetry<T>(
        maxAttempts: Int = 3,
        operation: () async throws -> T
    ) async throws -> T {
        var lastError: Error?
        
        for attempt in 1...maxAttempts {
            do {
                return try await operation()
            } catch let error as RatchetError {
                lastError = error
                
                // Don't retry certain errors
                if shouldNotRetry(error) {
                    throw error
                }
                
                // Wait before retry
                if attempt < maxAttempts {
                    try await Task.sleep(nanoseconds: backoffStrategy.delay(for: attempt))
                }
            } catch {
                throw error
            }
        }
        
        throw lastError ?? RatchetError.encryptionFailed
    }
    
    private func shouldNotRetry(_ error: RatchetError) -> Bool {
        switch error {
        case .stateUninitialized, .missingConfiguration, .missingProps:
            return true // These require manual intervention
        case .duplicateMessage:
            return true // No point retrying
        default:
            return false
        }
    }
}
```

## Error Prevention

### Input Validation

```swift
class InputValidator {
    func validateMessage(_ data: Data) throws {
        guard !data.isEmpty else {
            throw RatchetError.encryptionFailed
        }
        
        guard data.count <= maxMessageSize else {
            throw RatchetError.encryptionFailed
        }
    }
    
    func validateKeys(_ keys: LocalKeys) throws {
        guard keys.longTerm.rawRepresentation.count == 32 else {
            throw KeyError.invalidKeySize
        }
        
        guard keys.pqKem.rawRepresentation.count == Int(kyber1024PrivateKeyLength) else {
            throw KeyError.invalidKeySize
        }
    }
    
    func validateSessionIdentity(_ identity: SessionIdentity) throws {
        guard !identity.id.uuidString.isEmpty else {
            throw RatchetError.missingConfiguration
        }
        
        guard !identity.data.isEmpty else {
            throw RatchetError.missingProps
        }
    }
}
```

### State Validation

```swift
class StateValidator {
    func validateRatchetState(_ state: RatchetState?) throws {
        guard let state = state else {
            throw RatchetError.stateUninitialized
        }
        
        guard state.messageNumber >= 0 else {
            throw RatchetError.invalidMessageNumber
        }
        
        guard state.sendingHeaderKey.bitCount == 256 else {
            throw RatchetError.invalidKeySize
        }
        
        guard state.receivingHeaderKey.bitCount == 256 else {
            throw RatchetError.invalidKeySize
        }
    }
    
    func validateSessionConfiguration(_ config: SessionConfiguration?) throws {
        guard let config = config else {
            throw RatchetError.missingConfiguration
        }
        
        guard !config.sessionIdentity.id.uuidString.isEmpty else {
            throw RatchetError.missingConfiguration
        }
        
        guard config.sessionSymmetricKey.bitCount == 256 else {
            throw RatchetError.invalidKeySize
        }
    }
}
```

## Testing Error Scenarios

### Unit Tests

```swift
class RatchetErrorTests: XCTestCase {
    var ratchetManager: RatchetStateManager<SHA256>!
    
    override func setUp() {
        super.setUp()
        ratchetManager = RatchetStateManager<SHA256>(
            executor: TestExecutor(),
            logger: TestLogger()
        )
    }
    
    func testEncryptionWithoutInitialization() async throws {
        let data = "test".data(using: .utf8)!
        
        do {
            _ = try await ratchetManager.ratchetEncrypt(plainText: data)
            XCTFail("Should throw stateUninitialized error")
        } catch RatchetError.stateUninitialized {
            // Expected error
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testDecryptionWithInvalidMessage() async throws {
        let invalidMessage = RatchetMessage(
            header: EncryptedHeader(/* invalid data */),
            encryptedData: Data()
        )
        
        do {
            _ = try await ratchetManager.ratchetDecrypt(invalidMessage)
            XCTFail("Should throw decryptionFailed error")
        } catch RatchetError.decryptionFailed {
            // Expected error
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testMissingOneTimeKey() async throws {
        // Setup session without one-time keys
        let sessionIdentity = createSessionIdentity(includeOneTimeKey: false)
        
        do {
            try await ratchetManager.senderInitialization(
                sessionIdentity: sessionIdentity,
                sessionSymmetricKey: sessionKey,
                remoteKeys: remoteKeysWithoutOneTime,
                localKeys: localKeysWithoutOneTime
            )
            XCTFail("Should throw missingOneTimeKey error")
        } catch RatchetError.missingOneTimeKey {
            // Expected error
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}
```

### Integration Tests

```swift
class ErrorRecoveryTests: XCTestCase {
    func testSessionRecoveryAfterFailure() async throws {
        // 1. Create session
        let session = try await createSession()
        
        // 2. Simulate failure
        try await simulateFailure(session)
        
        // 3. Attempt recovery
        try await session.recover()
        
        // 4. Verify session works
        let message = "test message"
        let encrypted = try await session.send(message)
        let decrypted = try await session.receive(encrypted)
        
        XCTAssertEqual(decrypted, message)
    }
    
    func testKeyRefreshOnFailure() async throws {
        // 1. Create session with expired keys
        let session = try await createSessionWithExpiredKeys()
        
        // 2. Attempt to send message
        do {
            _ = try await session.send("test")
        } catch RatchetError.missingOneTimeKey {
            // 3. Refresh keys
            try await session.refreshKeys()
            
            // 4. Retry send
            let encrypted = try await session.send("test")
            let decrypted = try await session.receive(encrypted)
            XCTAssertEqual(decrypted, "test")
        }
    }
}
```

## Error Reporting

### Error Context

```swift
struct ErrorContext {
    let operation: String
    let sessionId: UUID?
    let messageNumber: Int?
    let timestamp: Date
    let stackTrace: [String]
    
    init(
        operation: String,
        sessionId: UUID? = nil,
        messageNumber: Int? = nil
    ) {
        self.operation = operation
        self.sessionId = sessionId
        self.messageNumber = messageNumber
        self.timestamp = Date()
        self.stackTrace = Thread.callStackSymbols
    }
}
```

### Error Reporting

```swift
class ErrorReporter {
    private let analytics: AnalyticsService
    private let crashReporter: CrashReporter
    
    func reportError(_ error: Error, context: ErrorContext) {
        // Report to analytics
        analytics.track("ratchet_error", properties: [
            "error_type": String(describing: type(of: error)),
            "operation": context.operation,
            "session_id": context.sessionId?.uuidString ?? "unknown",
            "message_number": context.messageNumber ?? -1,
            "timestamp": context.timestamp.timeIntervalSince1970
        ])
        
        // Report to crash reporter for critical errors
        if isCriticalError(error) {
            crashReporter.reportError(error, context: context)
        }
    }
    
    private func isCriticalError(_ error: Error) -> Bool {
        // Define which errors are critical
        switch error {
        case RatchetError.encryptionFailed,
             RatchetError.decryptionFailed,
             RatchetError.keyDerivationFailed:
            return true
        default:
            return false
        }
    }
}
```

## Related Documentation

- <doc:RatchetStateManager> - Main ratchet state management
- <doc:SessionIdentity> - Session identity management
- <doc:BestPractices> - Best practices for implementation
- <doc:SecurityModel> - Security considerations 