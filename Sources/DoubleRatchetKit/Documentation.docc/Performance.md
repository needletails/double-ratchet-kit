# Performance

Performance characteristics, optimization strategies, and best practices for DoubleRatchetKit.

## Overview

DoubleRatchetKit is designed for high-performance secure messaging with efficient cryptographic operations and memory management. This document covers performance characteristics and optimization strategies.

## Performance Characteristics

### Cryptographic Operations

#### Key Derivation Performance

```swift
// Key derivation benchmarks (typical values)
let keyDerivationTimes = [
    "Chain Key Derivation": "~0.1ms",
    "Message Key Derivation": "~0.05ms", 
    "Header Key Derivation": "~0.1ms",
    "Root Key Derivation": "~0.5ms"
]
```

**Factors affecting performance:**
- **Hash function choice**: SHA-256 vs SHA-512
- **Key size**: 256-bit vs 512-bit keys
- **Hardware acceleration**: CryptoKit vs custom implementation
- **Memory allocation**: Stack vs heap allocation

#### Encryption/Decryption Performance

```swift
// AES-256-GCM performance (typical values)
let encryptionPerformance = [
    "Small message (1KB)": "~0.2ms",
    "Medium message (10KB)": "~1.5ms",
    "Large message (100KB)": "~15ms",
    "Header encryption": "~0.1ms"
]
```

**Performance considerations:**
- **Message size**: Linear scaling with data size
- **Hardware acceleration**: AES-NI support
- **Memory layout**: Contiguous vs fragmented data
- **Concurrent operations**: Actor isolation overhead

### Memory Usage

#### Memory Footprint

```swift
// Typical memory usage per session
let memoryUsage = [
    "RatchetState": "~2KB",
    "SessionIdentity": "~1KB", 
    "SkippedMessageKeys": "~100KB (max)",
    "Key cache": "~50KB",
    "Total per session": "~150KB"
]
```

#### Memory Management

```swift
class MemoryOptimizedRatchetManager {
    private let keyCache = NSCache<NSString, SymmetricKey>()
    private let maxSkippedKeys = 1000
    
    init() {
        // Configure cache limits
        keyCache.countLimit = 100
        keyCache.totalCostLimit = 50 * 1024 // 50KB
    }
    
    func optimizeMemoryUsage() {
        // Clear old cached keys
        keyCache.removeAllObjects()
        
        // Trim skipped message keys
        if skippedKeys.count > maxSkippedKeys {
            skippedKeys.removeFirst(skippedKeys.count - maxSkippedKeys)
        }
    }
}
```

## Optimization Strategies

### Key Management Optimization

#### Key Caching

```swift
class KeyCache {
    private let cache = NSCache<NSString, SymmetricKey>()
    private let queue = DispatchQueue(label: "key-cache", qos: .userInitiated)
    
    func getDerivedKey(from baseKey: SymmetricKey, purpose: String) -> SymmetricKey {
        let key = "\(baseKey.hashValue)_\(purpose)"
        
        return queue.sync {
            if let cached = cache.object(forKey: key as NSString) {
                return cached
            }
            
            let derived = deriveKey(from: baseKey, purpose: purpose)
            cache.setObject(derived, forKey: key as NSString)
            return derived
        }
    }
    
    func clearCache() {
        queue.sync {
            cache.removeAllObjects()
        }
    }
}
```

#### Batch Key Generation

```swift
class BatchKeyGenerator {
    private let keyQueue = DispatchQueue(label: "key-generation", qos: .background)
    
    func generateOneTimeKeys(count: Int) async throws -> [CurvePrivateKey] {
        return try await withCheckedThrowingContinuation { continuation in
            keyQueue.async {
                do {
                    var keys: [CurvePrivateKey] = []
                    for _ in 0..<count {
                        let privateKey = try Curve25519.KeyAgreement.PrivateKey()
                        let wrappedKey = try CurvePrivateKey(
                            id: UUID(),
                            privateKey.rawRepresentation
                        )
                        keys.append(wrappedKey)
                    }
                    continuation.resume(returning: keys)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
```

### Session Management Optimization

#### Session Pooling

```swift
class SessionPool {
    private var activeSessions: [UUID: RatchetStateManager<SHA256>] = [:]
    private let sessionQueue = DispatchQueue(label: "session-pool", qos: .userInitiated)
    
    func getSession(for sessionId: UUID) -> RatchetStateManager<SHA256>? {
        return sessionQueue.sync {
            return activeSessions[sessionId]
        }
    }
    
    func addSession(_ session: RatchetStateManager<SHA256>, for sessionId: UUID) {
        sessionQueue.sync {
            activeSessions[sessionId] = session
        }
    }
    
    func removeSession(for sessionId: UUID) {
        sessionQueue.sync {
            activeSessions.removeValue(forKey: sessionId)
        }
    }
    
    func cleanupInactiveSessions() {
        sessionQueue.sync {
            // Remove sessions inactive for more than 1 hour
            let cutoff = Date().addingTimeInterval(-3600)
            activeSessions = activeSessions.filter { session in
                // Check if session is still active
                return true // Implement actual check
            }
        }
    }
}
```

#### Lazy Initialization

```swift
class LazyRatchetManager {
    private var ratchetManager: RatchetStateManager<SHA256>?
    private let initializationQueue = DispatchQueue(label: "init", qos: .userInitiated)
    
    func getRatchetManager() async throws -> RatchetStateManager<SHA256> {
        if let manager = ratchetManager {
            return manager
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            initializationQueue.async {
                do {
                    let manager = RatchetStateManager<SHA256>(
                        executor: self.executor,
                        logger: self.logger
                    )
                    self.ratchetManager = manager
                    continuation.resume(returning: manager)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
```

### Message Processing Optimization

#### Batch Message Processing

```swift
class BatchMessageProcessor {
    private let processingQueue = DispatchQueue(
        label: "message-processing",
        qos: .userInitiated,
        attributes: .concurrent
    )
    
    func processMessages(_ messages: [RatchetMessage]) async throws -> [Data] {
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
            
            // Sort by original index
            return results.sorted { $0.0 < $1.0 }.map { $0.1 }
        }
    }
    
    private func decryptMessage(_ message: RatchetMessage) async throws -> Data {
        // Decrypt individual message
        return try await ratchetManager.ratchetDecrypt(message)
    }
}
```

#### Message Buffering

```swift
class MessageBuffer {
    private var buffer: [RatchetMessage] = []
    private let bufferQueue = DispatchQueue(label: "message-buffer", qos: .userInitiated)
    private let maxBufferSize = 100
    
    func addMessage(_ message: RatchetMessage) {
        bufferQueue.sync {
            buffer.append(message)
            
            if buffer.count >= maxBufferSize {
                processBuffer()
            }
        }
    }
    
    private func processBuffer() {
        let messagesToProcess = buffer
        buffer.removeAll()
        
        Task {
            do {
                let decryptedMessages = try await processMessages(messagesToProcess)
                await handleDecryptedMessages(decryptedMessages)
            } catch {
                await handleProcessingError(error)
            }
        }
    }
}
```

## Concurrency Optimization

### Actor Isolation Benefits

```swift
public actor RatchetStateManager<Hash: HashFunction & Sendable> {
    // All state mutations are automatically serialized
    private var state: RatchetState?
    private var sessionConfigurations: [SessionConfiguration] = []
    
    // Concurrent access is safe
    public func ratchetEncrypt(plainText: Data) async throws -> RatchetMessage {
        // This method is automatically isolated
        guard let state = state else {
            throw RatchetError.stateUninitialized
        }
        
        // State mutations are serialized
        let newState = state.updateMessageNumber(state.messageNumber + 1)
        self.state = newState
        
        return try await performEncryption(plainText, state: newState)
    }
}
```

### Concurrent Session Management

```swift
class ConcurrentSessionManager {
    private let sessionPool: [UUID: RatchetStateManager<SHA256>] = [:]
    private let sessionQueue = DispatchQueue(
        label: "session-manager",
        qos: .userInitiated,
        attributes: .concurrent
    )
    
    func sendMessage(_ message: Data, to sessionId: UUID) async throws -> RatchetMessage {
        guard let session = getSession(for: sessionId) else {
            throw RatchetError.missingConfiguration
        }
        
        // Each session is an actor, so this is safe
        return try await session.ratchetEncrypt(plainText: message)
    }
    
    func receiveMessage(_ message: RatchetMessage, from sessionId: UUID) async throws -> Data {
        guard let session = getSession(for: sessionId) else {
            throw RatchetError.missingConfiguration
        }
        
        // Concurrent decryption is safe
        return try await session.ratchetDecrypt(message)
    }
}
```

## Benchmarking

### Performance Testing

```swift
class PerformanceBenchmark {
    private let iterations = 1000
    private let messageSizes = [1024, 10240, 102400] // 1KB, 10KB, 100KB
    
    func benchmarkEncryption() async throws -> [String: TimeInterval] {
        var results: [String: TimeInterval] = [:]
        
        for size in messageSizes {
            let data = Data(repeating: 0, count: size)
            let startTime = CFAbsoluteTimeGetCurrent()
            
            for _ in 0..<iterations {
                _ = try await ratchetManager.ratchetEncrypt(plainText: data)
            }
            
            let endTime = CFAbsoluteTimeGetCurrent()
            let averageTime = (endTime - startTime) / Double(iterations)
            results["\(size) bytes"] = averageTime
        }
        
        return results
    }
    
    func benchmarkDecryption() async throws -> [String: TimeInterval] {
        var results: [String: TimeInterval] = [:]
        
        for size in messageSizes {
            let data = Data(repeating: 0, count: size)
            let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: data)
            
            let startTime = CFAbsoluteTimeGetCurrent()
            
            for _ in 0..<iterations {
                _ = try await ratchetManager.ratchetDecrypt(encryptedMessage)
            }
            
            let endTime = CFAbsoluteTimeGetCurrent()
            let averageTime = (endTime - startTime) / Double(iterations)
            results["\(size) bytes"] = averageTime
        }
        
        return results
    }
    
    func benchmarkKeyDerivation() async throws -> [String: TimeInterval] {
        let startTime = CFAbsoluteTimeGetCurrent()
        
        for _ in 0..<iterations {
            _ = try deriveChainKey(from: SymmetricKey(size: .bits256))
        }
        
        let endTime = CFAbsoluteTimeGetCurrent()
        let averageTime = (endTime - startTime) / Double(iterations)
        
        return ["Key Derivation": averageTime]
    }
}
```

### Memory Profiling

```swift
class MemoryProfiler {
    func profileMemoryUsage() -> MemoryUsage {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size)/4
        
        let kerr: kern_return_t = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_,
                         task_flavor_t(MACH_TASK_BASIC_INFO),
                         $0,
                         &count)
            }
        }
        
        if kerr == KERN_SUCCESS {
            return MemoryUsage(
                residentSize: info.resident_size,
                virtualSize: info.virtual_size,
                peakResidentSize: info.resident_size_max
            )
        } else {
            return MemoryUsage(residentSize: 0, virtualSize: 0, peakResidentSize: 0)
        }
    }
}

struct MemoryUsage {
    let residentSize: UInt64
    let virtualSize: UInt64
    let peakResidentSize: UInt64
    
    var residentSizeMB: Double {
        return Double(residentSize) / 1024.0 / 1024.0
    }
    
    var virtualSizeMB: Double {
        return Double(virtualSize) / 1024.0 / 1024.0
    }
}
```

## Configuration Tuning

### Performance Configuration

```swift
struct PerformanceConfiguration {
    let maxSkippedMessageKeys: Int
    let keyCacheSize: Int
    let batchSize: Int
    let enableHardwareAcceleration: Bool
    let useOptimizedAlgorithms: Bool
    
    static let `default` = PerformanceConfiguration(
        maxSkippedMessageKeys: 1000,
        keyCacheSize: 100,
        batchSize: 50,
        enableHardwareAcceleration: true,
        useOptimizedAlgorithms: true
    )
    
    static let highPerformance = PerformanceConfiguration(
        maxSkippedMessageKeys: 2000,
        keyCacheSize: 200,
        batchSize: 100,
        enableHardwareAcceleration: true,
        useOptimizedAlgorithms: true
    )
    
    static let lowMemory = PerformanceConfiguration(
        maxSkippedMessageKeys: 500,
        keyCacheSize: 50,
        batchSize: 25,
        enableHardwareAcceleration: true,
        useOptimizedAlgorithms: false
    )
}
```

### Dynamic Configuration

```swift
class AdaptivePerformanceManager {
    private var currentConfig: PerformanceConfiguration
    private let metrics: PerformanceMetrics
    
    func adaptConfiguration() {
        let memoryUsage = metrics.currentMemoryUsage
        let cpuUsage = metrics.currentCPUUsage
        
        if memoryUsage > 0.8 { // 80% memory usage
            currentConfig = PerformanceConfiguration.lowMemory
        } else if cpuUsage < 0.3 { // Low CPU usage
            currentConfig = PerformanceConfiguration.highPerformance
        } else {
            currentConfig = PerformanceConfiguration.default
        }
        
        applyConfiguration(currentConfig)
    }
    
    private func applyConfiguration(_ config: PerformanceConfiguration) {
        // Apply configuration changes
        keyCache.countLimit = config.keyCacheSize
        maxSkippedKeys = config.maxSkippedMessageKeys
        batchSize = config.batchSize
    }
}
```

## Best Practices

### Performance Best Practices

1. **Use Hardware Acceleration**
   ```swift
   // Enable CryptoKit hardware acceleration
   let crypto = CryptoKit.AES.GCM.Nonce()
   ```

2. **Minimize Memory Allocations**
   ```swift
   // Reuse buffers when possible
   private let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: 1024)
   defer { buffer.deallocate() }
   ```

3. **Batch Operations**
   ```swift
   // Process multiple messages together
   let results = try await withThrowingTaskGroup(of: Data.self) { group in
       for message in messages {
           group.addTask { try await decryptMessage(message) }
       }
       return try await group.reduce(into: []) { $0.append($1) }
   }
   ```

4. **Use Appropriate Queue Priorities**
   ```swift
   let cryptoQueue = DispatchQueue(
       label: "crypto",
       qos: .userInitiated,
       attributes: .concurrent
   )
   ```

5. **Profile and Monitor**
   ```swift
   // Regular performance monitoring
   Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in
       Task {
           let metrics = await collectPerformanceMetrics()
           await reportMetrics(metrics)
       }
   }
   ```

### Memory Management Best Practices

1. **Limit Cache Sizes**
   ```swift
   keyCache.countLimit = 100
   keyCache.totalCostLimit = 50 * 1024 // 50KB
   ```

2. **Clean Up Unused Resources**
   ```swift
   func cleanup() {
       keyCache.removeAllObjects()
       skippedKeys.removeAll()
       sessionPool.removeAll()
   }
   ```

3. **Use Weak References**
   ```swift
   weak var delegate: SessionIdentityDelegate?
   ```

4. **Monitor Memory Usage**
   ```swift
   func checkMemoryUsage() {
       let usage = profileMemoryUsage()
       if usage.residentSizeMB > 100 {
           cleanup()
       }
   }
   ```

## Testing Performance

### Performance Tests

```swift
class PerformanceTests: XCTestCase {
    func testEncryptionPerformance() async throws {
        let data = Data(repeating: 0, count: 1024)
        let iterations = 1000
        
        measure {
            for _ in 0..<iterations {
                _ = try await ratchetManager.ratchetEncrypt(plainText: data)
            }
        }
    }
    
    func testDecryptionPerformance() async throws {
        let data = Data(repeating: 0, count: 1024)
        let encryptedMessage = try await ratchetManager.ratchetEncrypt(plainText: data)
        let iterations = 1000
        
        measure {
            for _ in 0..<iterations {
                _ = try await ratchetManager.ratchetDecrypt(encryptedMessage)
            }
        }
    }
    
    func testConcurrentPerformance() async throws {
        let data = Data(repeating: 0, count: 1024)
        let concurrentTasks = 10
        let iterations = 100
        
        measure {
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<concurrentTasks {
                    group.addTask {
                        for _ in 0..<iterations {
                            _ = try? await self.ratchetManager.ratchetEncrypt(plainText: data)
                        }
                    }
                }
            }
        }
    }
}
```

## Related Documentation

- <doc:RatchetStateManager> - Main ratchet state management
- <doc:BestPractices> - General best practices
- <doc:ErrorHandling> - Error handling patterns
- <doc:SecurityModel> - Security considerations 