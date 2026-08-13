//
//  RatchetState.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/15/25.
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
import Crypto
import Foundation

typealias RemoteLongTermPublicKey = Data
typealias RemoteOneTimePublicKey = X25519PublicKey
typealias RemoteMLKEMPublicKey = MLKEMPublicKey
typealias LocalLongTermPrivateKey = Data
typealias LocalOneTimePrivateKey = X25519PrivateKey
typealias LocalMLKEMPrivateKey = MLKEMPrivateKey
typealias LocalPrivateKey = Data
typealias RemotePublicKey = Data

/// A protocol defining operations related to managing a session identity and associated cryptographic keys.
///
/// Conforming types are responsible for persisting and retrieving identity and one-time key information.
/// This is typically implemented by a storage layer (e.g. database, in-memory store, or secure enclave manager).
public protocol SessionIdentityDelegate: AnyObject, Sendable {
    /// Updates the stored session identity.
    ///
    /// - Parameter identity: The new session identity to persist.
    /// - Throws: An error if the update operation fails.
    func updateSessionIdentity(_ identity: SessionIdentity) async throws

    /// Fetches a previously stored private one-time Curve25519 key by its unique identifier.
    ///
    /// - Parameter id: The UUID of the one-time key to retrieve.
    /// - Returns: The corresponding `X25519PrivateKey`.
    /// - Throws: An error if the key could not be found or retrieved.
    func fetchOneTimePrivateKey(_ id: UUID?) async throws -> X25519PrivateKey?

    /// Notifies that a new one-time key should be generated and made available.
    ///
    /// This may trigger background key generation or publication to a server.
    func updateOneTimeKey(remove id: UUID) async
}

/// Represents a set of skipped message keys for later processing in the Double Ratchet protocol.
public struct SkippedMessageKey: Codable, Sendable {
    /// The public key of the sender associated with the skipped message.
    let remoteLongTermPublicKey: Data

    /// The public key of the sender associated with the skipped message.
    let remoteOneTimePublicKey: Data?

    let remoteMLKEMPublicKey: Data

    /// The index of the skipped message.
    let messageIndex: Int

    /// Pre-derived message key for the skipped message (storage).
    let messageKey: SymmetricKey

    /// The sender's per-turn ratchet public key for the chain this key belongs to.
    /// Disambiguates equal message indices across ratchet turns.
    let chainRatchetPublicKey: Data

    private enum CodingKeys: String, CodingKey, Sendable {
        case remoteLongTermPublicKey = "a"
        case remoteOneTimePublicKey = "b"
        case remoteMLKEMPublicKey = "c"
        case messageIndex = "d"
        case messageKey = "e"
        case chainRatchetPublicKey = "f"
    }

    init(
        remoteLongTermPublicKey: Data,
        remoteOneTimePublicKey: Data?,
        remoteMLKEMPublicKey: Data,
        messageIndex: Int,
        messageKey: SymmetricKey,
        chainRatchetPublicKey: Data
    ) {
        self.remoteLongTermPublicKey = remoteLongTermPublicKey
        self.remoteOneTimePublicKey = remoteOneTimePublicKey
        self.remoteMLKEMPublicKey = remoteMLKEMPublicKey
        self.messageIndex = messageIndex
        self.messageKey = messageKey
        self.chainRatchetPublicKey = chainRatchetPublicKey
    }
}

/// Configuration for the Double Ratchet protocol, defining parameters for key management.
public struct RatchetConfiguration: Sendable, Codable {
    /// Data used to derive message keys.
    public let messageKeyData: Data
    /// Data used to derive chain keys.
    public let chainKeyData: Data
    /// Data used to derive the root key.
    public let rootKeyData: Data
    /// Protocol context authenticated as payload AEAD associated data.
    public let associatedData: Data
    /// Maximum number of skipped message keys to retain.
    public let maxSkippedMessageKeys: Int

    private enum CodingKeys: String, CodingKey, Sendable {
        case messageKeyData = "a"
        case chainKeyData = "b"
        case rootKeyData = "c"
        case associatedData = "d"
        case maxSkippedMessageKeys = "e"
    }

    /// Initializes a new RatchetConfiguration with the specified parameters.
    /// - Parameters:
    ///   - messageKeyData: Data used to derive message keys.
    ///   - chainKeyData: Data used to derive chain keys.
    ///   - rootKeyData: Data used to derive the root key.
    ///   - associatedData: Protocol context authenticated as payload AEAD associated data.
    ///   - maxSkippedMessageKeys: Maximum number of skipped message keys to retain.
    public init(
        messageKeyData: Data,
        chainKeyData: Data,
        rootKeyData: Data,
        associatedData: Data,
        maxSkippedMessageKeys: Int
    ) {
        self.messageKeyData = messageKeyData
        self.chainKeyData = chainKeyData
        self.rootKeyData = rootKeyData
        self.associatedData = associatedData
        self.maxSkippedMessageKeys = maxSkippedMessageKeys
    }
}

/// Represents the state of the Double Ratchet protocol.
struct RatchetState: Sendable, Codable {
    /// Coding keys for encoding and decoding the RatchetState.
    enum CodingKeys: String, CodingKey, Sendable, Codable {
        case localLongTermPrivateKey = "a" // Local long-term private key.
        case localOneTimePrivateKey = "b" // Local one-time private key.
        case localMLKEMPrivateKey = "c" // Local post-quantum key exchange private key.
        case remoteLongTermPublicKey = "d" // Remote long-term public key.
        case remoteOneTimePublicKey = "e" // Remote one-time public key.
        case remoteMLKEMPublicKey = "f" // Remote post-quantum key exchange public key.
        case messageCiphertext = "g" // Ciphertext of the message.
        case rootKey = "h" // Root symmetric key.
        case sendingKey = "i" // Chain key for sending.
        case receivingKey = "j" // Chain key for receiving.
        case sentMessagesCount = "k" // Count of sent messages.
        case receivedMessagesCount = "l" // Count of received messages.
        case previousMessagesCount = "m" // Count of messages in the previous sending chain.
        case skippedHeaderMessages = "n" // Dictionary of skipped header keys.
        case skippedMessageKeys = "o" // Dictionary of skipped message keys.
        case headerCiphertext = "p" // Header ciphertext.
        case sendingHeaderKey = "q" // Current sending header key.
        case nextSendingHeaderKey = "r" // Next sending header key.
        case receivingHeaderKey = "s" // Current receiving header key.
        case nextReceivingHeaderKey = "t" // Next receiving header key.
        case sendingHandshakeFinished = "u" // Whether the sending initial handshake has completed.
        case receivingHandshakeFinished = "v" // Whether the receiving initial handshake has completed.
        case lastSkippedIndex = "w" // Last skipped message index.
        case headerIndex = "x" // Index of the skipped header.
        case lastDecryptedMessageNumber = "y" // The message number for the last decrytped message.
        case alreadyDecryptedMessageNumbers = "z" // A Set of already decrypted messages
        case localRatchetPrivateKey = "A" // Per-turn local Curve25519 ratchet private key.
        case remoteRatchetPublicKey = "B" // Per-turn remote Curve25519 ratchet public key.
        case localRatchetKEMPrivateKey = "C" // Per-turn local ML-KEM ratchet private key.
        case remoteRatchetKEMPublicKey = "D" // Per-turn remote ML-KEM ratchet public key.
        case isSessionInitiator = "E" // Whether this party initiated the session (PQXDH sender).
        case sendingChainRemoteRatchetKey = "F" // Remote ratchet key the current sending chain is keyed against.
        case localRatchetKEMCiphertext = "G" // KEM ciphertext for the current sending chain (rides in every header).
        case suiteMarker = "H" // Protocol suite marker. Missing on pre-4.0 blobs; treat as current.
    }

    /// v4 production mix: HMAC-SHA256 (chain / message), HKDF-SHA512 (root / PQXDH), HKDF-SHA256 (header).
    static let currentSuiteMarker = 4

    // MARK: - Properties

    /// Local long-term private key.
    public private(set) var localLongTermPrivateKey: LocalLongTermPrivateKey

    /// Local one-time private key.
    public private(set) var localOneTimePrivateKey: LocalOneTimePrivateKey?

    /// Local post-quantum key exchange private key.
    public private(set) var localMLKEMPrivateKey: LocalMLKEMPrivateKey

    /// Remote long-term public key.
    public private(set) var remoteLongTermPublicKey: RemoteLongTermPublicKey

    /// Remote one-time public key.
    public private(set) var remoteOneTimePublicKey: RemoteOneTimePublicKey?

    /// Remote post-quantum key exchange public key.
    public private(set) var remoteMLKEMPublicKey: RemoteMLKEMPublicKey

    /// Ciphertext of the message being sent or received.
    private(set) var messageCiphertext: Data?

    /// Root symmetric key used for encryption.
    private(set) var rootKey: SymmetricKey?

    /// Current chain key for sending messages.
    private(set) var sendingKey: SymmetricKey?

    /// Current chain key for receiving messages.
    private(set) var receivingKey: SymmetricKey?

    /// Count of messages sent.
    /// Count of messages sent on this session.
    ///
    /// Publicly readable so hosts can distinguish a never-used initiating lane
    /// (`== 0`) from one that already transmitted frames the peer never answered
    /// (`> 0` with `receivedMessagesCount == 0`) when deciding whether a stale
    /// process-lifetime remint is safe.
    public private(set) var sentMessagesCount: Int = 0

    /// Count of messages received.
    ///
    /// Publicly readable so hosts can distinguish an initiating session the
    /// peer has answered (> 0) from one whose handshake never completed (== 0)
    /// when deciding whether a session reset is safe.
    public private(set) var receivedMessagesCount: Int = 0

    /// Count of messages in the previous sending chain.
    private(set) var previousMessagesCount: Int = 0

    /// List of skipped message keys.
    private(set) var skippedMessageKeys = [SkippedMessageKey]()

    /// Last Skipped Message
    private(set) var lastSkippedIndex: Int = 0

    /// A list of Skipped Header Message
    private(set) var skippedHeaderMessages = [SkippedHeaderMessage]()

    /// The Index of the Skipped Header
    private(set) var headerIndex: Int = 0

    /// Ciphertext for the header.
    private(set) var headerCiphertext: Data?

    /// Current sending header key.
    private(set) var sendingHeaderKey: SymmetricKey?

    /// Next sending header key.
    private(set) var nextSendingHeaderKey: SymmetricKey?

    /// Current receiving header key.
    private(set) var receivingHeaderKey: SymmetricKey?

    /// Next receiving header key.
    private(set) var nextReceivingHeaderKey: SymmetricKey?

    /// Indicates if the sending hanshake has finished
    private(set) var sendingHandshakeFinished: Bool = false

    /// Indicates if the receiving hanshake has finished
    private(set) var receivingHandshakeFinished: Bool = false

    /// Indicates if the receiving hanshake has finished
    private(set) var lastDecryptedMessageNumber: Int = 0

    private(set) var alreadyDecryptedMessageNumbers = Set<Int>()

    // MARK: - Per-Turn Hybrid Ratchet Properties
    //
    // These stay optional because they are absent until a given ratchet phase
    // (lifecycle), not because old snapshots omitted them.

    /// Per-turn local Curve25519 ratchet private key (raw representation).
    /// Regenerated on every sending ratchet step (first send after a received turn).
    private(set) var localRatchetPrivateKey: Data?

    /// The peer's latest per-turn Curve25519 ratchet public key, learned from a decrypted header.
    private(set) var remoteRatchetPublicKey: Data?

    /// Per-turn local ML-KEM-1024 ratchet private key (encoded). Regenerated per sending step;
    /// the peer encapsulates to its public counterpart on their next turn.
    private(set) var localRatchetKEMPrivateKey: Data?

    /// The peer's latest per-turn ML-KEM-1024 ratchet public key. Encapsulate to this on the
    /// next sending ratchet step.
    private(set) var remoteRatchetKEMPublicKey: Data?

    /// Whether this party initiated the session (ran PQXDH as sender).
    /// Used only to label bootstrap chains. `false` until `setState` records the role.
    private(set) var isSessionInitiator: Bool = false

    /// The peer ratchet public key the *current sending chain* was keyed against.
    /// A sending ratchet step is due exactly when `remoteRatchetPublicKey` differs from
    /// this value — i.e. the peer has taken a turn since we last rotated our sending chain.
    /// Bursts in one direction leave it equal, so no step is performed per message.
    private(set) var sendingChainRemoteRatchetKey: Data?

    /// The ML-KEM ciphertext produced at our last sending ratchet step. Rides in every
    /// header of the current sending chain so the receiver can complete its receiving
    /// step from any message of the chain, not just the (possibly lost) boundary frame.
    private(set) var localRatchetKEMCiphertext: Data?

    /// Protocol suite marker written on every persist. Absent on pre-4.0 blobs (treated as current).
    private(set) var suiteMarker: Int = currentSuiteMarker

    var sessionStatus: RatchetSessionStatus {
        RatchetSessionStatus(
            sentMessagesCount: sentMessagesCount,
            receivedMessagesCount: receivedMessagesCount,
            sendingHandshakeFinished: sendingHandshakeFinished,
            receivingHandshakeFinished: receivingHandshakeFinished)
    }

    // MARK: - Initializers

    /// Initializes a new RatchetState with the provided keys and parameters for receiving.
    /// - Parameters:
    ///   - remoteLongTermPublicKey: The remote party's long-term public key.
    ///   - remoteOneTimePublicKey: The remote party's one-time public key.
    ///   - remoteMLKEMPublicKey: The remote party's post-quantum key exchange public key.
    ///   - localLongTermPrivateKey: The local party's long-term private key.
    ///   - localOneTimePrivateKey: The local party's one-time private key.
    ///   - localMLKEMPrivateKey: The local party's post-quantum key exchange private key.
    ///   - rootKey: The root symmetric key used for encryption.
    ///   - messageCiphertext: The ciphertext of the message being sent or received.
    ///   - receivingKey: The current chain key for receiving messages.
    init(
        remoteLongTermPublicKey: RemoteLongTermPublicKey,
        remoteOneTimePublicKey: RemoteOneTimePublicKey?,
        remoteMLKEMPublicKey: RemoteMLKEMPublicKey,
        localLongTermPrivateKey: LocalLongTermPrivateKey,
        localOneTimePrivateKey: LocalOneTimePrivateKey?,
        localMLKEMPrivateKey: LocalMLKEMPrivateKey
    ) {
        self.remoteLongTermPublicKey = remoteLongTermPublicKey
        self.remoteOneTimePublicKey = remoteOneTimePublicKey
        self.remoteMLKEMPublicKey = remoteMLKEMPublicKey
        self.localLongTermPrivateKey = localLongTermPrivateKey
        self.localOneTimePrivateKey = localOneTimePrivateKey
        self.localMLKEMPrivateKey = localMLKEMPrivateKey
    }

    /// Initializes a new RatchetState with the provided keys and parameters for sending.
    /// - Parameters:
    ///   - remoteLongTermPublicKey: The remote party's long-term public key.
    ///   - remoteOneTimePublicKey: The remote party's one-time public key.
    ///   - remoteMLKEMPublicKey: The remote party's post-quantum key exchange public key.
    ///   - localLongTermPrivateKey: The local party's long-term private key.
    ///   - localOneTimePrivateKey: The local party's one-time private key.
    ///   - localMLKEMPrivateKey: The local party's post-quantum key exchange private key.
    ///   - rootKey: The root symmetric key used for encryption.
    ///   - messageCiphertext: The ciphertext of the message being sent or received.
    ///   - sendingKey: The current chain key for sending messages.
    init(
        remoteLongTermPublicKey: RemoteLongTermPublicKey,
        remoteOneTimePublicKey: RemoteOneTimePublicKey?,
        remoteMLKEMPublicKey: RemoteMLKEMPublicKey,
        localLongTermPrivateKey: LocalLongTermPrivateKey,
        localOneTimePrivateKey: LocalOneTimePrivateKey?,
        localMLKEMPrivateKey: LocalMLKEMPrivateKey,
        rootKey: SymmetricKey,
        messageCiphertext: Data,
        sendingKey: SymmetricKey
    ) {
        self.remoteLongTermPublicKey = remoteLongTermPublicKey
        self.remoteOneTimePublicKey = remoteOneTimePublicKey
        self.remoteMLKEMPublicKey = remoteMLKEMPublicKey
        self.localLongTermPrivateKey = localLongTermPrivateKey
        self.localOneTimePrivateKey = localOneTimePrivateKey
        self.localMLKEMPrivateKey = localMLKEMPrivateKey
        self.rootKey = rootKey
        self.messageCiphertext = messageCiphertext
        self.sendingKey = sendingKey
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        localLongTermPrivateKey = try container.decode(Data.self, forKey: .localLongTermPrivateKey)
        localOneTimePrivateKey = try container.decodeIfPresent(X25519PrivateKey.self, forKey: .localOneTimePrivateKey)
        localMLKEMPrivateKey = try container.decode(MLKEMPrivateKey.self, forKey: .localMLKEMPrivateKey)
        remoteLongTermPublicKey = try container.decode(Data.self, forKey: .remoteLongTermPublicKey)
        remoteOneTimePublicKey = try container.decodeIfPresent(X25519PublicKey.self, forKey: .remoteOneTimePublicKey)
        remoteMLKEMPublicKey = try container.decode(MLKEMPublicKey.self, forKey: .remoteMLKEMPublicKey)
        messageCiphertext = try container.decodeIfPresent(Data.self, forKey: .messageCiphertext)
        rootKey = try container.decodeIfPresent(SymmetricKey.self, forKey: .rootKey)
        sendingKey = try container.decodeIfPresent(SymmetricKey.self, forKey: .sendingKey)
        receivingKey = try container.decodeIfPresent(SymmetricKey.self, forKey: .receivingKey)
        sentMessagesCount = try container.decodeIfPresent(Int.self, forKey: .sentMessagesCount) ?? 0
        receivedMessagesCount = try container.decodeIfPresent(Int.self, forKey: .receivedMessagesCount) ?? 0
        previousMessagesCount = try container.decodeIfPresent(Int.self, forKey: .previousMessagesCount) ?? 0
        skippedHeaderMessages = try container.decodeIfPresent([SkippedHeaderMessage].self, forKey: .skippedHeaderMessages) ?? []
        let rawSkipped = try container.decodeIfPresent([LenientSkippedMessageKey].self, forKey: .skippedMessageKeys) ?? []
        skippedMessageKeys = rawSkipped.compactMap(\.tagged)
        headerCiphertext = try container.decodeIfPresent(Data.self, forKey: .headerCiphertext)
        sendingHeaderKey = try container.decodeIfPresent(SymmetricKey.self, forKey: .sendingHeaderKey)
        nextSendingHeaderKey = try container.decodeIfPresent(SymmetricKey.self, forKey: .nextSendingHeaderKey)
        receivingHeaderKey = try container.decodeIfPresent(SymmetricKey.self, forKey: .receivingHeaderKey)
        nextReceivingHeaderKey = try container.decodeIfPresent(SymmetricKey.self, forKey: .nextReceivingHeaderKey)
        sendingHandshakeFinished = try container.decodeIfPresent(Bool.self, forKey: .sendingHandshakeFinished) ?? false
        receivingHandshakeFinished = try container.decodeIfPresent(Bool.self, forKey: .receivingHandshakeFinished) ?? false
        lastSkippedIndex = try container.decodeIfPresent(Int.self, forKey: .lastSkippedIndex) ?? 0
        headerIndex = try container.decodeIfPresent(Int.self, forKey: .headerIndex) ?? 0
        lastDecryptedMessageNumber = try container.decodeIfPresent(Int.self, forKey: .lastDecryptedMessageNumber) ?? 0
        alreadyDecryptedMessageNumbers = try container.decodeIfPresent(Set<Int>.self, forKey: .alreadyDecryptedMessageNumbers) ?? []
        localRatchetPrivateKey = try container.decodeIfPresent(Data.self, forKey: .localRatchetPrivateKey)
        remoteRatchetPublicKey = try container.decodeIfPresent(Data.self, forKey: .remoteRatchetPublicKey)
        localRatchetKEMPrivateKey = try container.decodeIfPresent(Data.self, forKey: .localRatchetKEMPrivateKey)
        remoteRatchetKEMPublicKey = try container.decodeIfPresent(Data.self, forKey: .remoteRatchetKEMPublicKey)
        isSessionInitiator = try container.decodeIfPresent(Bool.self, forKey: .isSessionInitiator) ?? false
        sendingChainRemoteRatchetKey = try container.decodeIfPresent(Data.self, forKey: .sendingChainRemoteRatchetKey)
        localRatchetKEMCiphertext = try container.decodeIfPresent(Data.self, forKey: .localRatchetKEMCiphertext)
        if let marker = try container.decodeIfPresent(Int.self, forKey: .suiteMarker) {
            guard marker == Self.currentSuiteMarker else {
                throw DecodingError.dataCorruptedError(
                    forKey: .suiteMarker,
                    in: container,
                    debugDescription: "Unknown ratchet suite marker \(marker)")
            }
            suiteMarker = marker
        } else {
            suiteMarker = Self.currentSuiteMarker
        }
    }

    // MARK: - Methods

    /// Updates the list of skipped message keys by appending a new key.
    /// - Parameter skippedMessageKeys: The skipped message key to add.
    func updateSkippedMessage(skippedMessageKey: SkippedMessageKey) async -> Self {
        var ratchetState = self
        ratchetState.skippedMessageKeys.append(skippedMessageKey)
        return ratchetState
    }

    /// Drops the first `count` entries from `skippedMessageKeys`.
    /// - Parameter count: Number of oldest entries to remove.
    /// - Returns: A new `RatchetState` with those entries removed.
    func removeFirstSkippedMessages(count: Int = 1) async -> Self {
        var ratchetState = self
        guard count > 0, skippedMessageKeys.count > 0 else {
            return self
        }

        // Clamp to avoid slicing past end
        let dropCount = min(count, skippedMessageKeys.count)
        let remainingKeys = Array(skippedMessageKeys.dropFirst(dropCount))
        ratchetState.skippedMessageKeys = remainingKeys
        return ratchetState
    }

    /// Removes a skipped message key at the specified index.
    /// - Parameter index: The index of the skipped message key to remove.
    func removeSkippedMessages(at number: Int) async -> Self {
        var ratchetState = self
        ratchetState.skippedMessageKeys.removeAll(where: { $0.messageIndex == number })
        return ratchetState
    }

    func removeSkippedMessage(_ message: SkippedMessageKey) async -> Self {
        var ratchetState = self
        ratchetState.skippedMessageKeys.removeAll {
            $0.messageIndex == message.messageIndex &&
                $0.remoteLongTermPublicKey == message.remoteLongTermPublicKey &&
                $0.remoteOneTimePublicKey == message.remoteOneTimePublicKey &&
                $0.remoteMLKEMPublicKey == message.remoteMLKEMPublicKey
        }
        return ratchetState
    }

    func removeAllSkippedMessages() async -> Self {
        var ratchetState = self
        ratchetState.skippedMessageKeys.removeAll()
        return ratchetState
    }

    func incrementSkippedHeaderIndex() async -> Self {
        var ratchetState = self
        ratchetState.headerIndex += 1
        return ratchetState
    }

    /// Resets the skipped-header index for a fresh receiving chain (per-turn ratchet step).
    func resetHeaderIndex() async -> Self {
        var ratchetState = self
        ratchetState.headerIndex = 0
        return ratchetState
    }

    /// Increments the count of received messages by one.
    func incrementReceivedMessagesCount() async -> Self {
        var ratchetState = self
        ratchetState.receivedMessagesCount += 1
        return ratchetState
    }

    /// Increments the count of sent messages by one.
    func incrementSentMessagesCount() async -> Self {
        var ratchetState = self
        ratchetState.sentMessagesCount += 1
        return ratchetState
    }

    /// Updates the remote long-term public key.
    /// - Parameter remotePublicKey: The new remote long-term public key.
    func updateRemoteLongTermPublicKey(_ remotePublicKey: Data) async -> Self {
        var ratchetState = self
        ratchetState.remoteLongTermPublicKey = remotePublicKey
        return ratchetState
    }

    /// Updates the remote one-time public key.
    /// - Parameter remoteOTPublicKey: The new remote one-time public key.
    func updateRemoteOneTimePublicKey(_ remoteOneTimePublicKey: X25519PublicKey?) async -> Self {
        var ratchetState = self
        ratchetState.remoteOneTimePublicKey = remoteOneTimePublicKey
        return ratchetState
    }

    /// Updates the remote post-quantum key exchange public key.
    /// - Parameter remoteMLKEMPublicKey: The new remote post-quantum public key.
    func updateRemoteMLKEMPublicKey(_ remoteMLKEMPublicKey: MLKEMPublicKey) async -> Self {
        var ratchetState = self
        ratchetState.remoteMLKEMPublicKey = remoteMLKEMPublicKey
        return ratchetState
    }

    /// Updates the current sending chain key.
    /// - Parameter sendingKey: The new sending chain key.
    func updateSendingKey(_ sendingKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.sendingKey = sendingKey
        return ratchetState
    }

    /// Updates the current receiving chain key.
    /// - Parameter receivingKey: The new receiving chain key.
    func updateReceivingKey(_ receivingKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.receivingKey = receivingKey
        return ratchetState
    }

    /// Updates the local long-term private key.
    /// - Parameter localPrivateKey: The new local long-term private key.
    func updateLocalLongTermPrivateKey(_ localPrivateKey: Data) async -> Self {
        var ratchetState = self
        ratchetState.localLongTermPrivateKey = localPrivateKey
        return ratchetState
    }

    /// Updates the local one-time private key.
    /// - Parameter localOTPrivateKey: The new local one-time private key.
    func updateLocalOneTimePrivateKey(_ localOTPrivateKey: X25519PrivateKey?) async -> Self {
        var ratchetState = self
        ratchetState.localOneTimePrivateKey = localOTPrivateKey
        return ratchetState
    }

    /// Updates the local post-quantum key exchange private key.
    /// - Parameter localMLKEMPrivateKey: The new local post-quantum private key.
    func updateLocalMLKEMPrivateKey(_ localMLKEMPrivateKey: LocalMLKEMPrivateKey) async -> Self {
        var ratchetState = self
        ratchetState.localMLKEMPrivateKey = localMLKEMPrivateKey
        return ratchetState
    }

    /// Updates the count of sent messages.
    /// - Parameter sentMessagesCount: The new count of sent messages.
    func updateSentMessagesCount(_ sentMessagesCount: Int) async -> Self {
        var ratchetState = self
        ratchetState.sentMessagesCount = sentMessagesCount
        return ratchetState
    }

    /// Updates the count of received messages.
    /// - Parameter receivedMessagesCount: The new count of received messages.
    func updateReceivedMessagesCount(_ receivedMessagesCount: Int) async -> Self {
        var ratchetState = self
        ratchetState.receivedMessagesCount = receivedMessagesCount
        return ratchetState
    }

    /// Updates the count of messages in the previous sending chain.
    /// - Parameter previousMessagesCount: The new count of previous messages.
    func updatePreviousMessagesCount(_ previousMessagesCount: Int) async -> Self {
        var ratchetState = self
        ratchetState.previousMessagesCount = previousMessagesCount
        return ratchetState
    }

    /// Updates the root symmetric key.
    /// - Parameter rootKey: The new root symmetric key.
    func updateRootKey(_ rootKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.rootKey = rootKey
        return ratchetState
    }

    /// Updates the message ciphertext.
    /// - Parameter cipherText: The new ciphertext for the message.
    func updateCiphertext(_ cipherText: Data) async -> Self {
        var ratchetState = self
        ratchetState.messageCiphertext = cipherText
        return ratchetState
    }

    /// Updates the header ciphertext.
    /// - Parameter cipherText: The new ciphertext for the header.
    func updateHeaderCiphertext(_ cipherText: Data) async -> Self {
        var ratchetState = self
        ratchetState.headerCiphertext = cipherText
        return ratchetState
    }

    /// Updates the current sending header key.
    /// - Parameter HKs: The new current sending header key.
    func updateSendingHeaderKey(_ sendingHeaderKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.sendingHeaderKey = sendingHeaderKey
        return ratchetState
    }

    /// Updates the next sending header key.
    /// - Parameter NHKs: The new next sending header key.
    func updateSendingNextHeaderKey(_ nextSendingHeaderKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.nextSendingHeaderKey = nextSendingHeaderKey
        return ratchetState
    }

    /// Updates the current receiving header key.
    /// - Parameter HKr: The new current receiving header key.
    func updateReceivingHeaderKey(_ receivingHeaderKey: SymmetricKey) async -> Self {
        var ratchetState = self
        ratchetState.receivingHeaderKey = receivingHeaderKey
        return ratchetState
    }

    /// Updates the next receiving header key.
    /// - Parameter NHKr: The new next receiving header key.
    func updateReceivingNextHeaderKey(_ nextReceivingHeaderKey: SymmetricKey?) async -> Self {
        var ratchetState = self
        ratchetState.nextReceivingHeaderKey = nextReceivingHeaderKey
        return ratchetState
    }

    /// Marks the initial post-quantum X3DH handshake as completed.
    /// - Parameter handshakeFinished: A Boolean value indicating whether the handshake has finished.
    func updateSendingHandshakeFinished(_ handshakeFinished: Bool) async -> Self {
        var ratchetState = self
        ratchetState.sendingHandshakeFinished = handshakeFinished
        return ratchetState
    }

    func updateReceivingHandshakeFinished(_ handshakeFinished: Bool) async -> Self {
        var ratchetState = self
        ratchetState.receivingHandshakeFinished = handshakeFinished
        return ratchetState
    }

    func updateSkippedHeaderMessage(_ message: SkippedHeaderMessage) async -> Self {
        var ratchetState = self
        ratchetState.skippedHeaderMessages.append(message)
        return ratchetState
    }

    func removeSkippedHeaderMessage(_ message: SkippedHeaderMessage) async -> Self {
        var ratchetState = self
        ratchetState.skippedHeaderMessages.removeAll(where: { $0.chainKey == message.chainKey })
        return ratchetState
    }

    func removeAllSkippedHeaderMessage() async -> Self {
        var ratchetState = self
        ratchetState.skippedHeaderMessages.removeAll()
        return ratchetState
    }

    func incrementSkippedMessageIndex() async -> Self {
        var ratchetState = self
        ratchetState.lastSkippedIndex += 1
        return ratchetState
    }

    func updateSkippedMessageIndex(_ currentIndex: Int) async -> Self {
        var ratchetState = self
        ratchetState.lastSkippedIndex = currentIndex
        return ratchetState
    }

    func updateLastDecryptedMessageNumber(_ number: Int) async -> Self {
        var ratchetState = self
        ratchetState.lastDecryptedMessageNumber = number
        return ratchetState
    }

    func setAlreadyDecryptedMessageNumbers(_ numbers: Set<Int>) async -> Self {
        var ratchetState = self
        ratchetState.alreadyDecryptedMessageNumbers = numbers
        return ratchetState
    }

    func updateAlreadyDecryptedMessageNumber(_ number: Int) async -> Self {
        var ratchetState = self
        ratchetState.alreadyDecryptedMessageNumbers.insert(number)
        return ratchetState
    }

    func resetAlreadyDecryptedMessageNumber() async -> Self {
        var ratchetState = self
        ratchetState.alreadyDecryptedMessageNumbers.removeAll()
        return ratchetState
    }

    // MARK: - Per-Turn Hybrid Ratchet Updaters

    /// Updates the per-turn local Curve25519 ratchet private key.
    func updateLocalRatchetPrivateKey(_ key: Data?) async -> Self {
        var ratchetState = self
        ratchetState.localRatchetPrivateKey = key
        return ratchetState
    }

    /// Updates the peer's per-turn Curve25519 ratchet public key.
    func updateRemoteRatchetPublicKey(_ key: Data?) async -> Self {
        var ratchetState = self
        ratchetState.remoteRatchetPublicKey = key
        return ratchetState
    }

    /// Updates the per-turn local ML-KEM ratchet private key.
    func updateLocalRatchetKEMPrivateKey(_ key: Data?) async -> Self {
        var ratchetState = self
        ratchetState.localRatchetKEMPrivateKey = key
        return ratchetState
    }

    /// Updates the peer's per-turn ML-KEM ratchet public key.
    func updateRemoteRatchetKEMPublicKey(_ key: Data?) async -> Self {
        var ratchetState = self
        ratchetState.remoteRatchetKEMPublicKey = key
        return ratchetState
    }

    /// Records whether this party initiated the session (PQXDH sender).
    func updateIsSessionInitiator(_ value: Bool) async -> Self {
        var ratchetState = self
        ratchetState.isSessionInitiator = value
        return ratchetState
    }

    /// Records the remote ratchet key the current sending chain is keyed against.
    func updateSendingChainRemoteRatchetKey(_ key: Data?) async -> Self {
        var ratchetState = self
        ratchetState.sendingChainRemoteRatchetKey = key
        return ratchetState
    }

    /// Updates the ML-KEM ciphertext for the current sending chain.
    func updateLocalRatchetKEMCiphertext(_ ciphertext: Data?) async -> Self {
        var ratchetState = self
        ratchetState.localRatchetKEMCiphertext = ciphertext
        return ratchetState
    }
}

struct SkippedHeaderMessage: Codable, Sendable, Equatable {
    let chainKey: SymmetricKey
    let index: Int
}

/// Decode-only shape for skipped keys. Entries whose chain tag (`"f"`) is absent
/// are pre–per-turn stashes and are dropped on load — they cannot match a v4 frame.
private struct LenientSkippedMessageKey: Codable {
    let remoteLongTermPublicKey: Data
    let remoteOneTimePublicKey: Data?
    let remoteMLKEMPublicKey: Data
    let messageIndex: Int
    let messageKey: SymmetricKey
    let chainRatchetPublicKey: Data?

    private enum CodingKeys: String, CodingKey {
        case remoteLongTermPublicKey = "a"
        case remoteOneTimePublicKey = "b"
        case remoteMLKEMPublicKey = "c"
        case messageIndex = "d"
        case messageKey = "e"
        case chainRatchetPublicKey = "f"
    }

    var tagged: SkippedMessageKey? {
        guard let chainRatchetPublicKey else { return nil }
        return SkippedMessageKey(
            remoteLongTermPublicKey: remoteLongTermPublicKey,
            remoteOneTimePublicKey: remoteOneTimePublicKey,
            remoteMLKEMPublicKey: remoteMLKEMPublicKey,
            messageIndex: messageIndex,
            messageKey: messageKey,
            chainRatchetPublicKey: chainRatchetPublicKey)
    }
}

/// Public view of ratchet progress for a session. Hosts should not reach into `RatchetState`.
public struct RatchetSessionStatus: Sendable, Equatable {
    public let sentMessagesCount: Int
    public let receivedMessagesCount: Int
    public let sendingHandshakeFinished: Bool
    public let receivingHandshakeFinished: Bool
}

