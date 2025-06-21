//
//  Keys.swift
//  double-ratchet-kit
//
//  Created by Cole M on 6/16/25.
//
import Foundation
import SwiftKyber

/// A representation of a Kyber1024 private key.
///
/// This struct wraps the raw `Data` of a Kyber1024 private key and ensures it is valid upon initialization.
public struct Kyber1024PrivateKeyRepresentable: Codable, Sendable, Equatable {
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Kyber1024 private key wrapper.
    ///
    /// - Parameter rawRepresentation: The raw Kyber1024 private key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        let key = rawRepresentation.decodeKyber1024()
        
        guard key.rawRepresentation.count == Int(kyber1024PrivateKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Kyber1024 public key.
///
/// This struct validates and stores the raw public key data for Kyber1024.
public struct Kyber1024PublicKeyRepresentable: Codable, Sendable, Equatable, Hashable {
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Kyber1024 public key wrapper.
    ///
    /// - Parameter rawRepresentation: The raw Kyber1024 public key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == Int(kyber1024PublicKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Curve25519 private key with an associated UUID.
///
/// This is useful for identifying specific device keys across sessions.
public struct Curve25519PrivateKeyRepresentable: Codable, Sendable, Equatable {
    
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Curve25519 private key wrapper.
    ///
    /// - Parameters:
    ///   - id: An optional UUID to tag this key. A new UUID is generated if not provided.
    ///   - rawRepresentation: The raw 32-byte Curve25519 private key data.
    /// - Throws: `KyberError.invalidKeySize` if the key size is not 32 bytes.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Curve25519 public key with an associated UUID.
public struct Curve25519PublicKeyRepresentable: Codable, Sendable, Hashable {
    
    /// A unique identifier for the key.
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Curve25519 public key wrapper.
    ///
    /// - Parameters:
    ///   - id: An optional UUID to tag this key. A new UUID is generated if not provided.
    ///   - rawRepresentation: The raw 32-byte Curve25519 public key data.
    /// - Throws: `KyberError.invalidKeySize` if the key size is not 32 bytes.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

public struct Curve25519PublicKeySigningRepresentable: Codable, Sendable, Hashable {
    
    /// A unique identifier for the key.
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Curve25519 public key wrapper.
    ///
    /// - Parameters:
    ///   - id: An optional UUID to tag this key. A new UUID is generated if not provided.
    ///   - rawRepresentation: The raw 32-byte Curve25519 public key data.
    /// - Throws: `KyberError.invalidKeySize` if the key size is not 32 bytes.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A container for all remote public keys used during session setup.
public struct RemoteKeys {
    
    /// The remote party's long-term Curve25519 public key.
    let longTerm: Curve25519PublicKeyRepresentable
    
    /// The remote party's one-time Curve25519 public key.
    let oneTime: Curve25519PublicKeyRepresentable?
    
    /// The remote party's Kyber1024 public key.
    let kyber: Kyber1024PublicKeyRepresentable
    
    /// Initializes a container of remote keys for session initialization.
    public init(
        longTerm: Curve25519PublicKeyRepresentable,
        oneTime: Curve25519PublicKeyRepresentable?,
        kyber: Kyber1024PublicKeyRepresentable
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.kyber = kyber
    }
}

/// A container for all local private keys used during session setup.
public struct LocalKeys {
    
    /// The local party's long-term Curve25519 private key.
    let longTerm: Curve25519PrivateKeyRepresentable
    
    /// The local party's one-time Curve25519 private key.
    let oneTime: Curve25519PrivateKeyRepresentable?
    
    /// The local party's Kyber1024 private key.
    let kyber: Kyber1024PrivateKeyRepresentable
    
    /// Initializes a container of local keys for session initialization.
    public init(
        longTerm: Curve25519PrivateKeyRepresentable,
        oneTime: Curve25519PrivateKeyRepresentable?,
        kyber: Kyber1024PrivateKeyRepresentable
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.kyber = kyber
    }
}
