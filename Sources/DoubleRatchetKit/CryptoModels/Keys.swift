//
//  Keys.swift
//  double-ratchet-kit
//
//  Created by Cole M on 6/16/25.
//
import Foundation
import SwiftKyber

/// A representation of a PQKem private key.
///
/// This struct wraps the raw `Data` of a PQKem private key and ensures it is valid upon initialization.
public struct PQKemPrivateKey: Codable, Sendable, Equatable {
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new PQKem private key wrapper.
    ///
    /// - Parameter rawRepresentation: The raw PQKem private key bytes.
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

/// A representation of a PQKem public key.
///
/// This struct validates and stores the raw public key data for PQKem.
public struct PQKemPublicKey: Codable, Sendable, Equatable, Hashable {
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new PQKem public key wrapper.
    ///
    /// - Parameter rawRepresentation: The raw PQKem public key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == Int(kyber1024PublicKeyLength) else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Curve private key with an associated UUID.
///
/// This is useful for identifying specific device keys across sessions.
public struct CurvePrivateKey: Codable, Sendable, Equatable {
    
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Curve private key wrapper.
    ///
    /// - Parameters:
    ///   - id: An optional UUID to tag this key. A new UUID is generated if not provided.
    ///   - rawRepresentation: The raw 32-byte Curve private key data.
    /// - Throws: `KyberError.invalidKeySize` if the key size is not 32 bytes.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == 32 else {
            throw KyberError.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a Curve public key with an associated UUID.
public struct CurvePublicKey: Codable, Sendable, Hashable {
    
    /// A unique identifier for the key.
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data
    
    /// Initializes a new Curve public key wrapper.
    ///
    /// - Parameters:
    ///   - id: An optional UUID to tag this key. A new UUID is generated if not provided.
    ///   - rawRepresentation: The raw 32-byte Curve public key data.
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
    
    /// The remote party's long-term Curve public key.
    let longTerm: CurvePublicKey
    
    /// The remote party's one-time Curve public key.
    let oneTime: CurvePublicKey?
    
    /// The remote party's PQKem public key.
    let pqKem: PQKemPublicKey
    
    /// Initializes a container of remote keys for session initialization.
    public init(
        longTerm: CurvePublicKey,
        oneTime: CurvePublicKey?,
        pqKem: PQKemPublicKey
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.pqKem = pqKem
    }
}

/// A container for all local private keys used during session setup.
public struct LocalKeys {
    
    /// The local party's long-term Curve private key.
    let longTerm: CurvePrivateKey
    
    /// The local party's one-time Curve private key.
    let oneTime: CurvePrivateKey?
    
    /// The local party's pqKem private key.
    let pqKem: PQKemPrivateKey
    
    /// Initializes a container of local keys for session initialization.
    public init(
        longTerm: CurvePrivateKey,
        oneTime: CurvePrivateKey?,
        pqKem: PQKemPrivateKey
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.pqKem = pqKem
    }
}
