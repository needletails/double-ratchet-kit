//
//  Keys.swift
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
import Foundation

enum KeyErrors: Error {
    case invalidKeySize
}

/// A representation of a MLKEM private key.
///
/// This struct wraps the raw `Data` of a MLKEM private key and ensures it is valid upon initialization.
public struct MLKEMPrivateKey: Codable, Sendable, Equatable {
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID
    
    /// The raw key data.
    public let rawRepresentation: Data

    /// Initializes a new MLKEM private key wrapper.
    ///
    /// - Parameters
    ///  id: An Identifier for the object
    ///  rawRepresentation: The raw MLKEM private key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        let key = rawRepresentation.decodeMLKem1024()
        guard key.seedRepresentation.count == Int(64) else {
            throw KeyErrors.invalidKeySize
        }
        guard key.integrityCheckedRepresentation.count == Int(96) else {
            throw KeyErrors.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A representation of a MLKEM public key.
///
/// This struct validates and stores the raw public key data for MLKEM.
public struct MLKEMPublicKey: Codable, Sendable, Equatable, Hashable {
    /// A unique identifier for the key (e.g. device or session key).
    public let id: UUID

    /// The raw key data.
    public let rawRepresentation: Data

    /// Initializes a new MLKEM public key wrapper.
    ///
    /// - Parameters
    ///  id: An Identifier for the object
    ///  rawRepresentation: The raw MLKEM public key bytes.
    /// - Throws: `KyberError.invalidKeySize` if the key size is incorrect.
    public init(id: UUID = UUID(), _ rawRepresentation: Data) throws {
        guard rawRepresentation.count == Int(1568) else {
            throw KeyErrors.invalidKeySize
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
            throw KeyErrors.invalidKeySize
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
            throw KeyErrors.invalidKeySize
        }
        self.id = id
        self.rawRepresentation = rawRepresentation
    }
}

/// A container for all remote public keys used during session setup.
public struct RemoteKeys: Sendable {
    /// The remote party's long-term Curve public key.
    let longTerm: CurvePublicKey

    /// The remote party's one-time Curve public key.
    let oneTime: CurvePublicKey?

    /// The remote party's MLKEM public key.
    let mlKEM: MLKEMPublicKey

    /// Initializes a container of remote keys for session initialization.
    public init(
        longTerm: CurvePublicKey,
        oneTime: CurvePublicKey?,
        mlKEM: MLKEMPublicKey
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.mlKEM = mlKEM
    }
}

/// A container for all local private keys used during session setup.
public struct LocalKeys: Sendable {
    /// The local party's long-term Curve private key.
    let longTerm: CurvePrivateKey

    /// The local party's one-time Curve private key.
    let oneTime: CurvePrivateKey?

    /// The local party's mlKEM private key.
    let mlKEM: MLKEMPrivateKey

    /// Initializes a container of local keys for session initialization.
    public init(
        longTerm: CurvePrivateKey,
        oneTime: CurvePrivateKey?,
        mlKEM: MLKEMPrivateKey
    ) {
        self.longTerm = longTerm
        self.oneTime = oneTime
        self.mlKEM = mlKEM
    }
}
