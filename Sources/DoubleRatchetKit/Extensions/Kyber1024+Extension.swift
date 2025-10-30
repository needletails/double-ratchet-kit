//
//  Kyber1024+Extension.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/29/25.
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
import BSON
import Foundation
import NeedleTailCrypto
import SwiftKyber
import Crypto

public extension MLKem1024PrivateKey {
    
    func encode() -> Data {
        do {
            return try BSONEncoder().encodeData(self)
        } catch {
            fatalError("Kyber1024.KeyAgreement.PrivateKey encoding failed: \(error)")
        }
    }
}

public extension Data {
    func decodeMLKem1024() -> MLKem1024PrivateKey {
        do {
            let decoder = BSONDecoder()
#if os(iOS) || os(macOS) || os(watchOS) || os(tvOS)
            if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *) {
                return try decoder.decodeData(MLKEM1024.PrivateKey.self, from: self)
            } else {
                return try decoder.decodeData(Kyber1024.KeyAgreement.PrivateKey.self, from: self)
            }
#else
            return try decoder.decodeData(MLKEM1024.PrivateKey.self, from: self)
#endif
        } catch {
            fatalError("Kyber1024.KeyAgreement.PrivateKey encoding failed: \(error)")
        }
    }
}


