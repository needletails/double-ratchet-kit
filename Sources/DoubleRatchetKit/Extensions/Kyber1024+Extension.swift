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
import SwiftKyber

public extension Kyber1024.KeyAgreement.PrivateKey {
    func encode() -> Data {
        do {
            return try BSONEncoder().encodeData(self)
        } catch {
            fatalError("Kyber1024.KeyAgreement.PrivateKey encoding failed: \(error)")
        }
    }
}

public extension Data {
    func decodeKyber1024() -> Kyber1024.KeyAgreement.PrivateKey {
        do {
            return try BSONDecoder().decodeData(Kyber1024.KeyAgreement.PrivateKey.self, from: self)
        } catch {
            fatalError("Kyber1024.KeyAgreement.PrivateKey encoding failed: \(error)")
        }
    }
}
