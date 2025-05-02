//
//  Kyber1024+Extension.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/29/25.
//
import SwiftKyber
import Foundation
import BSON

extension Kyber1024.KeyAgreement.PrivateKey {
    public func encode() -> Data {
        do {
            return try BSONEncoder().encodeData(self)
        } catch {
            fatalError("Kyber1024.KeyAgreement.PrivateKey encoding failed: \(error)")
        }
    }
}

extension Data {
    public func decodeKyber1024() -> Kyber1024.KeyAgreement.PrivateKey {
        do {
            return try BSONDecoder().decodeData(Kyber1024.KeyAgreement.PrivateKey.self, from: self)
        } catch {
            fatalError("Kyber1024.KeyAgreement.PrivateKey encoding failed: \(error)")
        }
    }
}
