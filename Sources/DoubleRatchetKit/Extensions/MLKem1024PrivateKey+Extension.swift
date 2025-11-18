//
//  MLKem1024PrivateKey+Extension.swift
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

import Foundation
import NeedleTailCrypto
import BinaryCodable

public extension MLKEM1024.PrivateKey {
    
    func encode() -> Data {
        do {
            return try BinaryEncoder().encode(self)
        } catch {
            fatalError("MLKem1024PrivateKey encoding failed: \(error)")
        }
    }
}

public extension Data {
    func decodeMLKem1024() -> MLKEM1024.PrivateKey {
        let decoder = BinaryDecoder()
        do {
            return try decoder.decode(MLKEM1024.PrivateKey.self, from: self)
        } catch {
            fatalError("MLKem1024PrivateKey decoding failed for both MLKEM1024")
        }
    }
}
