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
    
    func encode() throws -> Data {
        return try BinaryEncoder().encode(self)
    }
}

public extension Data {
    func decodeMLKem1024() throws -> MLKEM1024.PrivateKey {
        let decoder = BinaryDecoder()
        return try decoder.decode(MLKEM1024.PrivateKey.self, from: self)
    }
}
