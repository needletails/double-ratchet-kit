//
//  BSON+Extension.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/17/25.
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
import struct BSON.BSONDecoder
import class BSON.BSONEncoder
import struct BSON.Document
import Foundation
import struct NIOCore.ByteBuffer

public extension BSONEncoder {
    func encodeData(_ encodable: some Codable) throws -> Data {
        try encode(encodable).makeData()
    }
}

public extension BSONDecoder {
    func decodeBuffer<T: Codable>(_ type: T.Type, from buffer: ByteBuffer) throws -> T {
        try decode(type, from: Document(buffer: buffer))
    }

    func decodeData<T: Codable>(_ type: T.Type, from data: Data) throws -> T {
        try decode(type, from: Document(data: data))
    }
}
