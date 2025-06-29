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
import Foundation
import class BSON.BSONEncoder
import struct BSON.BSONDecoder
import struct BSON.Document
import struct NIOCore.ByteBuffer

extension BSONEncoder {
    public func encodeData<T: Codable>(_ encodable: T) throws -> Data {
        try encode(encodable).makeData()
    }
}

extension BSONDecoder {
    public func decodeBuffer<T: Codable>(_ type: T.Type, from buffer: ByteBuffer) throws -> T {
        return try decode(type, from: Document(buffer: buffer))
    }
    
    public func decodeData<T: Codable>(_ type: T.Type, from data: Data) throws -> T {
        return try decode(type, from: Document(data: data))
    }
}
