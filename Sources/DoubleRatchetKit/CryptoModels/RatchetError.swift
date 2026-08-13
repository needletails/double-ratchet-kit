//
//  RatchetError.swift
//  double-ratchet-kit
//
//  Created by Cole M on 4/15/25.
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

// MARK: - RatchetError Enum

/// Enum representing possible errors that can occur in the Double Ratchet protocol.
public enum RatchetError: Error, Equatable {
    case missingConfiguration
    case missingProps
    case sendingKeyIsNil
    case receivingKeyIsNil
    case encryptionFailed
    case decryptionFailed
    case expiredKey
    case stateUninitialized
    case missingCipherText
    case headerKeysNil
    case headerEncryptionFailed
    case headerDecryptFailed
    case missingOneTimeKey
    case receivingHeaderKeyIsNil
    case maxSkippedHeadersExceeded
    case rootKeyIsNil
}
