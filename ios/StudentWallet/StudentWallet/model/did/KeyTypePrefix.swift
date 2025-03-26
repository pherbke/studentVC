//
//  KeyTypePrefix.swift
//  StudentWallet
//
//  Created by Anders Hausding on 14.12.24.
//

import Foundation

enum KeyTypePrefix {
    case publicKeyType

    func getPrefix() -> Data {
        switch self {
        case .publicKeyType:
            return  Data([0x12, 0x0])
        }
    }
}
