//
//  CredentialResponse.swift
//  StudentWallet
//
//  Created by Anders Hausding on 03.12.24.
//

struct CredentialResponse: Codable {
    enum CodingKeys: String, CodingKey {
        case cNonce = "c_nonce"
        case cNonceExpiresIn = "c_nonce_expires_in"
        case credential
        case format
        case signature
    }
    let cNonce: String
    let cNonceExpiresIn: Int
    let credential: String
    let signature: String
    let format: CredentialFormat
}
