//
//  IDTokenPayload.swift
//  StudentWallet
//
//  Created by Anders Hausding on 02.12.24.
//

struct IDTokenPayload: Codable {
    enum CodingKeys: String, CodingKey {
        case issuerState = "issuer_state"
        case iss
        case nonce
        case state
        case codeChallenge = "code_challenge"
    }
    let issuerState: String
    let iss: String
    let nonce: String
    let state: String
    let codeChallenge: String
}
