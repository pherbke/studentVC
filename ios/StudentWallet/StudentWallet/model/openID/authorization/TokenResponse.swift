//
//  TokenResponse.swift
//  StudentWallet
//
//  Created by Anders Hausding on 28.11.24.
//

import Foundation

enum TokenResponseTokenType: String, Codable {
    case bearer
}

struct TokenResponse: Codable {
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case cNonce = "c_nonce"
        case cNonceExpiresIn = "c_nonce_expires_in"
    }
    let accessToken: String
    let tokenType: TokenResponseTokenType
    let expiresIn: TimeInterval
    let cNonce: String
    let cNonceExpiresIn: TimeInterval

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.accessToken, forKey: .accessToken)
        try container.encode(self.tokenType, forKey: .tokenType)
        try container.encode(self.expiresIn, forKey: .expiresIn)
        try container.encode(self.cNonce, forKey: .cNonce)
        try container.encode(self.cNonceExpiresIn, forKey: .cNonceExpiresIn)
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.accessToken = try container.decode(String.self, forKey: .accessToken)
        self.tokenType = try container.decode(TokenResponseTokenType.self, forKey: .tokenType)
        self.expiresIn = try container.decode(TimeInterval.self, forKey: .expiresIn)
        self.cNonce = try container.decode(String.self, forKey: .cNonce)
        self.cNonceExpiresIn = try container.decode(TimeInterval.self, forKey: .cNonceExpiresIn)
    }
}
