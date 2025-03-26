//
//  PreAuthGrantsResponse.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

struct PreAuthGrantAuthorizationCode: Codable {
    enum CodingKeys: String, CodingKey {
        case issuerState = "issuer_state"
    }
    let issuerState: String

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.issuerState = try container.decode(String.self, forKey: .issuerState)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.issuerState, forKey: .issuerState)
    }
}

struct PreAuthGrantPreAuthCode : Codable {
    enum CodingKeys: String, CodingKey {
        case preAuthCode = "pre_auth_code"
        case userPinRequired = "user_pin_required"
    }
    let preAuthCode: String
    let userPinRequired: Bool

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.preAuthCode = try container.decode(String.self, forKey: .preAuthCode)
        self.userPinRequired = try container.decodeIfPresent(Bool.self, forKey: .userPinRequired) ?? false
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.preAuthCode, forKey: .preAuthCode)
        try container.encode(self.userPinRequired, forKey: .userPinRequired)
    }
}

struct PreAuthGrantsResponse: Codable {
    enum CodingKeys: String, CodingKey {
        case authorizationCode = "authorization_code"
//        case preAuthCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
    let authorizationCode: PreAuthGrantAuthorizationCode
//    let preAuthCode: PreAuthGrantPreAuthCode

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.authorizationCode = try container.decode(PreAuthGrantAuthorizationCode.self, forKey: .authorizationCode)
//        self.preAuthCode = try container.decode(PreAuthGrantPreAuthCode.self, forKey: .preAuthCode)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.authorizationCode, forKey: .authorizationCode)
//        try container.encode(self.preAuthCode, forKey: .preAuthCode)
    }
}
