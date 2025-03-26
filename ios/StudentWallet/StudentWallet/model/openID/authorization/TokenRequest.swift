//
//  Untitled.swift
//  StudentWallet
//
//  Created by Anders Hausding on 28.11.24.
//

enum TokenRequestGrantTypeMeta: String, Codable {
    case authorizationCode = "authorization_code"
    case preAuthorisedCode = "pre-authorised_code"
}

enum TokenRequestClientAssertionType: String, Codable {
    case jwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
}

struct TokenRequest: Codable {
    enum CodingKeys: String, CodingKey {
        case grantType = "grant_type"
        case clientID = "client_id"
        case code
        case redirectURI = "redirect_uri"
        case preAuthorisedCode = "pre-authorised_code"
        case userPin = "user_pin"
        case clientAssertion = "client_assertion"
        case clientAssertionType = "client_assertion_type"
        case codeVerifier = "code_verifier"
    }

    let grantType: TokenRequestGrantTypeMeta
    let clientID: String
    let code: String
    let redirectURI: String
    let preAuthorisedCode: String?
    let userPin: String?
    let clientAssertion: String?
    let clientAssertionType: TokenRequestClientAssertionType?
    let codeVerifier: String?

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.grantType, forKey: .grantType)
        try container.encode(self.clientID, forKey: .clientID)
        try container.encode(self.code, forKey: .code)
        try container.encode(self.redirectURI, forKey: .redirectURI)
        try container.encodeIfPresent(self.preAuthorisedCode, forKey: .preAuthorisedCode)
        try container.encodeIfPresent(self.userPin, forKey: .userPin)
        try container.encodeIfPresent(self.clientAssertion, forKey: .clientAssertion)
        try container.encodeIfPresent(self.clientAssertionType, forKey: .clientAssertionType)
        try container.encodeIfPresent(self.codeVerifier, forKey: .codeVerifier)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        grantType = try container.decode(TokenRequestGrantTypeMeta.self, forKey: .grantType)
        clientID = try container.decode(String.self, forKey: .clientID)
        code = try container.decode(String.self, forKey: .code)
        redirectURI = try container.decode(String.self, forKey: .redirectURI)
        preAuthorisedCode = try container.decodeIfPresent(String.self, forKey: .preAuthorisedCode)
        userPin = try container.decodeIfPresent(String.self, forKey: .userPin)
        clientAssertion = try container.decodeIfPresent(String.self, forKey: .clientAssertion)
        clientAssertionType = try container.decodeIfPresent(
            TokenRequestClientAssertionType.self,
            forKey: .clientAssertionType
        )
        codeVerifier = try container.decodeIfPresent(String.self, forKey: .codeVerifier)
    }

    init (
        grantType: TokenRequestGrantTypeMeta,
        clientID: String,
        code: String,
        redirectURI: String,
        preAuthorisedCode: String?,
        userPin: String?,
        clientAssertion: String?,
        clientAssertionType: TokenRequestClientAssertionType?,
        codeVerifier: String?
    ) {
        self.grantType = grantType
        self.clientID = clientID
        self.code = code
        self.redirectURI = redirectURI
        self.preAuthorisedCode = preAuthorisedCode
        self.userPin = userPin
        self.clientAssertion = clientAssertion
        self.clientAssertionType = clientAssertionType
        self.codeVerifier = codeVerifier
    }
}
