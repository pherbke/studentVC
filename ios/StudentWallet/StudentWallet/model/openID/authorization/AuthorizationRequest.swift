//
//  AuthorizationRequest.swift
//  StudentWallet
//
//  Created by Anders Hausding on 28.11.24.
//
import Foundation

enum AuthorizationResponseType: String, Codable {
    case code
}

enum AuthorizationScope: String, Codable {
    case openid
}

enum AuthorizationCodeChallengeMethod: String, Codable {
    case s256 = "S256"
}

enum AuthorizationDetailType: String, Codable {
    case openIDCredential = "openid_credential"
}

struct AuthorizationRequest: Codable {
    enum CodingKeys: String, CodingKey {
        case responseType = "response_type"
        case clientID = "client_id"
        case redirectURI = "redirect_uri"
        case scope
        case issuerState = "issuer_state"
        case state
        case authorizationDetails = "authorization_details"
        case nonce
        case codeChallenge = "code_challenge"
        case codeChallengeMethod = "code_challenge_method"
        case clientMetadata = "client_metadata"
    }

    let responseType: AuthorizationResponseType
    let clientID: String
    let redirectURI: String
    let scope: AuthorizationScope
    let issuerState: String?
    let state: String?
    let authorizationDetails: AuthorizationDetails
    let nonce: String?
    let codeChallenge: String?
    let codeChallengeMethod: AuthorizationCodeChallengeMethod?
    let clientMetadata: ClientMetadata?

    init(
        responseType: AuthorizationResponseType,
        clientID: String,
        redirectURI: String,
        scope: AuthorizationScope,
        issuerState: String,
        state: String,
        authorizationDetails: AuthorizationDetails,
        nonce: String?,
        codeChallenge: String?,
        codeChallengeMethod: AuthorizationCodeChallengeMethod?,
        clientMetadata: ClientMetadata?
    ) {
        self.responseType = responseType
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scope = scope
        self.issuerState = issuerState
        self.state = state
        self.authorizationDetails = authorizationDetails
        self.nonce = nonce
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.clientMetadata = clientMetadata
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.responseType = try container.decode(
            AuthorizationResponseType.self,
            forKey: .responseType
        )
        self.clientID = try container.decode(String.self, forKey: .clientID)
        self.redirectURI = try container.decode(String.self, forKey: .redirectURI)
        self.scope = try container.decode(AuthorizationScope.self, forKey: .scope)
        self.issuerState = try container.decodeIfPresent(String.self, forKey: .issuerState)
        self.state = try container.decodeIfPresent(String.self, forKey: .state)
        self.authorizationDetails = try container.decode(
            AuthorizationDetails.self,
            forKey: .authorizationDetails
        )
        self.nonce = try container.decode(String.self, forKey: .nonce)
        self.codeChallenge = try container.decode(String.self, forKey: .codeChallenge)
        self.codeChallengeMethod = try container.decode(
            AuthorizationCodeChallengeMethod.self,
            forKey: .codeChallengeMethod
        )
        self.clientMetadata = try container.decode(ClientMetadata.self, forKey: .clientMetadata)
    }


    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.responseType, forKey: .responseType)
        try container.encode(self.clientID, forKey: .clientID)
        try container.encode(self.redirectURI, forKey: .redirectURI)
        try container.encode(self.scope, forKey: .scope)
        try container.encodeIfPresent(self.issuerState, forKey: .issuerState)
        try container.encodeIfPresent(self.state, forKey: .state)
        try container.encode(self.authorizationDetails, forKey: .authorizationDetails)
        try container.encodeIfPresent(self.nonce, forKey: .nonce)
        try container.encodeIfPresent(self.codeChallenge, forKey: .codeChallenge)
        try container.encodeIfPresent(self.codeChallengeMethod, forKey: .codeChallengeMethod)
        try container.encodeIfPresent(self.clientMetadata, forKey: .clientMetadata)
    }
}

struct AuthorizationDetails: Codable {
    enum CodingKeys: String, CodingKey {
        case type
        case locations
        case format
        case types
    }

    let type: AuthorizationDetailType
    let locations: String?
    let format: FormatType
    let types: [String]

    init(
        type: AuthorizationDetailType,
        locations: String?,
        format: FormatType,
        types: [String]
    ) {
        self.type = type
        self.locations = locations
        self.format = format
        self.types = types
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(AuthorizationDetailType.self, forKey: .type)
        self.locations = try container.decodeIfPresent(String.self, forKey: .locations)
        self.format = try container.decode(FormatType.self, forKey: .format)
        self.types = try container.decode([String].self, forKey: .types)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.type, forKey: .type)
        try container.encodeIfPresent(self.locations, forKey: .locations)
        try container.encode(self.format, forKey: .format)
        try container.encode(self.types, forKey: .types)
    }
}
