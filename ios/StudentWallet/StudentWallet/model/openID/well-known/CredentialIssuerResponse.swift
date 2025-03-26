//
//  CredentialIssuerResponse.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

struct CredentialResponseEncryption: Codable {
    enum CodingKeys: String, CodingKey {
        case suportedAlgValues = "alg_values_supported"
        case supportedEncValue = "enc_values_supported"
        case encryptionRequired = "encryption_required"
    }
    let suportedAlgValues: [String]
    let supportedEncValue: [String]
    let encryptionRequired: Bool

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.suportedAlgValues = try container.decode([String].self, forKey: .suportedAlgValues)
        self.supportedEncValue = try container.decode([String].self, forKey: .supportedEncValue)
        self.encryptionRequired = try container.decode(Bool.self, forKey: .encryptionRequired)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.suportedAlgValues, forKey: .suportedAlgValues)
        try container.encode(self.supportedEncValue, forKey: .supportedEncValue)
        try container.encode(self.encryptionRequired, forKey: .encryptionRequired)
    }
}

struct CredentialIssuerResponse: Codable {
    enum CodingKeys: String, CodingKey {
        case display
        case supportedCredentials = "credentials_supported"
        case authorizationServer = "authorization_server"
        case credentialEndpoint = "credential_endpoint"
        case credentialIssuer = "credential_issuer"
        case credentialResponseEncryption = "credential_response_encryption"
        case jwksURI = "jwks_uri"

    }
    let display: [CredentialLocalization]
    let supportedCredentials: [SupportedCredential]
    let authorizationServer: String
    let credentialEndpoint: String
    let credentialIssuer: String
    let credentialResponseEncryption: CredentialResponseEncryption
    let jwksURI: String

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        display = try container.decode([CredentialLocalization].self, forKey: .display)
        supportedCredentials = try container.decode([SupportedCredential].self, forKey: .supportedCredentials)
        authorizationServer = try container.decode(String.self, forKey: .authorizationServer)
        credentialEndpoint = try container.decode(String.self, forKey: .credentialEndpoint)
        credentialIssuer = try container.decode(String.self, forKey: .credentialIssuer)
        credentialResponseEncryption = try container.decode(CredentialResponseEncryption.self, forKey: .credentialResponseEncryption)
        jwksURI = try container.decode(String.self, forKey: .jwksURI)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(display, forKey: .display)
        try container.encode(supportedCredentials, forKey: .supportedCredentials)
        try container.encode(authorizationServer, forKey: .authorizationServer)
        try container.encode(credentialEndpoint, forKey: .credentialEndpoint)
        try container.encode(credentialIssuer, forKey: .credentialIssuer)
        try container.encode(credentialResponseEncryption, forKey: .credentialResponseEncryption)
        try container.encode(jwksURI, forKey: .jwksURI)
    }
}
