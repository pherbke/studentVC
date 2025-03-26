//
//  CredentialSupport.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

struct SupportedCredentialTrustFramework: Codable {
    let name: String
    let type: String
    let uri: String
}

struct SupportedCredentialSubjectField: Codable {
    let locale: String
    let name: String
}

struct SupportedCredentialSubjectContainer: Codable {
    let display: [SupportedCredentialSubjectField]
}

struct SupportedCredentialSubject: Codable {
    let dateOfBirth: SupportedCredentialSubjectContainer
    let familyName: SupportedCredentialSubjectContainer
    let givenNames: SupportedCredentialSubjectContainer
    let gpa: SupportedCredentialSubjectContainer
}

struct SupportedCredential: Codable {
    enum CodingKeys: String, CodingKey {
        case credentialSubject
        case format
        case trustFramework = "trust_framework"
        case supportedCryptographicBindingMethods = "cryptographic_binding_methods_supported"
        case supportedCryptographicSuites = "cryptographic_suites_supported"
        case display
        case types
    }
    let format: CredentialFormat
    let trustFramework: SupportedCredentialTrustFramework

    let supportedCryptographicBindingMethods: [String]
    let supportedCryptographicSuites: [String]
    let display: [SupportedCredentialLocalization]
    let types: [CredentialType]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.format = try container.decode(CredentialFormat.self, forKey: .format)
        self.trustFramework = try container.decode(SupportedCredentialTrustFramework.self, forKey: .trustFramework)
        self.supportedCryptographicBindingMethods = try container.decode([String].self, forKey: .supportedCryptographicBindingMethods)
        self.supportedCryptographicSuites = try container.decode([String].self, forKey: .supportedCryptographicSuites)
        self.display = try container.decode([SupportedCredentialLocalization].self, forKey: .display)
        self.types = try container.decode([CredentialType].self, forKey: .types)
//        self.credentialSubject = try container.decode(SupportedCredentialSubject.self, forKey: .types)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.format, forKey: .format)
        try container.encode(self.trustFramework, forKey: .trustFramework)
        try container.encode(self.supportedCryptographicBindingMethods, forKey: .supportedCryptographicBindingMethods)
        try container.encode(self.supportedCryptographicSuites, forKey: .supportedCryptographicSuites)
        try container.encode(self.display, forKey: .display)
        try container.encode(self.types, forKey: .types)
//        try container.encode(self.credentialSubject, forKey: .credentialSubject)
    }
}
