//
//  CredentialRequest.swift
//  StudentWallet
//
//  Created by Anders Hausding on 28.11.24.
//

enum CredentialRequestFormat: String, Codable {
    case jwtVCJson = "jwt_vc_json"
}

struct CredentialDefinition: Codable {
    let type: [CredentialType]
}

struct CredentialRequestProof: Codable {
    enum CodingKeys: String, CodingKey {
        case proofType = "proof_type"
        case jwt
    }
    let proofType: String
    let jwt: String

    init(proofType: String, jwt: String) {
        self.proofType = proofType
        self.jwt = jwt
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.proofType = try container.decode(String.self, forKey: .proofType)
        self.jwt = try container.decode(String.self, forKey: .jwt)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.proofType, forKey: .proofType)
        try container.encode(self.jwt, forKey: .jwt)
    }
}

struct CredentialRequest: Codable {
    enum CodingKeys: String, CodingKey {
        case format
        case credentialDefinition = "credential_definition"
//        case proof
    }
    let format: CredentialRequestFormat
    let credentialDefinition: CredentialDefinition
//    let proof: CredentialRequestProof

    init(
        format: CredentialRequestFormat,
        credentialDefinition: CredentialDefinition
//        proof: CredentialRequestProof
    ) {
        self.format = format
        self.credentialDefinition = credentialDefinition
//        self.proof = proof
    }
    
    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.format = try container.decode(CredentialRequestFormat.self, forKey: .format)
        self.credentialDefinition = try container.decode(CredentialDefinition.self, forKey: .credentialDefinition)
//        self.proof = try container.decode(CredentialRequestProof.self, forKey: .proof)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.format, forKey: .format)
//        try container.encode(self.proof, forKey: .proof)
    }
}
