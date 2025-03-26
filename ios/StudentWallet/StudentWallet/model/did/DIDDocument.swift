//
//  DIDDocument.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

struct DIDDocument: Codable {
    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case id
        case verificationMethod
        case authentication
    }
    let context: String
    let id: String
    let verificationMethod: [VerificationMethod]
    let authentication: [String]

    init(context: String, id: String, verificationMethod: [VerificationMethod], authentication: [String]) {
        self.context = context
        self.id = id
        self.verificationMethod = verificationMethod
        self.authentication = authentication
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.context = try container.decode(String.self, forKey: .context)
        self.id = try container.decode(String.self, forKey: .id)
        self.verificationMethod = try container.decode([VerificationMethod].self, forKey: .verificationMethod)
        self.authentication = try container.decode([String].self, forKey: .authentication)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.context, forKey: .context)
        try container.encode(self.id, forKey: .id)
        try container.encode(self.verificationMethod, forKey: .verificationMethod)
        try container.encode(self.authentication, forKey: .authentication)
    }
}

struct VerificationMethod: Codable {
    let id: String
    let type: String
    let controller: String
    let publicKeyJWK: JWK
}

struct JWK: Codable {
    let kty: String
    let crv: String
    let x: String
    let y: String
}
