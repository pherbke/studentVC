//
//  CredentialJWT.swift
//  StudentWallet
//
//  Created by Anders Hausding on 14.12.24.
//

struct CredentialVCSchema: Codable {
    let id: String
    let type: String

    init(id: String, type: String) {
        self.id = id
        self.type = type
    }
}

struct CredentialVC: Codable {
    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case credentialSchema
        case credentialSubject
        case expirationDate
        case id
        case issuanceDate
        case issuer
        case type
        case validFrom
    }
    let context: [String]
    let credentialSchema: CredentialVCSchema
    let credentialSubject: StudentIDCard //we only support our schema for now
    let expirationDate: String
    let id: String
    let issuanceDate: String
    let issuer: String
    let type: [CredentialType]
    let validFrom: String

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.context, forKey: .context)
        try container.encode(self.credentialSchema, forKey: .credentialSchema)
        try container.encode(self.credentialSubject, forKey: .credentialSubject)
        try container.encode(self.expirationDate, forKey: .expirationDate)
        try container.encode(self.id, forKey: .id)
        try container.encode(self.issuanceDate, forKey: .issuanceDate)
        try container.encode(self.issuer, forKey: .issuer)
        try container.encode(self.type, forKey: .type)
        try container.encode(self.validFrom, forKey: .validFrom)
    }

    init(
        context: [String],
        credentialSchema: CredentialVCSchema,
        credentialSubject: StudentIDCard,
        expirationDate: String,
        id: String,
        issuanceDate: String,
        issuer: String,
        type: [CredentialType],
        validFrom: String
    ) {
        self.context = context
        self.credentialSchema = credentialSchema
        self.credentialSubject = credentialSubject
        self.expirationDate = expirationDate
        self.id = id
        self.issuanceDate = issuanceDate
        self.issuer = issuer
        self.type = type
        self.validFrom = validFrom
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.context = try container.decode([String].self, forKey: .context)
        self.credentialSchema = try container.decode(CredentialVCSchema.self, forKey: .credentialSchema)
        self.credentialSubject = try container.decode(StudentIDCard.self, forKey: .credentialSubject)
        self.expirationDate = try container.decode(String.self, forKey: .expirationDate)
        self.id = try container.decode(String.self, forKey: .id)
        self.issuanceDate = try container.decode(String.self, forKey: .issuanceDate)
        self.issuer = try container.decode(String.self, forKey: .issuer)
        self.type = try container.decode([CredentialType].self, forKey: .type)
        self.validFrom = try container.decode(String.self, forKey: .validFrom)
    }
}

struct CredentialJWT: Codable {
    enum CodingKeys: String, CodingKey {
        case bbsDPK = "bbs_dpk"
        case exp
        case iat
        case iss
        case jti
        case nbf
        case nonce
        case signedNonce = "signed_nonce"
        case sub
        case vc
        case totalMessages = "total_messages"
        case validityIdentifier = "validity_identifier"
    }
    let bbsDPK: String
    let exp: Double
    let iat: Double
    let iss: String
    let jti: String
    let nbf: Double
    let nonce: String
    let signedNonce: String
    let sub: String
    let totalMessages: Int
    let validityIdentifier: String
    let vc: CredentialVC

    init(
        bbsDPK: String,
        exp: Double,
        iat: Double,
        iss: String,
        jti: String,
        nbf: Double,
        nonce: String,
        signedNonce: String,
        sub: String,
        totalMessage: Int,
        validityIdentifier: String,
        vc: CredentialVC
    ) {
        self.bbsDPK = bbsDPK
        self.exp = exp
        self.iat = iat
        self.iss = iss
        self.jti = jti
        self.nbf = nbf
        self.nonce = nonce
        self.signedNonce = signedNonce
        self.sub = sub
        self.totalMessages = totalMessage
        self.validityIdentifier = validityIdentifier
        self.vc = vc
    }
    
    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.bbsDPK = try container.decode(String.self, forKey: .bbsDPK)
        self.exp = try container.decode(Double.self, forKey: .exp)
        self.iat = try container.decode(Double.self, forKey: .iat)
        self.iss = try container.decode(String.self, forKey: .iss)
        self.jti = try container.decode(String.self, forKey: .jti)
        self.nbf = try container.decode(Double.self, forKey: .nbf)
        self.nonce = try container.decode(String.self, forKey: .nonce)
        self.signedNonce = try container.decode(String.self, forKey: .signedNonce)
        self.sub = try container.decode(String.self, forKey: .sub)
        self.totalMessages = try container.decode(Int.self, forKey: .totalMessages)
        self.validityIdentifier = try container.decode(String.self, forKey: .validityIdentifier)
        self.vc = try container.decode(CredentialVC.self, forKey: .vc)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.bbsDPK, forKey: .bbsDPK)
        try container.encode(self.exp, forKey: .exp)
        try container.encode(self.iat, forKey: .iat)
        try container.encode(self.iss, forKey: .iss)
        try container.encode(self.jti, forKey: .jti)
        try container.encode(self.nbf, forKey: .nbf)
        try container.encode(self.nonce, forKey: .nonce)
        try container.encode(self.signedNonce, forKey: .signedNonce)
        try container.encode(self.sub, forKey: .sub)
        try container.encode(self.totalMessages, forKey: .totalMessages)
        try container.encode(self.validityIdentifier, forKey: .validityIdentifier)
        try container.encode(self.vc, forKey: .vc)
    }
}
