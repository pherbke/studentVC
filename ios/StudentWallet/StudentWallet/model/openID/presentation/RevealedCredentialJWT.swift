//
//  RevealedCredential.swift
//  StudentWallet
//
//  Created by Anders Hausding on 11.01.25.
//
struct RevealedCredentialVCSchema: Codable {
    let id: String?
    let type: String?
}

struct RevealedCredentialVC: Codable {
    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case credentialSchema
        case credentialSubject
        case credentialStatus
        case expirationDate
        case id
        case issuanceDate
        case issuer
        case type
        case validFrom
        case x509Certificate
    }
    let context: [String]?
    let credentialSchema: RevealedCredentialVCSchema?
    let credentialSubject: RevealedStudentIDCard? //we only support our schema for now
    let credentialStatus: CredentialStatus?
    let expirationDate: String?
    let id: String?
    let issuanceDate: String?
    let issuer: String?
    let type: [CredentialType]?
    let validFrom: String?
    let x509Certificate: X509Certificate?

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(self.context, forKey: .context)
        try container.encodeIfPresent(self.credentialSchema, forKey: .credentialSchema)
        try container.encodeIfPresent(self.credentialSubject, forKey: .credentialSubject)
        try container.encodeIfPresent(self.credentialStatus, forKey: .credentialStatus)
        try container.encodeIfPresent(self.expirationDate, forKey: .expirationDate)
        try container.encodeIfPresent(self.id, forKey: .id)
        try container.encodeIfPresent(self.issuanceDate, forKey: .issuanceDate)
        try container.encodeIfPresent(self.issuer, forKey: .issuer)
        try container.encodeIfPresent(self.type, forKey: .type)
        try container.encodeIfPresent(self.validFrom, forKey: .validFrom)
        try container.encodeIfPresent(self.x509Certificate, forKey: .x509Certificate)
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.context = try container.decodeIfPresent([String].self, forKey: .context)
        self.credentialSchema = try container.decodeIfPresent(RevealedCredentialVCSchema.self, forKey: .credentialSchema)
        self.credentialSubject = try container.decodeIfPresent(RevealedStudentIDCard.self, forKey: .credentialSubject)
        self.credentialStatus = try container.decodeIfPresent(CredentialStatus.self, forKey: .credentialStatus)
        self.expirationDate = try container.decodeIfPresent(String.self, forKey: .expirationDate)
        self.id = try container.decodeIfPresent(String.self, forKey: .id)
        self.issuanceDate = try container.decodeIfPresent(String.self, forKey: .issuanceDate)
        self.issuer = try container.decodeIfPresent(String.self, forKey: .issuer)
        self.type = try container.decodeIfPresent([CredentialType].self, forKey: .type)
        self.validFrom = try container.decodeIfPresent(String.self, forKey: .validFrom)
        self.x509Certificate = try container.decodeIfPresent(X509Certificate.self, forKey: .x509Certificate)
    }
}

struct RevealedCredentialJWT: Codable {
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
        case totalMessages = "total_messages"
        case validityIdentifier = "validity_identifier"
        case vc
    }
    let bbsDPK: String?
    let exp: Double?
    let iat: Double?
    let iss: String?
    let jti: String?
    let nbf: Double?
    let nonce: String?
    let signedNonce: String?
    let sub: String?
    let totalMessages: Int?
    let validityIdentifier: String?
    let vc: RevealedCredentialVC?

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.bbsDPK = try container.decodeIfPresent(String.self, forKey: .bbsDPK)
        self.sub = try container.decodeIfPresent(String.self, forKey: .sub)
        self.exp = try container.decodeIfPresent(Double.self, forKey: .exp)
        self.iat = try container.decodeIfPresent(Double.self, forKey: .iat)
        self.iss = try container.decodeIfPresent(String.self, forKey: .iss)
        self.jti = try container.decodeIfPresent(String.self, forKey: .jti)
        self.nbf = try container.decodeIfPresent(Double.self, forKey: .nbf)
        self.nonce = try container.decodeIfPresent(String.self, forKey: .nonce)
        self.signedNonce = try container.decodeIfPresent(String.self, forKey: .signedNonce)
        self.totalMessages = try container.decodeIfPresent(Int.self, forKey: .totalMessages)
        self.validityIdentifier = try container.decodeIfPresent(String.self, forKey: .validityIdentifier)
        self.vc = try container.decodeIfPresent(RevealedCredentialVC.self, forKey: .vc)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(self.bbsDPK, forKey: .bbsDPK)
        try container.encodeIfPresent(self.exp, forKey: .exp)
        try container.encodeIfPresent(self.iat, forKey: .iat)
        try container.encodeIfPresent(self.iss, forKey: .iss)
        try container.encodeIfPresent(self.jti, forKey: .jti)
        try container.encodeIfPresent(self.nbf, forKey: .nbf)
        try container.encodeIfPresent(self.nonce, forKey: .nonce)
        try container.encodeIfPresent(self.signedNonce, forKey: .signedNonce)
        try container.encodeIfPresent(self.sub, forKey: .sub)
        try container.encodeIfPresent(self.totalMessages, forKey: .totalMessages)
        try container.encodeIfPresent(self.validityIdentifier, forKey: .validityIdentifier)
        try container.encodeIfPresent(self.vc, forKey: .vc)
    }
}
