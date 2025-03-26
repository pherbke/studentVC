//
//  CredentialProofType.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

protocol CredentialProofType: Codable {

}

struct CredentialJWtProof: CredentialProofType {
    let jwt: String
}

struct CredentialLDP_VPProof: CredentialProofType {
    let alg: String
    let typ: String
    let jwk: String?
}
