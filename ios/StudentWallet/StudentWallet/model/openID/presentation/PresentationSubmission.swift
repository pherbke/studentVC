//
//  PresentationSubmission.swift
//  StudentWallet
//
//  Created by Anders Hausding on 11.01.25.
//

struct PresentationSubmission: Encodable {
    enum CodingKeys: String, CodingKey {
        case nonce
        case proofRequest = "proof_req"
        case proof
        case values
    }
    let nonce: String
    let proofRequest: String
    let proof: String
    let values: RevealedCredentialJWT
}
