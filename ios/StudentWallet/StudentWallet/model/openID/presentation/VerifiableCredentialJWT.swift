//
//  VerifiableCredentialJWT.swift
//  StudentWallet
//
//  Created by Anders Hausding on 11.01.25.
//

struct VerifiableCredentialJWT: Encodable {
    enum CodingKeys: String, CodingKey {
        case verifiableCredential = "verifiable_credential"
    }
    let verifiableCredential: PresentationSubmission
}
