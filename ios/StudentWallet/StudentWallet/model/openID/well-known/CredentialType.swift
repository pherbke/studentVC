//
//  CredentialType.swift
//  StudentWallet
//
//  Created by Anders Hausding on 02.12.24.
//

enum CredentialType: String, Codable {
    case VerifiableCredential
    case VerifiableAttestation
    case UniversityDegreeCredential
    case CTWalletSamePreAuthorisedInTime
    case CTWalletSameAuthorisedInTime
    case VerifiablePortableDocumentA1
    case StudentIDCard
}
