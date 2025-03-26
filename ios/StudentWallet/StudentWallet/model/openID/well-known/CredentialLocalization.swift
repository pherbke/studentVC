//
//  CredentialLocalization.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

struct CredentialLocalization: Codable {
    let name: String?
    let locale: String?
    let logo: CredentialIssuerLocalizationLogo?
}

struct CredentialIssuerLocalizationLogo: Codable {
    let url: String
    let alt_text: String?
}
