//
//  SupportedCredentialLocalization.swift
//  StudentWallet
//
//  Created by Anders Hausding on 23.11.24.
//


struct SupportedCredentialLocalization: Codable {
    enum CodingKeys: String, CodingKey {
        case name
        case locale
        case logo
        case backgroundColor = "background_color"
        case backgroundImage = "background_image"
        case description
        case textColor = "text_color"
    }
    let name: String?
    let locale: String?
    let logo: SupportedCredentialLocalizationLogo?
    let backgroundColor: String
    let backgroundImage: SupportedCredentialLocalizationLogo?
    let description: String
    let textColor: String
}

struct SupportedCredentialLocalizationLogo: Codable {
    let uri: String
    let alt_text: String?
}
