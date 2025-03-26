//
//  OfferResponse.swift
//  StudentWallet
//
//  Created by Anders Hausding on 15.12.24.
//
import Foundation

struct OfferResponse: Decodable {
    enum CodingKeys: String, CodingKey {
        case credentialOffer = "credential_offer"
    }
    let credentialOffer: String

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.credentialOffer = try container.decode(String.self, forKey: .credentialOffer)
    }
}
