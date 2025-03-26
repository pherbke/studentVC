//
//  PreAuthResponse.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

struct PreAuthResponse: Codable {
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case grants
    }
    let credentialIssuer: String
    let grants: PreAuthGrantsResponse

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.credentialIssuer = try container.decode(String.self, forKey: .credentialIssuer)
        self.grants = try container.decode(PreAuthGrantsResponse.self, forKey: .grants)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.credentialIssuer, forKey: .credentialIssuer)
        try container.encode(self.grants, forKey: .grants)
    }
}
