//
//  DirectPostRequest.swift
//  StudentWallet
//
//  Created by Anders Hausding on 02.12.24.
//

struct DirectPostRequest: Codable {
    enum CodingKeys: String, CodingKey {
        case idToken = "id_token"
        case state
    }
    let idToken: String
    let state: String

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.idToken, forKey: .idToken)
        try container.encode(self.state, forKey: .state)
    }

    init(idToken: String, state: String) {
        self.idToken = idToken
        self.state = state
    }


    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.idToken = try container.decode(String.self, forKey: .idToken)
        self.state = try container.decode(String.self, forKey: .state)
    }
}
