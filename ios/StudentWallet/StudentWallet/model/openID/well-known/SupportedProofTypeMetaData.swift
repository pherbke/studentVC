//
//  SupportedProofTypeMetaData.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

struct SupportedProofTypeMetaData: Codable {
    enum CodingKeys: String, CodingKey {
        case supportedProofSigningAlgValues = "proof_signing_alg_values_supported"
    }
    let supportedProofSigningAlgValues: [String]

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.supportedProofSigningAlgValues = try container.decode([String].self, forKey: .supportedProofSigningAlgValues)
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.supportedProofSigningAlgValues, forKey: .supportedProofSigningAlgValues)
    }
}
