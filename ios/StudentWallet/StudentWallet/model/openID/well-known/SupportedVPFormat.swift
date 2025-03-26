//
//  SupportedVPFormat.swift
//  StudentWallet
//
//  Created by Anders Hausding on 21.11.24.
//
struct SupportedVPFormat: Codable {
    enum CodingKeys: String, CodingKey {
        case supportedAlgValues = "alg_values_supported"
    }
    let supportedAlgValues: [String]

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.supportedAlgValues = try container.decode([String].self, forKey: .supportedAlgValues)
    }

    init(supportedAlgValues: [String]) {
        self.supportedAlgValues = supportedAlgValues
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.supportedAlgValues, forKey: .supportedAlgValues)
    }
}

struct SupportedVPFormats: Codable {
    enum CodingKeys: String, CodingKey {
        case jwtVCJson = "jwt_vc"
        case jwtVPJson = "jwt_vp"
    }
    //For now we only support the ones our backend does...
    let jwtVCJson: SupportedVPFormat
    let jwtVPJson: SupportedVPFormat

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.jwtVCJson = try container.decode(SupportedVPFormat.self, forKey: .jwtVCJson)
        self.jwtVPJson = try container.decode(SupportedVPFormat.self, forKey: .jwtVPJson)
    }

    init(jwtVCJson: SupportedVPFormat, jwtVPJson: SupportedVPFormat) {
        self.jwtVCJson = jwtVCJson
        self.jwtVPJson = jwtVPJson
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.jwtVCJson, forKey: .jwtVCJson)
        try container.encode(self.jwtVPJson, forKey: .jwtVPJson)
    }
}
