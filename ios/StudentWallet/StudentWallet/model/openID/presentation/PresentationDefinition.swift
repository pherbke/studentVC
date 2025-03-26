//
//  PresentationDefinition.swift
//  StudentWallet
//
//  Created by Anders Hausding on 10.01.25.
//
struct FieldInfo {
    let key: String
    let field: String
    let explanation: String
}

struct FieldMapper {
    private let baseMappings: [String: String] = [
        "bbs_dpk": "BBS DPK",
        "exp": "Expiration Date",
        "iat": "Issued At",
        "iss": "Issuer",
        "jti": "JWT ID",
        "nbf": "Not Before",
        "nonce": "Nonce",
        "signed_nonce": "Signed Nonce",
        "sub": "Subject",
        "total_messages": "Total Messages",
        "validity_identifier": "Validity Identifier",
        "vc.@context": "Credential JSON Context",
        "vc.credentialSchema.id": "Credential Schema ID",
        "vc.credentialSchema.type": "Credential Schema Type",
        "vc.credentialSubject.firstName": "Credential Subject First Name",
        "vc.credentialSubject.image": "Credential Subject Image",
        "vc.credentialSubject.lastName": "Credential Subject Last Name",
        "vc.credentialSubject.studentId": "Credential Subject Student ID",
        "vc.credentialSubject.studentIdPrefix": "Credential Subject Student ID Prefix",
        "vc.credentialSubject.theme.bgColorCard": "Credential Subject Theme Background Color Card",
        "vc.credentialSubject.theme.bgColorSectionBot": "Credential Subject Theme Background Color Section Bottom",
        "vc.credentialSubject.theme.bgColorSectionTop": "Credential Subject Theme Background Color Section Top",
        "vc.credentialSubject.theme.fgColorTitle": "Credential Subject Theme Foreground Color Title",
        "vc.credentialSubject.theme.icon": "Credential Subject Theme Icon",
        "vc.credentialSubject.theme.name": "Credential Subject Theme Name",
        "vc.expirationDate": "Credential Expiration Date",
        "vc.id": "Credential ID",
        "vc.issuanceDate": "Credential Issuance Date",
        "vc.issuer": "Credential Issuer",
        "vc.type": "Credential Type",
        "vc.validFrom": "Credential valid from",
    ]

    func mapToReadable(for key: String) -> String {
        if let readable = baseMappings[key] {
            return readable
        }
        var components = key.split(separator: ".")

        if let lastComponent = components.last, Int(lastComponent) != nil {
            components.removeLast()
        }

        let baseKey = components.joined(separator: ".")

        if let readable = baseMappings[baseKey] {
            return readable
        }

        return key
    }
}


struct PresentationDefinition: Decodable {
    enum CodingKeys: String, CodingKey {
        case mandatoryFields = "mandatory_fields"
        case explanation
    }
    let mandatoryFields: [String]
    let explanation: [String: String]

    func getFields() -> [FieldInfo] {
        let mapper = FieldMapper()
        var fields: [FieldInfo] = []

        fields = mandatoryFields.map { field in
            let explanation = explanation[field] ?? "No explanation given."
            return FieldInfo(key: field, field: mapper.mapToReadable(for: field), explanation: explanation)
        }

        return fields
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.mandatoryFields = (try container.decode([String].self, forKey: .mandatoryFields))
        self.explanation = try container.decode([String: String].self, forKey: .explanation).mapValues { $0.replacingOccurrences(of: "+", with: " ")}
    }
}
