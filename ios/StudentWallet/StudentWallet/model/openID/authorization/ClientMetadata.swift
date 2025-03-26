//
//  ClientMetadata.swift
//  StudentWallet
//
//  Created by Anders Hausding on 28.11.24.
//

let DEFAULT_CLIENT_META_DATA = ClientMetadata(
    authorizationEndpoint: "openid:",
    supportedScopes: ["openid"],
    supportedResponseTypes: ["vp_token", "id_token"],
    supportedSubjectType: ["public"],
    supportedIDTokenSigningAlgValues: ["ES256"],
    supportedRequestObjectSigningAlgValues: ["ES256"],
    supportedVPFormats: SupportedVPFormats(
        jwtVCJson: SupportedVPFormat(
            supportedAlgValues: ["ES256"]
        ),
        jwtVPJson: SupportedVPFormat(
            supportedAlgValues: ["ES256"]
        )
    ),
    supportedSyntaxTypes: ["ES256"],
    supportedIDTokenTypes: ["subject_signed_id_token"]
)


class ClientMetadata: Codable {
    enum CodingKeys: String, CodingKey {
        case authorizationEndpoint = "authorization_endpoint"
        case supportedScopes = "scopes_supported"
        case supportedResponseTypes = "response_types_supported"
        case supportedSubjectType = "subject_types_supported"
        case supportedIDTokenSigningAlgValues = "id_token_signing_alg_values_supported"
        case supportedRequestObjectSigningAlgValues = "request_object_signing_alg_values_supported"
        case supportedVPFormats = "vp_formats_supported"
        case supportedSyntaxTypes = "syntax_types_supported"
        case supportedIDTokenTypes = "id_token_types_supported"
    }
    let authorizationEndpoint: String?
    let supportedScopes: [String]?
    let supportedResponseTypes: [String]?
    let supportedSubjectType: [String]?
    let supportedIDTokenSigningAlgValues: [String]?
    let supportedRequestObjectSigningAlgValues: [String]?
    let supportedVPFormats: SupportedVPFormats?
    let supportedSyntaxTypes: [String]?
    let supportedIDTokenTypes: [String]?

    required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        authorizationEndpoint = try container.decode(String.self, forKey: .authorizationEndpoint)
        supportedScopes = try container.decodeIfPresent(
            [String].self,
            forKey: .supportedScopes
        )
        supportedResponseTypes = try container.decodeIfPresent(
            [String].self,
            forKey: .supportedResponseTypes
        )
        supportedSubjectType = try container.decodeIfPresent(
            [String].self,
            forKey: .supportedSubjectType
        )
        supportedIDTokenSigningAlgValues = try container.decodeIfPresent(
            [String].self,
            forKey: .supportedIDTokenSigningAlgValues
        )
        supportedRequestObjectSigningAlgValues = try container.decodeIfPresent(
            [String].self,
            forKey: .supportedRequestObjectSigningAlgValues
        )
        supportedVPFormats = try container.decodeIfPresent(
            SupportedVPFormats.self,
            forKey: .supportedVPFormats
        )
        supportedSyntaxTypes = try container.decodeIfPresent(
            [String].self,
            forKey: .supportedSyntaxTypes
        )
        supportedIDTokenTypes = try container.decodeIfPresent(
            [String].self,
            forKey: .supportedIDTokenTypes
        )
    }

    init(authorizationEndpoint: String? = nil,
         supportedScopes: [String]? = nil,
         supportedResponseTypes: [String]? = nil,
         supportedSubjectType: [String]? = nil,
         supportedIDTokenSigningAlgValues: [String]? = nil,
         supportedRequestObjectSigningAlgValues: [String]? = nil,
         supportedVPFormats: SupportedVPFormats? = nil,
         supportedSyntaxTypes: [String]? = nil,
         supportedIDTokenTypes: [String]? = nil
    ) {

        self.authorizationEndpoint = authorizationEndpoint
        self.supportedScopes = supportedScopes
        self.supportedResponseTypes = supportedResponseTypes
        self.supportedSubjectType = supportedSubjectType
        self.supportedIDTokenSigningAlgValues = supportedIDTokenSigningAlgValues
        self.supportedRequestObjectSigningAlgValues = supportedRequestObjectSigningAlgValues
        self.supportedVPFormats = supportedVPFormats
        self.supportedSyntaxTypes = supportedSyntaxTypes
        self.supportedIDTokenTypes = supportedIDTokenTypes
    }


    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(authorizationEndpoint, forKey: .authorizationEndpoint)
        try container.encodeIfPresent(supportedScopes, forKey: .supportedScopes)
        try container.encodeIfPresent(supportedResponseTypes, forKey: .supportedResponseTypes)
        try container.encodeIfPresent(supportedSubjectType, forKey: .supportedSubjectType)
        try container.encodeIfPresent(supportedIDTokenSigningAlgValues, forKey: .supportedIDTokenSigningAlgValues)
        try container.encodeIfPresent(supportedRequestObjectSigningAlgValues, forKey: .supportedRequestObjectSigningAlgValues)
        try container.encodeIfPresent(supportedVPFormats, forKey: .supportedVPFormats)
        try container.encodeIfPresent(supportedSyntaxTypes, forKey: .supportedSyntaxTypes)
        try container.encode(supportedIDTokenTypes, forKey: .supportedIDTokenTypes)
    }
}
