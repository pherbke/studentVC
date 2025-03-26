//
//  AuthorizationServerMetaDataResponse.swift
//  StudentWallet
//
//  Created by Anders Hausding on 21.11.24.
//

struct AuthorizationServerMetaDataResponse: Codable {
    //https://hub.ebsi.eu/apis/pilot/authorisation/v4/get-well-known-openid-config
    enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case presentationDefinitionEndpoint = "presentation_definition_endpoint"
        case jwksURI = "jwks_uri"
        case supportedScopes = "scopes_supported"
        case supportedResponseTypes = "response_types_supported"
        case supportedResponseModes = "response_modes_supported"
        case supportedGrantTypes = "grant_types_supported"
        case supportedSubjectTypes = "subject_types_supported"
        case supportedIDTokenSigningAlgValues = "id_token_signing_alg_values"
        case supportedRequestObjectSigningAlgValues = "request_object_signing_alg_values"
        case supportedRequestParameter = "request_parameter_supported"
        case supportedURIParameter = "request_uri_parameter_supported"
        case supportedTokenEndpointAuthMethods = "token_endpoint_auth_methods_supported"
        case supportedVPFormats = "vp_formats_supported"
        case supportedSubjectSyntaxTypes = "subject_syntax_types_supported"
        case supportedSubjectTrustFrameworks = "subject_trust_frameworks_supported"
        case supportedIDTokenTypes = "id_token_types_supported"
    }
    let issuer: String
    let authorizationEndpoint: String
    let tokenEndpoint: String
    let presentationDefinitionEndpoint: String?
    let jwksURI: String
    let supportedScopes: [String]?
    let supportedResponseTypes: [String]?
    let supportedResponseModes: [String]?
    let supportedGrantTypes: [String]?
    let supportedSubjectTypes: [String]?
    let supportedIDTokenSigningAlgValues: [String]?
    let supportedRequestObjectSigningAlgValues: [String]?
    let supportedRequestParameter: Bool?
    let supportedURIParameter: Bool?
    let supportedTokenEndpointAuthMethods: [String]
    let supportedVPFormats: SupportedVPFormats
    let supportedSubjectSyntaxTypes: [String]
    let supportedSubjectTrustFrameworks: [String]
    let supportedIDTokenTypes: [String]?

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(issuer, forKey: .issuer)
        try container.encode(authorizationEndpoint, forKey: .authorizationEndpoint)
        try container.encode(tokenEndpoint, forKey: .tokenEndpoint)
        try container.encodeIfPresent(presentationDefinitionEndpoint, forKey: .presentationDefinitionEndpoint)
        try container.encodeIfPresent(jwksURI, forKey: .jwksURI)
        try container.encodeIfPresent(supportedScopes, forKey: .supportedScopes)
        try container.encodeIfPresent(supportedResponseTypes, forKey: .supportedResponseTypes)
        try container.encodeIfPresent(supportedResponseModes, forKey: .supportedResponseModes)
        try container.encodeIfPresent(supportedGrantTypes, forKey: .supportedGrantTypes)
        try container.encodeIfPresent(supportedSubjectTypes, forKey: .supportedSubjectTypes)
        try container.encodeIfPresent(supportedIDTokenSigningAlgValues, forKey: .supportedIDTokenSigningAlgValues)
        try container.encodeIfPresent(supportedRequestObjectSigningAlgValues, forKey: .supportedRequestObjectSigningAlgValues)
        try container.encodeIfPresent(supportedRequestParameter, forKey: .supportedRequestParameter)
        try container.encodeIfPresent(supportedURIParameter, forKey: .supportedURIParameter)
        try container.encode(supportedTokenEndpointAuthMethods, forKey: .supportedTokenEndpointAuthMethods)
        try container.encode(supportedVPFormats, forKey: .supportedVPFormats)
        try container.encode(supportedSubjectSyntaxTypes, forKey: .supportedSubjectSyntaxTypes)
        try container.encode(supportedSubjectTrustFrameworks, forKey: .supportedSubjectTrustFrameworks)
        try container.encodeIfPresent(supportedIDTokenTypes, forKey: .supportedIDTokenTypes)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        issuer = try container.decode(String.self, forKey: .issuer)
        authorizationEndpoint = try container.decode(String.self, forKey: .authorizationEndpoint)
        tokenEndpoint = try container.decode(String.self, forKey: .tokenEndpoint)
        presentationDefinitionEndpoint = try container.decodeIfPresent(String.self, forKey: .presentationDefinitionEndpoint)
        jwksURI = try container.decode(String.self, forKey: .jwksURI)
        supportedScopes = try container.decodeIfPresent([String].self, forKey: .supportedScopes)
        supportedResponseTypes = try container.decodeIfPresent([String].self, forKey: .supportedResponseTypes)
        supportedResponseModes = try container.decodeIfPresent([String].self, forKey: .supportedResponseModes)
        supportedGrantTypes = try container.decodeIfPresent([String].self, forKey: .supportedGrantTypes)
        supportedSubjectTypes = try container.decodeIfPresent([String].self, forKey: .supportedSubjectTypes)
        supportedIDTokenSigningAlgValues = try container.decodeIfPresent([String].self, forKey: .supportedIDTokenSigningAlgValues)
        supportedRequestObjectSigningAlgValues = try container.decodeIfPresent([String].self, forKey: .supportedRequestObjectSigningAlgValues)
        supportedRequestParameter = try container.decodeIfPresent(Bool.self, forKey: .supportedRequestParameter)
        supportedURIParameter = try container.decodeIfPresent(Bool.self, forKey: .supportedURIParameter)
        supportedTokenEndpointAuthMethods = try container.decode([String].self, forKey: .supportedTokenEndpointAuthMethods)
        supportedVPFormats = try container.decode(SupportedVPFormats.self, forKey: .supportedVPFormats)
        supportedSubjectSyntaxTypes = try container.decode([String].self, forKey: .supportedSubjectSyntaxTypes)
        supportedSubjectTrustFrameworks = try container.decode([String].self, forKey: .supportedSubjectTrustFrameworks)
        supportedIDTokenTypes = try container.decode([String].self, forKey: .supportedIDTokenTypes)
    }
}
