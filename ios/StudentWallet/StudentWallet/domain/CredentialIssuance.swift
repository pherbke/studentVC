//
//  CredentialIssuance.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//

import Foundation
import CryptoKit

private func requestPreAuthCode(uri: URL) async throws -> RequestResult<PreAuthResponse> {
    let initialOfferRequest = createRequest(url: uri, method: .Get)
    let (data,response) = try await INSECURE_SESSION.data(for: initialOfferRequest)
    print("Server response: \(response): \(try? JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary)")
    let statusCode = (response as? HTTPURLResponse)?.statusCode
    do {
        switch statusCode {
        case 200:
            return .Success(try JSONDecoder().decode(PreAuthResponse.self, from: data))
        default:
            return .BackendError(code: statusCode ?? -1)
        }
    } catch let error {
        return .InvalidResponse(error: error)
    }
}

private func requestWellKnownIssuers(issuerURL: String) async throws -> RequestResult<CredentialIssuerResponse> {
    let builder = UrlQueryBuilder(baseURL: issuerURL)
        .setPath(path: "/.well-known/openid-credential-issuer")
    let wellKnownIssuersRequest = createRequest(url: builder.build()!, method: .Get)
    let (data, response) = try await INSECURE_SESSION.data(for: wellKnownIssuersRequest)
    print("Server response: \(response): \(try? JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary)")
    let statusCode = (response as? HTTPURLResponse)?.statusCode
    do {
        switch statusCode {
        case 200:
            return .Success(try JSONDecoder().decode(CredentialIssuerResponse.self, from: data))
        default:
            return .BackendError(code: statusCode ?? -1)
        }
    } catch let error {
        return .InvalidResponse(error: error)
    }
}

private func requestWellKnownOpenIDConfig(authServerURL: String) async throws -> RequestResult<AuthorizationServerMetaDataResponse> {
    let builder = UrlQueryBuilder(baseURL: authServerURL)
        .setPath(path: "/.well-known/openid-configuration")
    let wellKnownIssuersRequest = createRequest(url: builder.build()!, method: .Get)
    let (data, response) = try await INSECURE_SESSION.data(for: wellKnownIssuersRequest)
    print("Server response: \(response): \(try? JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary)")
    let statusCode = (response as? HTTPURLResponse)?.statusCode
    do {
        switch statusCode {
        case 200:
            return .Success(try JSONDecoder().decode(AuthorizationServerMetaDataResponse.self, from: data))
        default:
            return .BackendError(code: statusCode ?? -1)
        }
    } catch let error {
        return .InvalidResponse(error: error)
    }
}

private func requestAuthorization(
    issuerURL: String,
    authorizationRequest: AuthorizationRequest
) async throws -> RequestResult<URLComponents> {
    let authorizationDetails = try JSONEncoder().encode(authorizationRequest.authorizationDetails)
    guard let authorizationDetailsJson = String(data: authorizationDetails, encoding: .utf8)?
        .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
        return .Error(
            error: EncodingError.invalidValue(
                authorizationDetails, EncodingError.Context(
                    codingPath: [],
                    debugDescription: "Could not encode authorization details to JSON String."
                )
            )
        )
    }
    //this field is not optional for holder wallets so we enforce it

    let clientMetadata = try JSONEncoder().encode(authorizationRequest.clientMetadata)
    guard let clientMetadataJson = String(data: clientMetadata, encoding: .utf8)?
        .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
        return .Error(
            error: EncodingError.invalidValue(
                authorizationDetails, EncodingError.Context(
                    codingPath: [],
                    debugDescription: "Could not encode client metadata to JSON String."
                )
            )
        )
    }
    let builder = UrlQueryBuilder(baseURL: issuerURL)
        .setPath(path: "/authorize")
        .addQueryComponent(
            key: AuthorizationRequest.CodingKeys.responseType.rawValue,
            value: authorizationRequest.responseType.rawValue
        )
        .addQueryComponent(
            key: AuthorizationRequest.CodingKeys.clientID.rawValue,
            value: authorizationRequest.clientID
        )
        .addQueryComponent(
            key: AuthorizationRequest.CodingKeys.redirectURI.rawValue,
            value: authorizationRequest.redirectURI
        )
        .addQueryComponent(
            key: AuthorizationRequest.CodingKeys.scope.rawValue,
            value: authorizationRequest.scope.rawValue
        )
        .addOptionalQueryComponent(
            key: AuthorizationRequest.CodingKeys.issuerState.rawValue,
            value: authorizationRequest.issuerState
        )
        .addOptionalQueryComponent(
            key: AuthorizationRequest.CodingKeys.state.rawValue,
            value: authorizationRequest.state
        )
        .addQueryComponent(
            key: AuthorizationRequest.CodingKeys.authorizationDetails.rawValue,
            value: authorizationDetailsJson
        )
        .addOptionalQueryComponent(
            key: AuthorizationRequest.CodingKeys.nonce.rawValue,
            value: authorizationRequest.state
        )
        .addOptionalQueryComponent(
            key: AuthorizationRequest.CodingKeys.codeChallenge.rawValue,
            value: authorizationRequest.codeChallenge
        )
        .addOptionalQueryComponent(
            key: AuthorizationRequest.CodingKeys.codeChallengeMethod.rawValue,
            value: authorizationRequest.codeChallengeMethod?.rawValue
        )
        .addQueryComponent( //technically its optional but were a holder wallet so
            key: AuthorizationRequest.CodingKeys.clientMetadata.rawValue,
            value: clientMetadataJson
        )

    let authorizationRequest = createRequest(url: builder.build()!, method: .Get)
    let (data, response) = try await INSECURE_SESSION.data(for: authorizationRequest)
    print("Server response: \(response): \(try? JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary)")

    let statusCode = (response as? HTTPURLResponse)?.statusCode
    switch statusCode {
    case 302:
        guard let offerResponse = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Location"),
              let components = URLComponents(string: offerResponse) else {
            return .InvalidResponse(error: nil)
        }
        return .Success(components)
    default:
        return .BackendError(code: statusCode ?? -1)
    }
}

private func requestDirectPost(redirectURIComponents: URLComponents, requestBody: DirectPostRequest) async throws -> RequestResult<URLComponents> {
    let builder = UrlQueryBuilder(components: redirectURIComponents)
        .addQueryComponent(
            key: DirectPostRequest.CodingKeys.state.rawValue,
            value: requestBody.state
        )
        .addQueryComponent(
            key: DirectPostRequest.CodingKeys.idToken.rawValue,
            value: requestBody.idToken
        )
    var authorizationRequest = createRequest(url: builder.build()!, method: .Post)
    authorizationRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
    authorizationRequest.httpBody = try? JSONEncoder().encode(requestBody)
    let (data, response) = try await INSECURE_SESSION.data(for: authorizationRequest)
    print("Server response: \(response): \(try? JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary)")

    let statusCode = (response as? HTTPURLResponse)?.statusCode
    switch statusCode {
    case 302:
        guard let offerResponse = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "Location"),
              let components = URLComponents(string: offerResponse) else {
            return .InvalidResponse(error: nil)
        }
        return .Success(components)
    default:
        return .BackendError(code: statusCode ?? -1)
    }
}

private func requestToken(issuerURL: String, tokenRequestBody: TokenRequest) async throws -> RequestResult<TokenResponse> {
    let builder = UrlQueryBuilder(baseURL: issuerURL)
        .setPath(path: "/token")
        .addQueryComponent(
            key: TokenRequest.CodingKeys.grantType.rawValue,
            value: tokenRequestBody.grantType.rawValue
        )
        .addQueryComponent(
            key: TokenRequest.CodingKeys.clientID.rawValue,
            value: tokenRequestBody.clientID
        )
        .addQueryComponent(
            key: TokenRequest.CodingKeys.code.rawValue,
            value: tokenRequestBody.code
        )
        .addQueryComponent(
            key: TokenRequest.CodingKeys.redirectURI.rawValue,
            value: tokenRequestBody.redirectURI
        )
        .addOptionalQueryComponent(
            key: TokenRequest.CodingKeys.preAuthorisedCode.rawValue,
            value: tokenRequestBody.preAuthorisedCode
        )
        .addOptionalQueryComponent(
            key: TokenRequest.CodingKeys.userPin.rawValue,
            value: tokenRequestBody.userPin
        )
        .addOptionalQueryComponent(
            key: TokenRequest.CodingKeys.clientAssertion.rawValue,
            value: tokenRequestBody.clientAssertion
        )
        .addOptionalQueryComponent(
            key: TokenRequest.CodingKeys.clientAssertionType.rawValue,
            value: tokenRequestBody.clientAssertionType?.rawValue
        )
        .addOptionalQueryComponent(
            key: TokenRequest.CodingKeys.codeVerifier.rawValue,
            value: tokenRequestBody.codeVerifier
        )
    let tokenRequest = createRequest(url: builder.build()!, method: .Post)
    let (data, response) = try await INSECURE_SESSION.data(for: tokenRequest)
    print("Server response: \(response): \(try? JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary)")
    let statusCode = (response as? HTTPURLResponse)?.statusCode
    do {
        switch statusCode {
        case 200:
            return .Success(try JSONDecoder().decode(TokenResponse.self, from: data))
        default:
            return .BackendError(code: statusCode ?? -1)
        }
    } catch let error {
        return .InvalidResponse(error: error)
    }
}

private func requestCredential(
    issuerURL: String,
    bearerToken: String,
    credentialRequest: CredentialRequest
) async throws -> RequestResult<CredentialResponse> {
    let builder = UrlQueryBuilder(baseURL: issuerURL)
        .setPath(path: "/credential")
    var request = createRequest(url: builder.build()!, method: .Post)
    request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.httpBody = try JSONEncoder().encode(credentialRequest)
    let (data, response) = try await INSECURE_SESSION.data(for: request)
    print("Server response: \(response): \(try? JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary)")
    let statusCode = (response as? HTTPURLResponse)?.statusCode
    do {
        switch statusCode {
        case 200:
            return .Success(try JSONDecoder().decode(CredentialResponse.self, from: data))
        default:
            return .BackendError(code: statusCode ?? -1)
        }
    } catch let error {
        return .InvalidResponse(error: error)
    }
}

func requestCredentialIssuance(
    privateKey: P256.Signing.PrivateKey,
    credentialOfferUri: String
) -> Task<RequestResult<CredentialData>, Error> {
    return Task {
        let publicKey = privateKey.publicKey
        let did = generateDID(publicKey: publicKey)
        guard let receivedOfferUriComponents = URLComponents(string: credentialOfferUri) else {
            return .Error(
                error: DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: [],
                        debugDescription: "Couldnt decode credential offer uri"
                    )
                )
            )
        }
        let credentialOfferUri: URL
        if let offerUri = receivedOfferUriComponents.queryItems?.first(where: { $0.name == "credential_offer_uri" })?.value,
           let url = URL(string: offerUri) {
            credentialOfferUri = url
        } else {
            return .Error(error: DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: [],
                    debugDescription: "Couldnt decode credential offer uri"
                )
            ))
        }
        print("credential offer uri: \(credentialOfferUri)")

        if Task.isCancelled {
            return .Cancelled
        }

        let preAuthResult = try await requestPreAuthCode(uri: credentialOfferUri)
        let preAuthResponse: PreAuthResponse
        switch preAuthResult {
        case .Success(let response):
            preAuthResponse = response
        case .Cancelled:
            return .Cancelled
        case .InvalidResponse(let error):
            return .InvalidResponse(error: error)
        case .BackendError(let code):
            return .BackendError(code: code)
        case .Error(let error):
            return .Error(error: error)
        }

        if Task.isCancelled {
            return .Cancelled
        }
        let wellKnownIssuerResult = try await requestWellKnownIssuers(
            issuerURL: preAuthResponse.credentialIssuer
        )
        let wellKnownIssuerResponse: CredentialIssuerResponse
        switch wellKnownIssuerResult {
        case .Success(let response):
            wellKnownIssuerResponse = response
        case .Cancelled:
            return .Cancelled
        case .InvalidResponse(let error):
            return .InvalidResponse(error: error)
        case .BackendError(let code):
            return .BackendError(code: code)
        case .Error(let error):
            return .Error(error: error)
        }

        if Task.isCancelled {
            return .Cancelled
        }

        let wellKnownOpenIDRequest = try await requestWellKnownOpenIDConfig(
            authServerURL: wellKnownIssuerResponse.authorizationServer)
        let wellKnownOpenIDResponse: AuthorizationServerMetaDataResponse
        switch wellKnownOpenIDRequest {
        case .Success(let response):
            wellKnownOpenIDResponse = response
        case .Cancelled:
            return .Cancelled
        case .InvalidResponse(let error):
            return .InvalidResponse(error: error)
        case .BackendError(let code):
            return .BackendError(code: code)
        case .Error(let error):
            return .Error(error: error)
        }

        if Task.isCancelled {
            return .Cancelled
        }

        let codeVerifier = generateCodeVerifier()
        let codeChallenge = generateCodeChallenge(codeVerifier: codeVerifier)
        let walletState = generateSecureState()

        let authorizationRequestBody = AuthorizationRequest(
            responseType: .code,
            clientID: did,
            redirectURI: "\(preAuthResponse.credentialIssuer)/direct_post",
            scope: .openid,
            issuerState: preAuthResponse.grants.authorizationCode.issuerState,
            state: walletState,
            authorizationDetails: AuthorizationDetails(
                type: .openIDCredential,
                locations: did,
                format: .jwtVC,
                types: []
            ),
            nonce: generateNonce(),
            codeChallenge: codeChallenge,
            codeChallengeMethod: .s256,
            clientMetadata: DEFAULT_CLIENT_META_DATA
        )
        let authorizationRequest = try await requestAuthorization(
            issuerURL: preAuthResponse.credentialIssuer,
            authorizationRequest: authorizationRequestBody
        )
        let authorizationRedirectURIComponents: URLComponents
        switch authorizationRequest {
        case .Success(let response):
            authorizationRedirectURIComponents = response
        case .Cancelled:
            return .Cancelled
        case .InvalidResponse(let error):
            return .InvalidResponse(error: error)
        case .BackendError(let code):
            return .BackendError(code: code)
        case .Error(let error):
            return .Error(error: error)
        }

        if Task.isCancelled {
            return .Cancelled
        }


        let directPostRequestBody = DirectPostRequest(
            idToken: try! JWT.encode(
                header: try! JSONEncoder().encode(
                    JWTHeader(
                        alg: "ES256",
                        typ: "JWT"
                    )
                ),
                payload: try! JSONEncoder().encode(
                    IDTokenPayload(
                        issuerState: preAuthResponse.grants.authorizationCode.issuerState,
                        iss: did,
                        nonce: generateNonce(),
                        state: generateSecureState(),
                        codeChallenge: codeChallenge
                    )
                ),
                key: privateKey
            ),
            state: walletState
        )

        let directPostRequest = try await requestDirectPost(
            redirectURIComponents: authorizationRedirectURIComponents,
            requestBody: directPostRequestBody
        )
        let authorizationResponse: URLComponents
        let authCode: String
        switch directPostRequest {
        case .Success(let response):
            authorizationResponse = response
            guard let code = authorizationResponse.queryItems?.first(where: { $0.name == "code" })?.value else {
                return .InvalidResponse(
                    error: DecodingError.dataCorrupted(
                        DecodingError.Context(
                            codingPath: [],
                            debugDescription: "No code found in authorization response"
                        )
                    )
                )
            }
            authCode = code
        case .Cancelled:
            return .Cancelled
        case .InvalidResponse(let error):
            return .InvalidResponse(error: error)
        case .BackendError(let code):
            return .BackendError(code: code)
        case .Error(let error):
            return .Error(error: error)
        }

        if Task.isCancelled {
            return .Cancelled
        }

        let tokenRequestBody = TokenRequest(
            grantType: .authorizationCode,
            clientID: did,
            code: authCode,
            redirectURI: preAuthResponse.credentialIssuer,
            preAuthorisedCode: nil,
            userPin: nil,
            clientAssertion: nil,
            clientAssertionType: nil,
            codeVerifier: codeVerifier
        )
        let tokenRequest = try await requestToken(
            issuerURL: preAuthResponse.credentialIssuer,
            tokenRequestBody: tokenRequestBody)
        let tokenResponse: TokenResponse
        switch tokenRequest {
        case .Success(let response):
            tokenResponse = response
        case .Cancelled:
            return .Cancelled
        case .InvalidResponse(let error):
            return .InvalidResponse(error: error)
        case .BackendError(let code):
            return .BackendError(code: code)
        case .Error(let error):
            return .Error(error: error)
        }

        if Task.isCancelled {
            return .Cancelled
        }

        let credentialRequest = try await requestCredential(
            issuerURL: preAuthResponse.credentialIssuer,
            bearerToken: tokenResponse.accessToken,
            credentialRequest: CredentialRequest(
                format: .jwtVCJson,
                credentialDefinition: CredentialDefinition(
                    type: [.VerifiableCredential, .VerifiablePortableDocumentA1]
                )
//                proof: CredentialRequestProof(
//                    proofType: "jwt",
//                    jwt: try! JWT.encode(
//                        header: try! JSONEncoder().encode(
//                            JWTHeader(
//                                alg: "ES256",
//                                typ: "JWT"
//                            )
//                        ),
//                        payload: try! JSONEncoder()
//                            .encode(
//                                ProofPayload(
//                                    iss: iss,
//                                    sub: did
//                                )
//                            ),
//                        key: privateKey
//                    )
//                )
            )
        )
        switch credentialRequest {
        case .Success(let credentialResponse):
            do {
                let jwt = try JWT.decode(token: credentialResponse.credential)
                return .Success(
                    CredentialData(
                        jwt: jwt.payload,
                        signature: credentialResponse.signature
                    )
                )
            } catch let error {
                print("Error decoding jwt: \(error)")
                return .Error(error: error)
            }

        case .Cancelled:
            return .Cancelled
        case .InvalidResponse(let error):
            return .InvalidResponse(error: error)
        case .BackendError(let code):
            return .BackendError(code: code)
        case .Error(let error):
            return .Error(error: error)
        }
    }
}
