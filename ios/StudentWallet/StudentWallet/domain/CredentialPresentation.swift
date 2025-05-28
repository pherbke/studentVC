//
//  CredentialPresentation.swift
//  StudentWallet
//
//  Created by Anders Hausding on 15.12.24.
//

import CryptoKit
import Foundation
import RustFramework

private func requestCredentialPresentationURI(url: URL) async throws -> RequestResult<URLComponents> {
    let initialPresentationRequest = createRequest(url: url, method: .Post)
    let (data, response) = try await INSECURE_SESSION.data(for: initialPresentationRequest)
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

private func postCredentialPresentation(url: URL, requestBody: PresentationRequest) async throws -> RequestResult<Bool> {
    let presentationSubmission = try JSONEncoder().encode(requestBody.presentationSubmission)
    guard let presentationSubmissionJson = String(data: presentationSubmission, encoding: .utf8)?
        .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else {
        return .Error(
            error: EncodingError.invalidValue(
                presentationSubmission, EncodingError.Context(
                    codingPath: [],
                    debugDescription: "Could not encode client metadata to JSON String."
                )
            )
        )
    }
    let builder = UrlQueryBuilder(baseURL: url.absoluteString)
        .addQueryComponent(
            key: PresentationRequest.CodingKeys.vpToken.rawValue,
            value: requestBody.vpToken
        )
        .addQueryComponent(
            key: PresentationRequest.CodingKeys.presentationSubmission.rawValue,
            value: presentationSubmissionJson
        )
    var presentationRequest = createRequest(url: builder.build()!, method: .Post)
    presentationRequest.httpBody = try? JSONEncoder().encode(requestBody)
    let (data, response) = try await INSECURE_SESSION.data(for: presentationRequest)
    print("Server response: \(response): \(try? JSONSerialization.jsonObject(with: data, options: []) as? NSDictionary)")
    let statusCode = (response as? HTTPURLResponse)?.statusCode
    switch statusCode {
    case 200:
        return .Success(true)
    default:
        return .BackendError(code: statusCode ?? -1)
    }
}
func requestPresentationDefinition(presentationURI: String) -> Task<RequestResult<(URL, PresentationDefinition)>, Error> {
    return Task {
        let parsedURL: URL
        if let components = URLComponents(string: presentationURI),
           let uriString = components.queryItems?.first(where: { $0.name == "request_uri" })?.value,
           let url = URL(string: uriString) {
            parsedURL = url
        } else {
            return .Error(
                error: DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: [],
                        debugDescription: "Couldnt decode credential presentation uri"
                    )
                )
            )
        }
        let credentialPresentationURIRequest = try await requestCredentialPresentationURI(
            url: parsedURL
        )
        let presentationURIComponents: URLComponents
        switch credentialPresentationURIRequest {
        case .Success(let response):
            presentationURIComponents = response
        case .Cancelled:
            return .Cancelled
        case .InvalidResponse(let error):
            return .InvalidResponse(error: error)
        case .BackendError(let code):
            return .BackendError(code: code)
        case .Error(let error):
            return .Error(error: error)
        }

        guard let uriString = presentationURIComponents.queryItems?.first(where: { $0.name == "response_uri" })?.value,
              let presentationURI = URL(string: uriString),
              let presentationDefinitionString = presentationURIComponents.queryItems?.first(where: { $0.name == "presentation_definition" })?.value,
              let presentationDefintionData = presentationDefinitionString.removingPercentEncoding?
            .replacingOccurrences(of: ":+", with: ":")
            .replacingOccurrences(of: ",+", with: ",")
            .data(using: .utf8),
              let presentationDefinition = try? JSONDecoder().decode(PresentationDefinition.self, from: presentationDefintionData) else {
            return .Error(
                error: DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: [],
                        debugDescription: "Couldnt decode credential presentation uri parameters"
                    )
                )
            )
        }
        return .Success((presentationURI, presentationDefinition))
    }
}
func sendCredentialForPresentation(presentationURI: URL, presentationDefinition: PresentationDefinition, privateKey: P256.Signing.PrivateKey, credentialData: CredentialData) -> Task<RequestResult<Bool>, Error> {
    return Task {
        guard let dpkBytes = Data(base64Encoded: credentialData.jwt.bbsDPK),
              let signatureBytes = Data(base64Encoded: credentialData.signature) else {
            return .Error(
                error: DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: [],
                        debugDescription: "Signature and/or public key is corrupted"
                    )
                )
            )
        }
        
        guard let jwtData = try? JSONEncoder().encode(credentialData.jwt),
              let jwtDict = try JSONSerialization.jsonObject(with: jwtData, options: .fragmentsAllowed
              ) as? [String: Any] else {
            return .Error(
                error: DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: [],
                        debugDescription: "Couldnt create flattened vc for presentation"
                    )
                )
            )
        }

        let flatJWT = flattenJSON(jwtDict)

        if Task.isCancelled {
            return .Cancelled
        }

        let sortedKeys = flatJWT.keys.sorted()
        let revealedIndices = sortedKeys.enumerated()
            .filter { index,key in
                for mandatoryField in presentationDefinition.mandatoryFields {
                    if key.starts(with: "\(mandatoryField).") || key == mandatoryField {
                        return true
                    }
                }
                return key.starts(with: "vc.credentialSubject.firstName")
            }
            .map {
                UInt64($0.offset)
            }

        let messages: [String]
        do {
            messages = try sortedKeys.compactMap { key -> String? in
                let singlePairDict = [key: flatJWT[key]!]
                let jsonData = try JSONSerialization.data(withJSONObject: singlePairDict, options: .withoutEscapingSlashes)
                // JSONSerialization doesnt put a space after : so we have to insert it manually, since all keys should never contain a : so this operation should be safe
                return String(data: jsonData, encoding: .utf8)?.replacing(":", with: ": ", maxReplacements: 1)
            }
        } catch let error {
            return .Error(
                error: error
            )
        }

        if messages.count != sortedKeys.count {
            return .Error(
                error: DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: [],
                        debugDescription: "Couldnt create presentation object"
                    )
                )
            )
        }
        
        let extractedValues = Dictionary<String,Any>(uniqueKeysWithValues: revealedIndices.map { index in
            let index = Int(index)
            return (sortedKeys[index], flatJWT[sortedKeys[index]]!)
        })
        let presentedValues = unflattenJSON(extractedValues)

        let proof = GenerateProofRequest(
            pubKeyBytes: dpkBytes,
            signatureBytes: signatureBytes,
            revealedIndices: revealedIndices,
            messages: messages
        ).generateProof()

        let presentedData: Data
        let revealedCredential: RevealedCredentialJWT
        do {
            presentedData = try JSONSerialization.data(withJSONObject: presentedValues, options: [])
            revealedCredential = try JSONDecoder().decode(RevealedCredentialJWT.self, from: presentedData)
        } catch let error {
            return .Error(
                error: error
            )
        }

        let presentationSubmission = PresentationSubmission(
            nonce:  proof.nonceBytes.base64EncodedString(),
            proofRequest: proof.proofRequestBytes.base64EncodedString(),
            proof: proof.proofBytes.base64EncodedString(),
            values: revealedCredential
        )
        guard let verifiableCredential = try? JSONEncoder().encode(
            VerifiableCredentialJWT(verifiableCredential: presentationSubmission)
        ) else {
            return .Error(
                error: DecodingError.dataCorrupted(
                    DecodingError.Context(
                        codingPath: [],
                        debugDescription: "Couldnt create presentation submission object json"
                    )
                )
            )
        }
        let credentialPresentationRequest = try await postCredentialPresentation(
            url: presentationURI,
            requestBody: PresentationRequest(
                vpToken: try! JWT.encode(
                    header: try! JSONEncoder().encode(
                        JWTHeader(
                            alg: "ES256",
                            typ: "JWT"
                        )
                    ),
                    payload: verifiableCredential,
                    key: privateKey
                ),
                presentationSubmission: presentationSubmission
            )
        )
        switch credentialPresentationRequest {
        case .Success(let response):
            return .Success(response)
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
