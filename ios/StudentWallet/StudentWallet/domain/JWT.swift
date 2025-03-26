//
//  JWT.swift
//  StudentWallet
//
//  Created by Anders Hausding on 02.12.24.
//

import Foundation
import CryptoKit

struct JWT {
    static func encode(header: Data, payload: Data, key: P256.Signing.PrivateKey) throws -> String {
        let headerBase64 = header.base64URLEncodedString()
        let payloadBase64 = payload.base64URLEncodedString()

        let signingInput = "\(headerBase64).\(payloadBase64)"
        guard let signingInputData = signingInput.data(using: .utf8) else {
            throw NSError(domain: "JWTError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Failed to create signing input data"])
        }

        let signature = try key.signature(for: signingInputData).rawRepresentation
        let signatureBase64 = signature.base64URLEncodedString()

        return "\(signingInput).\(signatureBase64)"
    }

    static func decode(token: String) throws -> (header: [String: Any], payload: CredentialJWT) {
        let parts = token.components(separatedBy: ".")
        guard parts.count == 3 else {
            throw NSError(domain: "JWTError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Invalid JWT format"])
        }

        let headerBase64 = parts[0]
        let payloadBase64 = parts[1]
        let signatureBase64 = parts[2]

        guard let headerData = Data(base64Encoded: headerBase64.base64urlToBase64()),
              let payloadData = Data(base64Encoded: payloadBase64.base64urlToBase64()),
              let signatureData = Data(base64Encoded: signatureBase64.base64urlToBase64()) else {
            throw NSError(domain: "JWTError", code: 2, userInfo: [NSLocalizedDescriptionKey: "Failed to decode base64URL data"])
        }

        let signingInput = "\(headerBase64).\(payloadBase64)"
        guard let signingInputData = signingInput.data(using: .utf8) else {
            throw NSError(domain: "JWTError", code: 3, userInfo: [NSLocalizedDescriptionKey: "Failed to create signing input data"])
        }
        guard let header = try JSONSerialization.jsonObject(with: headerData, options: []) as? [String: Any],
              let payload = try? JSONDecoder().decode(CredentialJWT.self, from: payloadData) else {
            throw NSError(domain: "JWTError", code: 4, userInfo: [NSLocalizedDescriptionKey: "Failed to parse JSON data"])
        }
        let did = payload.iss
        guard let publicKey = readDidKey(did: did) else {
            throw NSError(domain: "JWTError", code: 4, userInfo: [NSLocalizedDescriptionKey: "Failed to parse signature key"])
        }

        guard publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: signatureData), for: signingInputData) else {
            throw NSError(domain: "JWTError", code: 6, userInfo: [NSLocalizedDescriptionKey: "Invalid signature"])
        }
        return (header: header, payload: payload)
    }
}
