//
//  DIDGen.swift
//  StudentWallet
//
//  Created by Anders Hausding on 18.11.24.
//
import Foundation
import CryptoKit

//Most values here are static placeholder for now.

let didPrefix = "did:key:z"

func generateKey() -> P256.Signing.PrivateKey {
    return P256.Signing.PrivateKey()
}

func readDidKey(did: String) -> P256.Signing.PublicKey? {
    if !did.hasPrefix(didPrefix) {
        print("Did key has wrong prefix: \(did)")
        return nil
    }

    let key = String(did.dropFirst(didPrefix.count))
    guard let keyBytes = key.decodeBase58() else {
        print("Did key not base58 aligned")
        return nil
    }
    guard keyBytes[0] == 0x12 && keyBytes[1] == 0x0 else {
        print("Did key has wrong key type")
        return nil
    }
    guard let publicKey = try? P256.Signing.PublicKey(x963Representation: keyBytes[2...]) else {
        print("Did key is not valid public key")
        return nil
    }
    return publicKey
}

func generateDID(publicKey: P256.Signing.PublicKey) -> String {
    return "\(didPrefix)\(publicKey.x963Representation.base58EncodedString(keyTypePrefix: .publicKeyType))"
}

func generateSecureState() -> String {
    /**
     This implementation basically does the same thing as the code challenge generation
     Usually states are just random byte strings, that are not hashed, but why not hash it?
     If we dont hash our states, we could just use the same function for generating code verifier and state..
    **/
    var buffer = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
    let hash = SHA256.hash(data: buffer)
    return Data(hash).base64URLEncodedString()
}

func generateNonce() -> String {
    let nonce = AES.GCM.Nonce()
    let timestamp = UInt64(Date().timeIntervalSince1970)
    let timestampData = withUnsafeBytes(of: timestamp.bigEndian) { Data($0) }
    let combinedData = Data(nonce) + timestampData
    return combinedData.base64EncodedString()
}

func generateCodeVerifier() -> String {
    var buffer = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
    return Data(buffer).base64URLEncodedString()
}

func generateCodeChallenge(codeVerifier: String) -> String {
    let hash = SHA256.hash(data: Data(codeVerifier.utf8))
    return Data(hash).base64URLEncodedString()
}
