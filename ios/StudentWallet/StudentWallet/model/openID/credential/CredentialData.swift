//
//  CredentialData.swift
//  StudentWallet
//
//  Created by Anders Hausding on 10.01.25.
//

struct CredentialData: Codable {
    let jwt: CredentialJWT
    let signature: String
    
    
}
