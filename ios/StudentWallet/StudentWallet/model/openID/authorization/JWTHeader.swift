//
//  IDTokenHeader.swift
//  StudentWallet
//
//  Created by Anders Hausding on 02.12.24.
//

struct JWTHeader: Codable {
    let alg: String
    let typ: String
}
