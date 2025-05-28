//
//  CrdentialFormat.swift
//  StudentWallet
//
//  Created by Anders Hausding on 28.11.24.
//

enum CredentialFormat: String, Codable {
    case jwtVC = "jwt_vc"
    case jwtVCJson = "jwt_vc_json"
    case ldpVC = "ldp_vc"
    case bbsVC = "bbs+_vc"
}
