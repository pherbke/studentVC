//
//  RouterDestination.swift
//  Student Wallet
//
//  Created by Anders Hausding on 15.11.24.
//


enum RouterDestination: Codable, Hashable {
    case qrScanner(action: QRCodeAction)
    case detail(cardID: String)
}
