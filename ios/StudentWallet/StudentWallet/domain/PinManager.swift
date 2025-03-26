//
//  PinManager.swift
//  Student Wallet
//
//  Created by Timo Oeltze on 05.12.24.
//

import Foundation

class PinManager {
    static let shared = PinManager()
    private let pinKey = "sutdentWalletAppPin"  //key for the pin in the keychain
    private let keychain = KeychainWrapper.shared

    private init() {}

    //only allows to save the pin once
    func savePin(_ pin: String) throws {
        do {
            _ = try keychain.getString(forKey: pinKey)
            throw KeychainError.duplicateItem(errSecDuplicateItem)
        } catch KeychainError.itemNotFound {
            try keychain.addString(pin, forKey: pinKey)
        }
    }

    func checkPin(_ pin: String) -> Bool {
        let savedPin = try? keychain.getString(forKey: pinKey)
        return savedPin == pin
    }

    /**
        Deletes the pin from the keychain
        - shoud only be called when setting a new pin the first time to garantuee to set a new pin (reinstalled all)
     */
    func deletePin() {
        do {
            try keychain.deleteString(forKey: pinKey)
        } catch {
            //do nothing
        }
    }

    /**
        Deletes all data from the keychain
        - only used to reset the app
     */
    func deleteAllData() throws {
        deletePin()
        try KeychainWrapper.shared.deleteAll()
    }

    func isPinSet() -> Bool {
        do {
            _ = try keychain.getString(forKey: pinKey)
            return true
        } catch {
            return false
        }
    }
}
