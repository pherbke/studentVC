//
//  KeychainTest.swift
//  Student WalletTests
//
//  Created by Timo Oeltze on 21.11.24.
//

import XCTest
@testable import Student_Wallet

//Testfälle teils unter Hilfe von ChatGPT erstellt
final class KeychainTest: XCTestCase {
    
    func testAddStringSuccess() throws {
        let key = "testStringKey"
        let value = "TestStringValue"

        // Versuche, den String hinzuzufügen
        XCTAssertNoThrow(try KeychainWrapper.shared.addString(value, forKey: key))

        // Überprüfe, ob der String korrekt gespeichert wurde
        let storedValue = try KeychainWrapper.shared.getString(forKey: key)
        XCTAssertEqual(storedValue, value)

        // Bereinige den Keychain-Eintrag
        try KeychainWrapper.shared.deleteString(forKey: key)
    }

    func testAddStringFailure() throws {
        let key = "testStringKey"
        let value = "TestStringValue"

        // Füge den String zum ersten Mal hinzu
        try KeychainWrapper.shared.addString(value, forKey: key)

        // Versuche, den gleichen String erneut hinzuzufügen, was zu einem Fehler führen sollte
        XCTAssertThrowsError(try KeychainWrapper.shared.addString(value, forKey: key)) { error in
            XCTAssertEqual(error as? KeychainError, KeychainError.duplicateItem(errSecDuplicateItem))
        }

        // Bereinige den Keychain-Eintrag
        try KeychainWrapper.shared.deleteString(forKey: key)
    }

    func testUpdateStringSuccess() throws {
        let key = "testStringKey"
        let initialValue = "InitialValue"
        let updatedValue = "UpdatedValue"

        // Füge den initialen String hinzu
        try KeychainWrapper.shared.addString(initialValue, forKey: key)

        // Aktualisiere den String
        XCTAssertNoThrow(try KeychainWrapper.shared.updateString(updatedValue, forKey: key))

        // Überprüfe, ob der String aktualisiert wurde
        let storedValue = try KeychainWrapper.shared.getString(forKey: key)
        XCTAssertEqual(storedValue, updatedValue)

        // Bereinige den Keychain-Eintrag
        try KeychainWrapper.shared.deleteString(forKey: key)
    }

    func testUpdateStringFailure() throws {
        let key = "nonExistentKey"
        let value = "Value"

        // Versuche, einen nicht existierenden Key zu aktualisieren
        XCTAssertThrowsError(try KeychainWrapper.shared.updateString(value, forKey: key)) { error in
            XCTAssertEqual(error as? KeychainError, KeychainError.itemNotFound)
        }
    }

    func testGetStringFailure() throws {
        let key = "nonExistentKey"

        // Versuche, einen String für einen nicht existierenden Key abzurufen
        XCTAssertThrowsError(try KeychainWrapper.shared.getString(forKey: key)) { error in
            XCTAssertEqual(error as? KeychainError, KeychainError.itemNotFound)
        }
    }

    func testDeleteStringSuccess() throws {
        let key = "testStringKey"
        let value = "TestValue"

        // Füge den String hinzu
        try KeychainWrapper.shared.addString(value, forKey: key)

        // Lösche den String
        XCTAssertNoThrow(try KeychainWrapper.shared.deleteString(forKey: key))

        // Überprüfe, ob der String gelöscht wurde
        XCTAssertThrowsError(try KeychainWrapper.shared.getString(forKey: key)) { error in
            XCTAssertEqual(error as? KeychainError, KeychainError.itemNotFound)
        }
    }

    func testDeleteStringFailure() throws {
        let key = "nonExistentKey"

        // Versuche, einen nicht existierenden Key zu löschen
        XCTAssertThrowsError(try KeychainWrapper.shared.deleteString(forKey: key)) { error in
            XCTAssertEqual(error as? KeychainError, KeychainError.itemNotFound)
        }
    }
}
