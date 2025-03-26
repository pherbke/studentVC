//
//  KeychainWrapper.swift
//  StudentWallet
//
//  Created by Timo Oeltze on 20.11.24.
//

import Foundation

enum KeychainError: Error, Equatable {
    case itemNotFound  //not found in keychain and no code needet because of static error value
    case unexpectedData
    case conversionError
    case unableToSave(OSStatus)
    case unableToDelete(OSStatus)
    case unableToUpdate(OSStatus)
    case duplicateItem(OSStatus)
    case unknownError(OSStatus)
}

// used to store keys and the app pin
class KeychainWrapper {
    //singleton holder
    public static let shared = KeychainWrapper()
    private let serviceName: String = "studentWalletChain"

    private init() {}

    //----------------------- main wrapper functions -----------------------
    private func add(_ data: Data, forKey key: String) throws {
        var query = baseQuery(forKey: key)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked

        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            throw KeychainError.duplicateItem(status)
        } else if status != errSecSuccess {
            throw KeychainError.unableToSave(status)
        }
    }

    private func update(_ data: Data, forKey key: String, addIfNotFound: Bool = false) throws {
        let query = baseQuery(forKey: key)
        let attributesToUpdate = [kSecValueData as String: data]

        let status = SecItemUpdate(
            query as CFDictionary, attributesToUpdate as CFDictionary)
        if status == errSecItemNotFound {
            if addIfNotFound {
                try add(data, forKey: key)
            } else {
                throw KeychainError.itemNotFound
            }
        } else if status != errSecSuccess {
            throw KeychainError.unableToUpdate(status)
        }
    }

    private func get(forKey key: String) throws -> Data {
        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess {
            guard let data = item as? Data else {
                throw KeychainError.unexpectedData
            }
            return data
        } else if status == errSecItemNotFound {
            throw KeychainError.itemNotFound
        } else {
            throw KeychainError.unknownError(status)
        }
    }

    private func delete(forKey key: String) throws {
        let query = baseQuery(forKey: key)
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound {
            throw KeychainError.itemNotFound
        } else if status != errSecSuccess {
            throw KeychainError.unableToDelete(status)
        }
    }

    private func baseQuery(forKey key: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,  // Type of element to save
            kSecAttrService as String: serviceName,  // Service-Name
            kSecAttrAccount as String: key,
        ]
    }

    //----------------------- functions for strings -----------------------
    func addString(_ string: String, forKey key: String) throws {
        //convert String to Data
        guard let data = string.data(using: .utf8) else {
            throw KeychainError.unexpectedData
        }

        try add(data, forKey: key)
    }

    func updateString(_ string: String, forKey key: String, addIfNotFound: Bool = false) throws {
        guard let data = string.data(using: .utf8) else {
            throw KeychainError.unexpectedData
        }

        try update(data, forKey: key, addIfNotFound: addIfNotFound)
    }

    func getString(forKey key: String) throws -> String {
        let data = try get(forKey: key)
        guard let string = String(data: data, encoding: .utf8) else {
            throw KeychainError.unexpectedData
        }

        return string
    }

    func deleteString(forKey key: String) throws {
        try delete(forKey: key)
    }

    //----------------------- functions for JSON -----------------------
    func addJSON<T: Encodable>(_ json: T, forKey key: String) throws {
        let data = try JSONEncoder().encode(json)
        try add(data, forKey: key)
    }

    func updateJSON<T: Encodable>(_ json: T, forKey key: String, addIfNotFound: Bool = false) throws {
        let data = try JSONEncoder().encode(json)
        try update(data, forKey: key, addIfNotFound: addIfNotFound)
    }

    func getJSON<T: Decodable>(forKey key: String) throws -> T {
        let data = try get(forKey: key)
        return try JSONDecoder().decode(T.self, from: data)
    }

    func deleteJSON(forKey key: String) throws {
        try delete(forKey: key)
    }

    //----------------------- functions for Data (Bytes) -----------------------
    func addDataAsBytes(_ data: Data, forKey key: String) throws {
        try add(data, forKey: key)
    }

    func updateDataAsBytes(_ data: Data, forKey key: String, addIfNotFound: Bool = false) throws {
        try update(data, forKey: key, addIfNotFound: addIfNotFound)
    }

    func getDataAsBytes(forKey key: String) throws -> Data {
        return try get(forKey: key)
    }

    func deleteDataAsBytes(forKey key: String) throws {
        try delete(forKey: key)
    }
    
    func deleteAll() throws {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword]
        let status = SecItemDelete(query as CFDictionary)
        
        if status != errSecSuccess && status != errSecItemNotFound {
            throw KeychainError.unknownError(status)
        }
    }
}
