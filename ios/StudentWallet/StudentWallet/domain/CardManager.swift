//
//  CardManager.swift
//  StudentWallet
//
//  Created by Anders Hausding on 14.12.24.
//
import Foundation
import CryptoKit
import Combine

enum CardManagerError: LocalizedError {
    case privateKeyGenerationFailed(String)
    case cardNotFound(String)
    case cardAlreadyPresent(String)
    case unableToStoreCard(String)
    case unableToLoadCards(String)
    case unableToLoadPrivateKey(String)
    case unableToStorePrivateKey(String)
    case unableToDeleteCard(String)
    case unexpectedStorageError(String)
    
    var errorDescription: String? {
        switch self {
        case .privateKeyGenerationFailed(let message):
            return "Failed to generate private key: \(message)"
        case .cardNotFound(let message):
            return "Card not found: \(message)"
        case .cardAlreadyPresent(let message):
            return "Card already exists: \(message)"
        case .unableToStoreCard(let message):
            return "Failed to store card: \(message)"
        case .unableToLoadCards(let message):
            return "Failed to load cards: \(message)"
        case .unableToLoadPrivateKey(let message):
            return "Failed to load private key: \(message)"
        case .unableToStorePrivateKey(let message):
            return "Failed to store private key: \(message)"
        case .unableToDeleteCard(let message):
            return "Failed to delete card: \(message)"
        case .unexpectedStorageError(let message):
            return "Unexpected storage error: \(message)"
        }
    }
}

class CardManager: ObservableObject {
    public static let shared = CardManager()
    @Published var cards: [CredentialData]
    private var privateKey: P256.Signing.PrivateKey
    let errorPublisher = CurrentValueSubject<CardManagerError?, Never>(nil)

    private init() {
        guard let privateKeyBytes = try? KeychainWrapper.shared.getDataAsBytes(forKey: Constants.keychainKeysKey),
              let privateKey = try? P256.Signing.PrivateKey(rawRepresentation: privateKeyBytes) else {
            self.privateKey = generateKey()
            do {
                try? KeychainWrapper.shared.deleteJSON(forKey: Constants.keychainCardsKey) // we cant do anything if this fails
                try KeychainWrapper.shared.updateDataAsBytes(
                    privateKey.rawRepresentation,
                    forKey: Constants.keychainKeysKey,
                    addIfNotFound: true
                )
                print("Generated and stored new private key.")
            } catch let error {
                let error = CardManagerError.unableToStorePrivateKey(error.localizedDescription)
                print(error.localizedDescription)
                errorPublisher.send(error)
            }
            self.cards = []
            return
        }
        self.privateKey = privateKey
        do {
            self.cards = try KeychainWrapper.shared.getJSON(forKey: Constants.keychainCardsKey)
            print("Loaded cards: \(self.cards)")
        } catch let error as KeychainError {
            switch error {
            case .itemNotFound:
                // Its okay if there is nothing.
                break
            default:
                let cardError = CardManagerError.unableToLoadCards(error.localizedDescription)
                print(cardError.localizedDescription)
                errorPublisher.send(cardError)
            }
            self.cards = []
        } catch {
            let unexpectedError = CardManagerError.unexpectedStorageError(error.localizedDescription)
            print(unexpectedError.localizedDescription)
            errorPublisher.send(unexpectedError)
            self.cards = []
        }
    }
    
    func requestIssuance(credentialOfferUri: String) -> Task<RequestResult<CredentialData>, Error> {
        return requestCredentialIssuance(
            privateKey: privateKey,
            credentialOfferUri: credentialOfferUri
        )
    }
    
    func addCard(card: CredentialData) throws {
        cards.append(card)
        try storeCardsToKeychain()
    }
    

    func deleteCard(byID id: String) -> Bool {
        if let index = cards.firstIndex(where: { $0.jwt.vc.id == id }) {
            cards.remove(at: index)
            
            do {
                try storeCardsToKeychain()
                return true
            } catch {
                print("Error deleting card from keychain: \(error.localizedDescription)")
                return false
            }
        } else {
            print("Card with \(id) not found")
            return true
        }
    }
    
    func presentCard(credentialPresentationUri: URL, presentationDefinition: PresentationDefinition, cardID: String) throws -> Task<RequestResult<Bool>, Error> {
        guard let credentialData = cards.first(where: { $0.jwt.vc.id == cardID }) else {
            let error = CardManagerError.cardNotFound(cardID)
            print(error.localizedDescription)
            return Task { throw error }
        }
        
        return sendCredentialForPresentation(
            presentationURI: credentialPresentationUri,
            presentationDefinition: presentationDefinition,
            privateKey: privateKey,
            credentialData: credentialData
        )
    }
    
    private func storeCardsToKeychain() throws {
        do {
            try KeychainWrapper.shared.updateJSON(cards, forKey: Constants.keychainCardsKey, addIfNotFound: true)
        } catch let error as KeychainError {
            switch error {
            case .duplicateItem:
                throw CardManagerError.unableToStoreCard("Duplicate card found.")
            default:
                throw CardManagerError.unexpectedStorageError(error.localizedDescription)
            }
        } catch {
            throw CardManagerError.unexpectedStorageError(error.localizedDescription)
        }
    }
}
