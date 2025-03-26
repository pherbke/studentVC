//
//  Student_WalletApp.swift
//  Student Wallet
//
//  Created by Anders Hausding on 15.11.24.
//

import SwiftUI

@main
struct Student_WalletApp: App {
    @ObservedObject var router = Router()
#if SKIP_AUTH
    @State private var isAuthentificated = true
    @State private var isPinSet = true
#else
    @State private var isAuthentificated = false
    @State private var isPinSet = PinManager.shared.isPinSet()
#endif
    @Environment(\.scenePhase) var scenePhase
    @State private var previousScenePhase: ScenePhase?
    
    @State private var showErrorAlert = false
    @State private var errorMessage: String = ""
    
    
    var body: some Scene {
        WindowGroup {
            if isAuthentificated {
                NavigationStack(path: $router.navPath) {
                    ContentView()
                        .navigationDestination(for: RouterDestination.self) {
                            destination in
                            switch destination {
                            case .qrScanner(let action):
                                QrScannerView(
                                    viewModel: QrScannerViewModel(
                                        action: action)
                                )
                            case .detail(let cardID):
                                if let viewModel = CardDetailViewModel(cardID: cardID) {
                                    CardDetailView(
                                        viewModel: viewModel
                                    )
                                } else {
                                    CardErrorView()
                                }
                            }
                        }
                }
                .environmentObject(router)
                .onChange(of: scenePhase) { scenePhase in
                    if scenePhase == .background {
                        isAuthentificated = false
                    }
                }
                .onReceive(CardManager.shared.errorPublisher) { error in
                    guard let error = error else { return }
                    errorMessage = error.errorDescription ?? "An unknown error occurred."
                    showErrorAlert = true
                    CardManager.shared.errorPublisher.send(nil) // Reset the error event
                }
                .alert(isPresented: $showErrorAlert) {
                    Alert(
                        title: Text("Error"),
                        message: Text(errorMessage),
                        dismissButton: .default(Text("OK"))
                    )
                }
            } else {
                if isPinSet {
                    AuthentificationView(
                        isAuthentificated: $isAuthentificated,
                        isPinSet: $isPinSet)
                } else {
                    SetPinView(isPinSet: $isPinSet)
                }
            }
        }
#if !SKIP_AUTH
        .onChange(of: isPinSet) { isPinSet in
            if !isPinSet {
                // If the PIN has been reset, switch to SetPinView
                isAuthentificated = false
            }
        }
#endif
    }
}
