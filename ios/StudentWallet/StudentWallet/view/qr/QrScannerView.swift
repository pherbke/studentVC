//
//  QrScannerView.swift
//  Student Wallet
//
//  Created by Timo Oeltze on 18.11.24.
//

import SwiftUI

enum QRCodeAction: Codable, Comparable, Hashable {
    case issuance
    case presentation(id: String)
    
    static func == (lhs: QRCodeAction, rhs: QRCodeAction) -> Bool {
        switch (lhs, rhs) {
        case (.issuance, .issuance):
            return true
        case (.presentation, .presentation):
            return true
        default:
            return false
        }
    }
}

class QrScannerViewModel: ObservableObject {
    @Published var scannedCode: String?
    @Published var foundCode: Bool = false
    @Published var alert: Alert? = nil
    @Published var displayAlert: Bool = false
    @Published var activePresentationSheet: PresentationSheet? = nil
    @Published var displayPresentationSheet: Bool = false
    @Published var displayLoadingOverlay: Bool = false
    @Published var overlayTitle: String = ""
    var action: QRCodeAction
    
    init(action: QRCodeAction) {
        self.action = action
    }
    
    func onScannedCode(router: Router) {
        switch action {
        case .issuance:
            alert = createIssuanceDialog(router: router)
        case .presentation(let cardID):
            alert = createPresentationRequestDialog(
                cardID: cardID,
                router: router
            )
        }
        displayAlert = true
    }
    
    func createIssuanceDialog(router: Router) -> Alert {
        Alert(
            title: Text("Found Offer URL"),
            message: Text(scannedCode ?? "Error"),
            primaryButton: .default(
                Text("Start Issuance"),
                action: {
                    Task {
                        guard let scannedCode = self.scannedCode else {
                            await MainActor.run {
                                self.showAlert(
                                    "Invalid QR Code",
                                    "No scanned code available."
                                ) {
                                    router.navigateBack()
                                }
                            }
                            return
                        }
                        await MainActor.run {
                            self.overlayTitle = "Issuance in Progress"
                            self.displayLoadingOverlay = true
                        }
                        let issuanceResult = await CardManager.shared.requestIssuance(
                            credentialOfferUri: scannedCode
                        ).result
                        await MainActor.run {
                            self.displayLoadingOverlay = false
                        }
                        switch issuanceResult {
                        case .success(let result):
                            switch result {
                            case .Success(let card):
                                do {
                                    try await MainActor.run {
                                        try CardManager.shared.addCard(card: card)
                                        router.navigateBack()
                                    }
                                } catch {
                                    await MainActor.run {
                                        self.showAlert(
                                            "Issuance Error",
                                            "Error during issuance: \(error.localizedDescription)"
                                        ) {
                                            router.navigateBack()
                                        }
                                    }
                                }
                                
                            case .Cancelled:
                                return
                            case .InvalidResponse(let error):
                                await MainActor.run {
                                    self.showAlert(
                                        "Issuance Error",
                                        "Invalid response from backend: \(error)"
                                    ) {
                                        router.navigateBack()
                                    }
                                }
                            case .BackendError(let code):
                                await MainActor.run {
                                    self.showAlert(
                                        "Issuance Error",
                                        "Unexpected Backend error code during issuance: \(code)"
                                    ) {
                                        router.navigateBack()
                                    }
                                }
                            case .Error(let error):
                                await MainActor.run {
                                    self.showAlert(
                                        "Issuance Error",
                                        "Error during issuance: \(error)"
                                    ) {
                                        router.navigateBack()
                                    }
                                }
                            }
                        case .failure(let error):
                            await MainActor.run {
                                self.showAlert(
                                    "Issuance Error",
                                    "Error during issuance: \(error)"
                                ) {
                                    router.navigateBack()
                                }
                            }
                        }
                    }
                }
            ),
            secondaryButton: .cancel {
                router.navigateBack()
            }
        )
    }
    
    func createPresentationRequestDialog(cardID: String, router: Router) -> Alert {
        Alert(
            title: Text("Found Presentation URL"),
            message: Text(scannedCode ?? "Error"),
            primaryButton: .default(
                Text("Request Presentation Fields"),
                action: {
                    Task {
                        guard let scannedCode = self.scannedCode else {
                            self.showAlert(
                                "Invalid QR Code",
                                "No scanned code available."
                            ) {
                                router.navigateBack()
                            }
                            return
                        }
                        await MainActor.run {
                            self.overlayTitle = "Requesting Presentation Fields"
                            self.displayLoadingOverlay = true
                        }
                        let fieldsResult = await requestPresentationDefinition(presentationURI: scannedCode).result
                        await MainActor.run {
                            self.displayLoadingOverlay = false
                        }
                        switch fieldsResult {
                        case .success(let result):
                            switch result {
                            case .Success((let presentationURI, let presentationDefinition)):
                                await MainActor.run { [weak self] in
                                    guard let self = self else { return }
                                    self.displayAlert = false
                                    createPresentationDialog(
                                        cardID: cardID,
                                        router: router,
                                        presentationURI: presentationURI,
                                        presentationDefinition: presentationDefinition
                                    )
                                }
                            case .Cancelled:
                                return
                            case .InvalidResponse(let error):
                                await MainActor.run {
                                    self.showAlert(
                                        "Presentation Definition Error",
                                        "Invalid response from backend: \(error)"
                                    ) {
                                        router.navigateBack()
                                    }
                                }
                            case .BackendError(let code):
                                await MainActor.run {
                                    self.showAlert(
                                        "Presentation Definition Error",
                                        "Unexpected Backend error code during presentation definition: \(code)"
                                    ) {
                                        router.navigateBack()
                                    }
                                }
                            case .Error(let error):
                                await MainActor.run {
                                    self.showAlert(
                                        "Presentation Definition Error",
                                        "Error during presentation definition: \(error)"
                                    ) {
                                        router.navigateBack()
                                    }
                                }
                            }
                        case .failure(let error):
                            await MainActor.run {
                                self.showAlert(
                                    "Presentation Definition Error",
                                    "Error during presentation: \(error)"
                                ) {
                                    router.navigateBack()
                                }
                            }
                        }
                    }
                }
            ),
            secondaryButton: .cancel {
                router.navigateBack()
            }
        )
    }
    
    func createPresentationDialog(cardID: String, router: Router, presentationURI: URL, presentationDefinition: PresentationDefinition) {
        activePresentationSheet = PresentationSheet(
            fieldInfos: presentationDefinition.getFields(),
            onPresent: {
                self.hidePresentationSheet()
                Task {
                    do {
                        await MainActor.run {
                            self.overlayTitle = "Presentation in Progress"
                            self.displayLoadingOverlay = true
                        }
                        let presentationResult = try await CardManager.shared.presentCard(
                            credentialPresentationUri: presentationURI,
                            presentationDefinition: presentationDefinition,
                            cardID: cardID
                        ).result
                        await MainActor.run {
                            self.displayLoadingOverlay = false
                        }
                        switch presentationResult {
                        case .success(let result):
                            switch result {
                            case .Success(let validPresentation):
                                await MainActor.run { [weak self] in
                                    guard let self = self else { return }
                                    let title: String
                                    let message: String
                                    if validPresentation {
                                        title = "Presentation Success"
                                        message = "Card has been successfully presented"
                                    } else {
                                        title = "Presentation Failed"
                                        message = "Card is not valid"
                                    }
                                    showAlert(
                                        title,
                                        message,
                                        onDismiss: {
                                            router.navigateBack()
                                        }
                                    )
                                }
                            case .Cancelled:
                                return
                            case .InvalidResponse(let error):
                                await MainActor.run {
                                    self.showAlert(
                                        "Presentation Error",
                                        "Invalid response from backend: \(error)",
                                        onDismiss: {
                                            router.navigateBack()
                                        }
                                    )
                                }
                            case .BackendError(let code):
                                await MainActor.run { [weak self] in
                                    guard let self = self else { return }
                                    let title: String
                                    let message: String
                                    if code == 401 {
                                        title = "Presentation Failed"
                                        message = "Card is not valid"
                                    } else {
                                        title = "Presentation Error"
                                        message = "Unexpected Backend error code during presentation: \(code)"
                                    }
                                    showAlert(
                                        title,
                                        message,
                                        onDismiss: {
                                            router.navigateBack()
                                        }
                                    )
                                }
                            case .Error(let error):
                                await MainActor.run {
                                    self.showAlert(
                                        "Presentation Error",
                                        "Error during presentation: \(error)",
                                        onDismiss: {
                                            router.navigateBack()
                                        }
                                    )
                                }
                            }
                        case .failure(let error):
                            await MainActor.run {
                                self.showAlert(
                                    "Presentation Error",
                                    "Error during presentation: \(error)",
                                    onDismiss: {
                                        router.navigateBack()
                                    }
                                )
                            }
                        }
                    } catch {
                        await MainActor.run {
                            self.showAlert(
                                "Unexpected storage error",
                                "An unexpected error occurred: \(error.localizedDescription)",
                                onDismiss: {
                                    router.navigateBack()
                                }
                            )
                        }
                    }
                }
            },
            onCancel: {
                self.hidePresentationSheet()
                router.navigateBack()
            }
        )
        displayPresentationSheet = true
    }
    
    private func hidePresentationSheet() {
        self.displayPresentationSheet = false
        self.activePresentationSheet = nil
        
    }
    
    func showAlert(_ title: String, _ message: String, onDismiss: (() -> Void)? = nil) {
        showAlert(
            alert: Alert(
                title: Text(title),
                message: Text(message),
                dismissButton: .default(Text("OK")) {
                    onDismiss?()
                }
            )
        )
    }
    
    func showAlert(alert: Alert) {
        self.displayAlert = false
        self.alert = alert
        self.displayAlert = true
    }
}

struct QrScannerView: View {
    @EnvironmentObject var router: Router
    @StateObject var viewModel: QrScannerViewModel
    @State private var showErrorAlert: Bool = false
    
    var body: some View {
        QrScanner { type, url, fullString in
            // Determine the action based on QR code type
            if type != viewModel.action {
                viewModel.showAlert(
                    "Invalid QR Code",
                    "The scanned QR code does not match the expected type."
                ) {
                    router.navigateBack()
                }
                return
            } else {
                // Process the returned data
                viewModel.scannedCode = fullString
                viewModel.onScannedCode(router: router)
            }
        }
        .alert(isPresented: $viewModel.displayAlert) {
            viewModel.alert!
        }.sheet(isPresented: $viewModel.displayPresentationSheet) {
            viewModel.activePresentationSheet!
                .interactiveDismissDisabled()
        }
        .overlay {
            LoadingOverlay(
                isActive: $viewModel.displayLoadingOverlay,
                title: $viewModel.overlayTitle,
                message: .constant("Please Wait...")
            )
        }
    }
}

#Preview {
    QrScannerView(
        viewModel: QrScannerViewModel(
            action: .issuance
        )
    )
    .environmentObject(Router())
}
