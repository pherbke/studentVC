//
//  AuthetificationView.swift
//  Student Wallet
//
//  Created by Timo Oeltze on 29.11.24.
//

import Foundation
import LocalAuthentication
import SwiftUI

struct AuthentificationView: View {
    @Binding var isAuthentificated: Bool
    @Binding var isPinSet: Bool
    
    @Environment(\.horizontalSizeClass) var hSizeClass
    
    @State private var authentificationFailed: Bool = false
    @State private var errorMessage: String?
    @State private var showAlert: Bool = false
    @State private var activeAlert: Alert? = nil
    @State private var showPinEntry: Bool = false
    @State private var biometricAttempts = 0
    @State private var pinAttempts = 0
    @State private var enteredPin: String = ""
    @State private var showResetButton: Bool = false

    private let pinLength: Int = 6
    
    var body: some View {
        let isLargeLayout = (hSizeClass == .regular)
        
        VStack(spacing: isLargeLayout ? 24 : 16) {
            Spacer()
            
            Image(systemName: "lock.shield.fill")
                .resizable()
                .scaledToFit()
                .frame(maxWidth: isLargeLayout ? 300 : 200)
                .foregroundColor(.accentColor)
                .padding(.horizontal)
            
            Text("Student Wallet")
                .font(.title3)
                .fontWeight(.bold)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            
            Text("Please authenticate yourself to unlock your wallet.")
                .font(.headline)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
                .lineLimit(nil)
                .fixedSize(horizontal: false, vertical: true)
            
            // PIN Display (Dots)
            HStack(spacing: 15) {
                ForEach(0..<pinLength, id: \.self) { index in
                    Circle()
                        .stroke(Color.primary, lineWidth: 2)
                        .frame(width: 20, height: 20)
                        .overlay(
                            Circle().fill(
                                enteredPin.count > index
                                ? Color.accentColor : Color.clear
                            )
                        )
                }
            }
            .padding(.horizontal, 40)
            
            // Error Message or Reset Button
            if showResetButton {
                Button("Want to reset the PIN?") {
                    activeAlert = Alert(
                        title: Text("Reset App PIN"),
                        message: Text(
                            "Do you really want to reset your app pin? This will automatically delete all your data stored in the wallet."
                        ),
                        primaryButton: .destructive(Text("Yes")) {
                            showAlert = false
                            resetAppData()
                        },
                        secondaryButton: .cancel(Text("No"))
                    )
                    showAlert = true
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .font(.subheadline)
            } else if let errorMessage = errorMessage {
                Text(errorMessage)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                    .lineLimit(nil)
                    .fixedSize(horizontal: false, vertical: true)
            }
            
            Spacer()
            
            // Numeric Keypad
            NumericKeypad(
                pin: $enteredPin,
                onDelete: deleteLast,
                onEnter: handlePinEnter,
                spacingRatio: 0.1,
                buttonScaleFactor: 1.0,
                buttonSize: isLargeLayout ? 100 : 80,
                pinLength: pinLength
            )
            .padding(.horizontal)
            
            Spacer()
        }
        .padding()
        .onAppear {
            authenticateUser()
        }
        .alert(isPresented: $showAlert) {
            activeAlert!
        }
    }
    
    func authenticateUser() {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &error)
        {
            let reason = "Please authenticate yourself.."
            
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { success, authenticationError in
                DispatchQueue.main.async {
                    if success {
                        // Successful biometric authentication
                        self.isAuthentificated = true
                    } else {
                        // Biometric authentication failed
                        self.biometricAttempts += 1
                        if self.biometricAttempts >= 2 {
                            // After 2 failed attempts, show PIN entry
                            self.showPinEntry = true
                            self.errorMessage =
                            "Biometric authentication failed. Please enter your App PIN."
                        } else {
                            self.errorMessage =
                            "Biometric authentication failed. Attempts left: \(2 - self.biometricAttempts)"
                        }
                        self.authentificationFailed = true
                    }
                }
            }
        } else {
            // Biometric authentication not available, show PIN entry
            DispatchQueue.main.async {
                self.showPinEntry = true
                self.errorMessage = "Biometric authentication is not available."
            }
        }
    }
    
    func checkPin() {
        if PinManager.shared.checkPin(enteredPin) {
            self.isAuthentificated = true
        } else {
            self.pinAttempts += 1
            if self.pinAttempts >= 3 {
                // After 3 failed attempts, display the reset button instead of the error message
                self.errorMessage = nil
                self.showResetButton = true
            } else {
                let remaining = 3 - pinAttempts
                self.errorMessage =
                "Incorrect PIN. You have \(remaining) attempts left."
            }
            self.authentificationFailed = true
            self.enteredPin = ""
        }
    }
    
    func handlePinEnter() {
        if enteredPin.count == pinLength {
            if PinManager.shared.checkPin(enteredPin) {
                self.isAuthentificated = true
            } else {
                self.pinAttempts += 1
                if self.pinAttempts >= 3 {
                    // After 3 failed attempts, display the reset button instead of the error message
                    self.errorMessage = nil
                    self.showResetButton = true
                } else {
                    let remaining = 3 - pinAttempts
                    self.errorMessage =
                    "Incorrect PIN. You have \(remaining) attempts left."
                }
                self.enteredPin = ""
            }
        }
    }
    
    func deleteLast() {
        if !enteredPin.isEmpty {
            enteredPin.removeLast()
        }
    }
    
    func resetAppData() {
        do {
            try PinManager.shared.deleteAllData()
            self.isAuthentificated = false
            self.isPinSet = false
            self.showPinEntry = false
            self.enteredPin = ""
            self.errorMessage = nil
            self.showResetButton = false
        } catch {
            activeAlert = Alert(
                title: Text("Error"),
                message: Text("An error occurred while resetting the app: \(error.localizedDescription)"),
                dismissButton: .default(Text("Ok")) {
                    showAlert = false
                }
            )
            showAlert = true
        }
    }
}

struct AuthenticationView_Previews: PreviewProvider {
    static var previews: some View {
        AuthentificationView(
            isAuthentificated: .constant(false), isPinSet: .constant(true))
    }
}
