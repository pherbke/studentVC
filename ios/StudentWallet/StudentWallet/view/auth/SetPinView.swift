//
//  SetPinView.swift
//  Student Wallet
//
//  Created by Timo Oeltze on 05.12.24.
//

import Foundation
import SwiftUI

let pinLength: Int = 6

//Adjustment of the centring by ChatGPT
struct SetPinView: View {
    @State private var pin: String = ""
    @State private var confirmPin: String = ""
    @State private var isConfirming: Bool = false
    @State private var errorMessage: String?
    @Binding var isPinSet: Bool
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(alignment: .center, spacing: 30) {
            Spacer()

            Text(isConfirming ? "Confirm your PIN" : "Enter Passcode")
                .font(.title2)
                .fontWeight(.semibold)
                .multilineTextAlignment(.center)
                .foregroundColor(.primary)
                .frame(width: UIScreen.main.bounds.width * 0.5, height: UIScreen.main.bounds.width * 0.2)


            HStack(spacing: 20) {
                ForEach(0..<pinLength, id: \.self) { index in
                    Circle()
                        .fill(
                            index < getCurrentInput().count
                                ? Color.primary : Color.clear
                        )
                        .frame(width: 15, height: 15)
                        .overlay(
                            Circle().stroke(Color.primary, lineWidth: 1.5)
                        )
                }
            }

            if let errorMessage = errorMessage {
                Text(errorMessage)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }

            NumericKeypad(
                pin: isConfirming ? $confirmPin : $pin,
                onDelete: deleteLast,
                onEnter: handleEnter,
                spacingRatio: 0.1,
                buttonScaleFactor: 1.0,
                buttonSize: 90,
                pinLength: pinLength
            )
            .frame(maxHeight: .infinity, alignment: .bottom)

        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // Get the current input (either PIN or confirmation PIN)
    private func getCurrentInput() -> String {
        return isConfirming ? confirmPin : pin
    }

    private func handleEnter() {
        if isConfirming {
            // Confirm the PIN
            if pin == confirmPin {
                do {
                    try PinManager.shared.savePin(pin)
                    isPinSet = true
                    navigateToMainView()
                } catch {
                    errorMessage = "Failed to save the PIN. Please try again."
                }
            } else {
                // PINs do not match
                errorMessage = "The PINs do not match. Please try again."
                resetInput()
            }
        } else if pin.count == pinLength {
            // Proceed to confirmation phase
            isConfirming = true
        }
    }

    // Delete the last entered digit
    private func deleteLast() {
        if isConfirming && !confirmPin.isEmpty {
            confirmPin.removeLast()
        } else if !pin.isEmpty {
            pin.removeLast()
        }
    }

    // Reset the input fields
    private func resetInput() {
        pin = ""
        confirmPin = ""
        isConfirming = false
    }

    // Navigate to the main view
    private func navigateToMainView() {
        presentationMode.wrappedValue.dismiss()
    }
}

// Define keypad buttons
enum KeypadButton: Hashable {
    case number(Int)
    case delete
    case blank

    var label: String {
        switch self {
        case .number(let value):
            return "\(value)"
        case .delete:
            return "⌫"
        case .blank:
            return ""
        }
    }

    var backgroundColor: Color {
        switch self {
        case .delete:
            return Color(UIColor.secondarySystemBackground)
        case .blank:
            return Color.clear
        default:
            return Color(UIColor.secondarySystemBackground)
        }
    }

    var textColor: Color {
        switch self {
        case .delete:
            return .accentColor
        case .blank:
            return .clear
        default:
            return .primary
        }
    }
}
