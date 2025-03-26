//
//  PinKeypad.swift
//  Student Wallet
//
//  Created by Timo Oeltze on 07.12.24.
//

import Foundation
import SwiftUI

struct NumericKeypad: View {
    @Binding var pin: String
    var onDelete: () -> Void
    var onEnter: () -> Void
    let spacingRatio: CGFloat  //spacing buttons (default 0.08)
    let buttonScaleFactor: CGFloat  //scale buttons (default 1)
    let buttonSize: CGFloat // fixed button size
    let pinLength: Int

    private let buttons: [[KeypadButton]] = [
        [.number(1), .number(2), .number(3)],
        [.number(4), .number(5), .number(6)],
        [.number(7), .number(8), .number(9)],
        [.blank, .number(0), .delete],
    ]

    var body: some View {
        VStack(spacing: buttonSize * spacingRatio) {
            ForEach(buttons, id: \.self) { row in
                HStack(spacing: buttonSize * spacingRatio) {
                    ForEach(row, id: \.self) { button in
                        if button == .blank {
                            Rectangle()
                                .opacity(0)
                                .frame(width: buttonSize, height: buttonSize)
                        } else {
                            Button(action: {
                                handleButtonPress(button, pinLength: pinLength)
                            }) {
                                Text(button.label)
                                    .font(.title2)
                                    .fontWeight(.medium)
                                    .foregroundColor(button.textColor)
                                    .frame(
                                        width: buttonSize, height: buttonSize
                                    )
                                    .background(button.backgroundColor)
                                    .cornerRadius(buttonSize * 0.15)
                            }
                        }
                    }
                }
            }
        }
        .padding()
    }

    private func handleButtonPress(_ button: KeypadButton, pinLength: Int) {
        switch button {
        case .number(let value):
            if pin.count < pinLength {  // Maximum PIN length
                pin.append("\(value)")
            }
        case .delete:
            onDelete()
        case .blank:
            break
        }

        // Automatically trigger Enter when PIN length is reached
        if pin.count == pinLength {
            onEnter()
        }
    }
}
