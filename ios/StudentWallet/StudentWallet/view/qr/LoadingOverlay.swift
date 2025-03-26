//
//  LoadingOverlay.swift
//  StudentWallet
//
//  Created by Anders Hausding on 23.01.25.
//
import SwiftUI

struct LoadingOverlay: View {
    @Binding var isActive: Bool
    @Binding var title: String
    @Binding var message: String

    var body: some View {
        Group {
            if isActive {
                HStack {
                    Spacer()
                    VStack(alignment: .center) {
                        Spacer()
                        VStack {
                            Text(title)
                                .font(.title2)
                                .bold()
                            Text(message)
                            ProgressView()
                        }
                        .padding()
                        .background(
                            Color(.systemBackground)
                                .cornerRadius(16)
                        )
                        Spacer()
                    }
                    Spacer()
                }
                .background(Color.black.opacity(0.5))
            }
        }
    }
}

#Preview() {
    LoadingOverlay(
        isActive: .constant(true),
        title: .constant("Title"),
        message: .constant("Message")
    )
}
