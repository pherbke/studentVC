//
//  CardErrorView.swift
//  StudentWallet
//
//  Created by Anders Hausding on 21.01.25.
//
import SwiftUI

struct CardErrorView: View {
    var body: some View {
        Text("Error loading Card Detail")
        .modifier(NavbarModifier())
        .toolbar {
            ToolbarItem(placement: .principal) {
                Text("Error")
                    .font(.title2)
                    .bold()
            }
        }
    }
}

#Preview {
    CardErrorView()
}
