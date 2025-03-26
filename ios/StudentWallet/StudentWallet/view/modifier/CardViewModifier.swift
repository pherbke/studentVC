//
//  CardViewModifier.swift
//  StudentWallet
//
//  Created by Luzie on 05.12.24.
//

import SwiftUI

struct CardViewModifier: ViewModifier {
    var backgroundColor = Color(.systemBackground)
    var cornerRadius: CGFloat = 12
    func body(content: Content) -> some View {
        content
            .frame(maxWidth: .infinity)
            .background(backgroundColor)
            .cornerRadius(cornerRadius)
    }
}
