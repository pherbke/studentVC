//
//  NavbarModifier.swift
//  StudentWallet
//
//  Created by Anders Hausding on 15.12.24.
//

import SwiftUI

struct NavbarModifier: ViewModifier {
    func body(content: Content) -> some View {
        content
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.visible, for: .navigationBar)
    }
}
