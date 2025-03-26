//
//  Router.swift
//  Student Wallet
//
//  Created by Anders Hausding on 15.11.24.
//
import SwiftUI

final class Router: ObservableObject {
    @Published var navPath = NavigationPath()

    func navigate(to destination: RouterDestination) {
        navPath.append(destination)
    }

    func navigateBack() {
        navPath.removeLast()
    }
}
