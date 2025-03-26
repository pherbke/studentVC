//
//  ContentView.swift
//  StudentWallet
//
//  Created by Luzie on 12.12.24.
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var router: Router
    @ObservedObject var cardManager = CardManager.shared
    @State private var errorMessage: String?
    @State private var showErrorAlert: Bool = false
    @State private var showDeleteAlert = false
 //   @State private var cancellables = Set<AnyCancellable>()
    @State private var selectedCardID: String?

    
    var body: some View {
        ZStack {
            List {
                ForEach(cardManager.cards, id: \.jwt.vc.id) { container in
                    HStack {
                        Spacer()
                        CardView(
                            firstName: container.jwt.vc.credentialSubject.firstName,
                            lastName: container.jwt.vc.credentialSubject.lastName,
                            studentID: container.jwt.vc.credentialSubject.studentID,
                            studentImage: container.jwt.vc.credentialSubject.image,
                            verifyURL: container.jwt.validityIdentifier,
                            barcodeData: container.jwt.vc.credentialSubject.getBarcodeData(),
                            universityIcon: container.jwt.vc.credentialSubject.theme.icon,
                            bgColorCard: Color(
                                hex: container.jwt.vc.credentialSubject.theme.bgColorCard
                            ) ?? .secondary,
                            bgColorSectionTop: Color(
                                hex: container.jwt.vc.credentialSubject.theme.bgColorSectionTop
                            ) ?? .secondary,
                            bgColorSectionBot: Color(
                                hex: container.jwt.vc.credentialSubject.theme.bgColorSectionBot
                            ) ?? .secondary,
                            fgColorTitle: Color(
                                hex: container.jwt.vc.credentialSubject.theme.fgColorTitle
                            ) ?? .white
                        )
                        Spacer()
                    }
                    .onTapGesture {
                        router.navigate(to: .detail(cardID: container.jwt.vc.id))
                    }
                    .onLongPressGesture {
                        selectedCardID = container.jwt.vc.id
                        showDeleteAlert = true
                    }
                    .alert(isPresented: $showDeleteAlert) {
                        Alert(
                            title: Text("Delete Card"),
                            message: Text("Do you really with to delete this card, you can not undo this action."),
                            primaryButton: .destructive(Text("Delete")) {
                                guard let cardID = selectedCardID, CardManager.shared.deleteCard(byID: cardID) else {
                                    print("Error deleting card")
                                    return
                                }
                            },
                            secondaryButton: .cancel()
                        )
                    }
                }
                .listRowBackground(Color(.systemGroupedBackground))
                .listRowInsets(EdgeInsets())
            }
            .listRowSpacing(16)
            VStack(alignment: .center) {
                Spacer()
                Button(action: {
                    router.navigate(to: .qrScanner(action: .issuance))
                }) {
                    Image(systemName: "plus.circle.fill")
                        .resizable()
                        .frame(width: 58, height: 58)
                }
                .foregroundStyle(Color.secondary)
                .padding()
            }
        }
        .modifier(NavbarModifier())
        .toolbar {
            ToolbarItem(placement: .principal) {
                Text("Overview")
                    .font(.title2)
                    .bold()
            }
        }
    }
}


#Preview {
    NavigationStack {
        ContentView()
            .environmentObject(Router())
    }
}
