//
//  CardDetailView.swift
//  StudentWallet
//
//  Created by Anders Hausding on 15.12.24.
//
import SwiftUI

class CardDetailViewModel: ObservableObject {
    var data: CredentialData
    var barcodeData: String
    
    init(data: CredentialData) {
        self.data = data
        self.barcodeData = data.jwt.vc.credentialSubject.getBarcodeData()
    }
    
    init?(cardID: String) {
        guard let data = CardManager.shared.cards.first(
            where: {
                $0.jwt.vc.id == cardID
            }
        ) else {
            print("App tried to load unknown card id \(cardID)")
            return nil
        }
        self.data = data
        self.barcodeData = data.jwt.vc.credentialSubject.getBarcodeData()
    }
}

struct CardDetailView: View {
    @EnvironmentObject var router: Router
    @StateObject var viewModel: CardDetailViewModel
    var body: some View {
        ZStack(alignment: .topLeading) {
            Color(.lightGray)
                .ignoresSafeArea(edges: .vertical)
            HStack {
                Spacer()
                VStack(alignment: .center) {
                    VStack(spacing: 8) {
                        Text("Student ID")
                            .font(.title2)
                            .bold()
                        Text(viewModel.data.jwt.vc.credentialSubject.theme.name)
                            .font(.title2)
                        Divider()
                        if let data = Data(
                            base64Encoded: viewModel.data.jwt.vc.credentialSubject.image),
                           let image = UIImage(data: data) {
                            Image(
                                uiImage: image
                            )
                            .resizable()
                            .scaledToFit()
                        } else {
                            Image(
                                systemName: "person.crop.square"
                            )
                            .resizable()
                            .scaledToFit()
                        }
                        HStack {
                            VStack(alignment: .center) {
                                Text("First name")
                                    .bold()
                                Text(viewModel.data.jwt.vc.credentialSubject.firstName)
                                Text("Last Name")
                                    .bold()
                                Text(viewModel.data.jwt.vc.credentialSubject.lastName)
                                Text("Student ID")
                                    .bold()
                                Text(viewModel.data.jwt.vc.credentialSubject.studentID)
                            }
                            .font(.title3)
                        }
                        
                        if let qrCodeImage = viewModel.data.jwt.validityIdentifier.generateQRCode(){
                            Image(uiImage: qrCodeImage)
                                .interpolation(.none)
                                .resizable()
                                .aspectRatio(1, contentMode: .fit)
                                .scaledToFit()
                        }
                        if let barcodeImage = viewModel.barcodeData.generateBarcode() {
                            Image(uiImage: barcodeImage)
                                .interpolation(.none)
                                .resizable()
                                .frame(height: 64)
                            
                        }
                        
                    }
                    .foregroundStyle(Color.black)
                    .padding()
                    .background(Color.white)
                    .modifier(
                        CardViewModifier(
                            backgroundColor: Color.white,
                            cornerRadius: 24
                        )
                    )
                    .aspectRatio(0.6, contentMode: .fit)
                    .padding(.all, 24)
                    .background(Color(.lightGray))
                    .fixedSize(horizontal: true, vertical: false)
                    Button(
                        action: {
                            router.navigate(
                                to: .qrScanner(
                                    action: .presentation(id: viewModel.data.jwt.vc.id)
                                )
                            )
                        },
                        label: {
                            Text("Scan Presentation QR Code")
                                .bold()
                                .padding()
                        }
                    )
                    .buttonStyle(.borderedProminent)
                }
                Spacer()
            }
        }
        .modifier(NavbarModifier())
        .toolbar {
            ToolbarItem(placement: .principal) {
                Text("Card Detail")
                    .font(.title2)
                    .bold()
            }
        }
    }
}

#Preview {
    NavigationStack {
        CardDetailView(
            viewModel: CardDetailViewModel(
                data: CredentialData(
                    jwt: CredentialJWT(
                        bbsDPK: "",
                        exp: 123,
                        iat: 123,
                        iss: "",
                        jti: "",
                        nbf: 123,
                        nonce: "",
                        signedNonce: "",
                        sub: "",
                        totalMessage: 123,
                        validityIdentifier: "somecoolqr",
                        vc: CredentialVC(
                            context: [],
                            credentialSchema: CredentialVCSchema(id: "", type: ""),
                            credentialSubject: StudentIDCard(
                                firstName: "Maxi",
                                lastName: "Mustermann",
                                studentID: "999999",
                                image: "",
                                studentIDPrefix: "1690",
                                theme: StudentCardTheme(
                                    bgColorCard: "",
                                    bgColorSectionBot: "",
                                    bgColorSectionTop: "",
                                    fgColorTitle: "",
                                    icon: "",
                                    name: "Technische Universität Berlin"
                                ), 
                                issuanceCount: "1"
                            ),
                            expirationDate: "",
                            id: "did:key:zXwpREKDfPXW8cNGN5KMyes93VgVQNNQhmMBkLmBPr5MBWmCDgtD8UMHQ8jcsjXdmBg2LDTBV76xYozDjTj8xGPqvZSV",
                            issuanceDate: "",
                            issuer: "",
                            type: [],
                            validFrom: ""
                        )
                    ),
                    signature: ""
                )
            )
        )
    }
    .environmentObject(Router())
}
