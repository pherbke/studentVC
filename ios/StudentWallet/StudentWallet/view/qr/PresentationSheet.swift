//
//  PresentationDialog.swift
//  StudentWallet
//
//  Created by Anders Hausding on 16.01.25.
//

import SwiftUI

struct PresentationSheet: View {
    let fieldInfos: [FieldInfo]
    let onPresent: () -> Void
    let onCancel: () -> Void

    var body: some View {
        List {
            Section {
                ForEach(fieldInfos, id: \.key) { fieldInfo in
                    VStack(alignment: .leading) {
                        Text(fieldInfo.field)
                            .font(.headline)
                        Text(fieldInfo.explanation)
                            .font(.subheadline)
                            .foregroundColor(.gray)
                    }
                    .padding()
                }
            } header: {
                Text("Server requested the following fields")
            } footer: {
                VStack(alignment: .center) {
                    Button(
                        action: {
                            onPresent()
                        },
                        label: {
                            HStack {
                                Spacer()
                                Text("Start Presentation")
                                Spacer()
                            }

                        }
                    )
                    .buttonStyle(.bordered)
                    Button(
                        action: {
                            onCancel()
                        },
                        label: {
                            Spacer()
                            Text("Cancel")
                            Spacer()
                        }
                    )
                    .buttonStyle(.bordered)
                }
            }
        }
    }
}

#Preview {
    VStack {
        Spacer()
    }
    .sheet(isPresented: .constant(true)) {
        PresentationSheet(
            fieldInfos: [
                FieldInfo(key: "test", field: "Test", explanation: "For testing"),
                FieldInfo(key: "test", field: "Test", explanation: "For testing"),
                FieldInfo(key: "test", field: "Test", explanation: "For testing"),
                FieldInfo(key: "test", field: "Test", explanation: "For testing"),
                FieldInfo(key: "test", field: "Test", explanation: "For testing"),
                FieldInfo(key: "test", field: "Test", explanation: "For testing"),
                FieldInfo(key: "test", field: "Test", explanation: "For testing"),
                FieldInfo(key: "test", field: "Test", explanation: "For testing"),
                FieldInfo(key: "test", field: "Test", explanation: "For testing")
            ],
            onPresent: { },
            onCancel: { }
        )
    }
}
