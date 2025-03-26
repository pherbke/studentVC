//
//  PresentationRequest.swift
//  StudentWallet
//
//  Created by Anders Hausding on 15.12.24.
//

struct PresentationRequest: Encodable {
    enum CodingKeys: String, CodingKey {
        case vpToken = "vp_token"
        case presentationSubmission = "presentation_submission"
    }
    let vpToken: String
    let presentationSubmission: PresentationSubmission

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.vpToken, forKey: .vpToken)
        try container.encode(self.presentationSubmission, forKey: .presentationSubmission)
    }
}
