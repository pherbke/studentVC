//
//  RevealedStudentIDCard.swift
//  StudentWallet
//
//  Created by Anders Hausding on 11.01.25.
//

struct RevealedStudentCardTheme: Codable {
    enum CodingKeys: String, CodingKey {
        case bgColorCard
        case bgColorSectionBot
        case bgColorSectionTop
        case fgColorTitle
        case icon
        case name
    }
    let bgColorCard: String?
    let bgColorSectionBot: String?
    let bgColorSectionTop: String?
    let fgColorTitle: String?
    let icon: String?
    let name: String?
}

struct RevealedStudentIDCard: Codable {
    enum CodingKeys: String, CodingKey {
        case firstName
        case lastName
        case studentID = "studentId"
        case id
        case image
        case theme
        case issuanceCount
    }
    let firstName: String?
    let lastName: String?
    let id: String?
    let image: String?
    let studentID: String?
    let issuanceCount: String?
    let theme: RevealedStudentCardTheme?

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(self.firstName, forKey: .firstName)
        try container.encodeIfPresent(self.lastName, forKey: .lastName)
        try container.encodeIfPresent(self.studentID, forKey: .studentID)
        try container.encodeIfPresent(self.id, forKey: .id)
        try container.encodeIfPresent(self.image, forKey: .image)
        try container.encodeIfPresent(self.theme, forKey: .theme)
        try container.encodeIfPresent(self.issuanceCount, forKey: .issuanceCount)
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.firstName = try container.decodeIfPresent(String.self, forKey: .firstName)
        self.lastName = try container.decodeIfPresent(String.self, forKey: .lastName)
        self.studentID = try container.decodeIfPresent(String.self, forKey: .studentID)
        self.id = try container.decodeIfPresent(String.self, forKey: .id)
        self.image = try container.decodeIfPresent(String.self, forKey: .image)
        self.theme = try container.decodeIfPresent(RevealedStudentCardTheme.self, forKey: .theme)
        self.issuanceCount = try container.decodeIfPresent(String.self, forKey: .issuanceCount)
    }
}
