//
//  StudentIDCard.swift
//  StudentWallet
//
//  Created by Anders Hausding on 14.12.24.
//

struct StudentCardTheme: Codable {
    enum CodingKeys: String, CodingKey {
        case bgColorCard
        case bgColorSectionBot
        case bgColorSectionTop
        case fgColorTitle
        case icon
        case name
    }
    let bgColorCard: String
    let bgColorSectionBot: String
    let bgColorSectionTop: String
    let fgColorTitle: String
    let icon: String
    let name: String
}

struct StudentIDCard: Codable {
    enum CodingKeys: String, CodingKey {
        case firstName
        case lastName
        case image
        case studentID = "studentId"
        case studentIDPrefix = "studentIdPrefix"
        case theme
        case issuanceCount
    }
    let firstName: String
    let lastName: String
    let image: String
    let studentID: String
    let studentIDPrefix: String
    let issuanceCount: String
    let theme: StudentCardTheme

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.firstName, forKey: .firstName)
        try container.encode(self.lastName, forKey: .lastName)
        try container.encode(self.studentID, forKey: .studentID)
        try container.encode(self.image, forKey: .image)
        try container.encode(self.studentIDPrefix, forKey: .studentIDPrefix)
        try container.encode(self.issuanceCount, forKey: .issuanceCount)
        try container.encode(self.theme, forKey: .theme)
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.firstName = try container.decode(String.self, forKey: .firstName)
        self.lastName = try container.decode(String.self, forKey: .lastName)
        self.studentID = try container.decode(String.self, forKey: .studentID)
        self.image = try container.decode(String.self, forKey: .image)
        self.studentIDPrefix = try container.decode(String.self, forKey: .studentIDPrefix)
        self.theme = try container.decode(StudentCardTheme.self, forKey: .theme)
        self.issuanceCount = try container.decode(String.self, forKey: .issuanceCount)
    }

    init(
        firstName: String,
        lastName: String,
        studentID: String,
        image: String,
        studentIDPrefix: String,
        theme: StudentCardTheme,
        issuanceCount: String
    ) {
        self.firstName = firstName
        self.lastName = lastName
        self.studentID = studentID
        self.image = image
        self.studentIDPrefix = studentIDPrefix
        self.theme = theme
        self.issuanceCount = issuanceCount
    }

    func getBarcodeData() -> String {
        return "\(studentIDPrefix)\(studentID)\(issuanceCount)"
    }
}
