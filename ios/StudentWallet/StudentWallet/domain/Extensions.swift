//
//  Extensions.swift
//  StudentWallet
//
//  Created by Anders Hausding on 28.11.24.
//
import Foundation
import SwiftUI

let base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

extension Data {
    func base58EncodedString(keyTypePrefix: KeyTypePrefix? = nil) -> String {
        var intData = self.map { UInt64($0) }
        if let keyTypePrefix {
            intData.insert(contentsOf: keyTypePrefix.getPrefix().map { UInt64($0)}, at: intData.startIndex)
        }
        var result: [Character] = []
        while !intData.isEmpty {
            var remain: UInt64 = 0
            var newDigits: [UInt64] = []
            for digit in intData {
                let value = digit + (remain * 256) // bytes are technically values of base 256 so if we use the remain of the previous value well have to adjust its value
                let newDigit = value / 58
                remain = value % 58
                if !newDigits.isEmpty || newDigit != 0 {
                    newDigits.append(newDigit)
                }
            }
            result.append(base58Alphabet[base58Alphabet.index(base58Alphabet.startIndex, offsetBy: Int(remain))])
            intData = newDigits
        }
        let prefix = String(repeating: "1", count: self.prefix(while: { $0 == 0 }).count) // Base58 encodes leading zeros into 1
        return "\(prefix)\(String(result.reversed()))"
    }

    func base64URLEncodedString() -> String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension String {
    func base64urlToBase64() -> String {
        var base64 = self
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return base64
    }
    
    func decodeBase58() -> Data? {
        let leadingOnesCount = self.prefix(while: { $0 == "1" }).count
        let cleanString = self.dropFirst(leadingOnesCount)

        // 0.733 is a conservative estimation of the decoded byte size
        let b58Count = Int(ceil(Double(cleanString.count) * 0.733))
        var resultArray = [UInt8](repeating: 0, count: b58Count)
        var count = 0

        for char in cleanString {
            guard let digit = base58Alphabet.firstIndex(of: char) else {
                print("Invalid base58 character: \(char)")
                return nil
            }
            var carry = UInt64(base58Alphabet.distance(from: base58Alphabet.startIndex, to: digit))
            var i = 0

            for j in (0..<b58Count).reversed() {
                carry += 58 * UInt64(resultArray[j])
                resultArray[j] = UInt8(carry % 256)
                carry /= 256
                if carry == 0 && i >= count {
                    break
                }
                i += 1
            }

            count = i
        }

        // Skip leading zeros
        let leadingZerosCount = resultArray.prefix(while: { $0 == 0 }).count
        let result = [UInt8](repeating: 0, count: leadingOnesCount) + resultArray[leadingZerosCount...]
        return Data(result)
    }

    func generateImageWithFilter(filter: CIFilter, reduceQuietSpace: Bool = false) -> UIImage? {
        guard let data = self.data(using: .utf8) else {
            return nil
        }
        filter.setValue(data, forKey: "inputMessage")
        if reduceQuietSpace {
            filter.setValue(2, forKey: "inputQuietSpace")
        }
        guard let ciImage = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 3, y: 3)) else {
            return nil
        }
        let context = CIContext()
        guard let cgImage = context.createCGImage(ciImage, from: ciImage.extent) else {
            return nil
        }
        return UIImage(cgImage: cgImage)
    }

    func generateQRCode() -> UIImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else {
            return nil
        }
        return generateImageWithFilter(filter: filter)
    }

    func generateBarcode() -> UIImage? {
        guard let filter = CIFilter(name: "CICode128BarcodeGenerator") else {
            return nil
        }
        return generateImageWithFilter(filter: filter, reduceQuietSpace: true)
    }
}

extension Encodable {
    func asDictionary() throws -> [String: Any] {
        let data = try JSONEncoder().encode(self)
        guard let dictionary = try JSONSerialization.jsonObject(with: data, options: .allowFragments) as? [String: Any] else {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: [],
                    debugDescription: "Failed to encode object into Dictionary"
                )
            )
        }
        return dictionary
    }
}

extension Color {
    init?(hex: String) {
        let cleanedHex = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        let hexString = cleanedHex.hasPrefix("#") ? String(cleanedHex.dropFirst()) : cleanedHex

        guard hexString.count <= 6 else {
            return nil
        }
        guard let hexValue = UInt64(hexString, radix: 16) else {
            return nil // Invalid hex string
        }

        let r = Double((hexValue >> 16) & 0xFF) / 255.0
        let g = Double((hexValue >> 8) & 0xFF) / 255.0
        let b = Double(hexValue & 0xFF) / 255.0

        self.init(red: r, green: g, blue: b)
    }
}
