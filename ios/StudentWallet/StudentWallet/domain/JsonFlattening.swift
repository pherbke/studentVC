//
//  JsonFlattening.swift
//  StudentWallet
//
//  Created by Anders Hausding on 11.01.25.
//
import Foundation

//These functions were generated using perplexity.ai

func flattenJSON(_ json: [String: Any], prefix: String = "", separator: String = ".") -> [String: Any] {
    var result: [String: Any] = [:]

    for (key, value) in json {
        let newKey = prefix.isEmpty ? key : "\(prefix)\(separator)\(key)"

        if let nestedDict = value as? [String: Any] {
            let nested = flattenJSON(nestedDict, prefix: newKey)
            result.merge(nested) { (_, new) in new }
        } else if let nestedArray = value as? [Any] {
            for (index, element) in nestedArray.enumerated() {
                if let nestedDict = element as? [String: Any] {
                    let nested = flattenJSON(nestedDict, prefix: "\(newKey)\(separator)\(index)")
                    result.merge(nested) { (_, new) in new }
                } else {
                    result["\(newKey)\(separator)\(index)"] = element
                }
            }
        } else {
            result[newKey] = value
        }
    }

    return result
}

func unflattenJSON(_ dict: [String: Any], separator: String = ".") -> [String: Any] {
    var result: [String: Any] = [:]

    for (key, value) in dict {
        let components = key.components(separatedBy: separator)
        insertValue(components, value: value, into: &result)
    }

    // Convert numeric-keyed dictionaries to arrays
    for (key, value) in result {
        if let dict = value as? [String: Any] {
            result[key] = convertToArrayIfNeeded(dict)
        }
    }

    return result
}

func insertValue(_ components: [String], value: Any, into dict: inout [String: Any]) {
    guard let firstComponent = components.first else { return }

    if components.count == 1 {
        dict[firstComponent] = value
    } else {
        var subDict = dict[firstComponent] as? [String: Any] ?? [:]
        insertValue(Array(components.dropFirst()), value: value, into: &subDict)
        dict[firstComponent] = subDict
    }
}

func convertToArrayIfNeeded(_ dict: [String: Any]) -> Any {
    let keys = dict.keys.sorted()
    if keys.allSatisfy({ Int($0) != nil }) {
        return keys.compactMap { key in
            let value = dict[key]
            if let nestedDict = value as? [String: Any] {
                return convertToArrayIfNeeded(nestedDict)
            }
            return value
        }
    } else {
        return dict.mapValues { value in
            if let nestedDict = value as? [String: Any] {
                return convertToArrayIfNeeded(nestedDict)
            }
            return value
        }
    }
}
