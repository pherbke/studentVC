//
//  UrlQueryBuilder.swift
//  StudentWallet
//
//  Created by Anders Hausding on 19.11.24.
//

import Foundation

enum UrlScheme: String {
   case HTTP = "http"
   case HTTPS = "https"
}

class UrlQueryBuilder {
    private var components: URLComponents
    init(baseURL: String? = nil) {
        if let baseURL {
            self.components = URLComponents(string: baseURL) ?? URLComponents()
        } else {
            self.components = URLComponents()
        }
    }

    init(components: URLComponents) {
        self.components = components
    }

    func setScheme(scheme: UrlScheme = .HTTPS) -> UrlQueryBuilder {
        components.scheme = scheme.rawValue
        return self
    }

    func setHost(host: String) -> UrlQueryBuilder {
        components.host = host
        return self
    }

    func setPort(port: Int) -> UrlQueryBuilder {
        components.port = port
        return self
    }

    func setPath(path: String) -> UrlQueryBuilder {
        components.path = path
        return self
    }

    func addQueryComponent(key: String, value: String) -> UrlQueryBuilder {
        let newItem = URLQueryItem(
            name: key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!,
            value: value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        )
        guard components.queryItems != nil else {
            components.queryItems = [newItem]
            return self
        }
        components.queryItems?.append(newItem)
        return self
    }

    func addOptionalQueryComponent(key: String, value: String?) -> UrlQueryBuilder {
        guard let value = value, !value.isEmpty else {
            return self
        }
        return addQueryComponent(
            key: key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!,
            value: value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        )
    }

    func build() -> URL? {
        return components.url
    }
}
