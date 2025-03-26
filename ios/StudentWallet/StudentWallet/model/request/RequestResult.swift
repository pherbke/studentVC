//
//  RequestResult.swift
//  StudentWallet
//
//  Created by Anders Hausding on 15.12.24.
//
import Foundation

enum HttpMethod: String {
    case Get = "GET"
    case Put = "PUT"
    case Post = "POST"
}

enum RequestResult<T> {
    case Success(T)
    case Cancelled
    case InvalidResponse(error: Error?)
    case BackendError(code: Int)
    case Error(error: Error)
}

func createRequest(url: URL, method: HttpMethod) -> URLRequest {
    var request = URLRequest(url: url)
    request.httpMethod = method.rawValue
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    return request
}
