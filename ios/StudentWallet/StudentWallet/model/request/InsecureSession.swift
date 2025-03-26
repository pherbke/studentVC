//
//  InsecureSession.swift
//  StudentWallet
//
//  Created by Anders Hausding on 15.12.24.
//
import Foundation

let INSECURE_SESSION = {
    let config = URLSessionConfiguration.default
    config.waitsForConnectivity = true
    return URLSession(configuration: config, delegate: InsecureDelegate(), delegateQueue: nil)
}()

class InsecureDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
            completionHandler(.useCredential, credential)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
