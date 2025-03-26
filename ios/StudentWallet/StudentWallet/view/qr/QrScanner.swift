//
//  QrScanner.swift
//  Student Wallet
//
//  Created by Timo Oeltze on 18.11.24.
//

import AVFoundation
import Foundation
import SwiftUI

struct QrScanner: UIViewControllerRepresentable {
    @EnvironmentObject var router: Router
    var onQRCodeProcessed: ((QRCodeAction, URL, String) -> Void)?  // Callback Closure

    class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        let parent: QrScanner
        var currentViewController: UIViewController?
        var isScanning: Bool = true

        init(parent: QrScanner) {
            self.parent = parent
        }

        func metadataOutput(
            _ output: AVCaptureMetadataOutput,
            didOutput metadataObjects: [AVMetadataObject],
            from connection: AVCaptureConnection
        ) {
            
            guard isScanning else { return }
            if let metadataObject = metadataObjects.first {
                guard
                    let readableObject = metadataObject
                        as? AVMetadataMachineReadableCodeObject,
                    let stringValue = readableObject.stringValue,
                    let viewController = currentViewController
                else { return }
                AudioServicesPlaySystemSound(
                    SystemSoundID(kSystemSoundID_Vibrate))

                isScanning = false
                parent.handleScannedCode(
                    stringValue, on: viewController)
            }
        }

    }

    func makeCoordinator() -> Coordinator {
        return Coordinator(parent: self)
    }

    func makeUIViewController(context: Context) -> UIViewController {
        let viewController = UIViewController()
        context.coordinator.currentViewController = viewController
        let captureSession = AVCaptureSession()

        //Does a camera exist
        guard let videoCaptureDevice = AVCaptureDevice.default(for: .video)
        else {
            showAlert(
                on: viewController, title: "Error", message: "No camera found.")
            return viewController
        }

        let videoInput: AVCaptureDeviceInput
        do {
            //try to access camera
            videoInput = try AVCaptureDeviceInput(device: videoCaptureDevice)
        } catch {
            showAlert(
                on: viewController, title: "Error",
                message: "Can't access camera.")
            return viewController
        }

        //add camera stream
        if captureSession.canAddInput(videoInput) {
            captureSession.addInput(videoInput)
        } else {
            showAlert(
                on: viewController, title: "Error",
                message: "Can't get video stream.")
            return viewController
        }

        let metadataOutput = AVCaptureMetadataOutput()

        //add meta data output to current session
        if captureSession.canAddOutput(metadataOutput) {
            captureSession.addOutput(metadataOutput)

            metadataOutput.setMetadataObjectsDelegate(
                context.coordinator, queue: DispatchQueue.main)  //waiting queue for meta data
            metadataOutput.metadataObjectTypes = [.qr]  //qr infos
        } else {
            showAlert(
                on: viewController, title: "Error",
                message: "Can't access metadata output.")
            return viewController
        }

        //get live view of the camera stream
        let previewLayer = AVCaptureVideoPreviewLayer(session: captureSession)
        previewLayer.frame = viewController.view.layer.bounds
        previewLayer.videoGravity = .resizeAspectFill
        viewController.view.layer.addSublayer(previewLayer)

        ///start camera session
        DispatchQueue.global(qos: .background).async {
            captureSession.startRunning()
        }

        return viewController
    }

    func updateUIViewController(
        _ uiViewController: UIViewControllerType, context: Context
    ) {}

    private func showAlert(
        on viewController: UIViewController, title: String, message: String
    ) {
        //main allert view /windows
        let alertController = UIAlertController(
            title: title, message: message, preferredStyle: .alert)

        //action when pressing ok
        alertController.addAction(
            UIAlertAction(
                title: "OK", style: .default,
                handler: { _ in
                    router.navigateBack()
                }
            )
        )

        DispatchQueue.main.async {
            viewController.present(alertController, animated: true)
        }
    }

    func handleScannedCode(_ code: String, on viewController: UIViewController)
    {
        if code.hasPrefix("openid-credential-offer://") {
            /// Issuer QR code detected
            if let url = extractURL(
                from: code, scheme: "openid-credential-offer",
                queryItemName: "credential_offer_uri")
            {
                processQRCode(type: .issuance, url: url, fullString: code)
            } else {
                showAlert(
                    on: viewController,
                    title: "Invalid QR Code",
                    message: "The contained URL is invalid.")
            }
        } else if code.hasPrefix("openid4vp://") {
            /// Verifier QR code detected
            if let url = extractURL(
                from: code, scheme: "openid4vp", queryItemName: "request_uri")
            {
                processQRCode(type: .presentation(id: ""), url: url, fullString: code)
            } else {
                showAlert(
                    on: viewController,
                    title: "Invalid QR Code",
                    message: "The contained URL is invalid.")
            }
        } else {
            print("Founde code \(code)")
            /// Unknown QR code type
            showAlert(
                on: viewController,
                title: "Unknown QR Code",
                message: "The QR code type is not supported.")
        }
    }

    private func extractURL(
        from code: String, scheme: String, queryItemName: String
    ) -> URL? {
        guard let components = URLComponents(string: code),
            components.scheme == scheme,
            let queryItems = components.queryItems,
            let urlString = queryItems.first(where: { $0.name == queryItemName }
            )?.value,
            let url = URL(string: urlString),
            UIApplication.shared.canOpenURL(url)
        else {
            return nil
        }
        return url
    }

    private func processQRCode(type: QRCodeAction, url: URL, fullString: String) {
        /// Stop the scanner
        stopScanner()

        /// Call the closure to return data
        onQRCodeProcessed?(type, url, fullString)
    }

    private func stopScanner() {
        if let windowScene = UIApplication.shared.connectedScenes.first
            as? UIWindowScene,
            let viewController = windowScene.windows.first(where: {
                $0.isKeyWindow
            })?.rootViewController?.presentedViewController,
            let previewLayer = viewController.view.layer.sublayers?.compactMap({
                $0 as? AVCaptureVideoPreviewLayer
            }).first,
            let session = previewLayer.session
        {
            /// Stop the session
            session.stopRunning()
        }

        let coordinator = makeCoordinator()
        coordinator.isScanning = false
    }

}
