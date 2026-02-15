import Flutter
import UIKit

public class SwiftLocalAuthCryptoPlugin: NSObject, FlutterPlugin {
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "local_auth_crypto", binaryMessenger: registrar.messenger())
        let instance = SwiftLocalAuthCryptoPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? Dictionary<String, Any>
        let allowDeviceCredential = args?[LocalAuthArgs.ALLOW_DEVICE_CREDENTIAL] as? Bool ?? false
        
        switch call.method {
        case LocalAuthMethod.ENCRYPT:
            guard let args = args,
                  let bioPayload = args[LocalAuthArgs.BIO_PAYLOAD] as? String else {
                result(FlutterError(code: "E01", message: "Biometric token is null", details: nil))
                return
            }
            do {
                let cipherText = try CryptoHelper.encrypt(plainText: bioPayload, allowDeviceCredential: allowDeviceCredential)
                result(cipherText)
            } catch {
                result(FlutterError(code: "E01", message: "Encryption failed: \(error)", details: nil))
            }
        case LocalAuthMethod.AUTHENTICATE:
            guard let args = args,
                  let bioCipherText = args[LocalAuthArgs.BIO_CIPHER_TEXT] as? String else {
                result(FlutterError(code: "E03", message: "Cipher is null", details: nil))
                return
            }
            let reason = (args[LocalAuthArgs.BIO_POLICY_REASON] as? String) ?? "Authenticate to decrypt"
            CryptoHelper.decrypt(
                cipherText: bioCipherText,
                allowDeviceCredential: allowDeviceCredential,
                reason: reason
            ) { decryptResult in
                DispatchQueue.main.async {
                    switch decryptResult {
                    case .success(let plainText):
                        result(plainText)
                    case .failure(let error):
                        if case CryptoHelper.CryptoError.userCancelled = error {
                            result(FlutterError(code: "E05", message: "Authenticate is cancel", details: nil))
                        } else {
                            result(FlutterError(code: "E04", message: "Authenticate is error: \(error)", details: nil))
                        }
                    }
                }
            }
        case LocalAuthMethod.EVALUATE_POLICY:
            let reason = (args?[LocalAuthArgs.BIO_POLICY_REASON] as? String) ?? "Authenticate"
            LocalAuthPolicy.evaluatePolicy(reason: reason, allowDeviceCredential: allowDeviceCredential) { (status) in
                result(status)
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
}
