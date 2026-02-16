import Foundation
import Security
import LocalAuthentication

class CryptoHelper {

    private static let keyTagBiometric = "com.prongbang.local_auth_crypto.biometric"
    private static let keyTagCredential = "com.prongbang.local_auth_crypto.credential"
    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    private static func keyTag(allowDeviceCredential: Bool) -> String {
        return allowDeviceCredential ? keyTagCredential : keyTagBiometric
    }

    private static func deleteKey(allowDeviceCredential: Bool) {
        let tag = keyTag(allowDeviceCredential: allowDeviceCredential)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        SecItemDelete(query as CFDictionary)
    }

    private static func getOrCreateKeyPair(allowDeviceCredential: Bool) throws -> SecKey {
        let tag = keyTag(allowDeviceCredential: allowDeviceCredential)

        // Try to load existing private key
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let key = item {
            return key as! SecKey
        }

        // Create new key pair
        var accessControlFlags: SecAccessControlCreateFlags
        if allowDeviceCredential {
            accessControlFlags = .userPresence
        } else {
            if #available(iOS 11.3, *) {
                accessControlFlags = .biometryAny
            } else {
                accessControlFlags = .touchIDAny
            }
        }

        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControlFlags,
            nil
        ) else {
            throw CryptoError.keyCreationFailed
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: accessControl
            ] as [String: Any]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            // Fallback: try without Secure Enclave (simulator)
            attributes.removeValue(forKey: kSecAttrTokenID as String)
            guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw CryptoError.keyCreationFailed
            }
            return privateKey
        }
        return privateKey
    }

    private static func encryptInternal(plainText: String, allowDeviceCredential: Bool) throws -> String {
        let privateKey = try getOrCreateKeyPair(allowDeviceCredential: allowDeviceCredential)
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CryptoError.publicKeyUnavailable
        }

        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw CryptoError.algorithmNotSupported
        }

        guard let plainData = plainText.data(using: .utf8) else {
            throw CryptoError.encodingFailed
        }

        var error: Unmanaged<CFError>?
        guard let cipherData = SecKeyCreateEncryptedData(publicKey, algorithm, plainData as CFData, &error) else {
            throw CryptoError.encryptionFailed
        }

        return (cipherData as Data).base64EncodedString()
    }

    static func encrypt(plainText: String, allowDeviceCredential: Bool) throws -> String {
        do {
            return try encryptInternal(plainText: plainText, allowDeviceCredential: allowDeviceCredential)
        } catch {
            // Auto-recovery: delete stale key and retry once
            deleteKey(allowDeviceCredential: allowDeviceCredential)
            return try encryptInternal(plainText: plainText, allowDeviceCredential: allowDeviceCredential)
        }
    }

    private static func decryptInternal(
        cipherText: String,
        allowDeviceCredential: Bool,
        completion: @escaping (Result<String, Error>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let privateKey = try getOrCreateKeyPair(allowDeviceCredential: allowDeviceCredential)

                guard SecKeyIsAlgorithmSupported(privateKey, .decrypt, algorithm) else {
                    completion(.failure(CryptoError.algorithmNotSupported))
                    return
                }

                guard !cipherText.isEmpty else {
                    completion(.failure(CryptoError.base64DecodingFailed))
                    return
                }

                guard let cipherData = Data(base64Encoded: cipherText, options: .ignoreUnknownCharacters) else {
                    completion(.failure(CryptoError.base64DecodingFailed))
                    return
                }

                var error: Unmanaged<CFError>?
                guard let plainData = SecKeyCreateDecryptedData(privateKey, algorithm, cipherData as CFData, &error) else {
                    let err = error?.takeRetainedValue()
                    let nsErr = err as? NSError
                    if let nsErr = nsErr, nsErr.domain == LAError.errorDomain,
                       nsErr.code == LAError.userCancel.rawValue {
                        completion(.failure(CryptoError.userCancelled))
                    } else {
                        completion(.failure(CryptoError.decryptionFailed))
                    }
                    return
                }

                guard let plainText = String(data: plainData as Data, encoding: .utf8) else {
                    completion(.failure(CryptoError.utf8DecodingFailed))
                    return
                }

                completion(.success(plainText))
            } catch {
                completion(.failure(error))
            }
        }
    }

    static func decrypt(
        cipherText: String,
        allowDeviceCredential: Bool,
        reason: String,
        completion: @escaping (Result<String, Error>) -> Void
    ) {
        decryptInternal(cipherText: cipherText, allowDeviceCredential: allowDeviceCredential) { result in
            switch result {
            case .success:
                completion(result)
            case .failure(let error):
                // Don't retry on user cancel or input validation errors
                if error is CryptoError,
                   let cryptoErr = error as? CryptoError,
                   cryptoErr == .userCancelled || cryptoErr == .base64DecodingFailed {
                    completion(result)
                    return
                }
                // Auto-recovery: delete stale key and retry once
                deleteKey(allowDeviceCredential: allowDeviceCredential)
                decryptInternal(cipherText: cipherText, allowDeviceCredential: allowDeviceCredential, completion: completion)
            }
        }
    }

    enum CryptoError: Error, Equatable {
        case keyCreationFailed
        case publicKeyUnavailable
        case algorithmNotSupported
        case encodingFailed
        case base64DecodingFailed
        case utf8DecodingFailed
        case encryptionFailed
        case decryptionFailed
        case userCancelled
    }
}
