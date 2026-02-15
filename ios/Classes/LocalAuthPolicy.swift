//
//  LocalAuthPolicy.swift
//  local_auth_crypto
//
//  Created by M on 14/12/2565 BE.
//

import LocalAuthentication

class LocalAuthPolicy {
    
    static func evaluatePolicy(reason: String, allowDeviceCredential: Bool, completion: @escaping (Bool) -> ()) {
        let context = LAContext()
        let policy: LAPolicy = allowDeviceCredential
            ? .deviceOwnerAuthentication
            : .deviceOwnerAuthenticationWithBiometrics

        var error: NSError?
        guard context.canEvaluatePolicy(policy, error: &error) else {
            DispatchQueue.main.async {
                completion(false)
            }
            return
        }

        context.evaluatePolicy(policy, localizedReason: reason) { (success, error) in
            DispatchQueue.main.async {
                completion(success)
            }
        }
    }
}
