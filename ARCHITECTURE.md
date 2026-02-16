# ARCHITECTURE — local_auth_crypto

Biometric-gated encrypt/decrypt for Flutter on Android & iOS. Encrypts data locally using hardware-backed keys and requires biometric (or device credential) authentication to decrypt.

## Directory Layout

```
lib/
  local_auth_crypto.dart                   # Abstract API class (singleton)
  local_auth_crypto_method_channel.dart     # MethodChannel implementation
  model/
    biometric_prompt_info.dart              # Prompt config data model

android/src/main/kotlin/com/prongbang/local_auth_crypto/
  LocalAuthCryptoPlugin.kt                 # Flutter plugin entry, BiometricPrompt orchestration
  CryptoHelper.kt                          # RSA-OAEP 2048-bit encrypt/decrypt via Android KeyStore
  LocalAuthArgs.kt                         # Method channel argument key constants
  LocalAuthMethod.kt                       # Method channel method name constants

ios/Classes/
  SwiftLocalAuthCryptoPlugin.swift         # Flutter plugin entry, method dispatch
  CryptoHelper.swift                       # ECIES P-256 encrypt/decrypt via Secure Enclave
  LocalAuthArgs.swift                      # Method channel argument key constants
  LocalAuthMethod.swift                    # Method channel method name constants
  LocalAuthPolicy.swift                    # LAContext evaluatePolicy wrapper
  LocalAuthCryptoPlugin.h / .m            # ObjC bridge (forwards to Swift plugin)
```

## Dart API Surface

### `LocalAuthCrypto` (abstract, singleton)

```dart
static LocalAuthCrypto get instance;  // defaults to MethodChannelLocalAuthCrypto

Future<String?> encrypt(String payload, {bool allowDeviceCredential = false});
Future<String?> authenticate(BiometricPromptInfo promptInfo, String cipherText, {bool allowDeviceCredential = false});
Future<bool?>   evaluatePolicy(String reason, {bool allowDeviceCredential = false});
```

- `encrypt` — encrypts plaintext, returns ciphertext. No auth prompt needed.
- `authenticate` — decrypts ciphertext after biometric/credential auth. Returns plaintext.
- `evaluatePolicy` — checks if biometric/credential auth is available on device.

### `BiometricPromptInfo`

```dart
class BiometricPromptInfo {
  String? title;
  String? subtitle;
  String? description;
  String? negativeButton;  // Android only (bio-only mode)
}
```

### Method Channel Contract

Channel name: `"local_auth_crypto"`

| Method         | Arguments                                                                                      | Return     |
|----------------|-----------------------------------------------------------------------------------------------|------------|
| `encrypt`      | `payload` (String), `allowDeviceCredential` (bool)                                            | `String`   |
| `authenticate` | `cipherText` (String), `allowDeviceCredential` (bool), `title`?, `subtitle`?, `description`?, `negativeButton`? | `String`   |
| `evaluatePolicy` | `reason` (String), `allowDeviceCredential` (bool)                                           | `bool`     |

## Android Native (Kotlin)

### Crypto: RSA-OAEP 2048-bit via Android KeyStore (asymmetric)

> **Breaking change in v3.0.0:** Switched from AES-256-GCM (symmetric) to RSA-OAEP (asymmetric). Old ciphertext is incompatible — re-encrypt after upgrade.

**Algorithm:** `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`, 2048-bit key pair

**Key aliases:**
- `local_auth_crypto_rsa_biometric` — biometric-only mode
- `local_auth_crypto_rsa_credential` — biometric + device credential mode

Old AES aliases (`local_auth_crypto_biometric` / `local_auth_crypto_credential`) are auto-deleted on first key pair creation.

**Key generation** (`CryptoHelper.getOrCreateKeyPair`):
- RSA 2048-bit key pair, stored in `AndroidKeyStore`
- `setUserAuthenticationRequired(true)` — **core security fix**: private key use requires hardware-enforced biometric/credential auth. Prevents bypass via direct `decrypt()` calls.
- `setInvalidatedByBiometricEnrollment(false)` — key survives biometric changes
- API 30+: `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL)` for credential mode
- Pre-API 30 credential: `setUserAuthenticationValidityDurationSeconds(10)` (time-based fallback)
- Pre-API 30 biometric-only: `setUserAuthenticationValidityDurationSeconds(-1)` (per-use via CryptoObject)

**Encrypt** uses `keyPair.public` — no auth needed, no BiometricPrompt required.

**Decrypt** uses `keyPair.private` — requires biometric/credential auth at the KeyStore level.

**Ciphertext format:**
```
base64(rsa_ciphertext)
```
Single base64 string (no IV separator — RSA-OAEP is stateless).

**Plaintext size limit:** 190 bytes (2048-bit RSA OAEP with SHA-256). Encrypt a symmetric key or short payload.

**Auto-recovery:** Both `encrypt()` and `getDecryptCipher()` wrap their internal calls in try/catch. On any crypto failure (stale key, invalidated key), the key is deleted and the operation retries once.

### BiometricPrompt Integration

**Authentication flow (`LocalAuthCryptoPlugin.onMethodCall` → `AUTHENTICATE`):**

1. `CryptoHelper.getDecryptCipher()` → produces a `Cipher` initialized for decryption + the encrypted byte array
2. Build `BiometricPrompt.PromptInfo`:
   - If `allowDeviceCredential`: authenticators = `BIOMETRIC_STRONG | DEVICE_CREDENTIAL`
   - Else: authenticators = `BIOMETRIC_STRONG`, set `negativeButtonText`
3. Create `BiometricPrompt` with single-thread executor for callback
4. Show prompt on UI thread via `runOnUiThread`

**Pre-API-30 workaround:** When `allowDeviceCredential = true` and `Build.VERSION.SDK_INT < 30`, `BiometricPrompt.authenticate()` is called **without** a `CryptoObject` (Android doesn't support `CryptoObject` with `DEVICE_CREDENTIAL` pre-API 30). After successful auth, decryption runs directly via `CryptoHelper.decryptFromCipherText()`.

**evaluatePolicy:** Uses `BiometricManager.canAuthenticate()` with appropriate authenticator flags.

## iOS Native (Swift)

### Crypto: ECIES P-256 via Secure Enclave

**Algorithm:** `eciesEncryptionCofactorVariableIVX963SHA256AESGCM`

This is **asymmetric** encryption (unlike Android's symmetric AES). The private key lives in the Secure Enclave; using it for decryption triggers the OS biometric/passcode prompt automatically.

**Key tags:**
- `com.prongbang.local_auth_crypto.biometric`
- `com.prongbang.local_auth_crypto.credential`

**Key generation** (`CryptoHelper.getOrCreateKeyPair`):
- EC P-256 key pair, stored in Secure Enclave (`kSecAttrTokenIDSecureEnclave`)
- Access control:
  - Biometric-only: `.biometryAny` (or `.touchIDAny` on iOS < 11.3)
  - With credential: `.userPresence` (biometric + passcode)
- Data protection: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- **Simulator fallback:** If Secure Enclave is unavailable, retries key creation without `kSecAttrTokenID`

**Ciphertext format:** `base64(ecies_ciphertext)` (single base64 string, no separator)

### Encrypt / Decrypt

**Encrypt** (`CryptoHelper.encrypt`):
- Extracts public key from the key pair via `SecKeyCopyPublicKey`
- Encrypts with `SecKeyCreateEncryptedData` — **no auth prompt** (public key is unrestricted)

**Decrypt** (`CryptoHelper.decrypt`):
- Dispatched to `DispatchQueue.global(qos: .userInitiated)` (background queue)
- Guards empty ciphertext and invalid base64 before attempting decryption
- Base64 decode uses `.ignoreUnknownCharacters` to tolerate whitespace/newlines
- Calls `SecKeyCreateDecryptedData` with the private key — **this triggers the OS biometric prompt** because the private key has access control
- Result marshalled back to main thread via `DispatchQueue.main.async`
- User cancellation detected by checking `LAError.userCancel` in the error domain

**Auto-recovery:** Both `encrypt()` and `decrypt()` wrap their internal calls in try/catch. On any crypto failure (stale key, corrupt Keychain entry), the key is deleted via `deleteKey()` and the operation retries once. User cancellation and base64 validation errors skip retry.

**CryptoError cases:** `base64DecodingFailed` (invalid base64 input), `utf8DecodingFailed` (decrypted bytes not valid UTF-8) — split for clear diagnosis.

### evaluatePolicy

`LocalAuthPolicy.evaluatePolicy` uses `LAContext`:
- Biometric-only: `.deviceOwnerAuthenticationWithBiometrics`
- With credential: `.deviceOwnerAuthentication`
- Checks `canEvaluatePolicy` then calls `evaluatePolicy`, result on main thread

## Platform Comparison

| Aspect                | Android                                  | iOS                                          |
|-----------------------|------------------------------------------|----------------------------------------------|
| **Crypto algorithm**  | RSA-OAEP 2048-bit (asymmetric)           | ECIES P-256 (asymmetric)                     |
| **Key storage**       | Android KeyStore                         | Secure Enclave                               |
| **Auth enforcement**  | `setUserAuthenticationRequired(true)` on private key | Secure Enclave access control flags |
| **Auth framework**    | AndroidX BiometricPrompt + KeyStore      | Security framework + LAContext               |
| **Auth trigger**      | KeyStore enforced + BiometricPrompt UI   | Implicit on private key use                  |
| **Ciphertext format** | `base64(rsa_ciphertext)`                 | `base64(ecies_blob)`                         |
| **Credential fallback** | `BIOMETRIC_STRONG \| DEVICE_CREDENTIAL`| `.userPresence` access control               |
| **Pre-API workaround**| API < 30: auth without CryptoObject      | N/A                                          |
| **Key recovery**      | Auto-delete stale key + retry            | Auto-delete stale key + retry                |
| **Simulator support** | Emulator with KeyStore                   | Software key (no Secure Enclave)             |

## Error Code Reference

| Code | Meaning              | Android trigger                                       | iOS trigger                              |
|------|----------------------|-------------------------------------------------------|------------------------------------------|
| E01  | Encryption failed    | `payload` is null or encrypt exception                | `payload` is null or encrypt exception   |
| E02  | Activity unavailable | `FragmentActivity` is null                            | N/A (no activity concept)                |
| E03  | Cipher text null     | `cipherText` argument missing                         | `cipherText` argument missing            |
| E04  | Auth/decrypt error   | BiometricPrompt error or decryption failure           | Decryption failure (non-cancel)          |
| E05  | User cancelled       | `ERROR_USER_CANCELED` or `ERROR_NEGATIVE_BUTTON`      | `LAError.userCancel` during decrypt      |

## Data Flow

### Encrypt

```
┌─────────┐      MethodChannel       ┌──────────────────┐
│  Dart    │ ──── "encrypt" ────────→ │  Native Plugin   │
│  Client  │      {payload, allow}    │                  │
└─────────┘                           └────────┬─────────┘
                                               │
                              ┌────────────────┴────────────────┐
                              │                                 │
                      ┌───────▼────────┐              ┌────────▼────────┐
                      │  Android       │              │  iOS            │
                      │                │              │                 │
                      │ RSA key pair   │              │ SE key pair     │
                      │ PublicKey enc  │              │ PublicKey enc   │
                      │ → base64      │              │ → base64        │
                      └───────┬────────┘              └────────┬────────┘
                              │                                 │
                              └────────────────┬────────────────┘
                                               │
                                        cipherText (String)
                                          back to Dart
```

### Decrypt (authenticate)

```
┌─────────┐      MethodChannel         ┌──────────────────┐
│  Dart    │ ── "authenticate" ──────→  │  Native Plugin   │
│  Client  │    {cipherText, prompt}    │                  │
└─────────┘                             └────────┬─────────┘
                                                 │
                              ┌──────────────────┴──────────────────┐
                              │                                     │
                      ┌───────▼─────────┐                 ┌────────▼─────────┐
                      │  Android        │                 │  iOS             │
                      │                 │                 │                  │
                      │ Init decrypt    │                 │ bg queue:        │
                      │ cipher w/ priv  │                 │ SecKeyCreate-    │
                      │       │         │                 │ DecryptedData    │
                      │       ▼         │                 │ (triggers bio    │
                      │ BiometricPrompt │                 │  prompt from OS) │
                      │ .authenticate() │                 │       │          │
                      │ (UI thread)     │                 │       ▼          │
                      │       │         │                 │ result → main    │
                      │       ▼         │                 │ thread           │
                      │ onAuthSuccess:  │                 └────────┬─────────┘
                      │ cipher.doFinal  │                          │
                      └───────┬─────────┘                          │
                              │                                    │
                              └──────────────────┬─────────────────┘
                                                 │
                                          plainText (String)
                                            back to Dart
```

## Security Properties

- **Hardware-backed keys** — Android KeyStore / iOS Secure Enclave. Keys never leave hardware.
- **Authenticated encryption** — RSA-OAEP (Android) and ECIES with AES-GCM (iOS) provide confidentiality + integrity.
- **No key export** — Neither platform allows extracting the private key material.
- **KeyStore-level auth enforcement** — Both platforms enforce authentication at the key level: Android via `setUserAuthenticationRequired(true)` on the private key, iOS via Secure Enclave access control flags. Direct `decrypt()` calls without authentication will fail.
- **Device-only keys** — iOS uses `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; Android KeyStore keys are device-bound by default.
- **Biometric re-enrollment safe** — `setInvalidatedByBiometricEnrollment(false)` — keys survive biometric changes on both platforms.
