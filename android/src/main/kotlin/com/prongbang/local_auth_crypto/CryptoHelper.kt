package com.prongbang.local_auth_crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

object CryptoHelper {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS_BIOMETRIC = "local_auth_crypto_rsa_biometric"
    private const val KEY_ALIAS_CREDENTIAL = "local_auth_crypto_rsa_credential"
    private const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    private const val MAX_PLAINTEXT_BYTES = 190 // 2048-bit RSA OAEP SHA-256: 256 - 2*32 - 2

    // Old AES key aliases to clean up
    private const val OLD_KEY_ALIAS_BIOMETRIC = "local_auth_crypto_biometric"
    private const val OLD_KEY_ALIAS_CREDENTIAL = "local_auth_crypto_credential"

    private val OAEP_PARAMS = OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA1,
        PSource.PSpecified.DEFAULT
    )

    private fun getKeyAlias(allowDeviceCredential: Boolean): String {
        return if (allowDeviceCredential) KEY_ALIAS_CREDENTIAL else KEY_ALIAS_BIOMETRIC
    }

    private fun getOrCreateKeyPair(allowDeviceCredential: Boolean): KeyPair {
        deleteOldAesKeys()

        val alias = getKeyAlias(allowDeviceCredential)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val existingKey = keyStore.getKey(alias, null)
        if (existingKey != null) {
            val cert = keyStore.getCertificate(alias)
            return KeyPair(cert.publicKey, existingKey as java.security.PrivateKey)
        }

        val purposes = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setKeySize(2048)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(false)

        if (allowDeviceCredential) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
            } else {
                // Pre-API 30: time-based fallback for credential mode
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(10)
            }
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG
                )
            } else {
                // Pre-API 30: per-use auth via CryptoObject
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
        }

        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE
        )
        keyPairGenerator.initialize(builder.build())
        return keyPairGenerator.generateKeyPair()
    }

    fun encrypt(plainText: String, allowDeviceCredential: Boolean): String {
        return try {
            encryptInternal(plainText, allowDeviceCredential)
        } catch (e: Exception) {
            deleteKey(allowDeviceCredential)
            encryptInternal(plainText, allowDeviceCredential)
        }
    }

    private fun encryptInternal(plainText: String, allowDeviceCredential: Boolean): String {
        val bytes = plainText.toByteArray(Charsets.UTF_8)
        if (bytes.size > MAX_PLAINTEXT_BYTES) {
            throw IllegalArgumentException(
                "Plaintext too large for RSA-OAEP (${bytes.size} bytes, max $MAX_PLAINTEXT_BYTES). " +
                "Encrypt a symmetric key or shorter payload instead."
            )
        }
        val keyPair = getOrCreateKeyPair(allowDeviceCredential)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.public, OAEP_PARAMS)
        val encrypted = cipher.doFinal(bytes)
        return Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    fun getDecryptCipher(cipherText: String, allowDeviceCredential: Boolean): Pair<Cipher, ByteArray> {
        return try {
            getDecryptCipherInternal(cipherText, allowDeviceCredential)
        } catch (e: Exception) {
            deleteKey(allowDeviceCredential)
            getDecryptCipherInternal(cipherText, allowDeviceCredential)
        }
    }

    private fun getDecryptCipherInternal(cipherText: String, allowDeviceCredential: Boolean): Pair<Cipher, ByteArray> {
        val encrypted = Base64.decode(cipherText, Base64.NO_WRAP)
        val keyPair = getOrCreateKeyPair(allowDeviceCredential)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, keyPair.private, OAEP_PARAMS)
        return Pair(cipher, encrypted)
    }

    fun decrypt(cipher: Cipher, encryptedData: ByteArray): String {
        val decrypted = cipher.doFinal(encryptedData)
        return String(decrypted, Charsets.UTF_8)
    }

    fun decryptFromCipherText(cipherText: String, allowDeviceCredential: Boolean): String {
        val (cipher, encrypted) = getDecryptCipher(cipherText, allowDeviceCredential)
        return decrypt(cipher, encrypted)
    }

    private fun deleteKey(allowDeviceCredential: Boolean) {
        val alias = getKeyAlias(allowDeviceCredential)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)
        keyStore.deleteEntry(alias)
    }

    private fun deleteOldAesKeys() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            if (keyStore.containsAlias(OLD_KEY_ALIAS_BIOMETRIC)) {
                keyStore.deleteEntry(OLD_KEY_ALIAS_BIOMETRIC)
            }
            if (keyStore.containsAlias(OLD_KEY_ALIAS_CREDENTIAL)) {
                keyStore.deleteEntry(OLD_KEY_ALIAS_CREDENTIAL)
            }
        } catch (_: Exception) {
            // Best-effort cleanup
        }
    }
}
