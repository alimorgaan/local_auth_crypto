package com.prongbang.local_auth_crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object CryptoHelper {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS_BIOMETRIC = "local_auth_crypto_biometric"
    private const val KEY_ALIAS_CREDENTIAL = "local_auth_crypto_credential"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128

    private fun getKeyAlias(allowDeviceCredential: Boolean): String {
        return if (allowDeviceCredential) KEY_ALIAS_CREDENTIAL else KEY_ALIAS_BIOMETRIC
    }

    private fun getOrCreateKey(allowDeviceCredential: Boolean): SecretKey {
        val alias = getKeyAlias(allowDeviceCredential)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        keyStore.getKey(alias, null)?.let { return it as SecretKey }

        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    fun encrypt(plainText: String, allowDeviceCredential: Boolean): String {
        val key = getOrCreateKey(allowDeviceCredential)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encrypted = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        val iv = cipher.iv
        val ivBase64 = Base64.encodeToString(iv, Base64.NO_WRAP)
        val encryptedBase64 = Base64.encodeToString(encrypted, Base64.NO_WRAP)
        return "$ivBase64:$encryptedBase64"
    }

    fun getDecryptCipher(cipherText: String, allowDeviceCredential: Boolean): Pair<Cipher, ByteArray> {
        val parts = cipherText.split(":")
        if (parts.size != 2) throw IllegalArgumentException("Invalid ciphertext format")
        val iv = Base64.decode(parts[0], Base64.NO_WRAP)
        val encrypted = Base64.decode(parts[1], Base64.NO_WRAP)
        val key = getOrCreateKey(allowDeviceCredential)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH, iv))
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
}
