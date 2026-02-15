package com.prongbang.local_auth_crypto

import android.os.Build
import androidx.annotation.NonNull
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.util.concurrent.Executors

class LocalAuthCryptoPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
    private lateinit var channel: MethodChannel
    private var activity: FragmentActivity? = null

    override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "local_auth_crypto")
        channel.setMethodCallHandler(this)
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        val allowDeviceCredential = call.argument<Boolean>(LocalAuthArgs.ALLOW_DEVICE_CREDENTIAL) ?: false

        when (call.method) {
            LocalAuthMethod.ENCRYPT -> {
                val payload = call.argument<String?>(LocalAuthArgs.BIO_PAYLOAD)
                if (payload == null) {
                    result.error("E01", "Biometric token is null", null)
                    return
                }
                try {
                    val cipherText = CryptoHelper.encrypt(payload, allowDeviceCredential)
                    result.success(cipherText)
                } catch (e: Exception) {
                    result.error("E01", "Encryption failed: ${e.message}", null)
                }
            }
            LocalAuthMethod.AUTHENTICATE -> {
                val cipherText = call.argument<String?>(LocalAuthArgs.BIO_CIPHER_TEXT)
                if (cipherText == null) {
                    result.error("E03", "Cipher is null", null)
                    return
                }
                val currentActivity = activity
                if (currentActivity == null) {
                    result.error("E02", "Activity is null", null)
                    return
                }

                val title = call.argument<String?>(LocalAuthArgs.BIO_TITLE) ?: ""
                val subtitle = call.argument<String?>(LocalAuthArgs.BIO_SUBTITLE) ?: ""
                val description = call.argument<String?>(LocalAuthArgs.BIO_DESCRIPTION) ?: ""
                val negativeButton = call.argument<String?>(LocalAuthArgs.BIO_NEGATIVE_BUTTON) ?: "Cancel"

                try {
                    val (cipher, encryptedData) = CryptoHelper.getDecryptCipher(cipherText, allowDeviceCredential)

                    val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
                        .setTitle(title)
                        .setSubtitle(subtitle)
                        .setDescription(description)

                    if (allowDeviceCredential) {
                        promptInfoBuilder.setAllowedAuthenticators(
                            Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
                        )
                    } else {
                        promptInfoBuilder.setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
                        promptInfoBuilder.setNegativeButtonText(negativeButton)
                    }

                    val promptInfo = promptInfoBuilder.build()
                    val executor = Executors.newSingleThreadExecutor()

                    val callback = object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
                            try {
                                val plainText = if (allowDeviceCredential && Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
                                    // Pre-API 30 with credential: auth without CryptoObject, use time-based key
                                    CryptoHelper.decryptFromCipherText(cipherText, allowDeviceCredential)
                                } else {
                                    val authenticatedCipher = authResult.cryptoObject?.cipher ?: cipher
                                    CryptoHelper.decrypt(authenticatedCipher, encryptedData)
                                }
                                result.success(plainText)
                            } catch (e: Exception) {
                                result.error("E04", "Decryption failed: ${e.message}", null)
                            }
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                                errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                                result.error("E05", "Authenticate is cancel", null)
                            } else {
                                result.error("E04", "Authenticate is error: $errString", null)
                            }
                        }

                        override fun onAuthenticationFailed() {
                            // Called on individual failed attempt; prompt stays open
                        }
                    }

                    val biometricPrompt = BiometricPrompt(currentActivity, executor, callback)

                    if (allowDeviceCredential && Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
                        // Pre-API 30: authenticate without CryptoObject
                        currentActivity.runOnUiThread {
                            biometricPrompt.authenticate(promptInfo)
                        }
                    } else {
                        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
                        currentActivity.runOnUiThread {
                            biometricPrompt.authenticate(promptInfo, cryptoObject)
                        }
                    }
                } catch (e: Exception) {
                    result.error("E04", "Authentication setup failed: ${e.message}", null)
                }
            }
            LocalAuthMethod.EVALUATE_POLICY -> {
                val currentActivity = activity
                if (currentActivity == null) {
                    result.success(false)
                    return
                }
                val biometricManager = BiometricManager.from(currentActivity)
                val authenticators = if (allowDeviceCredential) {
                    Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
                } else {
                    Authenticators.BIOMETRIC_STRONG
                }
                val canAuthenticate = biometricManager.canAuthenticate(authenticators)
                result.success(canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS)
            }
            else -> {
                result.notImplemented()
            }
        }
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        activity = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onDetachedFromActivityForConfigChanges() {}

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity as? FragmentActivity
    }

    override fun onDetachedFromActivity() {}
}
