import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:local_auth_crypto/local_auth_crypto.dart';

/// An implementation of [LocalAuthCrypto] that uses method channels.
class MethodChannelLocalAuthCrypto extends LocalAuthCrypto {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('local_auth_crypto');

  @override
  Future<String?> encrypt(
    String payload, {
    bool allowDeviceCredential = false,
  }) async {
    return await methodChannel.invokeMethod('encrypt', {
      'payload': payload,
      'allowDeviceCredential': allowDeviceCredential,
    });
  }

  @override
  Future<String?> authenticate(
    BiometricPromptInfo promptInfo,
    String cipherText, {
    bool allowDeviceCredential = false,
  }) async {
    dynamic arguments = {
      'cipherText': cipherText,
      'allowDeviceCredential': allowDeviceCredential,
    };
    if (promptInfo.title != null) {
      arguments['title'] = promptInfo.title;
    }
    if (promptInfo.subtitle != null) {
      arguments['subtitle'] = promptInfo.subtitle;
    }
    if (promptInfo.description != null) {
      arguments['description'] = promptInfo.description;
    }
    if (promptInfo.negativeButton != null) {
      arguments['negativeButton'] = promptInfo.negativeButton;
    }
    return await methodChannel.invokeMethod('authenticate', arguments);
  }

  @override
  Future<bool?> evaluatePolicy(
    String reason, {
    bool allowDeviceCredential = false,
  }) async {
    return await methodChannel.invokeMethod('evaluatePolicy', {
      'reason': reason,
      'allowDeviceCredential': allowDeviceCredential,
    });
  }
}
