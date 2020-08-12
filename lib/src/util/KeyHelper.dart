import 'dart:math';
import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:pointycastle/api.dart';

import '../IdentityKey.dart';
import '../IdentityKeyPair.dart';
import '../ecc/Curve.dart';
import '../ecc/ECKeyPair.dart';
import '../state/PreKeyRecord.dart';
import '../state/SignedPreKeyRecord.dart';
import 'Medium.dart';

class KeyHelper {
  static Future<IdentityKeyPair> generateIdentityKeyPair() async {
    var keyPair = await Curve.generateKeyPair();
    var publicKey = IdentityKey(keyPair.publicKey);
    return IdentityKeyPair(publicKey, keyPair.privateKey);
  }

  static int integerMax = 0x7fffffff;

  static int generateRegistrationId(bool extendedRange) {
    final secureRandom = Random.secure();
    if (extendedRange) {
      return secureRandom.nextInt(integerMax - 1) + 1;
    } else {
      return secureRandom.nextInt(16380) + 1;
    }
  }

  static Future<List<PreKeyRecord>> generatePreKeys(
      int start, int count) async {
    var results = <PreKeyRecord>[];
    start--;
    for (var i = 0; i < count; i++) {
      results.add(PreKeyRecord(((start + i) % (Medium.MAX_VALUE - 1)) + 1,
          await Curve.generateKeyPair()));
    }
    return results;
  }

  static Future<SignedPreKeyRecord> generateSignedPreKey(
      IdentityKeyPair identityKeyPair, int signedPreKeyId) async {
    var keyPair = await Curve.generateKeyPair();
    var signature = await Curve.calculateSignature(
        identityKeyPair.getPrivateKey(), keyPair.publicKey.serialize());

    return SignedPreKeyRecord(signedPreKeyId,
        Int64(DateTime.now().millisecondsSinceEpoch), keyPair, signature);
  }

  static Future<ECKeyPair> generateSenderSigningKey() {
    return Curve.generateKeyPair();
  }

  static Uint8List generateSenderKey() {
    var secureRandom = SecureRandom("AES/CTR/AUTO-SEED-PRNG");
    final key = Uint8List(32);
    final keyParam = KeyParameter(key);
    secureRandom.seed(keyParam);
    return secureRandom.nextBytes(32);
  }

  static int generateSenderKeyId() {
    final secureRandom = Random.secure();
    return secureRandom.nextInt(integerMax);
  }
}
