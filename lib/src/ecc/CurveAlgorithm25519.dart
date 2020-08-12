import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/secret_key.dart';
import 'package:cryptography/src/public_key.dart';
import 'package:cryptography/src/private_key.dart';
import 'package:cryptography/src/key_pair.dart';
import 'dart:typed_data';
import 'package:meta/meta.dart';

import 'CurveAlgorithm.dart';
import 'SignCurve25519.dart' as curve;

class CurveAlgorithmX25519 implements CurveAlgorithm {
  @override
  Future<KeyPair> newKeyPairSync() => Future.value(x25519.newKeyPairSync());

  @override
  SecretKey sharedSecretSync(
      {@required PrivateKey localPrivateKey,
      @required PublicKey remotePublicKey}) {
    return x25519.sharedSecretSync(
        localPrivateKey: localPrivateKey, remotePublicKey: remotePublicKey);
  }

  @override
  Future<Uint8List> sign(Uint8List privateKey, Uint8List message) {
    return Future.value(curve.sign(privateKey, message));
  }

  @override
  Future<bool> verify(
      Uint8List publicKey, Uint8List message, Uint8List signature) {
    return Future.value(curve.verify(publicKey, message, signature));
  }
}
