import 'package:cryptography/cryptography.dart';
import 'package:cryptography/src/secret_key.dart';
import 'package:cryptography/src/public_key.dart';
import 'package:cryptography/src/private_key.dart';
import 'package:cryptography/src/key_pair.dart';
import 'dart:typed_data';
import 'package:meta/meta.dart';
import 'package:libsignal_protocol_dart/src/ecc/CurveAlgorithm.dart';
import 'package:pm_curve25519/pm_curve25519.dart';

class CurveAlgorithmPmCurve25519 implements CurveAlgorithm {
  @override
  Future<KeyPair> newKeyPairSync() async {
    final pmKeyPair = await PmCurve25519.generateIdentityPair();
    return KeyPair(
      publicKey: PublicKey(pmKeyPair.publicKey),
      privateKey: PrivateKey(pmKeyPair.secretKey),
    );
  }

  @override
  SecretKey sharedSecretSync(
      {@required PrivateKey localPrivateKey,
      @required PublicKey remotePublicKey}) {
    throw UnimplementedError();
  }

  @override
  Future<Uint8List> sign(Uint8List privateKey, Uint8List message) =>
      PmCurve25519.getSignature(message, privateKey);

  @override
  Future<bool> verify(
      Uint8List publicKey, Uint8List message, Uint8List signature) {
    return PmCurve25519.verifySignature(publicKey, message, signature);
  }
}
