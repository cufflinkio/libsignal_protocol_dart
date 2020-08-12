import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:meta/meta.dart';

abstract class CurveAlgorithm {
  Future<KeyPair> newKeyPairSync();

  SecretKey sharedSecretSync({
    @required PrivateKey localPrivateKey,
    @required PublicKey remotePublicKey,
  });

  Future<Uint8List> sign(Uint8List privateKey, Uint8List message);

  Future<bool> verify(
      Uint8List publicKey, Uint8List message, Uint8List signature);
}
