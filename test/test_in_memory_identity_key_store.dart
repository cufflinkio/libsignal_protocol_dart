import 'package:libsignal_protocol_dart/src/IdentityKey.dart';
import 'package:libsignal_protocol_dart/src/IdentityKeyPair.dart';
import 'package:libsignal_protocol_dart/src/ecc/Curve.dart';
import 'package:libsignal_protocol_dart/src/state/impl/InMemoryIdentityKeyStore.dart';
import 'package:libsignal_protocol_dart/src/util/KeyHelper.dart';

class TestInMemoryIdentityKeyStore extends InMemoryIdentityKeyStore {
  static Future<TestInMemoryIdentityKeyStore> create() async {
    return TestInMemoryIdentityKeyStore._(
        await _generateIdentityKeyPair(), _generateRegistrationId());
  }

  TestInMemoryIdentityKeyStore._(
      IdentityKeyPair identityKeyPair, int registrationId)
      : super(identityKeyPair, registrationId);

  static Future<IdentityKeyPair> _generateIdentityKeyPair() async {
    var identityKeyPairKeys = await Curve.generateKeyPair();

    return IdentityKeyPair(IdentityKey(identityKeyPairKeys.publicKey),
        identityKeyPairKeys.privateKey);
  }

  static int _generateRegistrationId() {
    return KeyHelper.generateRegistrationId(false);
  }
}
