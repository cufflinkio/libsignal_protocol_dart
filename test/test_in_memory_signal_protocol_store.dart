import 'package:libsignal_protocol_dart/src/IdentityKey.dart';
import 'package:libsignal_protocol_dart/src/IdentityKeyPair.dart';
import 'package:libsignal_protocol_dart/src/ecc/Curve.dart';
import 'package:libsignal_protocol_dart/src/state/impl/InMemorySignalProtocolStore.dart';
import 'package:libsignal_protocol_dart/src/util/KeyHelper.dart';

class TestInMemorySignalProtocolStore extends InMemorySignalProtocolStore {
  static Future<TestInMemorySignalProtocolStore> create() async {
    return TestInMemorySignalProtocolStore._(
        await _generateIdentityKeyPair(), _generateRegistrationId());
  }

  TestInMemorySignalProtocolStore._(
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
