import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart'
    as libsignal;

import 'curve_algorithm_pm_curve25519.dart';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  MyApp({Key key}) : super(key: key) {
    WidgetsFlutterBinding.ensureInitialized();
    _createSignatureAndVerify();
  }

  Future<void> _createSignatureAndVerify() async {
    libsignal.Curve.algorithm = CurveAlgorithmPmCurve25519();
    libsignal.ECKeyPair keyPair = await libsignal.Curve.generateKeyPair();
    print('publicKey=${keyPair.publicKey.serialize()}');
    print('privateKey=${keyPair.privateKey.serialize()}');
    var message = Uint8List.fromList(List.generate(32, (index) => index));
    var signature =
        await libsignal.Curve.calculateSignature(keyPair.privateKey, message);
    print('signature=$signature');

    var verified = await libsignal.Curve.verifySignature(
      keyPair.publicKey,
      message,
      signature,
    );
    print('verified=$verified');
  }

  @override
  Widget build(BuildContext context) => Container();
}
