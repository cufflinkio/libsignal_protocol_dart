import 'package:collection/collection.dart';

import 'package:libsignal_protocol_dart/libsignal_protocol_dart.dart';
import 'package:test/test.dart';

void main() {
  test('should implement interface successfully', () {
    final address1 = SignalProtocolAddress('address-1', 123);
    final address2a = SignalProtocolAddress('address-2', 123);
    final address2b = SignalProtocolAddress('address-2', 456);
    final store = InMemorySessionStore();

    // containsSession & loadSession
    expect(store.containsSession(address1), false);
    final sessionRecord1 = store.loadSession(address1);
    store.storeSession(address1, sessionRecord1);
    expect(store.containsSession(address1), true);

    // loadSession & storeSession
    final sessionRecord2 = store.loadSession(address1);
    store.storeSession(address2a, sessionRecord2);
    store.storeSession(address2b, sessionRecord2);

    // getSubDeviceSessions
    final subDeviceSessions1 = store.getSubDeviceSessions(address1.getName());
    expect(subDeviceSessions1.length, 1);
    expect(subDeviceSessions1, [123]);
    final subDeviceSessions2 = store.getSubDeviceSessions(address2a.getName());
    expect(subDeviceSessions2.length, 2);
    expect(
        SetEquality().equals(
          subDeviceSessions2.toSet(),
          {123, 456}.toSet(),
        ),
        true);

    // deleteSession & containsSession
    expect(store.containsSession(address2a), true);
    store.deleteSession(address2a);
    expect(store.containsSession(address2a), false);

    // deleteAllSessions & containsSession
    expect(store.containsSession(address2b), true);
    store.deleteAllSessions(address2b.getName());
    expect(store.containsSession(address2b), false);
  });
}
