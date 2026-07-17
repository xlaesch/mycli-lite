from __future__ import annotations

import ast
import base64
import hashlib
import io
from pathlib import Path
import socket
import struct
import subprocess
import sys
from typing import Any

import pytest

import mycli_lite

ROOT = Path(__file__).parents[1]
NONCE = b'12345678abcdefgh1234'
CAPABILITIES = (
    mycli_lite.CLIENT_LONG_PASSWORD
    | mycli_lite.CLIENT_LONG_FLAG
    | mycli_lite.CLIENT_PROTOCOL_41
    | mycli_lite.CLIENT_INTERACTIVE
    | mycli_lite.CLIENT_SSL
    | mycli_lite.CLIENT_TRANSACTIONS
    | mycli_lite.CLIENT_SECURE_CONNECTION
    | mycli_lite.CLIENT_MULTI_STATEMENTS
    | mycli_lite.CLIENT_MULTI_RESULTS
    | mycli_lite.CLIENT_PLUGIN_AUTH
    | mycli_lite.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | mycli_lite.CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
    | mycli_lite.CLIENT_CONNECT_WITH_DB
)


def frame(payload: bytes, sequence_id: int) -> bytes:
    return len(payload).to_bytes(3, 'little') + bytes((sequence_id,)) + payload


def lenenc(value: int | None) -> bytes:
    if value is None:
        return b'\xfb'
    if value < 0xFB:
        return bytes((value,))
    if value <= 0xFFFF:
        return b'\xfc' + value.to_bytes(2, 'little')
    if value <= 0xFFFFFF:
        return b'\xfd' + value.to_bytes(3, 'little')
    return b'\xfe' + value.to_bytes(8, 'little')


def lenenc_bytes(value: bytes | None) -> bytes:
    return lenenc(None) if value is None else lenenc(len(value)) + value


def greeting(plugin: bytes = b'mysql_native_password', capabilities: int = CAPABILITIES) -> bytes:
    return (
        b'\x0a8.0.36-test\0'
        + struct.pack('<I', 1234)
        + NONCE[:8]
        + b'\0'
        + struct.pack('<H', capabilities & 0xFFFF)
        + b'\x2d'
        + struct.pack('<H', 2)
        + struct.pack('<H', capabilities >> 16)
        + bytes((len(NONCE) + 1,))
        + b'\0' * 10
        + NONCE[8:]
        + b'\0'
        + plugin
        + b'\0'
    )


def ok_packet(
    *,
    affected_rows: int = 0,
    insert_id: int = 0,
    status: int = 2,
    warnings: int = 0,
    info: bytes = b'',
) -> bytes:
    return b'\x00' + lenenc(affected_rows) + lenenc(insert_id) + struct.pack('<HH', status, warnings) + info


def eof_packet(*, status: int = 2, warnings: int = 0) -> bytes:
    return b'\xfe' + struct.pack('<HH', warnings, status)


def column_packet(name: bytes, *, charset_id: int = 45, type_code: int = 0xFD) -> bytes:
    values = (b'def', b'test', b't', b't', name, name)
    return b''.join(lenenc_bytes(value) for value in values) + b'\x0c' + struct.pack('<HIBHBH', charset_id, 1024, type_code, 0, 0, 0)


class ScriptedSocket:
    def __init__(self, incoming: bytes, *, read_size: int = 2) -> None:
        self.incoming = bytearray(incoming)
        self.read_size = read_size
        self.sent: list[bytes] = []
        self.closed = False
        self.options: list[tuple[int, int, int]] = []
        self.timeouts: list[float | None] = []

    def recv(self, size: int) -> bytes:
        if not self.incoming:
            return b''
        size = min(size, self.read_size, len(self.incoming))
        result = bytes(self.incoming[:size])
        del self.incoming[:size]
        return result

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))

    def settimeout(self, timeout: float | None) -> None:
        self.timeouts.append(timeout)

    def close(self) -> None:
        self.closed = True


class FakePackets:
    def __init__(self, reads: list[bytes]) -> None:
        self.reads = iter(reads)
        self.writes: list[bytes] = []

    def read_packet(self) -> bytes:
        return next(self.reads)

    def write_packet(self, payload: bytes) -> None:
        self.writes.append(payload)


@pytest.mark.parametrize(
    ('value', 'encoded'),
    [
        (0, b'\x00'),
        (250, b'\xfa'),
        (251, b'\xfc\xfb\x00'),
        (65535, b'\xfc\xff\xff'),
        (65536, b'\xfd\x00\x00\x01'),
        (16777215, b'\xfd\xff\xff\xff'),
        (16777216, b'\xfe\x00\x00\x00\x01\x00\x00\x00\x00'),
        (2**64 - 1, b'\xfe' + b'\xff' * 8),
    ],
)
def test_length_encoded_integer_boundaries(value: int, encoded: bytes) -> None:
    assert mycli_lite._encode_lenenc_int(value) == encoded
    assert mycli_lite._read_lenenc_int(encoded) == (value, len(encoded))


@pytest.mark.parametrize('encoded', [b'', b'\xfc', b'\xfc\x01', b'\xfd\x01\x02', b'\xfe' + b'\0' * 7])
def test_length_encoded_integer_rejects_truncation(encoded: bytes) -> None:
    with pytest.raises(mycli_lite.ProtocolError, match='truncated'):
        mycli_lite._read_lenenc_int(encoded)


def test_null_marker_is_context_sensitive() -> None:
    with pytest.raises(mycli_lite.ProtocolError, match='NULL'):
        mycli_lite._read_lenenc_int(b'\xfb')
    assert mycli_lite._read_lenenc_int(b'\xfb', allow_null=True) == (None, 1)


def test_packet_io_handles_partial_reads_and_sequence_wrap() -> None:
    sock = ScriptedSocket(frame(b'abcde', 255) + frame(b'f', 0), read_size=1)
    packets = mycli_lite.PacketIO(sock, fragment_size=5)
    packets.sequence_id = 255
    assert packets.read_packet() == b'abcdef'
    assert packets.sequence_id == 1


def test_packet_io_writes_empty_terminator_for_exact_fragment() -> None:
    sock = ScriptedSocket(b'')
    packets = mycli_lite.PacketIO(sock, fragment_size=5)
    packets.write_packet(b'abcde')
    assert sock.sent == [frame(b'abcde', 0), frame(b'', 1)]


def test_packet_io_rejects_oversized_outgoing_message() -> None:
    sock = ScriptedSocket(b'')
    packets = mycli_lite.PacketIO(sock, fragment_size=5, max_message_size=6)
    with pytest.raises(mycli_lite.ProtocolError, match='logical packet'):
        packets.write_packet(b'1234567')
    assert sock.sent == []


def test_packet_io_rejects_sequence_mismatch() -> None:
    packets = mycli_lite.PacketIO(ScriptedSocket(frame(b'x', 7)))
    with pytest.raises(mycli_lite.ProtocolError, match='sequence mismatch'):
        packets.read_packet()


def test_parse_protocol_v10_greeting() -> None:
    parsed = mycli_lite._parse_handshake(greeting())
    assert parsed == mycli_lite.Handshake(
        server_version='8.0.36-test',
        connection_id=1234,
        capabilities=CAPABILITIES,
        charset_id=45,
        status_flags=2,
        auth_data=NONCE,
        auth_plugin='mysql_native_password',
    )


def test_parse_greeting_rejects_old_protocol() -> None:
    with pytest.raises(mycli_lite.ProtocolError, match='protocol version'):
        mycli_lite._parse_handshake(b'\x09')


def test_auth_scrambles_match_known_answers() -> None:
    assert mycli_lite._scramble_native_password(b'secret', NONCE).hex() == '56787bb5faec2e23a51adb3ba35c584f75980fca'
    assert mycli_lite._scramble_caching_sha2(b'secret', NONCE).hex() == '0fe2d675b3fe1a8bf061f6c614a1774b5cdcc1c4faa6e275ab24568397253abf'
    assert mycli_lite._scramble_native_password(b'', NONCE) == b''
    assert mycli_lite._scramble_caching_sha2(b'', NONCE) == b''


def test_capabilities_are_intersected_with_server() -> None:
    connection = mycli_lite.Connection(database='db', ssl_mode='disabled')
    server_capabilities = CAPABILITIES & ~mycli_lite.CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
    handshake = mycli_lite._parse_handshake(greeting(capabilities=server_capabilities))
    chosen = connection._choose_capabilities(handshake, use_tls=False)
    assert chosen & ~server_capabilities == 0
    assert chosen & mycli_lite.CLIENT_CONNECT_WITH_DB
    assert not chosen & mycli_lite.CLIENT_SSL
    assert not chosen & mycli_lite.CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS


def test_handshake_response_layout_and_password_redaction() -> None:
    connection = mycli_lite.Connection(user='alice', password='secret', database='inventory', ssl_mode='disabled')
    handshake = mycli_lite._parse_handshake(greeting())
    connection.client_capabilities = connection._choose_capabilities(handshake, use_tls=False)
    response = connection._build_handshake_response(handshake.auth_plugin, handshake.auth_data)
    assert struct.unpack_from('<I', response)[0] == connection.client_capabilities
    assert response[4:8] == mycli_lite.MAX_PACKET_PAYLOAD.to_bytes(4, 'little')
    assert response[8] == 45
    assert response[9:32] == b'\0' * 23
    assert response[32:].startswith(b'alice\0\x14')
    assert response.endswith(b'inventory\0mysql_native_password\0')
    assert b'secret' not in response
    assert 'secret' not in repr(connection)


def test_caching_sha2_fast_auth_reads_final_ok() -> None:
    connection = connected_for_auth([b'\x01\x03', ok_packet()])
    connection._authenticate('caching_sha2_password', NONCE)
    packets: Any = connection._packets
    assert packets is not None
    assert packets.writes == []


def test_caching_sha2_full_auth_sends_password_only_on_secure_transport() -> None:
    connection = connected_for_auth([b'\x01\x04', ok_packet()], secure=True)
    connection._authenticate('caching_sha2_password', NONCE)
    packets: Any = connection._packets
    assert packets is not None
    assert packets.writes == [b'secret\0']


def test_caching_sha2_full_auth_fails_closed_on_plaintext_tcp() -> None:
    connection = connected_for_auth([b'\x01\x04'])
    with pytest.raises(mycli_lite.AuthenticationError, match='get-server-public-key'):
        connection._authenticate('caching_sha2_password', NONCE)
    packets: Any = connection._packets
    assert packets is not None
    assert packets.writes == []


def test_auth_switch_uses_requested_plugin_and_nonce() -> None:
    switched_nonce = b'zyxwvutsrqponmlkjihg'
    switch = b'\xfe' + b'mysql_native_password\0' + switched_nonce + b'\0'
    connection = connected_for_auth([switch, ok_packet()])
    connection._authenticate('caching_sha2_password', NONCE)
    packets: Any = connection._packets
    assert packets is not None
    assert packets.writes == [mycli_lite._scramble_native_password(b'secret', switched_nonce)]


def test_clear_password_auth_switch_needs_no_nonce_but_requires_secure_opt_in() -> None:
    switch = b'\xfemysql_clear_password\0'
    connection = connected_for_auth([switch, ok_packet()], secure=True)
    connection.allow_cleartext_plugin = True
    connection._authenticate('mysql_native_password', NONCE)
    packets: Any = connection._packets
    assert packets is not None
    assert packets.writes == [b'secret\0']


def connected_for_auth(reads: list[bytes], *, secure: bool = False) -> mycli_lite.Connection:
    connection = mycli_lite.Connection(password='secret', ssl_mode='disabled')
    connection._socket = ScriptedSocket(b'')  # type: ignore[assignment]
    connection._packets = FakePackets(reads)  # type: ignore[assignment]
    connection._closed = False
    connection._secure = secure
    return connection


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes((0x80 | len(encoded),)) + encoded


def der_value(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + der_length(len(value)) + value


def der_integer(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if encoded[0] & 0x80:
        encoded = b'\0' + encoded
    return der_value(0x02, encoded)


RSA_MODULUS = int(
    'e8463ff02787a275d82448d2a561c97186243e28abbb332e39bed14ca0bd8419'
    'bc99436880e92a83b1550884a49db22e06c67d74cb8bbd266491cfadcea04980'
    '8f33875d843de6e875380cc75455266e8170a822f2155856a70d8c92e8e4984b'
    'c06d5e1a9b634c05dcd8c041778ed45c1742c2d9b49589470c6bc05bf33182a1',
    16,
)
RSA_PRIVATE_EXPONENT = int(
    '8bd6bf67b664d24a607677e159f02577536b3e80fde3164d1e36e38b5ebaba6d'
    '443e8176c9259792f19060307b6af57b00593feeb11cd023ed285c0028061839'
    '485ebd26279873435ced545959d73ea3f55b05c856d50147652a2da63f9c6190'
    '7ffb80b67d4961a0473bebef957459f4539d92cbb11f72be5ed8d3aa80c45a81',
    16,
)


def rsa_public_key_pem() -> bytes:
    sequence = der_value(0x30, der_integer(RSA_MODULUS) + der_integer(65537))
    body = base64.encodebytes(sequence).replace(b'\n', b'')
    wrapped = b'\n'.join(body[index : index + 64] for index in range(0, len(body), 64))
    return b'-----BEGIN RSA PUBLIC KEY-----\n' + wrapped + b'\n-----END RSA PUBLIC KEY-----\n'


def spki_public_key_pem() -> bytes:
    pkcs1 = der_value(0x30, der_integer(RSA_MODULUS) + der_integer(65537))
    rsa_algorithm = der_value(0x30, bytes.fromhex('06092a864886f70d0101010500'))
    sequence = der_value(0x30, rsa_algorithm + der_value(0x03, b'\0' + pkcs1))
    body = base64.encodebytes(sequence).replace(b'\n', b'')
    wrapped = b'\n'.join(body[index : index + 64] for index in range(0, len(body), 64))
    return b'-----BEGIN PUBLIC KEY-----\n' + wrapped + b'\n-----END PUBLIC KEY-----\n'


def test_pure_python_rsa_oaep_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mycli_lite.os, 'urandom', lambda size: b'Z' * size)
    plaintext = b'secret\0'
    encrypted = mycli_lite._rsa_oaep_encrypt(plaintext, rsa_public_key_pem())
    assert len(encrypted) == 128
    encoded = pow(int.from_bytes(encrypted, 'big'), RSA_PRIVATE_EXPONENT, RSA_MODULUS).to_bytes(128, 'big')
    assert encoded[0] == 0
    masked_seed = encoded[1:21]
    masked_block = encoded[21:]
    seed = bytes(left ^ right for left, right in zip(masked_seed, independent_mgf1(masked_block, 20), strict=True))
    data_block = bytes(left ^ right for left, right in zip(masked_block, independent_mgf1(seed, len(masked_block)), strict=True))
    assert data_block[:20] == hashlib.sha1(b'', usedforsecurity=False).digest()
    assert data_block[data_block.index(b'\x01', 20) + 1 :] == plaintext


def test_spki_public_key_and_trailing_nul_are_accepted() -> None:
    assert mycli_lite._parse_rsa_public_key(spki_public_key_pem() + b'\0') == (
        RSA_MODULUS,
        65537,
    )


def test_caching_sha2_requested_and_pinned_rsa_flows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mycli_lite.os, 'urandom', lambda size: b'R' * size)
    requested = connected_for_auth([b'\x01\x04', b'\x01' + spki_public_key_pem(), ok_packet()])
    requested.get_server_public_key = True
    requested._authenticate('caching_sha2_password', NONCE)
    requested_packets: Any = requested._packets
    assert requested_packets.writes[0] == b'\x02'
    assert len(requested_packets.writes[1]) == 128
    assert b'secret' not in requested_packets.writes[1]

    pinned = connected_for_auth([b'\x01\x04', ok_packet()])
    pinned.server_public_key = spki_public_key_pem()
    pinned._authenticate('caching_sha2_password', NONCE)
    pinned_packets: Any = pinned._packets
    assert len(pinned_packets.writes) == 1
    assert len(pinned_packets.writes[0]) == 128


def test_sha256_password_initial_and_public_key_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mycli_lite.os, 'urandom', lambda size: b'S' * size)
    pinned = mycli_lite.Connection(password='secret', server_public_key=spki_public_key_pem(), ssl_mode='disabled')
    initial_response = pinned._initial_auth_response('sha256_password', NONCE)
    assert len(initial_response) == 128
    assert b'secret' not in initial_response

    requested = connected_for_auth([b'\x01' + spki_public_key_pem(), ok_packet()])
    requested.get_server_public_key = True
    requested._authenticate('sha256_password', NONCE)
    requested_packets: Any = requested._packets
    assert len(requested_packets.writes) == 1
    assert len(requested_packets.writes[0]) == 128


def independent_mgf1(seed: bytes, length: int) -> bytes:
    blocks: list[bytes] = []
    for counter in range((length + 19) // 20):
        blocks.append(hashlib.sha1(seed + counter.to_bytes(4, 'big'), usedforsecurity=False).digest())
    return b''.join(blocks)[:length]


def test_full_native_handshake_query_and_quit(monkeypatch: pytest.MonkeyPatch) -> None:
    response = bytearray()
    response.extend(frame(greeting(capabilities=CAPABILITIES & ~mycli_lite.CLIENT_SSL), 0))
    response.extend(frame(ok_packet(), 2))
    response.extend(frame(b'\x03', 1))
    response.extend(frame(column_packet(b'text'), 2))
    response.extend(frame(column_packet(b'blob', charset_id=63), 3))
    response.extend(frame(column_packet(b'nothing'), 4))
    response.extend(frame(eof_packet(), 5))
    response.extend(frame(lenenc_bytes(b'hello\n') + lenenc_bytes(b'\0\xff') + lenenc_bytes(None), 6))
    response.extend(frame(eof_packet(), 7))
    scripted_socket = ScriptedSocket(bytes(response), read_size=1)
    calls: list[tuple[tuple[str, int], float]] = []

    def fake_create_connection(address: tuple[str, int], timeout: float) -> socket.socket:
        calls.append((address, timeout))
        return scripted_socket  # type: ignore[return-value]

    monkeypatch.setattr(mycli_lite.socket, 'create_connection', fake_create_connection)
    connection = mycli_lite.Connection(host='db.example', user='alice', password='secret', ssl_mode='disabled', connect_timeout=3)
    connection.connect()
    results = connection.query('SELECT text, blob, nothing FROM t')
    connection.close()

    assert calls == [(('db.example', 3306), 3)]
    assert results[0].rows == [('hello\n', b'\0\xff', None)]
    assert [column.name for column in results[0].columns] == ['text', 'blob', 'nothing']
    assert scripted_socket.incoming == b''
    assert scripted_socket.closed
    assert scripted_socket.timeouts[-1] is None
    assert scripted_socket.sent[1] == frame(b'\x03SELECT text, blob, nothing FROM t', 0)
    assert scripted_socket.sent[2] == frame(b'\x01', 0)
    handshake_response = scripted_socket.sent[0][4:]
    assert b'secret' not in handshake_response


def test_tls_request_precedes_wrapping_and_handshake_response(monkeypatch: pytest.MonkeyPatch) -> None:
    response = frame(greeting(), 0) + frame(ok_packet(), 3)
    scripted_socket = ScriptedSocket(response)
    events: list[str] = []

    def fake_create_connection(_address: tuple[str, int], _timeout: float) -> socket.socket:
        return scripted_socket  # type: ignore[return-value]

    class FakeSSLContext:
        def wrap_socket(self, sock: socket.socket, *, server_hostname: str) -> socket.socket:
            assert server_hostname == 'db.example'
            assert len(scripted_socket.sent) == 1
            events.append('wrapped')
            return sock

    monkeypatch.setattr(mycli_lite.socket, 'create_connection', fake_create_connection)
    monkeypatch.setattr(mycli_lite.Connection, '_create_ssl_context', lambda _self: FakeSSLContext())
    connection = mycli_lite.Connection(host='db.example', user='alice', password='secret', ssl_mode='required')
    connection.connect()

    assert events == ['wrapped']
    assert scripted_socket.sent[0][3] == 1
    assert len(scripted_socket.sent[0][4:]) == 32
    ssl_flags = struct.unpack_from('<I', scripted_socket.sent[0], 4)[0]
    assert ssl_flags & mycli_lite.CLIENT_SSL
    assert scripted_socket.sent[1][3] == 2
    assert b'alice\0' in scripted_socket.sent[1]
    assert b'secret' not in scripted_socket.sent[1]
    connection.close()


def test_cold_caching_sha2_password_is_plaintext_only_after_tls_wrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = ScriptedSocket(frame(greeting(plugin=b'caching_sha2_password'), 0))
    wrapped_socket = ScriptedSocket(frame(b'\x01\x04', 3) + frame(ok_packet(), 5))

    def fake_create_connection(_address: tuple[str, int], _timeout: float) -> socket.socket:
        return raw_socket  # type: ignore[return-value]

    class FakeSSLContext:
        def wrap_socket(self, _sock: socket.socket, *, server_hostname: str) -> socket.socket:
            assert server_hostname == 'db.example'
            assert len(raw_socket.sent) == 1
            return wrapped_socket  # type: ignore[return-value]

    monkeypatch.setattr(mycli_lite.socket, 'create_connection', fake_create_connection)
    monkeypatch.setattr(mycli_lite.Connection, '_create_ssl_context', lambda _self: FakeSSLContext())
    connection = mycli_lite.Connection(host='db.example', user='alice', password='secret', ssl_mode='required')
    connection.connect()

    assert len(raw_socket.sent) == 1
    assert b'secret' not in raw_socket.sent[0]
    assert wrapped_socket.sent[0][3] == 2
    assert b'secret' not in wrapped_socket.sent[0]
    assert wrapped_socket.sent[1] == frame(b'secret\0', 4)
    assert wrapped_socket.timeouts[-1] is None
    connection.close()


def test_charset_63_only_preserves_binary_capable_types() -> None:
    columns = (
        mycli_lite.Column('number', '', '', '', '', 63, 0x03, 0),
        mycli_lite.Column('date', '', '', '', '', 63, 0x0A, 0),
        mycli_lite.Column('json', '', '', '', '', 63, 0xF5, 0),
        mycli_lite.Column('varchar', '', '', '', '', 63, mycli_lite.MYSQL_TYPE_VARCHAR, 0),
        mycli_lite.Column('blob', '', '', '', '', 63, mycli_lite.MYSQL_TYPE_BLOB, 0),
    )
    connection = mycli_lite.Connection(ssl_mode='disabled')
    payload = b''.join(lenenc_bytes(value) for value in (b'12', b'2026-07-16', b'{"ok": true}', b'\xfe\xff', b'\x00\xff'))
    assert connection._parse_row(payload, columns) == (
        '12',
        '2026-07-16',
        '{"ok": true}',
        b'\xfe\xff',
        b'\x00\xff',
    )


def test_protocol_failure_invalidates_connection() -> None:
    sock = ScriptedSocket(frame(ok_packet(), 7))
    connection = mycli_lite.Connection(ssl_mode='disabled')
    connection._socket = sock  # type: ignore[assignment]
    connection._packets = mycli_lite.PacketIO(sock)
    connection._closed = False
    with pytest.raises(mycli_lite.ProtocolError, match='sequence mismatch'):
        connection.query('SELECT 1')
    assert sock.closed
    assert not connection.connected
    assert not connection.secure


def test_query_reads_multiple_results() -> None:
    connection = mycli_lite.Connection(ssl_mode='disabled')
    first = ok_packet(status=2 | mycli_lite.SERVER_MORE_RESULTS_EXISTS, affected_rows=1)
    second = ok_packet(status=2, affected_rows=2)
    fake_packets = FakePackets([second])
    fake_packets.reset_sequence = lambda: None  # type: ignore[attr-defined]
    connection._socket = ScriptedSocket(b'')  # type: ignore[assignment]
    connection._packets = fake_packets  # type: ignore[assignment]
    connection._closed = False

    monkeypatch_start_command(connection, first)
    results = connection.query('UPDATE a; UPDATE b')
    assert [result.affected_rows for result in results] == [1, 2]


def monkeypatch_start_command(connection: mycli_lite.Connection, response: bytes) -> None:
    def start_command(_command: int, _payload: bytes = b'') -> bytes:
        return response

    connection._start_command = start_command  # type: ignore[assignment,method-assign]


def test_local_infile_request_is_rejected_and_closes_connection() -> None:
    connection = mycli_lite.Connection(ssl_mode='disabled')
    sock = ScriptedSocket(b'')
    connection._socket = sock  # type: ignore[assignment]
    connection._packets = FakePackets([])  # type: ignore[assignment]
    connection._closed = False
    with pytest.raises(mycli_lite.ProtocolError, match='LOCAL INFILE'):
        connection._read_response(b'\xfb/etc/passwd')
    assert sock.closed
    assert not connection.connected


def test_error_packet_exposes_code_state_and_safe_message() -> None:
    error = mycli_lite._parse_error_packet(b'\xff\x15\x04#28000Access denied\x1b[2J')
    assert error.code == 1045
    assert error.sqlstate == '28000'
    assert error.message == 'Access denied\x1b[2J'
    assert mycli_lite._escape_text(str(error)).endswith(r'Access denied\x1b[2J')


def test_output_distinguishes_null_empty_binary_and_controls() -> None:
    columns = (
        mycli_lite.Column('a', '', '', '', '', 45, 0xFD, 0),
        mycli_lite.Column('b', '', '', '', '', 45, 0xFD, 0),
        mycli_lite.Column('c', '', '', '', '', 63, 0xFC, 0),
    )
    result = mycli_lite.Result(columns=columns, rows=[(None, 'x\n\x1b', b'\0\xff')])
    output = io.StringIO()
    mycli_lite.write_results([result], output_format='tsv', output=output, null_value=r'\N')
    assert output.getvalue() == 'a\tb\tc\n\\N\tx\\n\\x1b\t0x00ff\n'


@pytest.mark.parametrize(
    ('sql', 'complete'),
    [
        ('select 1;', True),
        ("select ';'; -- done", True),
        ("select ';'", False),
        ('select 1; select 2', False),
        ('select 1 /* ; */;', True),
        ("select 'unterminated;", False),
    ],
)
def test_repl_completion_ignores_quoted_and_commented_semicolons(sql: str, complete: bool) -> None:
    assert mycli_lite._scan_sql_completion(sql) is complete


def test_artifact_runs_without_site_packages() -> None:
    result = subprocess.run(
        [sys.executable, '-I', '-S', str(ROOT / 'mycli_lite.py'), '--version'],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == 'mycli-lite 0.1.0\n'
    assert result.stderr == ''


def test_runtime_imports_are_standard_library_only() -> None:
    tree = ast.parse((ROOT / 'mycli_lite.py').read_text(encoding='utf-8'))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.partition('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.partition('.')[0])
    imports.discard('__future__')
    assert imports <= sys.stdlib_module_names


def test_public_library_api_is_explicit() -> None:
    assert set(mycli_lite.__all__) == {
        'AuthenticationError',
        'Cell',
        'Column',
        'Connection',
        'MySQLConnectionError',
        'MySQLError',
        'ProtocolError',
        'Result',
        'ServerError',
        '__version__',
        'connect',
        'main',
        'write_results',
    }
