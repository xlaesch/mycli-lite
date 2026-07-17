# -*- coding: utf-8 -*-
# ruff: noqa
"""Dependency-free compatibility tests for the universal legacy artifact."""

from __future__ import absolute_import, print_function, unicode_literals

import base64
import binascii
import hashlib
import io
import os
import struct
import subprocess
import sys
import unittest

import mycli_lite_legacy as legacy


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NONCE = b'12345678abcdefgh1234'
CAPABILITIES = (
    legacy.CLIENT_LONG_PASSWORD
    | legacy.CLIENT_LONG_FLAG
    | legacy.CLIENT_PROTOCOL_41
    | legacy.CLIENT_INTERACTIVE
    | legacy.CLIENT_SSL
    | legacy.CLIENT_TRANSACTIONS
    | legacy.CLIENT_SECURE_CONNECTION
    | legacy.CLIENT_MULTI_STATEMENTS
    | legacy.CLIENT_MULTI_RESULTS
    | legacy.CLIENT_PLUGIN_AUTH
    | legacy.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | legacy.CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
    | legacy.CLIENT_CONNECT_WITH_DB
)


def run_with_closed_stdout(command):
    read_fd, write_fd = os.pipe()
    os.close(read_fd)
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=write_fd,
            stderr=subprocess.PIPE,
        )
    finally:
        os.close(write_fd)
    stderr = process.stderr.read()
    process.stderr.close()
    return process.wait(), stderr


def byte(value):
    return struct.pack('B', value)


def uint24(value):
    return struct.pack('<I', value)[:3]


def frame(payload, sequence_id):
    return uint24(len(payload)) + byte(sequence_id) + payload


def lenenc(value):
    if value is None:
        return b'\xfb'
    if value < 0xFB:
        return byte(value)
    if value <= 0xFFFF:
        return b'\xfc' + struct.pack('<H', value)
    if value <= 0xFFFFFF:
        return b'\xfd' + uint24(value)
    return b'\xfe' + struct.pack('<Q', value)


def lenenc_bytes(value):
    if value is None:
        return lenenc(None)
    return lenenc(len(value)) + value


def greeting(plugin=b'mysql_native_password', capabilities=CAPABILITIES):
    return (
        b'\x0a8.0.36-test\0'
        + struct.pack('<I', 1234)
        + NONCE[:8]
        + b'\0'
        + struct.pack('<H', capabilities & 0xFFFF)
        + b'\x2d'
        + struct.pack('<H', 2)
        + struct.pack('<H', capabilities >> 16)
        + byte(len(NONCE) + 1)
        + b'\0' * 10
        + NONCE[8:]
        + b'\0'
        + plugin
        + b'\0'
    )


def ok_packet(affected_rows=0, insert_id=0, status=2, warnings=0, info=b''):
    return b'\x00' + lenenc(affected_rows) + lenenc(insert_id) + struct.pack('<HH', status, warnings) + info


def eof_packet(status=2, warnings=0):
    return b'\xfe' + struct.pack('<HH', warnings, status)


def column_packet(name, charset_id=45, type_code=0xFD):
    values = (b'def', b'test', b't', b't', name, name)
    return b''.join(lenenc_bytes(value) for value in values) + b'\x0c' + struct.pack('<HIBHBH', charset_id, 1024, type_code, 0, 0, 0)


class ScriptedSocket(object):
    def __init__(self, incoming, read_size=2):
        self.incoming = incoming
        self.read_size = read_size
        self.sent = []
        self.closed = False
        self.timeouts = []

    def recv(self, size):
        if not self.incoming:
            return b''
        size = min(size, self.read_size, len(self.incoming))
        result = self.incoming[:size]
        self.incoming = self.incoming[size:]
        return result

    def sendall(self, value):
        self.sent.append(value)

    def setsockopt(self, _level, _option, _value):
        pass

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def close(self):
        self.closed = True


class FakePackets(object):
    def __init__(self, reads):
        self.reads = iter(reads)
        self.writes = []

    def read_packet(self):
        return next(self.reads)

    def write_packet(self, payload):
        self.writes.append(payload)


def connected_for_auth(reads, secure=False):
    connection = legacy.Connection(password='secret', ssl_mode='disabled')
    connection._socket = ScriptedSocket(b'')
    connection._packets = FakePackets(reads)
    connection._closed = False
    connection._secure = secure
    return connection


def der_length(length):
    if length < 0x80:
        return byte(length)
    encoded = int_to_bytes(length)
    return byte(0x80 | len(encoded)) + encoded


def der_value(tag, value):
    return byte(tag) + der_length(len(value)) + value


def int_to_bytes(value, length=None):
    encoded = format(value, 'x')
    if len(encoded) % 2:
        encoded = '0' + encoded
    raw = binascii.unhexlify(encoded.encode('ascii'))
    if length is not None:
        raw = b'\0' * (length - len(raw)) + raw
    return raw


def bytes_to_int(value):
    encoded = binascii.hexlify(value)
    return int(encoded or b'0', 16)


def der_integer(value):
    encoded = int_to_bytes(value)
    if bytearray(encoded)[0] & 0x80:
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


def rsa_public_key_pem():
    sequence = der_value(0x30, der_integer(RSA_MODULUS) + der_integer(65537))
    body = base64.b64encode(sequence)
    wrapped = b'\n'.join(body[index : index + 64] for index in range(0, len(body), 64))
    return b'-----BEGIN RSA PUBLIC KEY-----\n' + wrapped + b'\n-----END RSA PUBLIC KEY-----\n'


def spki_public_key_pem():
    pkcs1 = der_value(0x30, der_integer(RSA_MODULUS) + der_integer(65537))
    algorithm = der_value(0x30, binascii.unhexlify(b'06092a864886f70d0101010500'))
    sequence = der_value(0x30, algorithm + der_value(0x03, b'\0' + pkcs1))
    body = base64.b64encode(sequence)
    wrapped = b'\n'.join(body[index : index + 64] for index in range(0, len(body), 64))
    return b'-----BEGIN PUBLIC KEY-----\n' + wrapped + b'\n-----END PUBLIC KEY-----\n'


class ProtocolTests(unittest.TestCase):
    def test_public_api_and_version_are_explicit(self):
        self.assertTrue(legacy.__version__)
        self.assertEqual(
            set(legacy.__all__),
            {
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
            },
        )

    def test_length_encoded_integer_boundaries(self):
        vectors = (
            (0, b'\x00'),
            (250, b'\xfa'),
            (251, b'\xfc\xfb\x00'),
            (65535, b'\xfc\xff\xff'),
            (65536, b'\xfd\x00\x00\x01'),
            (16777215, b'\xfd\xff\xff\xff'),
            (16777216, b'\xfe\x00\x00\x00\x01\x00\x00\x00\x00'),
            (2**64 - 1, b'\xfe' + b'\xff' * 8),
        )
        for value, encoded in vectors:
            self.assertEqual(legacy._encode_lenenc_int(value), encoded)
            self.assertEqual(legacy._read_lenenc_int(encoded), (value, len(encoded)))

    def test_length_encoded_integer_rejects_truncation_and_null(self):
        for encoded in (b'', b'\xfc', b'\xfc\x01', b'\xfd\x01\x02', b'\xfe' + b'\0' * 7):
            with self.assertRaises(legacy.ProtocolError):
                legacy._read_lenenc_int(encoded)
        with self.assertRaises(legacy.ProtocolError):
            legacy._read_lenenc_int(b'\xfb')
        self.assertEqual(legacy._read_lenenc_int(b'\xfb', allow_null=True), (None, 1))

    def test_packet_io_handles_partial_reads_and_sequence_wrap(self):
        sock = ScriptedSocket(frame(b'abcde', 255) + frame(b'f', 0), read_size=1)
        packets = legacy.PacketIO(sock, fragment_size=5)
        packets.sequence_id = 255
        self.assertEqual(packets.read_packet(), b'abcdef')
        self.assertEqual(packets.sequence_id, 1)

    def test_packet_io_writes_exact_fragment_terminator(self):
        sock = ScriptedSocket(b'')
        packets = legacy.PacketIO(sock, fragment_size=5)
        packets.write_packet(b'abcde')
        self.assertEqual(sock.sent, [frame(b'abcde', 0), frame(b'', 1)])

    def test_protocol_v10_handshake(self):
        parsed = legacy._parse_handshake(greeting())
        self.assertEqual(parsed.server_version, '8.0.36-test')
        self.assertEqual(parsed.connection_id, 1234)
        self.assertEqual(parsed.capabilities, CAPABILITIES)
        self.assertEqual(parsed.auth_data, NONCE)
        self.assertEqual(parsed.auth_plugin, 'mysql_native_password')

    def test_password_scrambles_match_known_answers(self):
        self.assertEqual(
            binascii.hexlify(legacy._scramble_native_password(b'secret', NONCE)),
            b'56787bb5faec2e23a51adb3ba35c584f75980fca',
        )
        self.assertEqual(
            binascii.hexlify(legacy._scramble_caching_sha2(b'secret', NONCE)),
            b'0fe2d675b3fe1a8bf061f6c614a1774b5cdcc1c4faa6e275ab24568397253abf',
        )

    def test_sha2_full_auth_sends_cleartext_only_on_secure_transport(self):
        insecure = connected_for_auth([b'\x01\x04'])
        with self.assertRaises(legacy.AuthenticationError):
            insecure._authenticate('caching_sha2_password', NONCE)
        self.assertEqual(insecure._packets.writes, [])

        secure = connected_for_auth([b'\x01\x04', ok_packet()], secure=True)
        secure._authenticate('caching_sha2_password', NONCE)
        self.assertEqual(secure._packets.writes, [b'secret\0'])

    def test_clear_password_switch_requires_secure_opt_in(self):
        switch = b'\xfemysql_clear_password\0'
        blocked = connected_for_auth([switch], secure=True)
        with self.assertRaises(legacy.AuthenticationError):
            blocked._authenticate('mysql_native_password', NONCE)
        self.assertEqual(blocked._packets.writes, [])

        allowed = connected_for_auth([switch, ok_packet()], secure=True)
        allowed.allow_cleartext_plugin = True
        allowed._authenticate('mysql_native_password', NONCE)
        self.assertEqual(allowed._packets.writes, [b'secret\0'])

    def test_rsa_oaep_round_trip(self):
        original_urandom = legacy.os.urandom
        legacy.os.urandom = lambda size: b'Z' * size
        try:
            encrypted = legacy._rsa_oaep_encrypt(b'secret\0', rsa_public_key_pem())
        finally:
            legacy.os.urandom = original_urandom
        self.assertEqual(len(encrypted), 128)
        encoded = int_to_bytes(pow(bytes_to_int(encrypted), RSA_PRIVATE_EXPONENT, RSA_MODULUS), 128)
        self.assertEqual(encoded[:1], b'\0')
        masked_seed = encoded[1:21]
        masked_block = encoded[21:]
        seed_mask = legacy._mgf1(masked_block, 20)
        seed = b''.join(byte(left ^ right) for left, right in zip(bytearray(masked_seed), bytearray(seed_mask)))
        block_mask = legacy._mgf1(seed, len(masked_block))
        data_block = b''.join(byte(left ^ right) for left, right in zip(bytearray(masked_block), bytearray(block_mask)))
        self.assertEqual(data_block[:20], hashlib.sha1(b'').digest())
        self.assertEqual(data_block[data_block.index(b'\x01', 20) + 1 :], b'secret\0')

    def test_spki_requested_pinned_and_sha256_rsa_flows(self):
        public_key = spki_public_key_pem()
        self.assertEqual(legacy._parse_rsa_public_key(public_key + b'\0'), (RSA_MODULUS, 65537))

        original_urandom = legacy.os.urandom
        legacy.os.urandom = lambda size: b'R' * size
        try:
            requested = connected_for_auth([b'\x01\x04', b'\x01' + public_key, ok_packet()])
            requested.get_server_public_key = True
            requested._authenticate('caching_sha2_password', NONCE)
            self.assertEqual(requested._packets.writes[0], b'\x02')
            self.assertEqual(len(requested._packets.writes[1]), 128)
            self.assertNotIn(b'secret', requested._packets.writes[1])

            pinned = connected_for_auth([b'\x01\x04', ok_packet()])
            pinned.server_public_key = public_key
            pinned._authenticate('caching_sha2_password', NONCE)
            self.assertEqual(len(pinned._packets.writes), 1)
            self.assertEqual(len(pinned._packets.writes[0]), 128)

            sha_pinned = legacy.Connection(password='secret', server_public_key=public_key, ssl_mode='disabled')
            initial = sha_pinned._initial_auth_response('sha256_password', NONCE)
            self.assertEqual(len(initial), 128)
            self.assertNotIn(b'secret', initial)

            sha_requested = connected_for_auth([b'\x01' + public_key, ok_packet()])
            sha_requested.get_server_public_key = True
            sha_requested._authenticate('sha256_password', NONCE)
            self.assertEqual(len(sha_requested._packets.writes), 1)
            self.assertEqual(len(sha_requested._packets.writes[0]), 128)
        finally:
            legacy.os.urandom = original_urandom

    def test_tls_wrap_precedes_authentication_and_cleartext_password(self):
        raw_socket = ScriptedSocket(frame(greeting(plugin=b'caching_sha2_password'), 0))
        wrapped_socket = ScriptedSocket(frame(b'\x01\x04', 3) + frame(ok_packet(), 5))

        class FakeSSLContext(object):
            def wrap_socket(self, _sock, **kwargs):
                self.server_hostname = kwargs.get('server_hostname')
                self.sent_before_wrap = list(raw_socket.sent)
                return wrapped_socket

        context = FakeSSLContext()
        original_create_connection = legacy.socket.create_connection
        original_create_ssl_context = legacy.Connection._create_ssl_context
        legacy.socket.create_connection = lambda _address, _timeout: raw_socket
        legacy.Connection._create_ssl_context = lambda _self: context
        try:
            connection = legacy.Connection(
                host='db.example',
                user='alice',
                password='secret',
                ssl_mode='required',
            )
            connection.connect()
        finally:
            legacy.socket.create_connection = original_create_connection
            legacy.Connection._create_ssl_context = original_create_ssl_context

        expected_hostname = b'db.example' if legacy.PY2 else 'db.example'
        self.assertEqual(context.server_hostname, expected_hostname)
        self.assertEqual(len(context.sent_before_wrap), 1)
        self.assertNotIn(b'secret', context.sent_before_wrap[0])
        self.assertEqual(wrapped_socket.sent[1], frame(b'secret\0', 4))
        connection.close()

    def test_frozen_models_and_legacy_ip_detection(self):
        column = legacy.Column('name', '', '', '', '', 45, 0xFD, 0)
        with self.assertRaises(AttributeError):
            del column.name
        for host in ('127.0.0.1', '127.1', '2130706433', '0x7f000001', '::1'):
            self.assertTrue(legacy._is_ip_address(host), host)
        self.assertFalse(legacy._is_ip_address('db.example'))

    def test_verify_identity_handles_idn_and_rejects_old_runtime_ip_forms(self):
        raw_socket = ScriptedSocket(frame(greeting(), 0))

        class VerifiedSocket(ScriptedSocket):
            def getpeercert(self):
                return {'subjectAltName': (('DNS', 'xn--tst-qla.example'),)}

        wrapped_socket = VerifiedSocket(frame(ok_packet(), 3))

        class FakeSSLContext(object):
            def wrap_socket(self, _sock, **kwargs):
                self.server_hostname = kwargs.get('server_hostname')
                return wrapped_socket

        context = FakeSSLContext()
        original_create_connection = legacy.socket.create_connection
        original_create_ssl_context = legacy.Connection._create_ssl_context
        legacy.socket.create_connection = lambda _address, _timeout: raw_socket
        legacy.Connection._create_ssl_context = lambda _self: context
        try:
            connection = legacy.Connection(
                host=u't\xe4st.example',
                user='alice',
                password='secret',
                ssl_mode='verify-identity',
            )
            connection.connect()
            connection.close()
        finally:
            legacy.socket.create_connection = original_create_connection
            legacy.Connection._create_ssl_context = original_create_ssl_context
        expected_hostname = b'xn--tst-qla.example' if legacy.PY2 else 'xn--tst-qla.example'
        self.assertEqual(context.server_hostname, expected_hostname)

        if sys.version_info[:2] < (3, 5):
            for host in ('127.1', '2130706433', '0x7f000001'):
                sock = ScriptedSocket(frame(greeting(), 0))
                legacy.socket.create_connection = lambda _address, _timeout, value=sock: value
                try:
                    blocked = legacy.Connection(host=host, user='alice', ssl_mode='verify-identity')
                    with self.assertRaises(legacy.MySQLConnectionError):
                        blocked.connect()
                finally:
                    legacy.socket.create_connection = original_create_connection

    def test_full_native_handshake_query_binary_and_quit(self):
        response = b''.join((
            frame(greeting(capabilities=CAPABILITIES & ~legacy.CLIENT_SSL), 0),
            frame(ok_packet(), 2),
            frame(b'\x03', 1),
            frame(column_packet(b'text'), 2),
            frame(column_packet(b'blob', charset_id=63), 3),
            frame(column_packet(b'nothing'), 4),
            frame(eof_packet(), 5),
            frame(lenenc_bytes(b'hello\n') + lenenc_bytes(b'\0\xff') + lenenc_bytes(None), 6),
            frame(eof_packet(), 7),
        ))
        scripted_socket = ScriptedSocket(response, read_size=1)
        original_create_connection = legacy.socket.create_connection
        legacy.socket.create_connection = lambda address, timeout: scripted_socket
        try:
            connection = legacy.Connection(user='alice', password='secret', ssl_mode='disabled')
            connection.connect()
            results = connection.query('SELECT text, blob, nothing FROM t')
            connection.close()
        finally:
            legacy.socket.create_connection = original_create_connection

        self.assertEqual(results[0].rows, [('hello\n', b'\0\xff', None)])
        self.assertEqual([column.name for column in results[0].columns], ['text', 'blob', 'nothing'])
        self.assertTrue(scripted_socket.closed)
        self.assertEqual(scripted_socket.sent[-1], frame(b'\x01', 0))
        self.assertNotIn(b'secret', scripted_socket.sent[0])

    def test_local_infile_is_rejected_and_closes_connection(self):
        connection = legacy.Connection(ssl_mode='disabled')
        sock = ScriptedSocket(b'')
        connection._socket = sock
        connection._packets = FakePackets([])
        connection._closed = False
        with self.assertRaises(legacy.ProtocolError):
            connection._read_response(b'\xfb/etc/passwd')
        self.assertTrue(sock.closed)
        self.assertFalse(connection.connected)


class OutputAndCliTests(unittest.TestCase):
    def test_output_distinguishes_unicode_null_binary_and_controls(self):
        columns = (
            legacy.Column('name', '', '', '', '', 45, 0xFD, 0),
            legacy.Column('blob', '', '', '', '', 63, 0xFC, 0),
            legacy.Column('empty', '', '', '', '', 45, 0xFD, 0),
        )
        result = legacy.Result(columns=columns, rows=[('snowman \u2603\n', b'\0\xff', None)])
        output = io.StringIO()
        legacy.write_results([result], output_format='tsv', output=output, null_value='NULL')
        self.assertEqual(output.getvalue(), 'name\tblob\tempty\nsnowman \u2603\\n\t0x00ff\tNULL\n')

    def test_sql_completion_ignores_literals_and_comments(self):
        vectors = (
            ('select 1;', True),
            ("select ';'; -- done", True),
            ("select ';'", False),
            ('select 1; select 2', False),
            ('select 1 /* ; */;', True),
            ("select 'unterminated;", False),
        )
        for sql, complete in vectors:
            self.assertIs(legacy._scan_sql_completion(sql), complete)

    def test_raw_artifact_runs_without_site_packages(self):
        artifact = os.path.join(ROOT, 'mycli_lite_legacy.py')
        process = subprocess.Popen(
            [sys.executable, '-B', '-E', '-s', '-S', artifact, '--version'],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0)
        self.assertEqual(stdout.decode('utf-8'), 'mycli-lite {0}\n'.format(legacy.__version__))
        self.assertEqual(stderr, b'')

    def test_raw_artifact_help_runs_without_site_packages(self):
        artifact = os.path.join(ROOT, 'mycli_lite_legacy.py')
        process = subprocess.Popen(
            [sys.executable, '-B', '-E', '-s', '-S', artifact, '--help'],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0)
        self.assertIn(b'--get-server-public-key', stdout)
        self.assertIn(b'--charset {ascii,latin1,utf8,utf8mb3,utf8mb4}', stdout)
        self.assertEqual(stderr, b'')

    def test_cli_returns_141_for_small_closed_pipe(self):
        if os.name == 'nt':
            self.skipTest('requires POSIX closed-pipe semantics')
        script = """
import mycli_lite_legacy as client

class FakeConnection(object):
    def __init__(self, **_kwargs):
        pass

    def connect(self):
        pass

    def close(self):
        pass

    def query(self, _sql):
        column = client.Column('value', '', '', '', '', 45, 0xfd, 0)
        return [client.Result(columns=(column,), rows=[('x',)])]

client.Connection = FakeConnection
raise SystemExit(client.main(['--execute', 'SELECT 1', '--ssl-mode', 'disabled']))
"""
        returncode, stderr = run_with_closed_stdout(
            [sys.executable, '-B', '-E', '-s', '-S', '-c', script]
        )
        self.assertEqual(returncode, 141)
        self.assertEqual(stderr, b'')

    def test_parser_output_returns_141_for_closed_pipe(self):
        if os.name == 'nt':
            self.skipTest('requires POSIX closed-pipe semantics')
        artifact = os.path.join(ROOT, 'mycli_lite_legacy.py')
        for option in ('--version', '--help'):
            returncode, stderr = run_with_closed_stdout(
                [sys.executable, '-B', '-E', '-s', '-S', artifact, option]
            )
            self.assertEqual(returncode, 141)
            self.assertEqual(stderr, b'')

    def test_non_ascii_output_is_safe_in_c_locale(self):
        environment = os.environ.copy()
        environment.update({
            'LANG': 'C',
            'LC_ALL': 'C',
            'PYTHONCOERCECLOCALE': '0',
            'PYTHONUTF8': '0',
        })
        process = subprocess.Popen(
            [
                sys.executable,
                '-B',
                '-E',
                '-s',
                '-S',
                '-c',
                (
                    "import mycli_lite_legacy as client; "
                    "column = client.Column('v', '', '', '', '', 45, 0xfd, 0); "
                    "result = client.Result(columns=(column,), rows=[(u'\\u2603',)]); "
                    "client.write_results([result], output_format='table')"
                ),
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        self.assertEqual(process.returncode, 0)
        self.assertIn(
            stdout,
            (
                b'+--------+\n| v      |\n+--------+\n| \\u2603 |\n+--------+\n',
                b'+---+\n| v |\n+---+\n| \xe2\x98\x83 |\n+---+\n',
            ),
        )
        self.assertEqual(stderr, b'')


if __name__ == '__main__':
    unittest.main()
