#!/usr/bin/env python3
# Copyright (c) 2026, mycli-lite contributors.
# Copyright (c) 2015-2026, mycli maintainers.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# * Neither the name of mycli nor the names of its contributors may be used to
#   endorse or promote products derived from this software without specific
#   prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""A dependency-free MySQL client library and command-line interface.

This module implements the small subset of the MySQL classic protocol needed
to authenticate, execute text queries, and display their results. It is meant
to remain useful when this single file is the only artifact available.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
from dataclasses import dataclass, field
import getpass
import hashlib
import os
import socket
import ssl
import struct
import sys
import time
from typing import NoReturn, Protocol, TextIO

__version__ = '0.2.0'

__all__ = [
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
]

MAX_PACKET_PAYLOAD = 0xFFFFFF
DEFAULT_MAX_MESSAGE_SIZE = 64 * 1024 * 1024
MAX_COLUMNS = 4096

# Client capability flags.
CLIENT_LONG_PASSWORD = 1 << 0
CLIENT_LONG_FLAG = 1 << 2
CLIENT_CONNECT_WITH_DB = 1 << 3
CLIENT_PROTOCOL_41 = 1 << 9
CLIENT_INTERACTIVE = 1 << 10
CLIENT_SSL = 1 << 11
CLIENT_TRANSACTIONS = 1 << 13
CLIENT_SECURE_CONNECTION = 1 << 15
CLIENT_MULTI_STATEMENTS = 1 << 16
CLIENT_MULTI_RESULTS = 1 << 17
CLIENT_PLUGIN_AUTH = 1 << 19
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1 << 21
CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 1 << 22

# Server status flags.
SERVER_MORE_RESULTS_EXISTS = 1 << 3

# Commands in the MySQL classic protocol.
COM_QUIT = 0x01
COM_INIT_DB = 0x02
COM_QUERY = 0x03
COM_PING = 0x0E

MYSQL_TYPE_VARCHAR = 0x0F
MYSQL_TYPE_BIT = 0x10
MYSQL_TYPE_TINY_BLOB = 0xF9
MYSQL_TYPE_MEDIUM_BLOB = 0xFA
MYSQL_TYPE_LONG_BLOB = 0xFB
MYSQL_TYPE_BLOB = 0xFC
MYSQL_TYPE_VAR_STRING = 0xFD
MYSQL_TYPE_STRING = 0xFE
MYSQL_TYPE_GEOMETRY = 0xFF
BINARY_CHARSET_ID = 63
BINARY_FIELD_TYPES = frozenset({
    MYSQL_TYPE_VARCHAR,
    MYSQL_TYPE_BIT,
    MYSQL_TYPE_TINY_BLOB,
    MYSQL_TYPE_MEDIUM_BLOB,
    MYSQL_TYPE_LONG_BLOB,
    MYSQL_TYPE_BLOB,
    MYSQL_TYPE_VAR_STRING,
    MYSQL_TYPE_STRING,
    MYSQL_TYPE_GEOMETRY,
})

CHARSETS: dict[str, tuple[int, str]] = {
    'ascii': (11, 'ascii'),
    'latin1': (8, 'latin1'),
    'utf8': (33, 'utf-8'),
    'utf8mb3': (33, 'utf-8'),
    'utf8mb4': (45, 'utf-8'),
}

SSL_MODES = ('disabled', 'preferred', 'required', 'verify-ca', 'verify-identity')


class MySQLError(Exception):
    """Base error raised by the lightweight client."""


class MySQLConnectionError(MySQLError):
    """A socket, TLS, or authentication connection failed."""


class ProtocolError(MySQLError):
    """The peer sent a malformed or unsupported protocol message."""


class AuthenticationError(MySQLConnectionError):
    """The server requested an unsupported or unsafe authentication flow."""


class ServerError(MySQLError):
    """The server returned an ERR packet."""

    def __init__(self, code: int, message: str, sqlstate: str | None = None) -> None:
        self.code = code
        self.sqlstate = sqlstate
        self.message = message
        state = f' [{sqlstate}]' if sqlstate else ''
        super().__init__(f'{code}{state}: {message}')


@dataclass(frozen=True, slots=True)
class Handshake:
    """The useful fields from a protocol-v10 server greeting."""

    server_version: str
    connection_id: int
    capabilities: int
    charset_id: int
    status_flags: int
    auth_data: bytes
    auth_plugin: str


@dataclass(frozen=True, slots=True)
class Column:
    """Column metadata from a text-protocol result set."""

    name: str
    schema: str
    table: str
    original_table: str
    original_name: str
    charset_id: int
    type_code: int
    flags: int


Cell = str | bytes | None


@dataclass(slots=True)
class Result:
    """One result returned by a query or stored procedure."""

    columns: tuple[Column, ...] = ()
    rows: list[tuple[Cell, ...]] = field(default_factory=list)
    affected_rows: int = 0
    last_insert_id: int = 0
    warning_count: int = 0
    status_flags: int = 0
    info: str = ''

    @property
    def has_rows(self) -> bool:
        return bool(self.columns)


def _pack_uint24(value: int) -> bytes:
    if not 0 <= value <= MAX_PACKET_PAYLOAD:
        raise ValueError('three-byte integer is out of range')
    return value.to_bytes(3, 'little')


def _read_uint24(value: bytes) -> int:
    if len(value) != 3:
        raise ProtocolError('truncated three-byte integer')
    return int.from_bytes(value, 'little')


def _encode_lenenc_int(value: int) -> bytes:
    if value < 0:
        raise ValueError('length-encoded integer cannot be negative')
    if value < 0xFB:
        return bytes((value,))
    if value <= 0xFFFF:
        return b'\xfc' + struct.pack('<H', value)
    if value <= 0xFFFFFF:
        return b'\xfd' + value.to_bytes(3, 'little')
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b'\xfe' + struct.pack('<Q', value)
    raise ValueError('length-encoded integer is too large')


def _read_lenenc_int(data: bytes, offset: int = 0, *, allow_null: bool = False) -> tuple[int | None, int]:
    if offset >= len(data):
        raise ProtocolError('truncated length-encoded integer')
    marker = data[offset]
    offset += 1
    if marker < 0xFB:
        return marker, offset
    if marker == 0xFB:
        if allow_null:
            return None, offset
        raise ProtocolError('unexpected NULL length marker')
    sizes = {0xFC: 2, 0xFD: 3, 0xFE: 8}
    if marker not in sizes:
        raise ProtocolError(f'invalid length marker 0x{marker:02x}')
    size = sizes[marker]
    end = offset + size
    if end > len(data):
        raise ProtocolError('truncated length-encoded integer payload')
    return int.from_bytes(data[offset:end], 'little'), end


def _read_lenenc_bytes(data: bytes, offset: int, *, allow_null: bool = False) -> tuple[bytes | None, int]:
    length, offset = _read_lenenc_int(data, offset, allow_null=allow_null)
    if length is None:
        return None, offset
    end = offset + length
    if end > len(data):
        raise ProtocolError('truncated length-encoded string')
    return data[offset:end], end


def _read_nul(data: bytes, offset: int, field_name: str) -> tuple[bytes, int]:
    end = data.find(b'\0', offset)
    if end < 0:
        raise ProtocolError(f'unterminated {field_name}')
    return data[offset:end], end + 1


class SocketLike(Protocol):
    """The socket operations used by the packet codec."""

    def recv(self, size: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...


class PacketIO:
    """Read and write logical MySQL packets on a connected socket."""

    def __init__(
        self,
        sock: SocketLike,
        *,
        fragment_size: int = MAX_PACKET_PAYLOAD,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
    ) -> None:
        if not 0 < fragment_size <= MAX_PACKET_PAYLOAD:
            raise ValueError('invalid packet fragment size')
        if max_message_size < fragment_size:
            raise ValueError('maximum message size is smaller than one fragment')
        self.socket = sock
        self.fragment_size = fragment_size
        self.max_message_size = max_message_size
        self.sequence_id = 0

    def replace_socket(self, sock: SocketLike) -> None:
        self.socket = sock

    def reset_sequence(self) -> None:
        self.sequence_id = 0

    def _read_exact(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            try:
                chunk = self.socket.recv(size - len(chunks))
            except OSError as exc:
                raise MySQLConnectionError(f'socket read failed: {exc}') from exc
            if not chunk:
                raise MySQLConnectionError('server closed the connection')
            chunks.extend(chunk)
        return bytes(chunks)

    def read_packet(self) -> bytes:
        payload = bytearray()
        while True:
            header = self._read_exact(4)
            size = _read_uint24(header[:3])
            sequence_id = header[3]
            if sequence_id != self.sequence_id:
                raise ProtocolError(f'packet sequence mismatch: received {sequence_id}, expected {self.sequence_id}')
            self.sequence_id = (self.sequence_id + 1) & 0xFF
            if size > self.fragment_size:
                raise ProtocolError(f'packet payload exceeds {self.fragment_size} bytes')
            if len(payload) + size > self.max_message_size:
                raise ProtocolError(f'logical packet exceeds {self.max_message_size} bytes')
            payload.extend(self._read_exact(size) if size else b'')
            if size < self.fragment_size:
                return bytes(payload)

    def write_packet(self, payload: bytes) -> None:
        if len(payload) > self.max_message_size:
            raise ProtocolError(f'logical packet exceeds {self.max_message_size} bytes')
        offset = 0
        while True:
            chunk = payload[offset : offset + self.fragment_size]
            header = _pack_uint24(len(chunk)) + bytes((self.sequence_id,))
            try:
                self.socket.sendall(header + chunk)
            except OSError as exc:
                raise MySQLConnectionError(f'socket write failed: {exc}') from exc
            self.sequence_id = (self.sequence_id + 1) & 0xFF
            offset += len(chunk)
            if len(chunk) < self.fragment_size:
                return


def _parse_error_packet(payload: bytes) -> ServerError:
    if len(payload) < 3 or payload[0] != 0xFF:
        raise ProtocolError('malformed server error packet')
    code = struct.unpack_from('<H', payload, 1)[0]
    offset = 3
    sqlstate: str | None = None
    if len(payload) >= 9 and payload[offset : offset + 1] == b'#':
        sqlstate = payload[offset + 1 : offset + 6].decode('ascii', 'replace')
        offset += 6
    message = payload[offset:].decode('utf-8', 'replace')
    return ServerError(code, message, sqlstate)


def _raise_if_error(payload: bytes) -> None:
    if payload[:1] == b'\xff':
        raise _parse_error_packet(payload)


def _parse_handshake(payload: bytes) -> Handshake:
    _raise_if_error(payload)
    if not payload or payload[0] != 10:
        version = payload[0] if payload else None
        raise ProtocolError(f'unsupported MySQL protocol version {version!r}')
    offset = 1
    server_version_raw, offset = _read_nul(payload, offset, 'server version')
    if offset + 4 + 8 + 1 + 2 > len(payload):
        raise ProtocolError('truncated server greeting')
    connection_id = struct.unpack_from('<I', payload, offset)[0]
    offset += 4
    auth_part_1 = payload[offset : offset + 8]
    offset += 9
    capabilities = struct.unpack_from('<H', payload, offset)[0]
    offset += 2
    if offset == len(payload):
        raise ProtocolError('server does not support protocol 4.1')
    if offset + 6 + 10 > len(payload):
        raise ProtocolError('truncated protocol-4.1 greeting')
    charset_id = payload[offset]
    status_flags = struct.unpack_from('<H', payload, offset + 1)[0]
    capabilities |= struct.unpack_from('<H', payload, offset + 3)[0] << 16
    auth_data_length = payload[offset + 5]
    offset += 6 + 10

    auth_part_2 = b''
    if capabilities & CLIENT_SECURE_CONNECTION and offset < len(payload):
        tail_size = max(13, auth_data_length - 8) if auth_data_length else 13
        tail = payload[offset : offset + tail_size]
        offset += len(tail)
        auth_part_2 = tail[:-1] if tail.endswith(b'\0') else tail
    auth_data = (auth_part_1 + auth_part_2)[:20]

    auth_plugin = 'mysql_native_password'
    if capabilities & CLIENT_PLUGIN_AUTH and offset < len(payload):
        plugin_raw = payload[offset:].split(b'\0', 1)[0]
        if plugin_raw:
            auth_plugin = plugin_raw.decode('ascii', 'replace')

    if not capabilities & CLIENT_PROTOCOL_41:
        raise ProtocolError('server does not advertise protocol 4.1')
    if len(auth_data) < 20:
        raise ProtocolError('server greeting has incomplete authentication data')
    return Handshake(
        server_version=server_version_raw.decode('latin1', 'replace'),
        connection_id=connection_id,
        capabilities=capabilities,
        charset_id=charset_id,
        status_flags=status_flags,
        auth_data=auth_data,
        auth_plugin=auth_plugin,
    )


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError('XOR operands must have equal lengths')
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _scramble_native_password(password: bytes, nonce: bytes) -> bytes:
    if not password:
        return b''
    stage_1 = hashlib.sha1(password, usedforsecurity=False).digest()
    stage_2 = hashlib.sha1(stage_1, usedforsecurity=False).digest()
    challenge = hashlib.sha1(nonce[:20] + stage_2, usedforsecurity=False).digest()
    return _xor_bytes(stage_1, challenge)


def _scramble_caching_sha2(password: bytes, nonce: bytes) -> bytes:
    if not password:
        return b''
    stage_1 = hashlib.sha256(password).digest()
    stage_2 = hashlib.sha256(stage_1).digest()
    challenge = hashlib.sha256(stage_2 + nonce[:20]).digest()
    return _xor_bytes(stage_1, challenge)


def _read_der_value(data: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise AuthenticationError('truncated RSA public key')
    tag = data[offset]
    length_byte = data[offset + 1]
    offset += 2
    if length_byte & 0x80:
        length_size = length_byte & 0x7F
        if length_size == 0 or length_size > 4 or offset + length_size > len(data):
            raise AuthenticationError('invalid RSA public-key length')
        length = int.from_bytes(data[offset : offset + length_size], 'big')
        offset += length_size
    else:
        length = length_byte
    end = offset + length
    if end > len(data):
        raise AuthenticationError('truncated RSA public-key value')
    return tag, data[offset:end], end


def _decode_der_integer(value: bytes) -> int:
    if not value or value[0] & 0x80:
        raise AuthenticationError('invalid RSA public-key integer')
    return int.from_bytes(value, 'big')


def _parse_pkcs1_rsa_key(data: bytes) -> tuple[int, int]:
    tag, sequence, end = _read_der_value(data, 0)
    if tag != 0x30 or end != len(data):
        raise AuthenticationError('RSA public key is not a DER sequence')
    tag, modulus_raw, offset = _read_der_value(sequence, 0)
    if tag != 0x02:
        raise AuthenticationError('RSA public key has no modulus')
    tag, exponent_raw, offset = _read_der_value(sequence, offset)
    if tag != 0x02 or offset != len(sequence):
        raise AuthenticationError('RSA public key has no exponent')
    return _decode_der_integer(modulus_raw), _decode_der_integer(exponent_raw)


def _parse_rsa_public_key(pem: bytes) -> tuple[int, int]:
    pem = pem.rstrip(b'\0')
    if len(pem) > 16384:
        raise AuthenticationError('RSA public key is unreasonably large')
    try:
        lines = pem.decode('ascii').strip().splitlines()
    except UnicodeDecodeError as exc:
        raise AuthenticationError('RSA public key is not PEM text') from exc
    if len(lines) < 3 or lines[0] not in (
        '-----BEGIN PUBLIC KEY-----',
        '-----BEGIN RSA PUBLIC KEY-----',
    ):
        raise AuthenticationError('unsupported RSA public-key PEM format')
    expected_footer = lines[0].replace('BEGIN', 'END')
    if lines[-1] != expected_footer:
        raise AuthenticationError('unterminated RSA public key')
    try:
        der = base64.b64decode(''.join(lines[1:-1]), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AuthenticationError('invalid RSA public-key base64') from exc

    if lines[0] == '-----BEGIN RSA PUBLIC KEY-----':
        modulus, exponent = _parse_pkcs1_rsa_key(der)
    else:
        tag, outer, end = _read_der_value(der, 0)
        if tag != 0x30 or end != len(der):
            raise AuthenticationError('invalid SubjectPublicKeyInfo sequence')
        tag, _algorithm, offset = _read_der_value(outer, 0)
        if tag != 0x30:
            raise AuthenticationError('invalid RSA algorithm identifier')
        tag, bit_string, offset = _read_der_value(outer, offset)
        if tag != 0x03 or offset != len(outer) or not bit_string or bit_string[0] != 0:
            raise AuthenticationError('invalid RSA public-key bit string')
        modulus, exponent = _parse_pkcs1_rsa_key(bit_string[1:])

    bit_length = modulus.bit_length()
    if not 1024 <= bit_length <= 16384 or exponent < 3 or exponent > 0xFFFFFFFF or not exponent & 1:
        raise AuthenticationError('unsupported RSA public-key parameters')
    return modulus, exponent


def _mgf1(seed: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha1(seed + counter.to_bytes(4, 'big'), usedforsecurity=False).digest())
        counter += 1
    return bytes(output[:length])


def _rsa_oaep_encrypt(message: bytes, public_key: bytes) -> bytes:
    modulus, exponent = _parse_rsa_public_key(public_key)
    key_size = (modulus.bit_length() + 7) // 8
    digest_size = hashlib.sha1(usedforsecurity=False).digest_size
    if len(message) > key_size - 2 * digest_size - 2:
        raise AuthenticationError('password is too long for the RSA public key')
    label_hash = hashlib.sha1(b'', usedforsecurity=False).digest()
    padding = b'\0' * (key_size - len(message) - 2 * digest_size - 2)
    data_block = label_hash + padding + b'\x01' + message
    seed = os.urandom(digest_size)
    masked_block = _xor_bytes(data_block, _mgf1(seed, key_size - digest_size - 1))
    masked_seed = _xor_bytes(seed, _mgf1(masked_block, digest_size))
    encoded = b'\0' + masked_seed + masked_block
    encrypted = pow(int.from_bytes(encoded, 'big'), exponent, modulus)
    return encrypted.to_bytes(key_size, 'big')


def _encrypt_sha2_password(password: bytes, nonce: bytes, public_key: bytes) -> bytes:
    plain = bytearray(password + b'\0')
    nonce = nonce[:20]
    if not nonce:
        raise AuthenticationError('server supplied an empty authentication nonce')
    for index in range(len(plain)):
        plain[index] ^= nonce[index % len(nonce)]
    return _rsa_oaep_encrypt(bytes(plain), public_key)


class Connection:
    """A small synchronous connection for MySQL text-protocol queries."""

    def __init__(
        self,
        *,
        host: str = '127.0.0.1',
        port: int = 3306,
        user: str | None = None,
        password: str = '',
        database: str | None = None,
        unix_socket: str | None = None,
        charset: str = 'utf8mb4',
        ssl_mode: str = 'preferred',
        ssl_ca: str | None = None,
        ssl_cert: str | None = None,
        ssl_key: str | None = None,
        connect_timeout: float = 10.0,
        multi_statements: bool = True,
        get_server_public_key: bool = False,
        server_public_key: bytes | None = None,
        allow_cleartext_plugin: bool = False,
        max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
    ) -> None:
        if charset not in CHARSETS:
            raise ValueError(f'unsupported character set {charset!r}')
        if ssl_mode not in SSL_MODES:
            raise ValueError(f'unsupported SSL mode {ssl_mode!r}')
        if not 1 <= port <= 65535:
            raise ValueError('port must be between 1 and 65535')
        if connect_timeout <= 0:
            raise ValueError('connection timeout must be positive')
        if max_message_size < MAX_PACKET_PAYLOAD:
            raise ValueError(f'maximum message size must be at least {MAX_PACKET_PAYLOAD}')
        self.host = host
        self.port = port
        self.user = user if user is not None else getpass.getuser()
        self.database = database
        self.unix_socket = unix_socket
        self.charset = charset
        self.ssl_mode = ssl_mode
        self.ssl_ca = ssl_ca
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.connect_timeout = connect_timeout
        self.multi_statements = multi_statements
        self.get_server_public_key = get_server_public_key
        self.server_public_key = server_public_key
        self.allow_cleartext_plugin = allow_cleartext_plugin
        self.max_message_size = max_message_size
        self._charset_id, self._encoding = CHARSETS[charset]
        self._password = password.encode('utf-8')
        self._socket: socket.socket | None = None
        self._packets: PacketIO | None = None
        self._closed = True
        self._secure = False
        self._tls_active = False
        self.server_version = ''
        self.connection_id = 0
        self.server_capabilities = 0
        self.client_capabilities = 0
        self.server_status = 0

    def __repr__(self) -> str:
        target = self.unix_socket or f'{self.host}:{self.port}'
        return f'Connection(user={self.user!r}, target={target!r}, database={self.database!r})'

    @property
    def connected(self) -> bool:
        return not self._closed and self._socket is not None and self._packets is not None

    @property
    def secure(self) -> bool:
        return self._secure

    @property
    def tls_active(self) -> bool:
        return self._tls_active

    @property
    def tls_version(self) -> str | None:
        if isinstance(self._socket, ssl.SSLSocket):
            return self._socket.version()
        return None

    def __enter__(self) -> Connection:
        if not self.connected:
            self.connect()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()

    def _open_socket(self) -> socket.socket:
        sock: socket.socket | None = None
        try:
            if self.unix_socket:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.connect_timeout)
                sock.connect(self.unix_socket)
                self._secure = True
                return sock
            sock = socket.create_connection((self.host, self.port), self.connect_timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            return sock
        except OSError as exc:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            target = self.unix_socket or f'{self.host}:{self.port}'
            raise MySQLConnectionError(f'cannot connect to {target}: {exc}') from exc

    def _use_tls(self, handshake: Handshake) -> bool:
        if self.unix_socket or self.ssl_mode == 'disabled':
            return False
        server_supports_tls = bool(handshake.capabilities & CLIENT_SSL)
        if not server_supports_tls and self.ssl_mode != 'preferred':
            raise MySQLConnectionError('TLS is required but the server does not advertise TLS support')
        return server_supports_tls

    def _create_ssl_context(self) -> ssl.SSLContext:
        verify = self.ssl_mode in ('verify-ca', 'verify-identity')
        if verify:
            context = ssl.create_default_context(cafile=self.ssl_ca)
            if hasattr(ssl, 'VERIFY_X509_STRICT'):
                context.verify_flags &= ~ssl.VERIFY_X509_STRICT
            context.check_hostname = self.ssl_mode == 'verify-identity'
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        if self.ssl_cert:
            context.load_cert_chain(self.ssl_cert, keyfile=self.ssl_key)
        elif self.ssl_key:
            raise MySQLConnectionError('--ssl-key requires --ssl-cert')
        return context

    def _choose_capabilities(self, handshake: Handshake, use_tls: bool) -> int:
        desired = (
            CLIENT_LONG_PASSWORD
            | CLIENT_LONG_FLAG
            | CLIENT_PROTOCOL_41
            | CLIENT_INTERACTIVE
            | CLIENT_TRANSACTIONS
            | CLIENT_SECURE_CONNECTION
            | CLIENT_MULTI_RESULTS
            | CLIENT_PLUGIN_AUTH
            | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
            | CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
        )
        if self.multi_statements:
            desired |= CLIENT_MULTI_STATEMENTS
        if self.database:
            desired |= CLIENT_CONNECT_WITH_DB
        if use_tls:
            desired |= CLIENT_SSL
        capabilities = desired & handshake.capabilities
        if not capabilities & CLIENT_PROTOCOL_41:
            raise ProtocolError('server and client have no common protocol-4.1 capability')
        return capabilities

    def _initial_auth_response(self, plugin: str, nonce: bytes) -> bytes:
        if plugin in ('', 'mysql_native_password'):
            return _scramble_native_password(self._password, nonce)
        if plugin == 'caching_sha2_password':
            return _scramble_caching_sha2(self._password, nonce)
        if plugin == 'sha256_password':
            if self._secure:
                return self._password + b'\0'
            if not self._password:
                return b'\0'
            if self.server_public_key:
                return _encrypt_sha2_password(self._password, nonce, self.server_public_key)
            if not (self.server_public_key or self.get_server_public_key):
                raise AuthenticationError(
                    'sha256_password over plaintext TCP requires TLS, a pinned public key, or get_server_public_key=True'
                )
            return b'\x01'
        if plugin == 'mysql_clear_password':
            if not self.allow_cleartext_plugin:
                raise AuthenticationError('mysql_clear_password is disabled')
            if not self._secure:
                raise AuthenticationError('mysql_clear_password requires TLS or a Unix socket')
            return self._password + b'\0'
        return b''

    def _build_handshake_response(self, plugin: str, nonce: bytes) -> bytes:
        response = self._initial_auth_response(plugin, nonce)
        payload = struct.pack('<IIB23s', self.client_capabilities, MAX_PACKET_PAYLOAD, self._charset_id, b'')
        payload += self.user.encode(self._encoding) + b'\0'
        if self.client_capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            payload += _encode_lenenc_int(len(response)) + response
        elif self.client_capabilities & CLIENT_SECURE_CONNECTION:
            if len(response) > 255:
                raise AuthenticationError('authentication response is too large')
            payload += bytes((len(response),)) + response
        else:
            payload += response + b'\0'
        if self.client_capabilities & CLIENT_CONNECT_WITH_DB and self.database:
            payload += self.database.encode(self._encoding) + b'\0'
        if self.client_capabilities & CLIENT_PLUGIN_AUTH:
            payload += plugin.encode('ascii', 'replace') + b'\0'
        return payload

    def _send_auth_switch_response(self, plugin: str, nonce: bytes) -> str | None:
        packets = self._require_packets()
        if plugin == 'mysql_native_password':
            packets.write_packet(_scramble_native_password(self._password, nonce))
            return None
        if plugin == 'caching_sha2_password':
            packets.write_packet(_scramble_caching_sha2(self._password, nonce))
            return None
        if plugin == 'sha256_password':
            if self._secure:
                packets.write_packet(self._password + b'\0')
                return None
            if not self._password:
                packets.write_packet(b'')
                return None
            if self.server_public_key:
                packets.write_packet(_encrypt_sha2_password(self._password, nonce, self.server_public_key))
                return None
            if self.get_server_public_key:
                packets.write_packet(b'\x01')
                return 'sha256_password'
            raise AuthenticationError('sha256_password over plaintext TCP requires TLS or --get-server-public-key')
        if plugin == 'mysql_clear_password':
            if not self.allow_cleartext_plugin:
                raise AuthenticationError('mysql_clear_password is disabled')
            if not self._secure:
                raise AuthenticationError('mysql_clear_password requires TLS or a Unix socket')
            packets.write_packet(self._password + b'\0')
            return None
        raise AuthenticationError(f'unsupported authentication plugin {plugin!r}')

    def _authenticate(self, plugin: str, nonce: bytes) -> None:
        packets = self._require_packets()
        pending_public_key_for: str | None = None
        while True:
            payload = packets.read_packet()
            if not payload:
                raise AuthenticationError('server sent an empty authentication packet')
            _raise_if_error(payload)
            if payload[:1] == b'\x00':
                result = self._parse_ok(payload)
                self.server_status = result.status_flags
                return
            if payload[:1] == b'\xfe':
                if len(payload) == 1:
                    raise AuthenticationError('legacy pre-4.1 authentication is unsupported')
                plugin_raw, offset = _read_nul(payload, 1, 'authentication plugin name')
                plugin = plugin_raw.decode('ascii', 'replace')
                nonce = payload[offset:].removesuffix(b'\0')[:20]
                if plugin != 'mysql_clear_password' and not nonce:
                    raise AuthenticationError('authentication switch has no nonce')
                pending_public_key_for = self._send_auth_switch_response(plugin, nonce)
                continue
            if payload[:1] != b'\x01':
                raise AuthenticationError(f'unexpected authentication packet 0x{payload[0]:02x}')
            extra = payload[1:]
            if pending_public_key_for:
                public_key = self.server_public_key or extra
                packets.write_packet(_encrypt_sha2_password(self._password, nonce, public_key))
                pending_public_key_for = None
                continue
            if plugin == 'caching_sha2_password':
                if extra == b'\x03':
                    continue
                if extra != b'\x04':
                    raise AuthenticationError('unexpected caching_sha2_password state')
                if self._secure:
                    packets.write_packet(self._password + b'\0')
                elif not self._password:
                    packets.write_packet(b'')
                elif self.server_public_key:
                    packets.write_packet(_encrypt_sha2_password(self._password, nonce, self.server_public_key))
                elif self.get_server_public_key:
                    packets.write_packet(b'\x02')
                    pending_public_key_for = plugin
                else:
                    raise AuthenticationError(
                        'caching_sha2_password full authentication over plaintext TCP requires TLS or --get-server-public-key'
                    )
                continue
            if plugin == 'sha256_password':
                public_key = self.server_public_key or extra
                packets.write_packet(_encrypt_sha2_password(self._password, nonce, public_key))
                continue
            raise AuthenticationError(f'unexpected extra data for authentication plugin {plugin!r}')

    def connect(self) -> None:
        if self.connected:
            return
        self._closed = False
        self._secure = False
        self._tls_active = False
        try:
            self._socket = self._open_socket()
            self._packets = PacketIO(self._socket, max_message_size=self.max_message_size)
            handshake = _parse_handshake(self._packets.read_packet())
            self.server_version = handshake.server_version
            self.connection_id = handshake.connection_id
            self.server_capabilities = handshake.capabilities
            self.server_status = handshake.status_flags
            use_tls = self._use_tls(handshake)
            self.client_capabilities = self._choose_capabilities(handshake, use_tls)

            if use_tls:
                ssl_request = struct.pack('<IIB23s', self.client_capabilities, MAX_PACKET_PAYLOAD, self._charset_id, b'')
                self._packets.write_packet(ssl_request)
                context = self._create_ssl_context()
                try:
                    wrapped = context.wrap_socket(self._socket, server_hostname=self.host)
                except (OSError, ssl.SSLError) as exc:
                    raise MySQLConnectionError(f'TLS handshake failed: {exc}') from exc
                self._socket = wrapped
                self._packets.replace_socket(wrapped)
                self._secure = True
                self._tls_active = True

            self._packets.write_packet(self._build_handshake_response(handshake.auth_plugin, handshake.auth_data))
            self._authenticate(handshake.auth_plugin, handshake.auth_data)
            if self.database and not self.client_capabilities & CLIENT_CONNECT_WITH_DB:
                self.select_db(self.database)
            if self._socket is not None:
                self._socket.settimeout(None)
        except UnicodeError as exc:
            self._abort()
            raise MySQLConnectionError(f'connection fields cannot be encoded as {self.charset}') from exc
        except BaseException:
            self._abort()
            raise

    def _require_packets(self) -> PacketIO:
        if not self.connected or self._packets is None:
            raise MySQLConnectionError('connection is closed')
        return self._packets

    def _abort(self) -> None:
        sock, self._socket = self._socket, None
        self._packets = None
        self._closed = True
        self._secure = False
        self._tls_active = False
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    def close(self) -> None:
        if self._closed:
            return
        packets = self._packets
        if packets is not None:
            try:
                packets.reset_sequence()
                packets.write_packet(bytes((COM_QUIT,)))
            except MySQLError:
                pass
        self._abort()

    def _start_command(self, command: int, payload: bytes = b'') -> bytes:
        try:
            packets = self._require_packets()
            packets.reset_sequence()
            packets.write_packet(bytes((command,)) + payload)
            response = packets.read_packet()
            _raise_if_error(response)
            return response
        except (MySQLConnectionError, ProtocolError):
            self._abort()
            raise

    def ping(self) -> None:
        try:
            response = self._start_command(COM_PING)
            if response[:1] != b'\x00':
                raise ProtocolError('COM_PING did not return an OK packet')
            self.server_status = self._parse_ok(response).status_flags
        except ProtocolError:
            self._abort()
            raise

    def select_db(self, database: str) -> None:
        try:
            response = self._start_command(COM_INIT_DB, database.encode(self._encoding))
            if response[:1] != b'\x00':
                raise ProtocolError('COM_INIT_DB did not return an OK packet')
            self.server_status = self._parse_ok(response).status_flags
            self.database = database
        except ProtocolError:
            self._abort()
            raise
        except UnicodeError as exc:
            raise MySQLError(f'database name cannot be encoded as {self.charset}') from exc

    def query(self, sql: str) -> list[Result]:
        if not sql.strip():
            return []
        try:
            first = self._start_command(COM_QUERY, sql.encode(self._encoding))
            results: list[Result] = []
            while True:
                result = self._read_response(first)
                results.append(result)
                self.server_status = result.status_flags
                if not result.status_flags & SERVER_MORE_RESULTS_EXISTS:
                    return results
                first = self._require_packets().read_packet()
                _raise_if_error(first)
        except (MySQLConnectionError, ProtocolError):
            self._abort()
            raise
        except UnicodeError as exc:
            raise MySQLError(f'query cannot be encoded as {self.charset}') from exc

    execute = query

    def _parse_ok(self, payload: bytes) -> Result:
        if not payload or payload[0] not in (0x00, 0xFE):
            raise ProtocolError('malformed OK packet')
        affected_rows, offset = _read_lenenc_int(payload, 1)
        last_insert_id, offset = _read_lenenc_int(payload, offset)
        if affected_rows is None or last_insert_id is None or offset + 4 > len(payload):
            raise ProtocolError('truncated OK packet')
        status_flags, warning_count = struct.unpack_from('<HH', payload, offset)
        info = payload[offset + 4 :].decode(self._encoding, 'replace')
        return Result(
            affected_rows=affected_rows,
            last_insert_id=last_insert_id,
            warning_count=warning_count,
            status_flags=status_flags,
            info=info,
        )

    def _parse_eof(self, payload: bytes) -> tuple[int, int]:
        if len(payload) < 5 or payload[0] != 0xFE:
            raise ProtocolError('malformed EOF packet')
        warning_count, status_flags = struct.unpack_from('<HH', payload, 1)
        return warning_count, status_flags

    def _parse_column(self, payload: bytes) -> Column:
        values: list[bytes] = []
        offset = 0
        for _index in range(6):
            value, offset = _read_lenenc_bytes(payload, offset)
            if value is None:
                raise ProtocolError('NULL field in column definition')
            values.append(value)
        fixed_length, offset = _read_lenenc_int(payload, offset)
        if fixed_length is None or fixed_length < 12 or offset + fixed_length > len(payload):
            raise ProtocolError('malformed column-definition metadata')
        charset_id = struct.unpack_from('<H', payload, offset)[0]
        type_code = payload[offset + 6]
        flags = struct.unpack_from('<H', payload, offset + 7)[0]

        def decode(value: bytes) -> str:
            return value.decode(self._encoding, 'replace')

        return Column(
            name=decode(values[4]),
            schema=decode(values[1]),
            table=decode(values[2]),
            original_table=decode(values[3]),
            original_name=decode(values[5]),
            charset_id=charset_id,
            type_code=type_code,
            flags=flags,
        )

    def _parse_row(self, payload: bytes, columns: tuple[Column, ...]) -> tuple[Cell, ...]:
        row: list[Cell] = []
        offset = 0
        for column in columns:
            value, offset = _read_lenenc_bytes(payload, offset, allow_null=True)
            if value is None:
                row.append(None)
            elif column.charset_id == BINARY_CHARSET_ID and column.type_code in BINARY_FIELD_TYPES:
                row.append(value)
            else:
                row.append(value.decode(self._encoding, 'replace'))
        if offset != len(payload):
            raise ProtocolError('row contains trailing or excess field data')
        return tuple(row)

    def _read_response(self, first: bytes) -> Result:
        _raise_if_error(first)
        if first[:1] == b'\x00':
            return self._parse_ok(first)
        if first[:1] == b'\xfb':
            self._abort()
            raise ProtocolError('server requested LOCAL INFILE, which is disabled')

        column_count, offset = _read_lenenc_int(first)
        if column_count is None or offset != len(first) or not 0 < column_count <= MAX_COLUMNS:
            raise ProtocolError('invalid result-set column count')
        packets = self._require_packets()
        parsed_columns: list[Column] = []
        for _index in range(column_count):
            column_payload = packets.read_packet()
            _raise_if_error(column_payload)
            parsed_columns.append(self._parse_column(column_payload))
        columns = tuple(parsed_columns)
        metadata_end = packets.read_packet()
        _raise_if_error(metadata_end)
        if not (metadata_end[:1] == b'\xfe' and len(metadata_end) < 9):
            raise ProtocolError('result-set metadata has no EOF terminator')
        self._parse_eof(metadata_end)

        rows: list[tuple[Cell, ...]] = []
        while True:
            payload = packets.read_packet()
            _raise_if_error(payload)
            if payload[:1] == b'\xfe' and len(payload) < 9:
                warning_count, status_flags = self._parse_eof(payload)
                return Result(
                    columns=columns,
                    rows=rows,
                    affected_rows=len(rows),
                    warning_count=warning_count,
                    status_flags=status_flags,
                )
            rows.append(self._parse_row(payload, columns))


def connect(
    *,
    host: str = '127.0.0.1',
    port: int = 3306,
    user: str | None = None,
    password: str = '',
    database: str | None = None,
    unix_socket: str | None = None,
    charset: str = 'utf8mb4',
    ssl_mode: str = 'preferred',
    ssl_ca: str | None = None,
    ssl_cert: str | None = None,
    ssl_key: str | None = None,
    connect_timeout: float = 10.0,
    multi_statements: bool = True,
    get_server_public_key: bool = False,
    server_public_key: bytes | None = None,
    allow_cleartext_plugin: bool = False,
    max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
) -> Connection:
    """Create and connect a :class:`Connection`."""

    connection = Connection(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        unix_socket=unix_socket,
        charset=charset,
        ssl_mode=ssl_mode,
        ssl_ca=ssl_ca,
        ssl_cert=ssl_cert,
        ssl_key=ssl_key,
        connect_timeout=connect_timeout,
        multi_statements=multi_statements,
        get_server_public_key=get_server_public_key,
        server_public_key=server_public_key,
        allow_cleartext_plugin=allow_cleartext_plugin,
        max_message_size=max_message_size,
    )
    connection.connect()
    return connection


def _escape_text(value: str) -> str:
    output: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == '\\':
            output.append('\\\\')
        elif character == '\n':
            output.append('\\n')
        elif character == '\r':
            output.append('\\r')
        elif character == '\t':
            output.append('\\t')
        elif codepoint < 0x20 or 0x7F <= codepoint < 0xA0:
            output.append(f'\\x{codepoint:02x}')
        else:
            output.append(character)
    return ''.join(output)


def _format_cell(value: Cell, null_value: str) -> str:
    if value is None:
        return null_value
    if isinstance(value, bytes):
        return f'0x{value.hex()}'
    return _escape_text(value)


def _output_safe_text(output: TextIO, value: str) -> str:
    encoding = getattr(output, 'encoding', None)
    if not encoding:
        return value
    try:
        value.encode(encoding)
    except UnicodeEncodeError:
        return value.encode(encoding, 'backslashreplace').decode(encoding)
    return value


def _write_table(result: Result, output: TextIO, show_headers: bool, null_value: str) -> None:
    headers = [_output_safe_text(output, _escape_text(column.name)) for column in result.columns]
    rows = [[_output_safe_text(output, _format_cell(value, null_value)) for value in row] for row in result.rows]
    widths = [0] * len(headers)
    for index, header in enumerate(headers):
        widths[index] = len(header) if show_headers else 0
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    separator = '+' + '+'.join('-' * (width + 2) for width in widths) + '+'
    print(separator, file=output)
    if show_headers:
        print('| ' + ' | '.join(value.ljust(widths[index]) for index, value in enumerate(headers)) + ' |', file=output)
        print(separator, file=output)
    for row in rows:
        print('| ' + ' | '.join(value.ljust(widths[index]) for index, value in enumerate(row)) + ' |', file=output)
    print(separator, file=output)


def _write_delimited(
    result: Result,
    output: TextIO,
    delimiter: str,
    show_headers: bool,
    null_value: str,
) -> None:
    writer = csv.writer(output, delimiter=delimiter, lineterminator='\n')
    if show_headers:
        writer.writerow(_output_safe_text(output, _escape_text(column.name)) for column in result.columns)
    for row in result.rows:
        writer.writerow(_output_safe_text(output, _format_cell(value, null_value)) for value in row)


def _write_vertical(result: Result, output: TextIO, null_value: str) -> None:
    names = tuple(_output_safe_text(output, _escape_text(column.name)) for column in result.columns)
    width = max((len(name) for name in names), default=0)
    for row_number, row in enumerate(result.rows, 1):
        print(f'*************************** {row_number}. row ***************************', file=output)
        for name, value in zip(names, row, strict=True):
            print(f'{name.rjust(width)}: {_output_safe_text(output, _format_cell(value, null_value))}', file=output)


def write_results(
    results: list[Result],
    *,
    output_format: str,
    output: TextIO | None = None,
    status_output: TextIO | None = None,
    show_headers: bool = True,
    show_status: bool = False,
    null_value: str = 'NULL',
) -> None:
    """Write query rows and optional status messages to separate streams."""

    if output is None:
        output = sys.stdout
    if status_output is None:
        status_output = sys.stderr
    for result in results:
        if result.has_rows:
            if output_format == 'table':
                _write_table(result, output, show_headers, null_value)
            elif output_format == 'vertical':
                _write_vertical(result, output, null_value)
            elif output_format == 'csv':
                _write_delimited(result, output, ',', show_headers, null_value)
            elif output_format == 'tsv':
                _write_delimited(result, output, '\t', show_headers, null_value)
            else:
                raise ValueError(f'unsupported output format {output_format!r}')
            if show_status:
                count = len(result.rows)
                print(f'{count} row{"" if count == 1 else "s"} in set', file=status_output)
        elif show_status:
            count = result.affected_rows
            message = f'Query OK, {count} row{"" if count == 1 else "s"} affected'
            if result.warning_count:
                message += f', {result.warning_count} warning{"" if result.warning_count == 1 else "s"}'
            print(message, file=status_output)


def _scan_sql_completion(sql: str) -> bool:
    state = 'normal'
    complete = False
    index = 0
    while index < len(sql):
        character = sql[index]
        following = sql[index + 1] if index + 1 < len(sql) else ''
        if state == 'line-comment':
            if character == '\n':
                state = 'normal'
            index += 1
            continue
        if state == 'block-comment':
            if character == '*' and following == '/':
                state = 'normal'
                index += 2
            else:
                index += 1
            continue
        if state in ('single', 'double', 'backtick'):
            quote = {'single': "'", 'double': '"', 'backtick': '`'}[state]
            if character == '\\' and state != 'backtick':
                index += 2
                continue
            if character == quote:
                if following == quote:
                    index += 2
                    continue
                state = 'normal'
            index += 1
            continue
        if character.isspace():
            index += 1
            continue
        if character == '#':
            state = 'line-comment'
            index += 1
            continue
        if character == '-' and following == '-' and (index + 2 == len(sql) or sql[index + 2].isspace()):
            state = 'line-comment'
            index += 2
            continue
        if character == '/' and following == '*':
            state = 'block-comment'
            index += 2
            continue
        if character in ("'", '"', '`'):
            state = {"'": 'single', '"': 'double', '`': 'backtick'}[character]
            complete = False
            index += 1
            continue
        complete = character == ';'
        index += 1
    return state in ('normal', 'line-comment') and complete


def _repl_terminator(sql: str) -> tuple[str, bool] | None:
    stripped = sql.rstrip()
    if stripped.endswith(('\\g', '\\G')):
        candidate = stripped[:-2]
        if _scan_sql_completion(candidate + ';'):
            return candidate, stripped.endswith('\\G')
    if _scan_sql_completion(sql):
        return sql, False
    return None


_SYSTEM_DATABASES = frozenset({'information_schema', 'performance_schema', 'mysql', 'sys', 'ndbinfo'})

_SERVERINFO_SQL = (
    'SELECT VERSION() AS version, @@hostname AS hostname, @@version_comment AS version_comment, '
    '@@version_compile_os AS compile_os, @@version_compile_machine AS compile_machine, '
    '@@datadir AS datadir, @@port AS port, @@socket AS socket, '
    '@@secure_file_priv AS secure_file_priv;'
)


class _ReplExit(Exception):
    """Internal signal to leave the REPL with a specific exit code."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def _quote_identifier(name: str) -> str:
    return '`' + name.replace('`', '``') + '`'


def _sql_literal(value: Cell) -> str:
    if value is None:
        return 'NULL'
    if isinstance(value, bytes | bytearray):
        return "X'" + bytes(value).hex() + "'"
    text = str(value)
    return (
        "'"
        + text
        .replace('\\', '\\\\')
        .replace("'", "\\'")
        .replace('\n', '\\n')
        .replace('\r', '\\r')
        .replace('\0', '\\0')
        .replace('\x1a', '\\Z')
        + "'"
    )


def _parse_qualified_name(arg: str) -> tuple[str | None, str]:
    parts = [part.strip().strip('`') for part in arg.split('.')]
    if len(parts) == 1:
        return None, parts[0]
    return parts[0], parts[1]


def _next_loot_path(extension: str) -> str:
    if not os.path.isdir('loot'):
        os.makedirs('loot')
    index = 1
    while True:
        candidate = os.path.join('loot', f'loot_{index:03d}.{extension}')
        if not os.path.exists(candidate):
            return candidate
        index += 1


def _execute_repl_query(
    connection: Connection,
    sql: str,
    arguments: argparse.Namespace,
    *,
    vertical: bool = False,
) -> list[Result] | None:
    """Run SQL, render results, and report errors for the interactive REPL."""
    started = time.monotonic()
    try:
        results = connection.query(sql)
    except KeyboardInterrupt:
        connection.close()
        print('Query interrupted; the connection was closed.', file=sys.stderr)
        raise _ReplExit(130) from None
    except MySQLError as exc:
        print(f'ERROR: {_escape_text(str(exc))}', file=sys.stderr)
        if not connection.connected:
            raise _ReplExit(5) from None
        return None
    output_format = 'vertical' if vertical else arguments.output_format
    if output_format == 'auto':
        output_format = 'table'
    write_results(
        results,
        output_format=output_format,
        show_headers=not arguments.skip_column_names,
        show_status=True,
        null_value=arguments.null,
    )
    print(f'{time.monotonic() - started:.3f} sec', file=sys.stderr)
    return results


def _loot_query(connection: Connection, sql: str, arguments: argparse.Namespace) -> None:
    """Run SQL and write the rows to a numbered TSV file under ./loot/."""
    try:
        results = connection.query(sql)
    except KeyboardInterrupt:
        connection.close()
        print('Query interrupted; the connection was closed.', file=sys.stderr)
        raise _ReplExit(130) from None
    except MySQLError as exc:
        print(f'ERROR: {_escape_text(str(exc))}', file=sys.stderr)
        return
    try:
        path = _next_loot_path('tsv')
    except OSError as exc:
        print(f'ERROR: cannot create loot directory: {exc}', file=sys.stderr)
        return
    try:
        with open(path, 'w', encoding='utf-8', newline='') as handle:
            write_results(
                results,
                output_format='tsv',
                output=handle,
                show_headers=True,
                show_status=False,
                null_value=arguments.null,
            )
    except OSError as exc:
        print(f'ERROR: cannot write {path}: {exc}', file=sys.stderr)
        return
    total = sum(len(result.rows) for result in results if result.columns)
    print(f'Wrote {total} row(s) to {path}', file=sys.stderr)


def _dump_table(connection: Connection, output: TextIO, database: str, table: str) -> None:
    qualified = f'{_quote_identifier(database)}.{_quote_identifier(table)}'
    print(f'-- Table structure for table {database}.{table}', file=output)
    print(f'DROP TABLE IF EXISTS {qualified};', file=output)
    try:
        create_results = connection.query(f'SHOW CREATE TABLE {qualified};')
    except MySQLError as exc:
        print(f'-- cannot read CREATE TABLE for {database}.{table}: {exc}', file=output)
        return
    for result in create_results:
        for row in result.rows:
            if len(row) >= 2 and row[1]:
                statement = row[1] if isinstance(row[1], str) else str(row[1])
                print(statement.rstrip(';').rstrip() + ';', file=output)
    print(file=output)
    print(f'-- Dumping data for table {database}.{table}', file=output)
    try:
        data_results = connection.query(f'SELECT * FROM {qualified};')
    except MySQLError as exc:
        print(f'-- cannot SELECT from {database}.{table}: {exc}', file=output)
        return
    columns: list[Column] = []
    rows: list[tuple[Cell, ...]] = []
    for result in data_results:
        if result.columns and not columns:
            columns = list(result.columns)
        if result.rows:
            rows.extend(result.rows)
    if not columns or not rows:
        print('-- (no rows)', file=output)
        return
    column_list = ', '.join(_quote_identifier(column.name) for column in columns)
    for row in rows:
        values = ', '.join(_sql_literal(value) for value in row)
        print(f'INSERT INTO {qualified} ({column_list}) VALUES ({values});', file=output)


def _dump_database(connection: Connection, output: TextIO, database: str) -> None:
    quoted_db = _quote_identifier(database)
    print(f'-- Database: {database}', file=output)
    print(f'CREATE DATABASE IF NOT EXISTS {quoted_db};', file=output)
    print(f'USE {quoted_db};', file=output)
    print(file=output)
    try:
        table_results = connection.query(f'SHOW TABLES FROM {quoted_db};')
    except MySQLError as exc:
        print(f'-- cannot list tables in {database}: {exc}', file=output)
        print(file=output)
        return
    tables: list[str] = []
    for result in table_results:
        for row in result.rows:
            if row and row[0] is not None:
                tables.append(row[0] if isinstance(row[0], str) else str(row[0]))
    for table in tables:
        _dump_table(connection, output, database, table)
        print(file=output)


def _dump_connection(connection: Connection, output: TextIO) -> None:
    """Write a portable SQL dump of accessible user databases to output."""
    print('-- mycli-lite database dump', file=output)
    print(f'-- Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}', file=output)
    print(f'-- Server: {connection.server_version}', file=output)
    print(file=output)
    print('SET NAMES utf8mb4;', file=output)
    print('SET FOREIGN_KEY_CHECKS=0;', file=output)
    print(file=output)
    try:
        db_results = connection.query('SHOW DATABASES;')
    except MySQLError as exc:
        print(f'-- cannot list databases: {exc}', file=output)
        return
    databases: list[str] = []
    for result in db_results:
        for row in result.rows:
            if row and row[0] is not None:
                name = row[0] if isinstance(row[0], str) else str(row[0])
                if name not in _SYSTEM_DATABASES:
                    databases.append(name)
    for database in databases:
        _dump_database(connection, output, database)
    print('SET FOREIGN_KEY_CHECKS=1;', file=output)


def _dump_repl(connection: Connection, path: str | None) -> None:
    """Write a portable SQL dump to stdout (path is None) or to the given file."""
    if path is None:
        try:
            _dump_connection(connection, sys.stdout)
        except KeyboardInterrupt:
            connection.close()
            print('Dump interrupted; the connection was closed.', file=sys.stderr)
            raise _ReplExit(130) from None
        except UnicodeEncodeError as exc:
            print(f'ERROR: stdout cannot encode dump data: {exc}', file=sys.stderr)
            print('Use \\dump PATH to write the dump with UTF-8 encoding.', file=sys.stderr)
        return
    try:
        with open(path, 'w', encoding='utf-8', newline='') as handle:
            _dump_connection(connection, handle)
    except KeyboardInterrupt:
        connection.close()
        print('Dump interrupted; the connection was closed.', file=sys.stderr)
        raise _ReplExit(130) from None
    except OSError as exc:
        print(f'ERROR: cannot write {path}: {exc}', file=sys.stderr)
        return
    print(f'Wrote dump to {path}', file=sys.stderr)


def _print_repl_help(output: TextIO) -> None:
    print(
        'Commands: \\q quit, \\c clear input, \\u DB change database, \\s status, '
        '\\whoami user, \\serverinfo server, \\privs grants, \\dbs databases, '
        '\\tables [DB], \\columns DB.TABLE|TABLE, \\loot SQL, \\dump [PATH] all databases, '
        '\\G vertical output, \\? help.',
        file=output,
    )


def _handle_repl_command(connection: Connection, arguments: argparse.Namespace, stripped: str) -> bool:
    """Dispatch a single slash command from an empty input buffer.

    Returns True when the line was a recognized command, False otherwise.
    Raises ``_ReplExit`` when the REPL should leave its loop with a code.
    """
    lowered = stripped.lower()
    if lowered in ('\\q', 'quit', 'exit'):
        raise _ReplExit(0)
    if stripped == '\\?':
        _print_repl_help(sys.stderr)
        return True
    if stripped == '\\s':
        server_version = _escape_text(connection.server_version)
        transport = connection.tls_version or ('Unix socket' if connection.unix_socket else 'Plain TCP')
        database = _escape_text(connection.database or '(none)')
        print(
            f'Server: {server_version}; connection id: {connection.connection_id}; database: {database}; transport: {transport}.',
            file=sys.stderr,
        )
        return True
    if stripped.startswith('\\u '):
        database = stripped[3:].strip().removeprefix('`').removesuffix('`')
        try:
            connection.select_db(database)
        except MySQLError as exc:
            print(f'ERROR: {_escape_text(str(exc))}', file=sys.stderr)
        else:
            print(f'Database changed to {_escape_text(database)}.', file=sys.stderr)
        return True
    if stripped == '\\whoami':
        _execute_repl_query(connection, 'SELECT CURRENT_USER();', arguments)
        return True
    if stripped == '\\serverinfo':
        _execute_repl_query(connection, _SERVERINFO_SQL, arguments)
        return True
    if stripped == '\\privs':
        _execute_repl_query(connection, 'SHOW GRANTS;', arguments)
        return True
    if stripped == '\\dbs':
        _execute_repl_query(connection, 'SHOW DATABASES;', arguments)
        return True
    if stripped == '\\tables' or stripped.startswith('\\tables '):
        target = stripped[len('\\tables') :].strip()
        if target:
            schema_name, table_name = _parse_qualified_name(target)
            sql = f'SHOW TABLES FROM {_quote_identifier(schema_name or table_name)};'
        else:
            sql = 'SHOW TABLES;'
        _execute_repl_query(connection, sql, arguments)
        return True
    if stripped == '\\columns' or stripped.startswith('\\columns '):
        target = stripped[len('\\columns ') :].strip() if stripped != '\\columns' else ''
        schema_name, table = _parse_qualified_name(target)
        if not table:
            print('ERROR: \\columns requires <database>.<table> or <table>.', file=sys.stderr)
            return True
        if schema_name:
            sql = f'SHOW COLUMNS FROM {_quote_identifier(table)} FROM {_quote_identifier(schema_name)};'
        else:
            sql = f'SHOW COLUMNS FROM {_quote_identifier(table)};'
        _execute_repl_query(connection, sql, arguments)
        return True
    if stripped == '\\loot' or stripped.startswith('\\loot '):
        sql = stripped[len('\\loot ') :].strip() if stripped != '\\loot' else ''
        if not sql:
            print('ERROR: \\loot requires a SQL statement.', file=sys.stderr)
            return True
        _loot_query(connection, sql, arguments)
        return True
    if stripped == '\\dump' or stripped.startswith('\\dump '):
        path = stripped[len('\\dump') :].strip() or None
        _dump_repl(connection, path)
        return True
    return False


def _run_repl(connection: Connection, arguments: argparse.Namespace) -> int:
    server_version = _escape_text(connection.server_version)
    target = _escape_text(connection.unix_socket or f'{connection.host}:{connection.port}')
    print(
        f'Connected to {server_version} at {target}.',
        file=sys.stderr,
    )
    print('History, completion, and LOCAL INFILE are disabled. Use \\? for help.', file=sys.stderr)
    buffer: list[str] = []
    while True:
        prompt = 'mysql> ' if not buffer else '    -> '
        try:
            print(prompt, end='', file=sys.stderr, flush=True)
            line = input()
        except EOFError:
            print(file=sys.stderr)
            return 0
        except KeyboardInterrupt:
            buffer.clear()
            print('^C', file=sys.stderr)
            continue

        stripped = line.strip()
        if stripped == '\\c':
            buffer.clear()
            print('Input cleared.', file=sys.stderr)
            continue
        if not buffer:
            try:
                if _handle_repl_command(connection, arguments, stripped):
                    continue
            except _ReplExit as signal:
                return signal.code
            if not stripped:
                continue

        buffer.append(line)
        sql = '\n'.join(buffer)
        terminated = _repl_terminator(sql)
        if terminated is None:
            continue
        statement, vertical = terminated
        buffer.clear()
        try:
            _execute_repl_query(connection, statement, arguments, vertical=vertical)
        except _ReplExit as signal:
            return signal.code


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='mycli-lite',
        add_help=False,
        description='A single-file, dependency-free MySQL classic-protocol client.',
    )
    parser.add_argument('--help', '-?', action='help', help='Show this help message and exit.')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('database', nargs='?', help='Initial database.')
    parser.add_argument('-D', '--database', dest='database_option', help='Initial database.')
    parser.add_argument('-h', '--host', help='Database host. Default: 127.0.0.1.')
    parser.add_argument('-P', '--port', type=int, help='Database TCP port. Default: 3306.')
    parser.add_argument('-S', '--socket', help='Explicit Unix-domain socket path.')
    parser.add_argument('-u', '--user', help='Database user. Default: current OS user.')
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument('-p', '--password', action='store_true', help='Prompt for the password.')
    password_group.add_argument('--password-env', metavar='NAME', help='Read the password from this environment variable.')
    password_group.add_argument('--password-file', metavar='PATH', help='Read the first line of this file as the password.')
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('-e', '--execute', metavar='SQL', help='Execute SQL and exit.')
    input_group.add_argument('-f', '--file', metavar='PATH', help='Execute a UTF-8 SQL file; use - for stdin.')
    parser.add_argument(
        '--format',
        dest='output_format',
        choices=('auto', 'table', 'tsv', 'csv', 'vertical'),
        default='auto',
        help='Result format. Auto uses table on a TTY and TSV otherwise.',
    )
    parser.add_argument('-N', '--skip-column-names', action='store_true', help='Do not write column names.')
    parser.add_argument('--null', default='NULL', help='Text used for SQL NULL. Default: NULL.')
    parser.add_argument('--charset', choices=tuple(CHARSETS), default='utf8mb4')
    parser.add_argument('--connect-timeout', type=float, default=10.0, metavar='SECONDS')
    parser.add_argument('--ssl-mode', choices=SSL_MODES, default='preferred')
    parser.add_argument('--ssl-ca', metavar='PATH')
    parser.add_argument('--ssl-cert', metavar='PATH')
    parser.add_argument('--ssl-key', metavar='PATH')
    parser.add_argument(
        '--get-server-public-key',
        action='store_true',
        help='Allow an insecure TCP server to provide its RSA key for SHA-2 authentication.',
    )
    parser.add_argument('--server-public-key', metavar='PATH', help='Pinned RSA public key for SHA-2 authentication.')
    parser.add_argument(
        '--allow-cleartext-plugin',
        action='store_true',
        help='Allow mysql_clear_password over TLS or a Unix socket.',
    )
    return parser


def _parser_error(parser: argparse.ArgumentParser, message: str) -> NoReturn:
    parser.error(message)


def _read_password(arguments: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    if arguments.password:
        if sys.stdin.isatty() or os.name == 'nt':
            return getpass.getpass('Password: ')
        try:
            with open('/dev/tty', 'w', encoding='utf-8') as terminal:
                return getpass.getpass('Password: ', stream=terminal)
        except OSError:
            _parser_error(parser, 'cannot prompt for a password without a controlling terminal')
    if arguments.password_env:
        if arguments.password_env not in os.environ:
            _parser_error(parser, f'environment variable {arguments.password_env!r} is not set')
        return os.environ[arguments.password_env]
    if arguments.password_file:
        try:
            stat_result = os.stat(arguments.password_file)
            if os.name != 'nt' and stat_result.st_mode & 0o077:
                print('Warning: password file is readable by group or others.', file=sys.stderr)
            with open(arguments.password_file, encoding='utf-8') as password_file:
                return password_file.readline().rstrip('\r\n')
        except OSError as exc:
            _parser_error(parser, f'cannot read password file: {exc}')
    return ''


def _read_public_key(path: str | None, parser: argparse.ArgumentParser) -> bytes | None:
    if path is None:
        return None
    try:
        with open(path, 'rb') as public_key_file:
            return public_key_file.read()
    except OSError as exc:
        _parser_error(parser, f'cannot read server public key: {exc}')


def _read_batch_sql(arguments: argparse.Namespace, parser: argparse.ArgumentParser) -> str | None:
    if arguments.execute is not None:
        return arguments.execute
    if arguments.file:
        if arguments.file == '-':
            return sys.stdin.read()
        try:
            with open(arguments.file, encoding='utf-8') as sql_file:
                return sql_file.read()
        except OSError as exc:
            _parser_error(parser, f'cannot read SQL file: {exc}')
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return None


def _silence_broken_stdout() -> None:
    """Redirect stdout after EPIPE so interpreter shutdown cannot flush it again."""

    try:
        stdout_fd = sys.stdout.fileno()
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
    except (AttributeError, OSError, ValueError):
        return
    try:
        os.dup2(devnull_fd, stdout_fd)
    except OSError:
        pass
    finally:
        os.close(devnull_fd)


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface and return its process exit code."""

    parser = _build_parser()
    arguments = parser.parse_args(argv)
    if arguments.database and arguments.database_option:
        parser.error('database was supplied both positionally and with --database')
    database = arguments.database_option or arguments.database
    host = arguments.host or os.getenv('MYSQL_HOST') or '127.0.0.1'
    raw_port = arguments.port if arguments.port is not None else os.getenv('MYSQL_TCP_PORT', '3306')
    try:
        port = int(raw_port)
    except ValueError:
        parser.error(f'invalid MySQL port {raw_port!r}')
    user = arguments.user or os.getenv('MYSQL_USER') or getpass.getuser()
    unix_socket = arguments.socket or os.getenv('MYSQL_UNIX_SOCKET')
    try:
        password = _read_password(arguments, parser)
        public_key = _read_public_key(arguments.server_public_key, parser)
        batch_sql = _read_batch_sql(arguments, parser)
    except KeyboardInterrupt:
        print('Interrupted.', file=sys.stderr)
        return 130
    if batch_sql is not None and not batch_sql.strip():
        return 0

    try:
        connection = Connection(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            unix_socket=unix_socket,
            charset=arguments.charset,
            ssl_mode=arguments.ssl_mode,
            ssl_ca=arguments.ssl_ca,
            ssl_cert=arguments.ssl_cert,
            ssl_key=arguments.ssl_key,
            connect_timeout=arguments.connect_timeout,
            get_server_public_key=arguments.get_server_public_key,
            server_public_key=public_key,
            allow_cleartext_plugin=arguments.allow_cleartext_plugin,
        )
    except ValueError as exc:
        parser.error(str(exc))
    try:
        connection.connect()
    except (MySQLError, OSError, ssl.SSLError) as exc:
        print(f'Connection error: {_escape_text(str(exc))}', file=sys.stderr)
        return 3

    try:
        if batch_sql is None:
            exit_code = _run_repl(connection, arguments)
            sys.stdout.flush()
            return exit_code
        try:
            results = connection.query(batch_sql)
        except ServerError as exc:
            print(f'ERROR: {_escape_text(str(exc))}', file=sys.stderr)
            return 4
        except MySQLError as exc:
            print(f'Protocol error: {_escape_text(str(exc))}', file=sys.stderr)
            return 5
        output_format = arguments.output_format
        if output_format == 'auto':
            output_format = 'table' if sys.stdout.isatty() else 'tsv'
        write_results(
            results,
            output_format=output_format,
            show_headers=not arguments.skip_column_names,
            show_status=sys.stdout.isatty(),
            null_value=arguments.null,
        )
        sys.stdout.flush()
        return 0
    except KeyboardInterrupt:
        print('Interrupted.', file=sys.stderr)
        return 130
    except BrokenPipeError:
        _silence_broken_stdout()
        return 141
    finally:
        connection.close()


def _main_entrypoint() -> int | str | None:
    """Run main while making argparse output obey the broken-pipe exit contract."""

    try:
        try:
            exit_code: int | str | None = main()
        except SystemExit as error:
            exit_code = error.code
        sys.stdout.flush()
    except BrokenPipeError:
        _silence_broken_stdout()
        return 141
    return exit_code


if __name__ == '__main__':
    raise SystemExit(_main_entrypoint())
