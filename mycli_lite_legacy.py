#!/usr/bin/env python
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
"""The dependency-free mycli-lite client for legacy CPython runtimes.

This artifact intentionally uses syntax accepted by CPython 2.7 and 3.4. It
implements the same public library and CLI surface as the modern single-file
client without importing third-party packages.
"""

from __future__ import print_function

import argparse
import base64
import binascii
import errno
import getpass
import hashlib
import io
import os
import re
import socket
import ssl
import struct
import sys
import time


__version__ = '0.3.0'

if not (
    sys.version_info[:3] >= (2, 7, 9)
    and (sys.version_info[0] == 2 or sys.version_info[0] == 3)
    and not (sys.version_info[0] == 3 and sys.version_info[:2] < (3, 4))
):
    raise RuntimeError('mycli_lite_legacy requires CPython 2.7.9+ or 3.4+')

PY2 = sys.version_info[0] == 2
if PY2:
    text_type = unicode
    binary_type = str
    integer_types = (int, long)
else:
    text_type = str
    binary_type = bytes
    integer_types = (int,)


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
BINARY_FIELD_TYPES = frozenset((
    MYSQL_TYPE_VARCHAR,
    MYSQL_TYPE_BIT,
    MYSQL_TYPE_TINY_BLOB,
    MYSQL_TYPE_MEDIUM_BLOB,
    MYSQL_TYPE_LONG_BLOB,
    MYSQL_TYPE_BLOB,
    MYSQL_TYPE_VAR_STRING,
    MYSQL_TYPE_STRING,
    MYSQL_TYPE_GEOMETRY,
))

CHARSETS = {
    'ascii': (11, 'ascii'),
    'latin1': (8, 'latin1'),
    'utf8': (33, 'utf-8'),
    'utf8mb3': (33, 'utf-8'),
    'utf8mb4': (45, 'utf-8'),
}

CHARSET_NAMES = ('ascii', 'latin1', 'utf8', 'utf8mb3', 'utf8mb4')
SSL_MODES = ('disabled', 'preferred', 'required', 'verify-ca', 'verify-identity')


class MySQLError(Exception):
    """Base error raised by the lightweight client."""

    def __unicode__(self):
        if not self.args:
            return u''
        value = self.args[0]
        if isinstance(value, text_type):
            return value
        if isinstance(value, binary_type):
            return value.decode('utf-8', 'replace')
        return text_type(value)

    def __str__(self):
        if PY2:
            return self.__unicode__().encode('utf-8')
        return Exception.__str__(self)


class MySQLConnectionError(MySQLError):
    """A socket, TLS, or authentication connection failed."""


class ProtocolError(MySQLError):
    """The peer sent a malformed or unsupported protocol message."""


class AuthenticationError(MySQLConnectionError):
    """The server requested an unsupported or unsafe authentication flow."""


class ServerError(MySQLError):
    """The server returned an ERR packet."""

    def __init__(self, code, message, sqlstate=None):
        self.code = code
        self.sqlstate = sqlstate
        self.message = message
        state = u' [{0}]'.format(sqlstate) if sqlstate else u''
        MySQLError.__init__(self, u'{0}{1}: {2}'.format(code, state, message))


def _record_values(name, fields, args, kwargs, defaults=None):
    if len(args) > len(fields):
        raise TypeError('{0}() takes at most {1} arguments ({2} given)'.format(name, len(fields), len(args)))
    values = {}
    for index, value in enumerate(args):
        values[fields[index]] = value
    for field_name in fields:
        if field_name in kwargs:
            if field_name in values:
                raise TypeError("{0}() got multiple values for argument '{1}'".format(name, field_name))
            values[field_name] = kwargs.pop(field_name)
    if kwargs:
        unexpected = sorted(kwargs)[0]
        raise TypeError("{0}() got an unexpected keyword argument '{1}'".format(name, unexpected))
    defaults = defaults or {}
    for field_name in fields:
        if field_name not in values:
            if field_name not in defaults:
                raise TypeError("{0}() missing required argument: '{1}'".format(name, field_name))
            default = defaults[field_name]
            values[field_name] = default() if callable(default) else default
    return values


class _FrozenRecord(object):
    __slots__ = ()
    _fields = ()

    def __setattr__(self, name, value):
        if hasattr(self, name):
            raise AttributeError("cannot assign to field '{0}'".format(name))
        object.__setattr__(self, name, value)

    def __delattr__(self, name):
        raise AttributeError("cannot delete field '{0}'".format(name))

    def __repr__(self):
        values = ', '.join('{0}={1!r}'.format(name, getattr(self, name)) for name in self._fields)
        return '{0}({1})'.format(self.__class__.__name__, values)

    def __eq__(self, other):
        return type(self) is type(other) and all(
            getattr(self, name) == getattr(other, name) for name in self._fields
        )

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(tuple(getattr(self, name) for name in self._fields))


class Handshake(_FrozenRecord):
    """The useful fields from a protocol-v10 server greeting."""

    __slots__ = (
        'server_version',
        'connection_id',
        'capabilities',
        'charset_id',
        'status_flags',
        'auth_data',
        'auth_plugin',
    )
    _fields = __slots__

    def __init__(self, *args, **kwargs):
        values = _record_values('Handshake', self._fields, args, kwargs)
        for name in self._fields:
            object.__setattr__(self, name, values[name])


class Column(_FrozenRecord):
    """Column metadata from a text-protocol result set."""

    __slots__ = (
        'name',
        'schema',
        'table',
        'original_table',
        'original_name',
        'charset_id',
        'type_code',
        'flags',
    )
    _fields = __slots__

    def __init__(self, *args, **kwargs):
        values = _record_values('Column', self._fields, args, kwargs)
        for name in self._fields:
            object.__setattr__(self, name, values[name])


Cell = (text_type, binary_type, type(None))


class Result(object):
    """One result returned by a query or stored procedure."""

    __slots__ = (
        'columns',
        'rows',
        'affected_rows',
        'last_insert_id',
        'warning_count',
        'status_flags',
        'info',
    )
    _fields = __slots__

    def __init__(self, *args, **kwargs):
        values = _record_values(
            'Result',
            self._fields,
            args,
            kwargs,
            {
                'columns': (),
                'rows': list,
                'affected_rows': 0,
                'last_insert_id': 0,
                'warning_count': 0,
                'status_flags': 0,
                'info': u'',
            },
        )
        for name in self._fields:
            setattr(self, name, values[name])

    @property
    def has_rows(self):
        return bool(self.columns)

    def __repr__(self):
        values = ', '.join('{0}={1!r}'.format(name, getattr(self, name)) for name in self._fields)
        return 'Result({0})'.format(values)

    def __eq__(self, other):
        return type(self) is type(other) and all(
            getattr(self, name) == getattr(other, name) for name in self._fields
        )

    def __ne__(self, other):
        return not self == other

    __hash__ = None


def _byte_at(value, index):
    item = value[index]
    return ord(item) if not isinstance(item, integer_types) else item


def _bytes_from_ints(values):
    return b''.join(struct.pack('B', value) for value in values)


def _bytearray_bytes(value):
    return value.decode('latin1').encode('latin1')


def _int_to_bytes(value, length, byteorder):
    if value < 0:
        raise OverflowError('cannot convert negative integer to unsigned bytes')
    if byteorder == 'little':
        shifts = range(0, length * 8, 8)
    elif byteorder == 'big':
        shifts = range((length - 1) * 8, -1, -8)
    else:
        raise ValueError('byteorder must be either little or big')
    result = _bytes_from_ints((value >> shift) & 0xFF for shift in shifts)
    if value >> (length * 8):
        raise OverflowError('integer does not fit in requested byte length')
    return result


def _int_from_bytes(value, byteorder):
    result = 0
    values = [_byte_at(value, index) for index in range(len(value))]
    if byteorder == 'little':
        values.reverse()
    elif byteorder != 'big':
        raise ValueError('byteorder must be either little or big')
    for item in values:
        result = (result << 8) | item
    return result


def _ensure_text(value, encoding='utf-8'):
    if isinstance(value, text_type):
        return value
    if isinstance(value, binary_type):
        return value.decode(encoding)
    return text_type(value)


def _encode_text(value, encoding):
    return _ensure_text(value).encode(encoding)


def _exception_text(error):
    try:
        return text_type(error)
    except UnicodeError:
        return str(error).decode('utf-8', 'replace')


def _pack_uint24(value):
    if not 0 <= value <= MAX_PACKET_PAYLOAD:
        raise ValueError('three-byte integer is out of range')
    return _int_to_bytes(value, 3, 'little')


def _read_uint24(value):
    if len(value) != 3:
        raise ProtocolError('truncated three-byte integer')
    return _int_from_bytes(value, 'little')


def _encode_lenenc_int(value):
    if value < 0:
        raise ValueError('length-encoded integer cannot be negative')
    if value < 0xFB:
        return _bytes_from_ints((value,))
    if value <= 0xFFFF:
        return b'\xfc' + struct.pack('<H', value)
    if value <= 0xFFFFFF:
        return b'\xfd' + _int_to_bytes(value, 3, 'little')
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b'\xfe' + struct.pack('<Q', value)
    raise ValueError('length-encoded integer is too large')


def _read_lenenc_int(data, offset=0, allow_null=False):
    if offset >= len(data):
        raise ProtocolError('truncated length-encoded integer')
    marker = _byte_at(data, offset)
    offset += 1
    if marker < 0xFB:
        return marker, offset
    if marker == 0xFB:
        if allow_null:
            return None, offset
        raise ProtocolError('unexpected NULL length marker')
    sizes = {0xFC: 2, 0xFD: 3, 0xFE: 8}
    if marker not in sizes:
        raise ProtocolError('invalid length marker 0x{0:02x}'.format(marker))
    size = sizes[marker]
    end = offset + size
    if end > len(data):
        raise ProtocolError('truncated length-encoded integer payload')
    return _int_from_bytes(data[offset:end], 'little'), end


def _read_lenenc_bytes(data, offset, allow_null=False):
    length, offset = _read_lenenc_int(data, offset, allow_null=allow_null)
    if length is None:
        return None, offset
    end = offset + length
    if end > len(data):
        raise ProtocolError('truncated length-encoded string')
    return data[offset:end], end


def _read_nul(data, offset, field_name):
    end = data.find(b'\0', offset)
    if end < 0:
        raise ProtocolError('unterminated {0}'.format(field_name))
    return data[offset:end], end + 1


class PacketIO(object):
    """Read and write logical MySQL packets on a connected socket."""

    def __init__(self, sock, *args, **kwargs):
        if args:
            raise TypeError('PacketIO() accepts only one positional argument')
        fragment_size = kwargs.pop('fragment_size', MAX_PACKET_PAYLOAD)
        max_message_size = kwargs.pop('max_message_size', DEFAULT_MAX_MESSAGE_SIZE)
        if kwargs:
            unexpected = sorted(kwargs)[0]
            raise TypeError("PacketIO() got an unexpected keyword argument '{0}'".format(unexpected))
        if not 0 < fragment_size <= MAX_PACKET_PAYLOAD:
            raise ValueError('invalid packet fragment size')
        if max_message_size < fragment_size:
            raise ValueError('maximum message size is smaller than one fragment')
        self.socket = sock
        self.fragment_size = fragment_size
        self.max_message_size = max_message_size
        self.sequence_id = 0

    def replace_socket(self, sock):
        self.socket = sock

    def reset_sequence(self):
        self.sequence_id = 0

    def _read_exact(self, size):
        chunks = bytearray()
        while len(chunks) < size:
            try:
                chunk = self.socket.recv(size - len(chunks))
            except (OSError, socket.error) as error:
                raise MySQLConnectionError('socket read failed: {0}'.format(_exception_text(error)))
            if not chunk:
                raise MySQLConnectionError('server closed the connection')
            chunks.extend(chunk)
        return _bytearray_bytes(chunks)

    def read_packet(self):
        payload = bytearray()
        while True:
            header = self._read_exact(4)
            size = _read_uint24(header[:3])
            sequence_id = _byte_at(header, 3)
            if sequence_id != self.sequence_id:
                raise ProtocolError(
                    'packet sequence mismatch: received {0}, expected {1}'.format(sequence_id, self.sequence_id)
                )
            self.sequence_id = (self.sequence_id + 1) & 0xFF
            if size > self.fragment_size:
                raise ProtocolError('packet payload exceeds {0} bytes'.format(self.fragment_size))
            if len(payload) + size > self.max_message_size:
                raise ProtocolError('logical packet exceeds {0} bytes'.format(self.max_message_size))
            payload.extend(self._read_exact(size) if size else b'')
            if size < self.fragment_size:
                return _bytearray_bytes(payload)

    def write_packet(self, payload):
        if len(payload) > self.max_message_size:
            raise ProtocolError('logical packet exceeds {0} bytes'.format(self.max_message_size))
        offset = 0
        while True:
            chunk = payload[offset : offset + self.fragment_size]
            header = _pack_uint24(len(chunk)) + _bytes_from_ints((self.sequence_id,))
            try:
                self.socket.sendall(header + chunk)
            except (OSError, socket.error) as error:
                raise MySQLConnectionError('socket write failed: {0}'.format(_exception_text(error)))
            self.sequence_id = (self.sequence_id + 1) & 0xFF
            offset += len(chunk)
            if len(chunk) < self.fragment_size:
                return


def _parse_error_packet(payload):
    if len(payload) < 3 or _byte_at(payload, 0) != 0xFF:
        raise ProtocolError('malformed server error packet')
    code = struct.unpack_from('<H', payload, 1)[0]
    offset = 3
    sqlstate = None
    if len(payload) >= 9 and payload[offset : offset + 1] == b'#':
        sqlstate = payload[offset + 1 : offset + 6].decode('ascii', 'replace')
        offset += 6
    message = payload[offset:].decode('utf-8', 'replace')
    return ServerError(code, message, sqlstate)


def _raise_if_error(payload):
    if payload[:1] == b'\xff':
        raise _parse_error_packet(payload)


def _parse_handshake(payload):
    _raise_if_error(payload)
    if not payload or _byte_at(payload, 0) != 10:
        version = _byte_at(payload, 0) if payload else None
        raise ProtocolError('unsupported MySQL protocol version {0!r}'.format(version))
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
    charset_id = _byte_at(payload, offset)
    status_flags = struct.unpack_from('<H', payload, offset + 1)[0]
    capabilities |= struct.unpack_from('<H', payload, offset + 3)[0] << 16
    auth_data_length = _byte_at(payload, offset + 5)
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


def _sha1(data=b''):
    try:
        return hashlib.sha1(data, usedforsecurity=False)
    except TypeError:
        try:
            return hashlib.sha1(data)
        except ValueError as error:
            raise AuthenticationError(
                'SHA-1 is unavailable under the active security policy: {0}'.format(error)
            )
    except ValueError as error:
        raise AuthenticationError('SHA-1 is unavailable under the active security policy: {0}'.format(error))


def _xor_bytes(left, right):
    if len(left) != len(right):
        raise ValueError('XOR operands must have equal lengths')
    return _bytes_from_ints(_byte_at(left, index) ^ _byte_at(right, index) for index in range(len(left)))


def _scramble_native_password(password, nonce):
    if not password:
        return b''
    stage_1 = _sha1(password).digest()
    stage_2 = _sha1(stage_1).digest()
    challenge = _sha1(nonce[:20] + stage_2).digest()
    return _xor_bytes(stage_1, challenge)


def _scramble_caching_sha2(password, nonce):
    if not password:
        return b''
    stage_1 = hashlib.sha256(password).digest()
    stage_2 = hashlib.sha256(stage_1).digest()
    challenge = hashlib.sha256(stage_2 + nonce[:20]).digest()
    return _xor_bytes(stage_1, challenge)


def _read_der_value(data, offset):
    if offset + 2 > len(data):
        raise AuthenticationError('truncated RSA public key')
    tag = _byte_at(data, offset)
    length_byte = _byte_at(data, offset + 1)
    offset += 2
    if length_byte & 0x80:
        length_size = length_byte & 0x7F
        if length_size == 0 or length_size > 4 or offset + length_size > len(data):
            raise AuthenticationError('invalid RSA public-key length')
        length = _int_from_bytes(data[offset : offset + length_size], 'big')
        offset += length_size
    else:
        length = length_byte
    end = offset + length
    if end > len(data):
        raise AuthenticationError('truncated RSA public-key value')
    return tag, data[offset:end], end


def _decode_der_integer(value):
    if not value or _byte_at(value, 0) & 0x80:
        raise AuthenticationError('invalid RSA public-key integer')
    return _int_from_bytes(value, 'big')


def _parse_pkcs1_rsa_key(data):
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


def _strict_b64decode(value):
    if len(value) % 4 or re.search(b'[^A-Za-z0-9+/=]', value):
        raise binascii.Error('invalid base64 data')
    padding = len(value) - len(value.rstrip(b'='))
    if padding > 2 or (b'=' in value[:-padding] if padding else b'=' in value):
        raise binascii.Error('invalid base64 padding')
    return base64.b64decode(value)


def _parse_rsa_public_key(pem):
    pem = pem.rstrip(b'\0')
    if len(pem) > 16384:
        raise AuthenticationError('RSA public key is unreasonably large')
    try:
        lines = pem.decode('ascii').strip().splitlines()
    except UnicodeDecodeError:
        raise AuthenticationError('RSA public key is not PEM text')
    if len(lines) < 3 or lines[0] not in (
        u'-----BEGIN PUBLIC KEY-----',
        u'-----BEGIN RSA PUBLIC KEY-----',
    ):
        raise AuthenticationError('unsupported RSA public-key PEM format')
    expected_footer = lines[0].replace(u'BEGIN', u'END')
    if lines[-1] != expected_footer:
        raise AuthenticationError('unterminated RSA public key')
    try:
        encoded = u''.join(lines[1:-1]).encode('ascii')
        der = _strict_b64decode(encoded)
    except (ValueError, binascii.Error):
        raise AuthenticationError('invalid RSA public-key base64')

    if lines[0] == u'-----BEGIN RSA PUBLIC KEY-----':
        modulus, exponent = _parse_pkcs1_rsa_key(der)
    else:
        tag, outer, end = _read_der_value(der, 0)
        if tag != 0x30 or end != len(der):
            raise AuthenticationError('invalid SubjectPublicKeyInfo sequence')
        tag, _algorithm, offset = _read_der_value(outer, 0)
        if tag != 0x30:
            raise AuthenticationError('invalid RSA algorithm identifier')
        tag, bit_string, offset = _read_der_value(outer, offset)
        if tag != 0x03 or offset != len(outer) or not bit_string or _byte_at(bit_string, 0) != 0:
            raise AuthenticationError('invalid RSA public-key bit string')
        modulus, exponent = _parse_pkcs1_rsa_key(bit_string[1:])

    bit_length = modulus.bit_length()
    if not 1024 <= bit_length <= 16384 or exponent < 3 or exponent > 0xFFFFFFFF or not exponent & 1:
        raise AuthenticationError('unsupported RSA public-key parameters')
    return modulus, exponent


def _mgf1(seed, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(_sha1(seed + _int_to_bytes(counter, 4, 'big')).digest())
        counter += 1
    return _bytearray_bytes(output[:length])


def _rsa_oaep_encrypt(message, public_key):
    modulus, exponent = _parse_rsa_public_key(public_key)
    key_size = (modulus.bit_length() + 7) // 8
    digest_size = _sha1().digest_size
    if len(message) > key_size - 2 * digest_size - 2:
        raise AuthenticationError('password is too long for the RSA public key')
    label_hash = _sha1(b'').digest()
    padding = b'\0' * (key_size - len(message) - 2 * digest_size - 2)
    data_block = label_hash + padding + b'\x01' + message
    seed = os.urandom(digest_size)
    masked_block = _xor_bytes(data_block, _mgf1(seed, key_size - digest_size - 1))
    masked_seed = _xor_bytes(seed, _mgf1(masked_block, digest_size))
    encoded = b'\0' + masked_seed + masked_block
    encrypted = pow(_int_from_bytes(encoded, 'big'), exponent, modulus)
    return _int_to_bytes(encrypted, key_size, 'big')


def _encrypt_sha2_password(password, nonce, public_key):
    plain = bytearray(password + b'\0')
    nonce = nonce[:20]
    if not nonce:
        raise AuthenticationError('server supplied an empty authentication nonce')
    for index in range(len(plain)):
        plain[index] ^= _byte_at(nonce, index % len(nonce))
    return _rsa_oaep_encrypt(_bytearray_bytes(plain), public_key)


def _is_ip_address(host):
    try:
        text_host = _ensure_text(host)
        address = text_host.encode('ascii') if PY2 else text_host
    except UnicodeError:
        return False
    if u':' in text_host:
        return True
    for family in (socket.AF_INET, getattr(socket, 'AF_INET6', None)):
        if family is None or not hasattr(socket, 'inet_pton'):
            continue
        try:
            socket.inet_pton(family, address)
            return True
        except (socket.error, TypeError, ValueError):
            pass
    try:
        socket.inet_aton(address)
        return True
    except (socket.error, TypeError, ValueError):
        pass
    return False


def _canonical_tls_host(host, is_ip_address):
    host = _ensure_text(host)
    if is_ip_address:
        address = host.encode('ascii') if PY2 else host
        try:
            return socket.inet_ntoa(socket.inet_aton(address))
        except (socket.error, TypeError, ValueError):
            return address
    encoded = host.encode('idna').lower()
    return encoded if PY2 else encoded.decode('ascii')


_CONNECTION_DEFAULTS = {
    'host': '127.0.0.1',
    'port': 3306,
    'user': None,
    'password': '',
    'database': None,
    'unix_socket': None,
    'charset': 'utf8mb4',
    'ssl_mode': 'preferred',
    'ssl_ca': None,
    'ssl_cert': None,
    'ssl_key': None,
    'connect_timeout': 10.0,
    'multi_statements': True,
    'get_server_public_key': False,
    'server_public_key': None,
    'allow_cleartext_plugin': False,
    'max_message_size': DEFAULT_MAX_MESSAGE_SIZE,
}


class Connection(object):
    """A small synchronous connection for MySQL text-protocol queries."""

    def __init__(self, *args, **kwargs):
        if args:
            raise TypeError('Connection() accepts keyword arguments only')
        values = dict(_CONNECTION_DEFAULTS)
        for name in list(kwargs):
            if name not in values:
                raise TypeError("Connection() got an unexpected keyword argument '{0}'".format(name))
            values[name] = kwargs.pop(name)

        charset = values['charset']
        ssl_mode = values['ssl_mode']
        port = values['port']
        connect_timeout = values['connect_timeout']
        max_message_size = values['max_message_size']
        if charset not in CHARSETS:
            raise ValueError('unsupported character set {0!r}'.format(charset))
        if ssl_mode not in SSL_MODES:
            raise ValueError('unsupported SSL mode {0!r}'.format(ssl_mode))
        if not 1 <= port <= 65535:
            raise ValueError('port must be between 1 and 65535')
        if connect_timeout <= 0:
            raise ValueError('connection timeout must be positive')
        if max_message_size < MAX_PACKET_PAYLOAD:
            raise ValueError('maximum message size must be at least {0}'.format(MAX_PACKET_PAYLOAD))

        self.host = _ensure_text(values['host'])
        self.port = port
        user = values['user'] if values['user'] is not None else getpass.getuser()
        self.user = _ensure_text(user, sys.getfilesystemencoding() or 'utf-8')
        self.database = _ensure_text(values['database']) if values['database'] is not None else None
        self.unix_socket = values['unix_socket']
        self.charset = charset
        self.ssl_mode = ssl_mode
        self.ssl_ca = values['ssl_ca']
        self.ssl_cert = values['ssl_cert']
        self.ssl_key = values['ssl_key']
        self.connect_timeout = connect_timeout
        self.multi_statements = values['multi_statements']
        self.get_server_public_key = values['get_server_public_key']
        self.server_public_key = values['server_public_key']
        self.allow_cleartext_plugin = values['allow_cleartext_plugin']
        self.max_message_size = max_message_size
        self._charset_id, self._encoding = CHARSETS[charset]
        self._password = _encode_text(values['password'], 'utf-8')
        self._socket = None
        self._packets = None
        self._closed = True
        self._secure = False
        self._tls_active = False
        self.server_version = u''
        self.connection_id = 0
        self.server_capabilities = 0
        self.client_capabilities = 0
        self.server_status = 0

    def __repr__(self):
        target = self.unix_socket or u'{0}:{1}'.format(self.host, self.port)
        return 'Connection(user={0!r}, target={1!r}, database={2!r})'.format(
            self.user,
            target,
            self.database,
        )

    @property
    def connected(self):
        return not self._closed and self._socket is not None and self._packets is not None

    @property
    def secure(self):
        return self._secure

    @property
    def tls_active(self):
        return self._tls_active

    @property
    def tls_version(self):
        if isinstance(self._socket, ssl.SSLSocket) and hasattr(self._socket, 'version'):
            return self._socket.version()
        if isinstance(self._socket, ssl.SSLSocket):
            cipher = self._socket.cipher()
            return cipher[1] if cipher else None
        return None

    def __enter__(self):
        if not self.connected:
            self.connect()
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        self.close()

    def _open_socket(self):
        sock = None
        try:
            if self.unix_socket:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.connect_timeout)
                sock.connect(self.unix_socket)
                self._secure = True
                return sock
            network_host = self.host.encode('idna') if PY2 else self.host
            sock = socket.create_connection((network_host, self.port), self.connect_timeout)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            return sock
        except (OSError, socket.error) as error:
            if sock is not None:
                try:
                    sock.close()
                except (OSError, socket.error):
                    pass
            target = self.unix_socket or u'{0}:{1}'.format(self.host, self.port)
            raise MySQLConnectionError(u'cannot connect to {0}: {1}'.format(target, _exception_text(error)))

    def _use_tls(self, handshake):
        if self.unix_socket or self.ssl_mode == 'disabled':
            return False
        server_supports_tls = bool(handshake.capabilities & CLIENT_SSL)
        if not server_supports_tls and self.ssl_mode != 'preferred':
            raise MySQLConnectionError('TLS is required but the server does not advertise TLS support')
        return server_supports_tls

    def _create_ssl_context(self):
        verify = self.ssl_mode in ('verify-ca', 'verify-identity')
        try:
            if verify:
                context = ssl.create_default_context(cafile=self.ssl_ca)
                if hasattr(ssl, 'VERIFY_X509_STRICT') and hasattr(context, 'verify_flags'):
                    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
                if hasattr(context, 'check_hostname'):
                    context.check_hostname = False
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                if hasattr(context, 'check_hostname'):
                    context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            for option_name in ('OP_NO_SSLv2', 'OP_NO_SSLv3'):
                option = getattr(ssl, option_name, 0)
                if option:
                    context.options |= option
            if self.ssl_cert:
                context.load_cert_chain(self.ssl_cert, keyfile=self.ssl_key)
            elif self.ssl_key:
                raise MySQLConnectionError('--ssl-key requires --ssl-cert')
            return context
        except MySQLConnectionError:
            raise
        except (OSError, IOError, ssl.SSLError) as error:
            raise MySQLConnectionError('cannot configure TLS: {0}'.format(_exception_text(error)))

    def _choose_capabilities(self, handshake, use_tls):
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

    def _initial_auth_response(self, plugin, nonce):
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
            if not self.get_server_public_key:
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

    def _build_handshake_response(self, plugin, nonce):
        response = self._initial_auth_response(plugin, nonce)
        payload = struct.pack(
            '<IIB23s',
            self.client_capabilities,
            MAX_PACKET_PAYLOAD,
            self._charset_id,
            b'',
        )
        payload += self.user.encode(self._encoding) + b'\0'
        if self.client_capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            payload += _encode_lenenc_int(len(response)) + response
        elif self.client_capabilities & CLIENT_SECURE_CONNECTION:
            if len(response) > 255:
                raise AuthenticationError('authentication response is too large')
            payload += _bytes_from_ints((len(response),)) + response
        else:
            payload += response + b'\0'
        if self.client_capabilities & CLIENT_CONNECT_WITH_DB and self.database:
            payload += self.database.encode(self._encoding) + b'\0'
        if self.client_capabilities & CLIENT_PLUGIN_AUTH:
            payload += _ensure_text(plugin).encode('ascii', 'replace') + b'\0'
        return payload

    def _send_auth_switch_response(self, plugin, nonce):
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
        raise AuthenticationError('unsupported authentication plugin {0!r}'.format(plugin))

    def _authenticate(self, plugin, nonce):
        packets = self._require_packets()
        pending_public_key_for = None
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
                switched_nonce = payload[offset:]
                nonce = switched_nonce[:-1] if switched_nonce.endswith(b'\0') else switched_nonce
                nonce = nonce[:20]
                if plugin != 'mysql_clear_password' and not nonce:
                    raise AuthenticationError('authentication switch has no nonce')
                pending_public_key_for = self._send_auth_switch_response(plugin, nonce)
                continue
            if payload[:1] != b'\x01':
                raise AuthenticationError(
                    'unexpected authentication packet 0x{0:02x}'.format(_byte_at(payload, 0))
                )
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
            raise AuthenticationError('unexpected extra data for authentication plugin {0!r}'.format(plugin))

    def connect(self):
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
                host_is_ip = _is_ip_address(self.host)
                if (
                    self.ssl_mode == 'verify-identity'
                    and sys.version_info[:2] < (3, 5)
                    and host_is_ip
                ):
                    raise MySQLConnectionError(
                        'verify-identity with an IP address requires Python 3.5+; use a DNS hostname'
                    )
                tls_host = _canonical_tls_host(self.host, host_is_ip)
                ssl_request = struct.pack(
                    '<IIB23s',
                    self.client_capabilities,
                    MAX_PACKET_PAYLOAD,
                    self._charset_id,
                    b'',
                )
                self._packets.write_packet(ssl_request)
                context = self._create_ssl_context()
                wrap_kwargs = {}
                if getattr(ssl, 'HAS_SNI', False) and not host_is_ip:
                    wrap_kwargs['server_hostname'] = tls_host
                wrapped = None
                try:
                    wrapped = context.wrap_socket(self._socket, **wrap_kwargs)
                    if self.ssl_mode == 'verify-identity':
                        ssl.match_hostname(wrapped.getpeercert(), tls_host)
                except (OSError, socket.error, ssl.SSLError, ssl.CertificateError) as error:
                    if wrapped is not None:
                        try:
                            wrapped.close()
                        except (OSError, socket.error):
                            pass
                    raise MySQLConnectionError('TLS handshake failed: {0}'.format(_exception_text(error)))
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
        except UnicodeError:
            self._abort()
            raise MySQLConnectionError('connection fields cannot be encoded as {0}'.format(self.charset))
        except BaseException:
            self._abort()
            raise

    def _require_packets(self):
        if not self.connected or self._packets is None:
            raise MySQLConnectionError('connection is closed')
        return self._packets

    def _abort(self):
        sock = self._socket
        self._socket = None
        self._packets = None
        self._closed = True
        self._secure = False
        self._tls_active = False
        if sock is not None:
            try:
                sock.close()
            except (OSError, socket.error):
                pass

    def close(self):
        if self._closed:
            return
        packets = self._packets
        if packets is not None:
            try:
                packets.reset_sequence()
                packets.write_packet(_bytes_from_ints((COM_QUIT,)))
            except MySQLError:
                pass
        self._abort()

    def _start_command(self, command, payload=b''):
        try:
            packets = self._require_packets()
            packets.reset_sequence()
            packets.write_packet(_bytes_from_ints((command,)) + payload)
            response = packets.read_packet()
            _raise_if_error(response)
            return response
        except (MySQLConnectionError, ProtocolError):
            self._abort()
            raise

    def ping(self):
        try:
            response = self._start_command(COM_PING)
            if response[:1] != b'\x00':
                raise ProtocolError('COM_PING did not return an OK packet')
            self.server_status = self._parse_ok(response).status_flags
        except ProtocolError:
            self._abort()
            raise

    def select_db(self, database):
        try:
            database = _ensure_text(database)
            response = self._start_command(COM_INIT_DB, database.encode(self._encoding))
            if response[:1] != b'\x00':
                raise ProtocolError('COM_INIT_DB did not return an OK packet')
            self.server_status = self._parse_ok(response).status_flags
            self.database = database
        except ProtocolError:
            self._abort()
            raise
        except UnicodeError:
            raise MySQLError('database name cannot be encoded as {0}'.format(self.charset))

    def query(self, sql):
        sql = _ensure_text(sql)
        if not sql.strip():
            return []
        try:
            first = self._start_command(COM_QUERY, sql.encode(self._encoding))
            results = []
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
        except UnicodeError:
            raise MySQLError('query cannot be encoded as {0}'.format(self.charset))

    execute = query

    def _parse_ok(self, payload):
        if not payload or _byte_at(payload, 0) not in (0x00, 0xFE):
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

    def _parse_eof(self, payload):
        if len(payload) < 5 or _byte_at(payload, 0) != 0xFE:
            raise ProtocolError('malformed EOF packet')
        warning_count, status_flags = struct.unpack_from('<HH', payload, 1)
        return warning_count, status_flags

    def _parse_column(self, payload):
        values = []
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
        type_code = _byte_at(payload, offset + 6)
        flags = struct.unpack_from('<H', payload, offset + 7)[0]

        def decode(value):
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

    def _parse_row(self, payload, columns):
        row = []
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

    def _read_response(self, first):
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
        parsed_columns = []
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

        rows = []
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


def connect(*args, **kwargs):
    """Create and connect a :class:`Connection`."""

    if args:
        raise TypeError('connect() accepts keyword arguments only')
    connection = Connection(**kwargs)
    connection.connect()
    return connection


def _escape_text(value):
    value = _ensure_text(value)
    output = []
    for character in value:
        codepoint = ord(character)
        if character == u'\\':
            output.append(u'\\\\')
        elif character == u'\n':
            output.append(u'\\n')
        elif character == u'\r':
            output.append(u'\\r')
        elif character == u'\t':
            output.append(u'\\t')
        elif codepoint < 0x20 or 0x7F <= codepoint < 0xA0:
            output.append(u'\\x{0:02x}'.format(codepoint))
        else:
            output.append(character)
    return u''.join(output)


def _format_cell(value, null_value):
    if value is None:
        return null_value
    if isinstance(value, binary_type):
        return u'0x' + binascii.hexlify(value).decode('ascii')
    return _escape_text(value)


def _write_text(output, value):
    value = _ensure_text(value)
    if not PY2:
        try:
            output.write(value)
        except UnicodeEncodeError:
            encoding = getattr(output, 'encoding', None) or 'utf-8'
            safe_value = value.encode(encoding, 'backslashreplace').decode(encoding)
            output.write(safe_value)
        return
    try:
        output.write(value)
    except (TypeError, UnicodeEncodeError):
        encoding = getattr(output, 'encoding', None) or 'utf-8'
        output.write(value.encode(encoding, 'backslashreplace'))


def _output_safe_text(output, value):
    value = _ensure_text(value)
    encoding = getattr(output, 'encoding', None)
    if not encoding:
        return value
    try:
        value.encode(encoding)
    except UnicodeEncodeError:
        return value.encode(encoding, 'backslashreplace').decode(encoding)
    return value


def _emit(output, value=u'', end=u'\n', flush=False):
    _write_text(output, _ensure_text(value) + end)
    if flush and hasattr(output, 'flush'):
        output.flush()


def _write_table(result, output, show_headers, null_value):
    headers = [_output_safe_text(output, _escape_text(column.name)) for column in result.columns]
    rows = [
        [_output_safe_text(output, _format_cell(value, null_value)) for value in row]
        for row in result.rows
    ]
    widths = [0] * len(headers)
    for index, header in enumerate(headers):
        widths[index] = len(header) if show_headers else 0
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    separator = u'+' + u'+'.join(u'-' * (width + 2) for width in widths) + u'+'
    _emit(output, separator)
    if show_headers:
        _emit(
            output,
            u'| '
            + u' | '.join(
                value.ljust(widths[index]) for index, value in enumerate(headers)
            )
            + u' |',
        )
        _emit(output, separator)
    for row in rows:
        _emit(
            output,
            u'| ' + u' | '.join(value.ljust(widths[index]) for index, value in enumerate(row)) + u' |',
        )
    _emit(output, separator)


def _quote_delimited(value, delimiter):
    if delimiter in value or u'"' in value or u'\r' in value or u'\n' in value:
        return u'"' + value.replace(u'"', u'""') + u'"'
    return value


def _write_delimited(result, output, delimiter, show_headers, null_value):
    if show_headers:
        values = [_escape_text(column.name) for column in result.columns]
        line = u'""' if len(values) == 1 and values[0] == u'' else delimiter.join(
            _quote_delimited(value, delimiter) for value in values
        )
        _emit(output, line)
    for row in result.rows:
        values = [_format_cell(value, null_value) for value in row]
        line = u'""' if len(values) == 1 and values[0] == u'' else delimiter.join(
            _quote_delimited(value, delimiter) for value in values
        )
        _emit(output, line)


def _write_vertical(result, output, null_value):
    names = [_output_safe_text(output, _escape_text(column.name)) for column in result.columns]
    width = max([len(name) for name in names] or [0])
    for row_number, row in enumerate(result.rows, 1):
        _emit(output, u'*************************** {0}. row ***************************'.format(row_number))
        if len(row) != len(result.columns):
            raise ValueError('row and column counts differ')
        for name, value in zip(names, row):
            _emit(
                output,
                u'{0}: {1}'.format(
                    name.rjust(width),
                    _output_safe_text(output, _format_cell(value, null_value)),
                ),
            )


def write_results(results, *args, **kwargs):
    """Write query rows and optional status messages to separate streams."""

    if args:
        raise TypeError('write_results() accepts only one positional argument')
    if 'output_format' not in kwargs:
        raise TypeError("write_results() missing required keyword argument: 'output_format'")
    output_format = kwargs.pop('output_format')
    output = kwargs.pop('output', None)
    status_output = kwargs.pop('status_output', None)
    show_headers = kwargs.pop('show_headers', True)
    show_status = kwargs.pop('show_status', False)
    null_value = _ensure_text(kwargs.pop('null_value', 'NULL'))
    if kwargs:
        unexpected = sorted(kwargs)[0]
        raise TypeError("write_results() got an unexpected keyword argument '{0}'".format(unexpected))
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
                _write_delimited(result, output, u',', show_headers, null_value)
            elif output_format == 'tsv':
                _write_delimited(result, output, u'\t', show_headers, null_value)
            else:
                raise ValueError('unsupported output format {0!r}'.format(output_format))
            if show_status:
                count = len(result.rows)
                _emit(status_output, u'{0} row{1} in set'.format(count, u'' if count == 1 else u's'))
        elif show_status:
            count = result.affected_rows
            message = u'Query OK, {0} row{1} affected'.format(count, u'' if count == 1 else u's')
            if result.warning_count:
                message += u', {0} warning{1}'.format(
                    result.warning_count,
                    u'' if result.warning_count == 1 else u's',
                )
            _emit(status_output, message)


def _scan_sql_completion(sql):
    sql = _ensure_text(sql)
    state = 'normal'
    complete = False
    index = 0
    while index < len(sql):
        character = sql[index]
        following = sql[index + 1] if index + 1 < len(sql) else u''
        if state == 'line-comment':
            if character == u'\n':
                state = 'normal'
            index += 1
            continue
        if state == 'block-comment':
            if character == u'*' and following == u'/':
                state = 'normal'
                index += 2
            else:
                index += 1
            continue
        if state in ('single', 'double', 'backtick'):
            quote = {'single': u"'", 'double': u'"', 'backtick': u'`'}[state]
            if character == u'\\' and state != 'backtick':
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
        if character == u'#':
            state = 'line-comment'
            index += 1
            continue
        if character == u'-' and following == u'-' and (
            index + 2 == len(sql) or sql[index + 2].isspace()
        ):
            state = 'line-comment'
            index += 2
            continue
        if character == u'/' and following == u'*':
            state = 'block-comment'
            index += 2
            continue
        if character in (u"'", u'"', u'`'):
            state = {u"'": 'single', u'"': 'double', u'`': 'backtick'}[character]
            complete = False
            index += 1
            continue
        complete = character == u';'
        index += 1
    return state in ('normal', 'line-comment') and complete


def _repl_terminator(sql):
    stripped = sql.rstrip()
    if stripped.endswith((u'\\g', u'\\G')):
        candidate = stripped[:-2]
        if _scan_sql_completion(candidate + u';'):
            return candidate, stripped.endswith(u'\\G')
    if _scan_sql_completion(sql):
        return sql, False
    return None


_SYSTEM_DATABASES = frozenset((
    u'information_schema',
    u'performance_schema',
    u'mysql',
    u'sys',
    u'ndbinfo',
))

_SERVERINFO_SQL = (
    u'SELECT VERSION() AS version, @@hostname AS hostname, @@version_comment AS version_comment, '
    u'@@version_compile_os AS compile_os, @@version_compile_machine AS compile_machine, '
    u'@@datadir AS datadir, @@port AS port, @@socket AS socket, '
    u'@@secure_file_priv AS secure_file_priv;'
)


class _ReplExit(Exception):
    """Internal signal to leave the REPL with a specific exit code."""

    def __init__(self, code):
        Exception.__init__(self, code)
        self.code = code


def _quote_identifier(name):
    return u'`' + name.replace(u'`', u'``') + u'`'


def _sql_literal(value):
    if value is None:
        return u'NULL'
    if isinstance(value, bytearray):
        return u"X'" + binascii.hexlify(bytes(value)).decode(u'ascii') + u"'"
    if isinstance(value, binary_type):
        return u"X'" + binascii.hexlify(value).decode(u'ascii') + u"'"
    text = _ensure_text(value)
    return (
        u"'"
        + text.replace(u'\\', u'\\\\')
        .replace(u"'", u"\\'")
        .replace(u'\n', u'\\n')
        .replace(u'\r', u'\\r')
        .replace(u'\0', u'\\0')
        .replace(u'\x1a', u'\\Z')
        + u"'"
    )


def _parse_qualified_name(arg):
    parts = [part.strip().strip(u'`') for part in arg.split(u'.')]
    if len(parts) == 1:
        return None, parts[0]
    return parts[0], parts[1]


def _next_loot_path(extension):
    if not os.path.isdir(u'loot'):
        os.makedirs(u'loot')
    index = 1
    while True:
        candidate = os.path.join(u'loot', u'loot_{0:03d}.{1}'.format(index, extension))
        if not os.path.exists(candidate):
            return candidate
        index += 1


def _print_repl_help(output):
    _emit(
        output,
        u'Commands: \\q quit, \\c clear input, \\u DB change database, \\s status, '
        u'\\whoami user, \\serverinfo server, \\privs grants, \\dbs databases, '
        u'\\tables [DB], \\columns DB.TABLE|TABLE, \\loot SQL, \\dump [PATH] all databases, '
        u'\\G vertical output, \\? help.',
    )


def _read_input():
    if PY2:
        value = raw_input()
        return value.decode(getattr(sys.stdin, 'encoding', None) or 'utf-8', 'replace')
    return input()


_monotonic = getattr(time, 'monotonic', time.time)


def _execute_repl_query(connection, sql, arguments, vertical=False):
    """Run SQL, render results, and report errors for the interactive REPL."""
    started = _monotonic()
    try:
        results = connection.query(sql)
    except KeyboardInterrupt:
        connection.close()
        _emit(sys.stderr, 'Query interrupted; the connection was closed.')
        raise _ReplExit(130)
    except MySQLError as error:
        _emit(sys.stderr, u'ERROR: {0}'.format(_escape_text(_exception_text(error))))
        if not connection.connected:
            raise _ReplExit(5)
        return None
    output_format = u'vertical' if vertical else arguments.output_format
    if output_format == u'auto':
        output_format = u'table'
    write_results(
        results,
        output_format=output_format,
        show_headers=not arguments.skip_column_names,
        show_status=True,
        null_value=arguments.null,
    )
    _emit(sys.stderr, u'{0:.3f} sec'.format(_monotonic() - started))
    return results


def _loot_query(connection, sql, arguments):
    """Run SQL and write the rows to a numbered TSV file under ./loot/."""
    try:
        results = connection.query(sql)
    except KeyboardInterrupt:
        connection.close()
        _emit(sys.stderr, 'Query interrupted; the connection was closed.')
        raise _ReplExit(130)
    except MySQLError as error:
        _emit(sys.stderr, u'ERROR: {0}'.format(_escape_text(_exception_text(error))))
        return
    try:
        path = _next_loot_path(u'tsv')
    except (OSError, IOError) as error:
        _emit(sys.stderr, u'ERROR: cannot create loot directory: {0}'.format(_exception_text(error)))
        return
    try:
        handle = io.open(path, u'w', encoding=u'utf-8', newline=u'')
        try:
            write_results(
                results,
                output_format=u'tsv',
                output=handle,
                show_headers=True,
                show_status=False,
                null_value=arguments.null,
            )
        finally:
            handle.close()
    except (OSError, IOError) as error:
        _emit(sys.stderr, u'ERROR: cannot write {0}: {1}'.format(path, _exception_text(error)))
        return
    total = sum(len(result.rows) for result in results if result.columns)
    _emit(sys.stderr, u'Wrote {0} row(s) to {1}'.format(total, path))


def _dump_table(connection, output, database, table):
    qualified = u'{0}.{1}'.format(_quote_identifier(database), _quote_identifier(table))
    _emit(output, u'-- Table structure for table {0}.{1}'.format(database, table))
    _emit(output, u'DROP TABLE IF EXISTS {0};'.format(qualified))
    try:
        create_results = connection.query(u'SHOW CREATE TABLE {0};'.format(qualified))
    except MySQLError as error:
        _emit(output, u'-- cannot read CREATE TABLE for {0}.{1}: {2}'.format(
            database, table, _exception_text(error)))
        return
    for result in create_results:
        for row in result.rows:
            if len(row) >= 2 and row[1]:
                statement = row[1] if isinstance(row[1], text_type) else _ensure_text(row[1])
                _emit(output, statement.rstrip(u';').rstrip() + u';')
    _emit(output)
    _emit(output, u'-- Dumping data for table {0}.{1}'.format(database, table))
    try:
        data_results = connection.query(u'SELECT * FROM {0};'.format(qualified))
    except MySQLError as error:
        _emit(output, u'-- cannot SELECT from {0}.{1}: {2}'.format(
            database, table, _exception_text(error)))
        return
    columns = []
    rows = []
    for result in data_results:
        if result.columns and not columns:
            columns = list(result.columns)
        if result.rows:
            rows.extend(result.rows)
    if not columns or not rows:
        _emit(output, '-- (no rows)')
        return
    column_list = u', '.join(_quote_identifier(column.name) for column in columns)
    for row in rows:
        values = u', '.join(_sql_literal(value) for value in row)
        _emit(output, u'INSERT INTO {0} ({1}) VALUES ({2});'.format(qualified, column_list, values))


def _dump_database(connection, output, database):
    quoted_db = _quote_identifier(database)
    _emit(output, u'-- Database: {0}'.format(database))
    _emit(output, u'CREATE DATABASE IF NOT EXISTS {0};'.format(quoted_db))
    _emit(output, u'USE {0};'.format(quoted_db))
    _emit(output)
    try:
        table_results = connection.query(u'SHOW TABLES FROM {0};'.format(quoted_db))
    except MySQLError as error:
        _emit(output, u'-- cannot list tables in {0}: {1}'.format(database, _exception_text(error)))
        _emit(output)
        return
    tables = []
    for result in table_results:
        for row in result.rows:
            if row and row[0] is not None:
                name = row[0] if isinstance(row[0], text_type) else _ensure_text(row[0])
                tables.append(name)
    for table in tables:
        _dump_table(connection, output, database, table)
        _emit(output)


def _dump_connection(connection, output):
    """Write a portable SQL dump of accessible user databases to output."""
    _emit(output, '-- mycli-lite database dump')
    _emit(output, u'-- Generated: {0}'.format(time.strftime(u'%Y-%m-%d %H:%M:%S')))
    _emit(output, u'-- Server: {0}'.format(connection.server_version))
    _emit(output)
    _emit(output, 'SET NAMES utf8mb4;')
    _emit(output, 'SET FOREIGN_KEY_CHECKS=0;')
    _emit(output)
    try:
        db_results = connection.query('SHOW DATABASES;')
    except MySQLError as error:
        _emit(output, u'-- cannot list databases: {0}'.format(_exception_text(error)))
        return
    databases = []
    for result in db_results:
        for row in result.rows:
            if row and row[0] is not None:
                name = row[0] if isinstance(row[0], text_type) else _ensure_text(row[0])
                if name not in _SYSTEM_DATABASES:
                    databases.append(name)
    for database in databases:
        _dump_database(connection, output, database)
    _emit(output, 'SET FOREIGN_KEY_CHECKS=1;')


def _dump_repl(connection, path=None):
    """Write a portable SQL dump to stdout (path is None) or to the given file."""
    if path is None:
        try:
            _dump_connection(connection, sys.stdout)
        except KeyboardInterrupt:
            connection.close()
            _emit(sys.stderr, 'Dump interrupted; the connection was closed.')
            raise _ReplExit(130)
        except UnicodeEncodeError as error:
            _emit(sys.stderr, u'ERROR: stdout cannot encode dump data: {0}'.format(_exception_text(error)))
            _emit(sys.stderr, u'Use \\dump PATH to write the dump with UTF-8 encoding.')
        return
    try:
        handle = io.open(path, u'w', encoding=u'utf-8', newline=u'')
        try:
            _dump_connection(connection, handle)
        finally:
            handle.close()
    except KeyboardInterrupt:
        connection.close()
        _emit(sys.stderr, 'Dump interrupted; the connection was closed.')
        raise _ReplExit(130)
    except (OSError, IOError) as error:
        _emit(sys.stderr, u'ERROR: cannot write {0}: {1}'.format(path, _exception_text(error)))
        return
    _emit(sys.stderr, u'Wrote dump to {0}'.format(path))


def _handle_repl_command(connection, arguments, stripped):
    """Dispatch a single slash command from an empty input buffer.

    Returns True when the line was a recognized command, False otherwise.
    Raises ``_ReplExit`` when the REPL should leave its loop with a code.
    """
    lowered = stripped.lower()
    if lowered in (u'\\q', u'quit', u'exit'):
        raise _ReplExit(0)
    if stripped == u'\\?':
        _print_repl_help(sys.stderr)
        return True
    if stripped == u'\\s':
        server_version = _escape_text(connection.server_version)
        transport = connection.tls_version or (u'Unix socket' if connection.unix_socket else u'Plain TCP')
        database = _escape_text(connection.database or u'(none)')
        _emit(
            sys.stderr,
            u'Server: {0}; connection id: {1}; database: {2}; transport: {3}.'.format(
                server_version,
                connection.connection_id,
                database,
                transport,
            ),
        )
        return True
    if stripped.startswith(u'\\u '):
        database = stripped[3:].strip()
        if database.startswith(u'`'):
            database = database[1:]
        if database.endswith(u'`'):
            database = database[:-1]
        try:
            connection.select_db(database)
        except MySQLError as error:
            _emit(sys.stderr, u'ERROR: {0}'.format(_escape_text(_exception_text(error))))
        else:
            _emit(sys.stderr, u'Database changed to {0}.'.format(_escape_text(database)))
        return True
    if stripped == u'\\whoami':
        _execute_repl_query(connection, u'SELECT CURRENT_USER();', arguments)
        return True
    if stripped == u'\\serverinfo':
        _execute_repl_query(connection, _SERVERINFO_SQL, arguments)
        return True
    if stripped == u'\\privs':
        _execute_repl_query(connection, u'SHOW GRANTS;', arguments)
        return True
    if stripped == u'\\dbs':
        _execute_repl_query(connection, u'SHOW DATABASES;', arguments)
        return True
    if stripped == u'\\tables' or stripped.startswith(u'\\tables '):
        target = stripped[len(u'\\tables'):].strip()
        if target:
            database, table_name = _parse_qualified_name(target)
            sql = u'SHOW TABLES FROM {0};'.format(_quote_identifier(database or table_name))
        else:
            sql = u'SHOW TABLES;'
        _execute_repl_query(connection, sql, arguments)
        return True
    if stripped == u'\\columns' or stripped.startswith(u'\\columns '):
        target = stripped[len(u'\\columns '):].strip() if stripped != u'\\columns' else u''
        database, table = _parse_qualified_name(target)
        if not table:
            _emit(sys.stderr, u'ERROR: \\columns requires <database>.<table> or <table>.')
            return True
        if database:
            sql = u'SHOW COLUMNS FROM {0} FROM {1};'.format(
                _quote_identifier(table), _quote_identifier(database))
        else:
            sql = u'SHOW COLUMNS FROM {0};'.format(_quote_identifier(table))
        _execute_repl_query(connection, sql, arguments)
        return True
    if stripped == u'\\loot' or stripped.startswith(u'\\loot '):
        sql = stripped[len(u'\\loot '):].strip() if stripped != u'\\loot' else u''
        if not sql:
            _emit(sys.stderr, u'ERROR: \\loot requires a SQL statement.')
            return True
        _loot_query(connection, sql, arguments)
        return True
    if stripped == u'\\dump' or stripped.startswith(u'\\dump '):
        path = stripped[len(u'\\dump'):].strip() or None
        _dump_repl(connection, path)
        return True
    return False


def _run_repl(connection, arguments):
    server_version = _escape_text(connection.server_version)
    target = _escape_text(connection.unix_socket or u'{0}:{1}'.format(connection.host, connection.port))
    _emit(sys.stderr, u'Connected to {0} at {1}.'.format(server_version, target))
    _emit(sys.stderr, 'History, completion, and LOCAL INFILE are disabled. Use \\? for help.')
    buffer = []
    while True:
        prompt = u'mysql> ' if not buffer else u'    -> '
        try:
            _emit(sys.stderr, prompt, end=u'', flush=True)
            line = _read_input()
        except EOFError:
            _emit(sys.stderr)
            return 0
        except KeyboardInterrupt:
            del buffer[:]
            _emit(sys.stderr, '^C')
            continue

        stripped = line.strip()
        if stripped == u'\\c':
            del buffer[:]
            _emit(sys.stderr, 'Input cleared.')
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
        sql = u'\n'.join(buffer)
        terminated = _repl_terminator(sql)
        if terminated is None:
            continue
        statement, vertical = terminated
        del buffer[:]
        try:
            _execute_repl_query(connection, statement, arguments, vertical=vertical)
        except _ReplExit as signal:
            return signal.code


class _VersionAction(argparse.Action):
    def __init__(self, option_strings, dest, default=None, help=None):
        argparse.Action.__init__(
            self,
            option_strings=option_strings,
            dest=dest,
            nargs=0,
            default=default,
            required=False,
            help=help,
        )

    def __call__(self, parser, namespace, values, option_string=None):
        del namespace, values, option_string
        _emit(sys.stdout, u'{0} {1}'.format(parser.prog, __version__))
        parser.exit()


def _build_parser():
    parser = argparse.ArgumentParser(
        prog='mycli-lite',
        add_help=False,
        description='A single-file, dependency-free MySQL classic-protocol client.',
    )
    parser.add_argument('--help', '-?', action='help', help='Show this help message and exit.')
    parser.add_argument(
        '--version',
        action=_VersionAction,
        help='show program\'s version number and exit',
    )
    parser.add_argument('database', nargs='?', help='Initial database.')
    parser.add_argument('-D', '--database', dest='database_option', help='Initial database.')
    parser.add_argument('-h', '--host', help='Database host. Default: 127.0.0.1.')
    parser.add_argument('-P', '--port', type=int, help='Database TCP port. Default: 3306.')
    parser.add_argument('-S', '--socket', help='Explicit Unix-domain socket path.')
    parser.add_argument('-u', '--user', help='Database user. Default: current OS user.')
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument('-p', '--password', action='store_true', help='Prompt for the password.')
    password_group.add_argument(
        '--password-env',
        metavar='NAME',
        help='Read the password from this environment variable.',
    )
    password_group.add_argument(
        '--password-file',
        metavar='PATH',
        help='Read the first line of this file as the password.',
    )
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
    parser.add_argument('--charset', choices=CHARSET_NAMES, default='utf8mb4')
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
    parser.add_argument(
        '--server-public-key',
        metavar='PATH',
        help='Pinned RSA public key for SHA-2 authentication.',
    )
    parser.add_argument(
        '--allow-cleartext-plugin',
        action='store_true',
        help='Allow mysql_clear_password over TLS or a Unix socket.',
    )
    return parser


def _parser_error(parser, message):
    parser.error(message)


def _read_password(arguments, parser):
    if arguments.password:
        if sys.stdin.isatty() or os.name == 'nt':
            return _ensure_text(getpass.getpass('Password: '), getattr(sys.stdin, 'encoding', None) or 'utf-8')
        try:
            terminal_open = open if PY2 else io.open
            terminal_kwargs = {} if PY2 else {'encoding': 'utf-8'}
            with terminal_open('/dev/tty', 'w', **terminal_kwargs) as terminal:
                return _ensure_text(getpass.getpass('Password: ', stream=terminal))
        except (OSError, IOError):
            _parser_error(parser, 'cannot prompt for a password without a controlling terminal')
    if arguments.password_env:
        if arguments.password_env not in os.environ:
            _parser_error(
                parser,
                'environment variable {0!r} is not set'.format(arguments.password_env),
            )
        return _ensure_text(os.environ[arguments.password_env])
    if arguments.password_file:
        try:
            stat_result = os.stat(arguments.password_file)
            if os.name != 'nt' and stat_result.st_mode & 0o077:
                _emit(sys.stderr, 'Warning: password file is readable by group or others.')
            with io.open(arguments.password_file, encoding='utf-8') as password_file:
                return password_file.readline().rstrip(u'\r\n')
        except (OSError, IOError) as error:
            _parser_error(parser, 'cannot read password file: {0}'.format(_exception_text(error)))
    return u''


def _read_public_key(path, parser):
    if path is None:
        return None
    try:
        with open(path, 'rb') as public_key_file:
            return public_key_file.read()
    except (OSError, IOError) as error:
        _parser_error(parser, 'cannot read server public key: {0}'.format(_exception_text(error)))


def _read_stream_text(stream):
    value = stream.read()
    if isinstance(value, binary_type):
        return value.decode(getattr(stream, 'encoding', None) or 'utf-8')
    return value


def _read_batch_sql(arguments, parser):
    if arguments.execute is not None:
        return _ensure_text(arguments.execute)
    if arguments.file:
        if arguments.file == '-':
            return _read_stream_text(sys.stdin)
        try:
            with io.open(arguments.file, encoding='utf-8') as sql_file:
                return sql_file.read()
        except (OSError, IOError) as error:
            _parser_error(parser, 'cannot read SQL file: {0}'.format(_exception_text(error)))
    if not sys.stdin.isatty():
        return _read_stream_text(sys.stdin)
    return None


def _silence_broken_stdout():
    """Redirect stdout after EPIPE so interpreter shutdown cannot flush it again."""

    try:
        stdout_fd = sys.stdout.fileno()
        devnull_fd = os.open(os.devnull, os.O_WRONLY)
    except (AttributeError, IOError, OSError, ValueError):
        return
    try:
        os.dup2(devnull_fd, stdout_fd)
    except (IOError, OSError):
        pass
    finally:
        os.close(devnull_fd)


def main(argv=None):
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
        parser.error('invalid MySQL port {0!r}'.format(raw_port))
    user = arguments.user or os.getenv('MYSQL_USER') or getpass.getuser()
    unix_socket = arguments.socket or os.getenv('MYSQL_UNIX_SOCKET')
    try:
        password = _read_password(arguments, parser)
        public_key = _read_public_key(arguments.server_public_key, parser)
        batch_sql = _read_batch_sql(arguments, parser)
    except KeyboardInterrupt:
        _emit(sys.stderr, 'Interrupted.')
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
    except ValueError as error:
        parser.error(_exception_text(error))
    try:
        connection.connect()
    except (MySQLError, OSError, IOError, socket.error, ssl.SSLError) as error:
        _emit(sys.stderr, u'Connection error: {0}'.format(_escape_text(_exception_text(error))))
        return 3

    try:
        if batch_sql is None:
            exit_code = _run_repl(connection, arguments)
            sys.stdout.flush()
            return exit_code
        try:
            results = connection.query(batch_sql)
        except ServerError as error:
            _emit(sys.stderr, u'ERROR: {0}'.format(_escape_text(_exception_text(error))))
            return 4
        except MySQLError as error:
            _emit(sys.stderr, u'Protocol error: {0}'.format(_escape_text(_exception_text(error))))
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
        _emit(sys.stderr, 'Interrupted.')
        return 130
    except (IOError, OSError) as error:
        if getattr(error, 'errno', None) == errno.EPIPE:
            _silence_broken_stdout()
            return 141
        raise
    finally:
        connection.close()


def _main_entrypoint():
    """Run main while making argparse output obey the broken-pipe exit contract."""

    try:
        try:
            exit_code = main()
        except SystemExit as error:
            exit_code = error.code
        sys.stdout.flush()
    except (IOError, OSError) as error:
        if getattr(error, 'errno', None) != errno.EPIPE:
            raise
        _silence_broken_stdout()
        return 141
    return exit_code


if __name__ == '__main__':
    raise SystemExit(_main_entrypoint())
