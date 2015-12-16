# Protocol Buffers - Google's data interchange format
# Copyright 2008 Google Inc.  All rights reserved.
# http://code.google.com/p/protobuf/
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import unicode_literals

"""Contains routines for printing protocol messages in text format."""

__author__ = 'kenton@google.com (Kenton Varda)'

import re

from collections import deque
import sys
#TODO: See if there is a better way to do this
if sys.version > '3':
    import codecs
    string_escape = codecs.getdecoder('unicode_escape')
    def loc_string_escape(input):
        return string_escape(input)[0]
else:
    def loc_string_escape(input):
        return input.decode('string_escape')

from google.protobuf.internal import type_checkers
from google.protobuf.internal.utils import bytes_to_string, \
    bytestr_to_string, string_to_bytestr, string_to_bytes, \
    byte_chr, SimIO, unicode
from google.protobuf import descriptor

__all__ = [ 'MessageToString', 'PrintMessage', 'PrintField',
            'PrintFieldValue', 'Merge' ]


# These constants won't work on Windows pre-Python-2.6.
_INFINITY = float('inf')
_NAN = float('nan')


class ParseError(Exception):
  """Thrown in case of ASCII parsing error."""


def MessageToString(message, as_utf8=False, as_one_line=False):
  out = SimIO()
  PrintMessage(message, out, as_utf8=as_utf8, as_one_line=as_one_line)
  result = out.getvalue()
  out.close()
  if as_one_line:
    return result.rstrip()
  return result


def PrintMessage(message, out, indent=0, as_utf8=False, as_one_line=False):
  for field, value in message.ListFields():
    if field.label == descriptor.FieldDescriptor.LABEL_REPEATED:
      for element in value:
        PrintField(field, element, out, indent, as_utf8, as_one_line)
    else:
      PrintField(field, value, out, indent, as_utf8, as_one_line)


def PrintField(field, value, out, indent=0, as_utf8=False, as_one_line=False):
  """Print a single field name/value pair.  For repeated fields, the value
  should be a single element."""

  out.write(b' ' * indent);
  if field.is_extension:
    out.write(b'[')
    if (field.containing_type.GetOptions().message_set_wire_format and
        field.type == descriptor.FieldDescriptor.TYPE_MESSAGE and
        field.message_type == field.extension_scope and
        field.label == descriptor.FieldDescriptor.LABEL_OPTIONAL):
      out.write(string_to_bytestr(field.message_type.full_name))
    else:
      out.write(string_to_bytestr(field.full_name))
    out.write(b']')
  elif field.type == descriptor.FieldDescriptor.TYPE_GROUP:
    # For groups, use the capitalized name.
    out.write(string_to_bytestr(field.message_type.name))
  else:
    out.write(string_to_bytestr(field.name))

  if field.cpp_type != descriptor.FieldDescriptor.CPPTYPE_MESSAGE:
    # The colon is optional in this case, but our cross-language golden files
    # don't include it.
    out.write(b': ')

  PrintFieldValue(field, value, out, indent, as_utf8, as_one_line)
  if as_one_line:
    out.write(b' ')
  else:
    out.write(b'\n')


def PrintFieldValue(field, value, out, indent=0,
                    as_utf8=False, as_one_line=False):
  """Print a single field value (not including name).  For repeated fields,
  the value should be a single element."""

  if field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_MESSAGE:
    if as_one_line:
      out.write(b' { ')
      PrintMessage(value, out, indent, as_utf8, as_one_line)
      out.write(b'}')
    else:
      out.write(b' {\n')
      PrintMessage(value, out, indent + 2, as_utf8, as_one_line)
      out.write(b' ' * indent + b'}')
  elif field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_ENUM:
    out.write(string_to_bytestr(field.enum_type.values_by_number[value].name))
  elif field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_STRING:
    out.write(b'\"')
    if type(value) is unicode:
      out.write(_CEscape(value.encode('utf-8'), as_utf8))
    else:
      out.write(_CEscape(value, as_utf8))
    out.write(b'\"')
  elif field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_BOOL:
    if value:
      out.write(b"true")
    else:
      out.write(b"false")
  else:
    out.write(string_to_bytestr(str(value)))


def Merge(text, message):
  """Merges an ASCII representation of a protocol message into a message.

  Args:
    text: Message ASCII representation.
    message: A protocol buffer message to merge into.

  Raises:
    ParseError: On ASCII parsing problems.
  """
  tokenizer = _Tokenizer(text)
  while not tokenizer.AtEnd():
    _MergeField(tokenizer, message)


def _MergeField(tokenizer, message):
  """Merges a single protocol message field into a message.

  Args:
    tokenizer: A tokenizer to parse the field name and values.
    message: A protocol message to record the data.

  Raises:
    ParseError: In case of ASCII parsing problems.
  """
  message_descriptor = message.DESCRIPTOR
  if tokenizer.TryConsume(b'['):
    name = [tokenizer.ConsumeIdentifier()]
    while tokenizer.TryConsume(b'.'):
      name.append(tokenizer.ConsumeIdentifier())
    name = '.'.join(name)

    if not message_descriptor.is_extendable:
      raise tokenizer.ParseErrorPreviousToken(
          'Message type "%s" does not have extensions.' %
          message_descriptor.full_name)
    field = message.Extensions._FindExtensionByName(name)
    if not field:
      raise tokenizer.ParseErrorPreviousToken(
          'Extension "%s" not registered.' % name)
    elif message_descriptor != field.containing_type:
      raise tokenizer.ParseErrorPreviousToken(
          'Extension "%s" does not extend message type "%s".' % (
              name, message_descriptor.full_name))
    tokenizer.Consume(b']')
  else:
    name = tokenizer.ConsumeIdentifier()
    field = message_descriptor.fields_by_name.get(name, None)

    # Group names are expected to be capitalized as they appear in the
    # .proto file, which actually matches their type names, not their field
    # names.
    if not field:
      field = message_descriptor.fields_by_name.get(name.lower(), None)
      if field and field.type != descriptor.FieldDescriptor.TYPE_GROUP:
        field = None

    if (field and field.type == descriptor.FieldDescriptor.TYPE_GROUP and
        field.message_type.name != name):
      field = None

    if not field:
      raise tokenizer.ParseErrorPreviousToken(
          'Message type "%s" has no field named "%s".' % (
              message_descriptor.full_name, name))

  if field.cpp_type == descriptor.FieldDescriptor.CPPTYPE_MESSAGE:
    tokenizer.TryConsume(b':')

    if tokenizer.TryConsume(b'<'):
      end_token = b'>'
    else:
      tokenizer.Consume(b'{')
      end_token = b'}'

    if field.label == descriptor.FieldDescriptor.LABEL_REPEATED:
      if field.is_extension:
        sub_message = message.Extensions[field].add()
      else:
        sub_message = getattr(message, field.name).add()
    else:
      if field.is_extension:
        sub_message = message.Extensions[field]
      else:
        sub_message = getattr(message, field.name)
      sub_message.SetInParent()

    while not tokenizer.TryConsume(end_token):
      if tokenizer.AtEnd():
        raise tokenizer.ParseErrorPreviousToken('Expected "%s".' %
                                                bytestr_to_string((end_token)))
      _MergeField(tokenizer, sub_message)
  else:
    _MergeScalarField(tokenizer, message, field)


def _MergeScalarField(tokenizer, message, field):
  """Merges a single protocol message scalar field into a message.

  Args:
    tokenizer: A tokenizer to parse the field value.
    message: A protocol message to record the data.
    field: The descriptor of the field to be merged.

  Raises:
    ParseError: In case of ASCII parsing problems.
    RuntimeError: On runtime errors.
  """
  tokenizer.Consume(b':')
  value = None

  if field.type in (descriptor.FieldDescriptor.TYPE_INT32,
                    descriptor.FieldDescriptor.TYPE_SINT32,
                    descriptor.FieldDescriptor.TYPE_SFIXED32):
    value = tokenizer.ConsumeInt32()
  elif field.type in (descriptor.FieldDescriptor.TYPE_INT64,
                      descriptor.FieldDescriptor.TYPE_SINT64,
                      descriptor.FieldDescriptor.TYPE_SFIXED64):
    value = tokenizer.ConsumeInt64()
  elif field.type in (descriptor.FieldDescriptor.TYPE_UINT32,
                      descriptor.FieldDescriptor.TYPE_FIXED32):
    value = tokenizer.ConsumeUint32()
  elif field.type in (descriptor.FieldDescriptor.TYPE_UINT64,
                      descriptor.FieldDescriptor.TYPE_FIXED64):
    value = tokenizer.ConsumeUint64()
  elif field.type in (descriptor.FieldDescriptor.TYPE_FLOAT,
                      descriptor.FieldDescriptor.TYPE_DOUBLE):
    value = tokenizer.ConsumeFloat()
  elif field.type == descriptor.FieldDescriptor.TYPE_BOOL:
    value = tokenizer.ConsumeBool()
  elif field.type == descriptor.FieldDescriptor.TYPE_STRING:
    value = tokenizer.ConsumeString()
  elif field.type == descriptor.FieldDescriptor.TYPE_BYTES:
    value = tokenizer.ConsumeByteString()
  elif field.type == descriptor.FieldDescriptor.TYPE_ENUM:
    # Enum can be specified by a number (the enum value), or by
    # a string literal (the enum name).
    enum_descriptor = field.enum_type
    if tokenizer.LookingAtInteger():
      number = tokenizer.ConsumeInt32()
      enum_value = enum_descriptor.values_by_number.get(number, None)
      if enum_value is None:
        raise tokenizer.ParseErrorPreviousToken(
            'Enum type "%s" has no value with number %d.' % (
                enum_descriptor.full_name, number))
    else:
      identifier = tokenizer.ConsumeIdentifier()
      enum_value = enum_descriptor.values_by_name.get(identifier, None)
      if enum_value is None:
        raise tokenizer.ParseErrorPreviousToken(
            'Enum type "%s" has no value named %s.' % (
                enum_descriptor.full_name, identifier))
    value = enum_value.number
  else:
    raise RuntimeError('Unknown field type %d' % field.type)

  if field.label == descriptor.FieldDescriptor.LABEL_REPEATED:
    if field.is_extension:
      message.Extensions[field].append(value)
    else:
      getattr(message, field.name).append(value)
  else:
    if field.is_extension:
      message.Extensions[field] = value
    else:
      setattr(message, field.name, value)


class _Tokenizer(object):
  """Protocol buffer ASCII representation tokenizer.

  This class handles the lower level string parsing by splitting it into
  meaningful tokens.

  It was directly ported from the Java protocol buffer API.
  """

  _WHITESPACE = re.compile('(\\s|(#.*$))+', re.MULTILINE)
  _WHITESPACE_BYTES = re.compile(b'(\\s|(#.*$))+', re.MULTILINE)
  _TOKEN = re.compile(
      '[a-zA-Z_][0-9a-zA-Z_+-]*|'           # an identifier
      '[0-9+-][0-9a-zA-Z_.+-]*|'            # a number
      '\"([^\"\n\\\\]|\\\\.)*(\"|\\\\?$)|'  # a double-quoted string
      '\'([^\'\n\\\\]|\\\\.)*(\'|\\\\?$)')  # a single-quoted string
  _TOKEN_BYTES = re.compile(
      b'[a-zA-Z_][0-9a-zA-Z_+-]*|'           # an identifier
      b'[0-9+-][0-9a-zA-Z_.+-]*|'            # a number
      b'\"([^\"\n\\\\]|\\\\.)*(\"|\\\\?$)|'  # a double-quoted string
      b'\'([^\'\n\\\\]|\\\\.)*(\'|\\\\?$)')  # a single-quoted string
  _IDENTIFIER = re.compile('\w+')
  _IDENTIFIER_BYTES = re.compile(b'\w+')
  _INTEGER_CHECKERS = [type_checkers.Uint32ValueChecker(),
                       type_checkers.Int32ValueChecker(),
                       type_checkers.Uint64ValueChecker(),
                       type_checkers.Int64ValueChecker()]
  _FLOAT_INFINITY = re.compile(b'-?inf(inity)?f?', re.IGNORECASE)
  _FLOAT_NAN = re.compile(b"nanf?", re.IGNORECASE)

  def __init__(self, text_message):
    self._text_message = text_message

    self._position = 0
    self._line = -1
    self._column = 0
    self._token_start = None
    self.token = b''
    self._lines = deque(text_message.split(b'\n'))
    self._current_line = b''
    self._previous_line = 0
    self._previous_column = 0
    self._SkipWhitespace()
    self.NextToken()

  def AtEnd(self):
    """Checks the end of the text was reached.

    Returns:
      True iff the end was reached.
    """
    return self.token == b''

  def _PopLine(self):
    while len(self._current_line) <= self._column:
      if not self._lines:
        self._current_line = b''
        return
      self._line += 1
      self._column = 0
      self._current_line = self._lines.popleft()

  def _SkipWhitespace(self):
    while True:
      self._PopLine()
      if isinstance(self._current_line, str):
        match = self._WHITESPACE.match(self._current_line, self._column)
      else:
        match = self._WHITESPACE_BYTES.match(self._current_line, self._column)
      if not match:
        break
      length = len(match.group(0))
      self._column += length

  def TryConsume(self, token):
    """Tries to consume a given piece of text.

    Args:
      token: Text to consume.

    Returns:
      True iff the text was consumed.
    """
    if self.token == token:
      self.NextToken()
      return True
    return False

  def Consume(self, token):
    """Consumes a piece of text.

    Args:
      token: Text to consume.

    Raises:
      ParseError: If the text couldn't be consumed.
    """
    if not self.TryConsume(token):
      raise self._ParseError('Expected "%s".' % token)

  def LookingAtInteger(self):
    """Checks if the current token is an integer.

    Returns:
      True iff the current token is an integer.
    """
    if not self.token:
      return False
    c = ord(self.token[0:1])
    return (c >= ord('0') and c <= ord('9')) or c == ord('-') or c == ord('+')

  def ConsumeIdentifier(self):
    """Consumes protocol message field identifier.

    Returns:
      Identifier string.

    Raises:
      ParseError: If an identifier couldn't be consumed.
    """
    result = self.token
    identifier_match = self._IDENTIFIER_BYTES.match(result)
    if not identifier_match:
      raise self._ParseError('Expected identifier.')
    self.NextToken()
    return bytes_to_string(result)

  def ConsumeInt32(self):
    """Consumes a signed 32bit integer number.

    Returns:
      The integer parsed.

    Raises:
      ParseError: If a signed 32bit integer couldn't be consumed.
    """
    try:
      result = self._ParseInteger(self.token, is_signed=True, is_long=False)
    except ValueError as e:
      raise self._IntegerParseError(e)
    self.NextToken()
    return result

  def ConsumeUint32(self):
    """Consumes an unsigned 32bit integer number.

    Returns:
      The integer parsed.

    Raises:
      ParseError: If an unsigned 32bit integer couldn't be consumed.
    """
    try:
      result = self._ParseInteger(self.token, is_signed=False, is_long=False)
    except ValueError as e:
      raise self._IntegerParseError(e)
    self.NextToken()
    return result

  def ConsumeInt64(self):
    """Consumes a signed 64bit integer number.

    Returns:
      The integer parsed.

    Raises:
      ParseError: If a signed 64bit integer couldn't be consumed.
    """
    try:
      result = self._ParseInteger(self.token, is_signed=True, is_long=True)
    except ValueError as e:
      raise self._IntegerParseError(e)
    self.NextToken()
    return result

  def ConsumeUint64(self):
    """Consumes an unsigned 64bit integer number.

    Returns:
      The integer parsed.

    Raises:
      ParseError: If an unsigned 64bit integer couldn't be consumed.
    """
    try:
      result = self._ParseInteger(self.token, is_signed=False, is_long=True)
    except ValueError as e:
      raise self._IntegerParseError(e)
    self.NextToken()
    return result

  def ConsumeFloat(self):
    """Consumes an floating point number.

    Returns:
      The number parsed.

    Raises:
      ParseError: If a floating point number couldn't be consumed.
    """
    text = self.token
    if self._FLOAT_INFINITY.match(text):
      self.NextToken()
      if text.startswith(b'-'):
        return -_INFINITY
      return _INFINITY

    if self._FLOAT_NAN.match(text):
      self.NextToken()
      return _NAN

    try:
      result = float(text)
    except ValueError as e:
      raise self._FloatParseError(e)
    self.NextToken()
    return result

  def ConsumeBool(self):
    """Consumes a boolean value.

    Returns:
      The bool parsed.

    Raises:
      ParseError: If a boolean value couldn't be consumed.
    """
    if self.token in (b'true', b't', b'1'):
      self.NextToken()
      return True
    elif self.token in (b'false', b'f', b'0'):
      self.NextToken()
      return False
    else:
      raise self._ParseError('Expected "true" or "false".')

  def ConsumeString(self):
    """Consumes a string value.

    Returns:
      The string parsed.

    Raises:
      ParseError: If a string value couldn't be consumed.
    """
    bytes_str = self.ConsumeByteString()
    try:
      return bytestr_to_string(bytes_str)
    except UnicodeDecodeError as e:
      raise self._StringParseError(e)

  def ConsumeByteString(self):
    """Consumes a byte array value.

    Returns:
      The array parsed (as a string).

    Raises:
      ParseError: If a byte array value couldn't be consumed.
    """
    list = [self._ConsumeSingleByteString()]
    while len(self.token) > 0 and ord(self.token[0:1]) in (ord('\''), ord('"')):
      list.append(self._ConsumeSingleByteString())
    return b"".join(list)

  def _ConsumeSingleByteString(self):
    """Consume one token of a string literal.

    String literals (whether bytes or text) can come in multiple adjacent
    tokens which are automatically concatenated, like in C or Python.  This
    method only consumes one token.
    """
    text = self.token
    if len(text) < 1 or ord(text[0:1]) not in (ord('\''), ord('"')):
      raise self._ParseError('Exptected string.')

    if len(text) < 2 or text[-1] != text[0]:
      raise self._ParseError('String missing ending quote.')

    try:
      result = _CUnescape(text[1:-1])
    except ValueError as e:
      raise self._ParseError(str(e))
    self.NextToken()
    return result

  def _ParseInteger(self, text, is_signed=False, is_long=False):
    """Parses an integer.

    Args:
      text: The text to parse.
      is_signed: True if a signed integer must be parsed.
      is_long: True if a long integer must be parsed.

    Returns:
      The integer value.

    Raises:
      ValueError: Thrown Iff the text is not a valid integer.
    """
    pos = 0
    if text.startswith(b'-'):
      pos += 1

    base = 10
    if text.startswith(b'0x', pos) or text.startswith(b'0X', pos):
      base = 16
    elif text.startswith(b'0', pos):
      base = 8

    # Do the actual parsing. Exception handling is propagated to caller.
    result = int(text, base)

    # Check if the integer is sane. Exceptions handled by callers.
    checker = self._INTEGER_CHECKERS[2 * int(is_long) + int(is_signed)]
    checker.CheckValue(result)
    return result

  def ParseErrorPreviousToken(self, message):
    """Creates and *returns* a ParseError for the previously read token.

    Args:
      message: A message to set for the exception.

    Returns:
      A ParseError instance.
    """
    return ParseError('%d:%d : %s' % (
        self._previous_line + 1, self._previous_column + 1, message))

  def _ParseError(self, message):
    """Creates and *returns* a ParseError for the current token."""
    return ParseError('%d:%d : %s' % (
        self._line + 1, self._column - len(self.token) + 1, message))

  def _IntegerParseError(self, e):
    return self._ParseError('Couldn\'t parse integer: ' + str(e))

  def _FloatParseError(self, e):
    return self._ParseError('Couldn\'t parse number: ' + str(e))

  def _StringParseError(self, e):
    return self._ParseError('Couldn\'t parse string: ' + str(e))

  def NextToken(self):
    """Reads the next meaningful token."""
    self._previous_line = self._line
    self._previous_column = self._column

    self._column += len(self.token)
    self._SkipWhitespace()

    if not self._lines and len(self._current_line) <= self._column:
      self.token = b''
      return

    match = self._TOKEN_BYTES.match(self._current_line, self._column)

    if match:
      token = match.group(0)
      self.token = token
    else:
      self.token = self._current_line[self._column:self._column+1]


# text.encode('string_escape') does not seem to satisfy our needs as it
# encodes unprintable characters using two-digit hex escapes whereas our
# C++ unescaping function allows hex escapes to be any length.  So,
# "\0011".encode('string_escape') ends up being "\\x011", which will be
# decoded in C++ as a single-character string with char code 0x11.
def _CEscape(byte_array, as_utf8):
  def escape(c):
    b = ord(c)
    if b == 10: return b"\\n"   # optional escape
    if b == 13: return b"\\r"   # optional escape
    if b ==  9: return b"\\t"   # optional escape
    if b == 39: return b"\\'"   # optional escape

    if b == 34: return b'\\"'   # necessary escape
    if b == 92: return b"\\\\"   # necessary escape

    # necessary escapes
    if not as_utf8 and (b >= 127 or b < 32): return string_to_bytes("\\%03o" % b)
    return c
  return b"".join([escape(byte_chr(c)) for c in byte_array])


_CUNESCAPE_HEX = re.compile(b'\\\\x([0-9a-fA-F]{2}|[0-9a-fA-F])')


def _CUnescape(text):
  def ReplaceHex(m):
    return m.group(0)
  # This is required because the 'string_escape' encoding doesn't
  # allow single-digit hex escapes (like '\xf').
  result = _CUNESCAPE_HEX.sub(ReplaceHex, text)
  return string_to_bytes(loc_string_escape(result))

