#!/usr/bin/env python2
#
# Copyright (c) 2015 by Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import shutil
import socket
import sys
import time
import os
import re
import imp
import threading
import struct
import json
import zlib
from subprocess import call

INDENT = "  "

###############################################################################
# Helper functions
###############################################################################

def timestamp_to_string (timestamp):
    """
    Convert a timestamp to a string
    """
    try:
        string = "{} ({}ms)".format(time.ctime(timestamp / 1000), 
                                    timestamp % 1000)
    except Exception as e:
        print("ERROR: Failed to decode timestamp {}: {}".format(timestamp, e))
        string = "{}".format(timestamp)
    return string


def bytes_to_string (bytes):
    """
    Convert a byte array into a string aa:bb:cc
    """
    return ":".join(["{:02x}".format(int(ord(c))) for c in bytes])

def print_at_indent (string, indent):
    """
    Print a string indented by the specified level
    """
    print("{}{}".format(INDENT*indent, string))


def parse_schema_from_proto(input_file):
    """
    Find the schema path and corresponding message definition in a .proto file
    """
    with open(input_file) as f:
        schema_path = None
        msg_name = None
        for line in f.readlines():
            # Look for the first instance of the string "message <message_name>"
            # and "...schema_path = <schema_path>"
            if msg_name == None:
                match = re.search("^message (\S+)", line)
                if match:
                    msg_name = match.group(1)
            else:
                match = re.search(".*schema_path = \"(\S+)\"", line)
                if match:
                    schema_path = match.group(1)
                    break

        return (schema_path,msg_name)
        

def compile_proto_file(input_files, output_path, include_path):
    """
    Compile a .proto file using protoc
    """
    command = ["protoc","--python_out", output_path, "-I", include_path] + input_files.split(',')
    call(command)

###############################################################################
# GPB Decoding
###############################################################################

def print_gpb_compact_msg (field, indent):
    """
    Recursively iterate over a compactGPB obejct, displaying all fields at an 
    appropriate indent.
    Argument: field
      The object to print.
    Argument: indent
      The indent level to start printing at.
    """
    for descriptor in field.DESCRIPTOR.fields:
        value = getattr(field, descriptor.name)
        if descriptor.type == descriptor.TYPE_MESSAGE:
            # 
            # If the value is a sub-message then recursively call this function
            # to decode it. If the message is repeated then iterate over each
            # item.
            #
            if descriptor.label == descriptor.LABEL_REPEATED:
                print_at_indent("{} ({} items) [".format(
                                           descriptor.name, len(value)), 
                                indent)
                for i, item in enumerate(value):
                    print_at_indent("{} {} {{".format(descriptor.name, i),
                                    indent)
                    print_gpb_compact_msg(item, indent+1)
                    print_at_indent("}", indent)
                    if not args.print_all:
                        # Stop after the first item unless all have been
                        # requested
                        break
                print_at_indent("]", indent)
            else:
                print_at_indent("{} {{".format(descriptor.name), indent)
                print_gpb_compact_msg(value, indent + 1)
                print_at_indent("}", indent)
        elif descriptor.type == descriptor.TYPE_ENUM:
            #
            # For enum types print the enum name
            #
            enum_name = descriptor.enum_type.values[value].name
            print_at_indent("{}: {}".format(descriptor.name, enum_name),
                            indent)
        elif descriptor.type == descriptor.TYPE_BYTES:
            print_at_indent("{}: {}".format(descriptor.name,
                                            bytes_to_string(value)), indent)
        else:
            # 
            # For everything else just print the value
            #
            print_at_indent("{}: {}".format(descriptor.name, value), indent)

def print_gpb_compact_hdr (header):
    """
    Print the compact GPB message header
    """
    print("""
Encoding:{:#x}
Policy Name:{}
Version:{}
Identifier:{}
Start Time:{}
End Time:{}
# Tables: {}""".format(header.encoding,
           header.policy_name,
           header.version,
           header.identifier,
           timestamp_to_string(header.start_time),
           timestamp_to_string(header.end_time),
           len(header.tables))
)

def decode_gpb_compact (message):
    """
    Decode and print a GPB compact message
    """
    header = telemetry_pb2.TelemetryHeader()
    try:
        header.ParseFromString(message)
    except Exception as e:
        print("ERROR decoding header. Not a valid 'TelemetryHeader' message. "
              "Full message dump below:")
        print(bytes_to_string(message))
        return

    # Check the encoding value is correct
    ENCODING = 0x87654321
    if header.encoding != ENCODING:
        print("Invalid 'encoding' value {:#x} (expected {:#x})".format(
                  header.encoding, ENCODING))
        return

    # Print the message header
    print_gpb_compact_hdr(header)

    # Loop over the tables within the message, printing either just the first 
    # row or all rows depending on the args specified

    for entry in header.tables:
        schema_path = entry.policy_path
        print(INDENT + "Schema Path:{}".format(schema_path))

        warning = ""
        if not args.print_all:
            warning = "(Only first row displayed)"
        print(INDENT + "# Rows:{} {}".format(len(entry.row), warning))

        if not schema_path in decoder_dict.keys():
            print(INDENT + "No decoder available")
        else:
            for i, row in enumerate(entry.row):
                print(INDENT * 2 + "Row {}:".format(i))
                row_msg = decoder_dict[schema_path]()
                try:
                    row_msg.ParseFromString(row)
                    print_gpb_compact_msg(row_msg, 2)
                    print("")
                except Exception as e:
                    print("ERROR decoding row. Not a valid GPB message. Full "
                          "message dump below:")
                    print(bytes_to_string(row))
                    
                if not args.print_all:
                    break

def print_gpb_kv_field_data (name, data, datatype, time, indent):
    """
    Print a single row for a TelemetryField message
    """
    if name == "":
        name = "<no name>"
    print_at_indent("{}: {} ({}) {}".format(name, data, datatype, time),
                    indent)

def print_gpb_kv_field (field, indent):
    """
    Pretty-print a TelemtryField message
    """
    # Decode the timestamp if there is one
    if field.timestamp != 0:
        time = timestamp_to_string(field.timestamp)
    else:
        time = ""
    
    # Find the datatype and print it
    datatypes = ["bytes_value",
                 "string_value",
                 "bool_value",
                 "uint32_value",
                 "uint64_value",
                 "sint32_value",
                 "sint64_value",
                 "double_value",
                 "float_value"]
    for d in datatypes:
        datatype = d[:-6]
        if field.HasField(d):
            if datatype == "bytes":
                print_gpb_kv_field_data(field.name,
                                        bytes_to_string(field.bytes_value),
                                        datatype, time, indent)
            else:
                print_gpb_kv_field_data(field.name, getattr(field,d), datatype,
                                        time, indent)

    # If 'fields' is used then recursively call this function to decode
    if len(field.fields) > 0:
        print_gpb_kv_field_data(field.name, 
                                "fields",
                                "items {}".format(len(field.fields)),
                                "{} {{".format(time), indent)

        for f in field.fields:
            print_gpb_kv_field(f, indent+1)
        print_at_indent("}", indent)



def print_gpb_kv_hdr (header):
    """
    Print the key-value GPB message header
    """
    print("""
Collection ID:{}
Base Path:{}
Subscription ID:{}
Model Version:{}
Start Time:{}
Msg Timestamp: {}
End Time:{}
# Fields: {}""".format(header.collection_id,
           header.base_path,
           header.subscription_identifier,
           header.model_version,
           timestamp_to_string(header.collection_start_time),
           timestamp_to_string(header.msg_timestamp),
           timestamp_to_string(header.collection_end_time),
           len(header.fields))
)
    

def decode_gpb_kv (message):
    """
    Decode and print a GPB key-value message
    """
    header = telemetry_kv_pb2.Telemetry()
    try:
        header.ParseFromString(message)
    except Exception as e:
        print("ERROR decoding header. Not a valid 'Telemetry' message. Full "
              "message dump below:")
        print(bytes_to_string(message))
        return

    # Print the message header
    print_gpb_kv_hdr(header)

    # Loop over the tables within the message, printing either just the first 
    # row or all rows depending on the args specified
    if args.print_all:
        for entry in header.fields:
            print_gpb_kv_field(entry, 2)
    elif len(header.fields) > 0 and not args.brief:
        print("  Displaying first entry only")
        print_gpb_kv_field(header.fields[0], 1)
        
###############################################################################
# JSON Decoder
###############################################################################

def print_json_hdr (message):
    """
    Print the values in the top level JSON object
    """
    # Print everything except the Data, displaying timestamps in date format
    print("")
    for key, value in message.items():
        if (key == "CollectionStartTime" or key == "CollectionEndTime" or
            key == "Start Time" or key == "End Time"):
            print("{}: {}".format(key, timestamp_to_string(value)))
        elif key != "Data":
            print("{}: {}".format(key, value))


def print_json_data(obj, indent):
    if type(obj) == dict:
        for key in list(obj.keys()):
            child = obj[key]
            # If the child object is a list or dictionary then indent using
            # braces. If the child is a leaf then just print on a single line.
            if type(child) == dict:
                print_at_indent("{} {{".format(key), indent)
                print_json_data(obj[key], indent + 1)
                print_at_indent("}", indent)
            elif type(child) == list:
                if not args.print_all:
                    warning = " - displaying first entry only"
                else:
                    warning = ""
                print_at_indent("{} ({} items{}) [".format(key, len(child),
                                                           warning), 
                                indent)
                print_json_data(obj[key], indent + 1)
                print_at_indent("]", indent)
            else:
                print_at_indent("{}: {}".format(key, str(child)), indent)
    elif type(obj) == list:
        for i, item in enumerate(obj):
            print_at_indent("[{}]".format(i), indent)
            print_json_data(item, indent + 1)
            if not args.print_all:
                # Stop after first item
                break
    else:
        print_at_indent("{}".format(str(obj)), indent)


def decode_json (message):
    """
    Pretty-print a JSON message
    """
    # Turn the binary data into ascii and convert it to JSON
    json_msg = None
    try:
        json_msg = json.loads(message.decode('ascii'))
    except Exception as e:
        print("ERROR: Failed to convert message to JSON: {}".format(e))

    if json_msg != None:
        print_json_hdr(json_msg)
        if not args.brief:
            print("Data: {")
            print_json_data(json_msg["Data"], 1)

##############################################################################
# JSON v1 (Pre XR 6.1.0)
##############################################################################

def unpack_v1_message(data):

    while len(data) > 0:
        _type = unpack_int(data)
        data = data[4:]

        if _type == 1:
            data = data[4:]
            yield 1, None
        elif _type == 2:
            msg_length = unpack_int(data)
            data = data[4:]
            msg = data[:msg_length]
            data = data[msg_length:]
            yield 2, msg

def get_v1_message(length, c):
    global v1_deco

    data = b""
    while len(data) < length:
        data += c.recv(length - len(data))

    tlvs = []
    for x in unpack_v1_message(data):
        tlvs.append(x)

    #find the data
    for x in tlvs:
        if x[0] == 1:
            print("  Reset Compressor TLV")
            v1_deco = zlib.decompressobj()
        if x[0] == 2:
            print("  Mesage TLV")
            c_msg = x[1]
            j_msg_b = v1_deco.decompress(c_msg)
            decode_json(j_msg_b)


###############################################################################
# Event handling
############################################################################### 

# Should use enum.Enum but not available in python2.7.1 on EnXR
class TCPMsgType():
    RESET_COMPRESSOR = 1
    JSON = 2
    GPB_COMPACT = 3
    GPB_KEY_VALUE = 4

    @classmethod
    def to_string (self, value):
        if value == 1:
            return "RESET_COMPRESSOR (1)"
        elif value == 2:
            return "JSON (2)"
        elif value == 3:
            return "GPB_COMPACT (3)"
        elif value == 4:
            return "GPB_KEY_VALUE (4)"
        else:
            raise ValueError("{} is not a valid TCP message type".format(value))


TCP_FLAG_ZLIB_COMPRESSION = 0x1

def tcp_flags_to_string (flags):
    strings = []
    if flags & TCP_FLAG_ZLIB_COMPRESSION != 0:
        strings.append("ZLIB compression")
    if len(strings) == 0:
        return "None"
    else:
        return "|".join(strings)

def unpack_int(raw_data):
    return struct.unpack_from(">I", raw_data, 0)[0]


def get_message(conn, deco):
    """
    Handle a receved TCP message
    Argument: conn
      TCP connection
    Argument: deco
      ZLIB decompression object
    Return: updated decompression object in the case where compression was
            reset
    """
    print("Getting TCP message")
    # v1 message header (from XR6.0) consists of just a 4-byte length
    # v2 message header (from XR6.1 onwards) consists of 3 4-byte fields:
    #     Type,Flags,Length
    # If the first 4 bytes read is <=4 then it is too small to be a 
    # valid length. Assume it is v2 instead
    # 
    t = conn.recv(4)
    msg_type = unpack_int(t)
    if msg_type > 4:
        # V1 message - compressed JSON
        flags = TCP_FLAG_ZLIB_COMPRESSION
        msg_type_str = "JSONv1 (COMPRESSED)"
        length = msg_type
        msg_type = TCPMsgType.JSON
        print("  Message Type: {}".format(msg_type_str))
        return get_v1_message(length, conn)
    else:
        # V2 message
        try:
            msg_type_str = TCPMsgType.to_string(msg_type)
            print("  Message Type: {})".format(msg_type_str))
        except:
            print("  Invalid Message type: {}".format(msg_type))
    
        t = conn.recv(4)
        flags = unpack_int(t)
        print("  Flags: {}".format(tcp_flags_to_string(flags)))
        t = conn.recv(4)
        length = unpack_int(t)
    print("  Length: {}".format(length))
   
    # Read all the bytes of the message according to the length in the header 
    data = b""
    while len(data) < length:
        data += conn.recv(length - len(data))

    # Decompress the message if necessary. Otherwise use as-is
    if flags & TCP_FLAG_ZLIB_COMPRESSION != 0:
        try:
            print("Decompressing message")
            msg = deco.decompress(data)
        except Exception as e:
            print("ERROR: failed to decompress message: {}".format(e))
            msg = None
    else:
        msg = data

    # Decode the data according to the message type in the header
    print("Decoding message")
    try:
        if msg_type == TCPMsgType.GPB_COMPACT:
            decode_gpb_compact(msg)
        elif msg_type == TCPMsgType.GPB_KEY_VALUE:
            decode_gpb_kv(msg)
        elif msg_type == TCPMsgType.JSON:
            decode_json(msg)
        elif msg_type == TCPMsgType.RESET_COMPRESSOR:
            deco = zlib.decompressobj()
    except Exception as e:
        print("ERROR: failed to decode TCP message: {}".format(e))

    return deco


def tcp_loop ():
    """
    Event Loop. Wait for TCP messages and pretty-print them
    """
    while True:
        print("Waiting for TCP connection")
        conn, addr = tcp_sock.accept()
        deco = zlib.decompressobj()
        print("Got TCP connection")
        try:
            while True:
                 deco = get_message(conn, deco)
        except Exception as e:
            print("ERROR: Failed to get TCP message. Attempting to reopen connection: {}".format(e))


def udp_loop():
    """
    Event loop. Wait for messages and then pretty-print them
    """
    while True:
        print("Waiting for UDP message")
        raw_message, address = udp_sock.recvfrom(2**16)
        # All UDP packets contain compact GPB messages
        decode_gpb_compact(raw_message)

###############################################################################
# Main
###############################################################################

# 
# Set up argument parsing
#
parser = argparse.ArgumentParser(description="")

parser.add_argument("--ip-address",
                    required=True,
                    type=str)

parser.add_argument("--port",
                    required=True,
                    type=int)

parser.add_argument("--protos",
                    required=False,
                    type=str,
                    nargs = '*',
                    default=[],
                    help = "List of .proto files to be received in messages")

parser.add_argument("--print-all",
                    required=False,
                    action='store_true',
                    help = "Display data for all items instead of just the first")

parser.add_argument("--brief",
                    required=False,
                    action='store_true',
                    help = "Only display message headers, no data")

parser.add_argument("--tmp-dir",
                    required=False,
                    type=str,
                    default="/tmp/telem_gpb/")

parser.add_argument("--include-path",
                    required=False,
                    type=str,
                    default=":".join([".",
                                      "/sw/packages/protoc/current/google/include/",
                                     ]))

#
# Parse all arguments and bind to the specified IP address and port
args = parser.parse_args(sys.argv[1:])


#
# Bind to two sockets to handle either UDP or TCP data
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp_sock.bind((args.ip_address, args.port))


tcp_sock = socket.socket()
tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_sock.bind((args.ip_address, args.port))
tcp_sock.listen(1)


#
# Make sure the temp directory exists
#
try:
    os.mkdir(args.tmp_dir)
except OSError:
    pass

sys.path.append(args.tmp_dir)
sys.path.append(args.include_path)
# For 'six' which is required by protobuf
#sys.path.append("/auto/usrcisco-linux-rhel5.0-x86-64/packages/python/python-2.7.8/lib/python2.7/site-packages")

#
# Compile the main telemetry proto files if they don't already exist.
#
try:
    import telemetry_pb2
except:
    compile_proto_file("telemetry.proto", args.tmp_dir, args.include_path)
    compile_proto_file("descriptor.proto", args.tmp_dir, args.include_path)
    compile_proto_file("cisco.proto", args.tmp_dir, args.include_path)
    import telemetry_pb2

# Key-value protobuf cannot be compiled using the old version of protoc 
# available so use a local pre-compiled version.
import telemetry_kv_pb2


#
# Create a dictionary for storing mapping from schema paths to
# decoder objects
#
decoder_dict = {}

#
# For each proto file
#   - attempt to compile it (this way we always use the latest .proto file)
#   - if that fails then try using an existing file (this means it is possible
#     to run the tool even if protoc is unavailable)
#   - import the compiled file
#   - find the schema path and message name
#   - store a mapping from schema path to msg class
#
for proto in args.protos:
    name,ext = os.path.splitext(proto)
    module = "{}_pb2".format(name) 
    compiled_filename = "{}/{}.py".format(args.tmp_dir, module)
    # protoc handily replaces hyphens with underscores in the filenames it
    # gnerates so we must do the same.
    compiled_filename = compiled_filename.replace("-","_")
    try:
        compile_proto_file(proto, args.tmp_dir, args.include_path)
    except Exception as e:
        if not os.path.isfile(compiled_filename):
            print("Failed to compile {}: {}".format(
                  proto, e))
            sys.exit(1)

    try:
        decoder = imp.load_source(module, compiled_filename)
        (schema_path, msg_name) = parse_schema_from_proto(proto)
        decoder_dict[schema_path] = getattr(decoder, msg_name)
    except Exception as e:
        print("Failed to load {}: {}".format(compiled_filename, e))
        sys.exit(1)



# 
# Spawn threads to listen on the TCP and UDP sockets
#
tcp_thread = threading.Thread(target=tcp_loop)
tcp_thread.daemon = True
tcp_thread.start()

udp_thread = threading.Thread(target=udp_loop)
udp_thread.daemon = True
udp_thread.start()

done = False
while not done:
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        done = True

