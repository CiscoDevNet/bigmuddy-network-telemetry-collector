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
import threading
import struct
import zlib
import ipaddress
from receiver_json import decode_json
from receiver_gpb import gpb_decoder_init, decode_gpb_kv, decode_gpb_compact

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
            if args.json_dump:
                # Print the message as-is
                print(j_msg_b)
            else:
                # Decode and pretty-print the message
                decode_json(j_msg_b, args)

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
            decode_gpb_compact(msg, args)
        elif msg_type == TCPMsgType.GPB_KEY_VALUE:
            decode_gpb_kv(msg, args)
        elif msg_type == TCPMsgType.JSON:
            if args.json_dump:
                # Print the message as-is
                print(msg)
            else:
                # Decode and pretty-print the message
                decode_json(msg, args)
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
        decode_gpb_compact(raw_message, args)

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

parser.add_argument("--json-dump",
                    required=False,
                    action='store_true',
                    help = "Dump JSON messages instead of pretty-printing")

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
 
# Figure out if the supplied address is ipv4 or ipv6 and set the socet type
# appropriately
listen_address = ipaddress.ip_address(unicode(args.ip_address))
socket_type = socket.AF_INET if listen_address.version == 4 else socket.AF_INET6   

# Bind to two sockets to handle either UDP or TCP data
udp_sock = socket.socket(socket_type, socket.SOCK_DGRAM)
udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
udp_sock.bind((args.ip_address, args.port))

tcp_sock = socket.socket(socket_type)
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

gpb_decoder_init(args)

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

