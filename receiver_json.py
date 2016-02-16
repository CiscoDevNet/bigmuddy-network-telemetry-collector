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

import json
from receiver_utils import (timestamp_to_string, 
                            print_at_indent, 
                            bytes_to_string) 

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


def print_json_data(obj, indent, args):
    """
    Print the body of a JSON message
    """
    if type(obj) == dict:
        for key in list(obj.keys()):
            child = obj[key]
            # If the child object is a list or dictionary then indent using
            # braces. If the child is a leaf then just print on a single line.
            if type(child) == dict:
                print_at_indent("{} {{".format(key), indent)
                print_json_data(obj[key], indent + 1, args)
                print_at_indent("}", indent)
            elif type(child) == list:
                if not args.print_all:
                    warning = " - displaying first entry only"
                else:
                    warning = ""
                print_at_indent("{} ({} items{}) [".format(key, len(child),
                                                           warning), 
                                indent)
                print_json_data(obj[key], indent + 1, args)
                print_at_indent("]", indent)
            elif key == "CollectionTime":
                # Pretty-print collection timestamp
                print_at_indent("{}: {}".format(key, timestamp_to_string(child)), 
                                indent)
            else:
                # Try printing values as a string and if that fails print
                # it as bytes
                try:
                    print_at_indent("{}: {}".format(key, str(child)), indent)
                except Exception:
                    prnit_at_indent("{}: {}".format(key, 
                                                    bytes_to_string(child)),
                                    indent) 
    elif type(obj) == list:
        for i, item in enumerate(obj):
            print_at_indent("[{}]".format(i), indent)
            print_json_data(item, indent + 1, args)
            if not args.print_all:
                # Stop after first item
                break
    else:
        print_at_indent("{}".format(str(obj)), indent)


def decode_json (message, args):
    """
    Pretty-print a JSON message
    """
    json_msg = None

    try:
        json_msg = json.loads(message.decode('ascii'))
    except Exception as e:
        print("ERROR: Failed to convert message to JSON: {}".format(e))

    if json_msg != None:
       # Pretty-print the message
       print_json_hdr(json_msg)
       if not args.brief:
           print("Data: {")
           print_json_data(json_msg["Data"], 1, args)
