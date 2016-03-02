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

import os
import sys
import json
import imp
import re
from subprocess import call
from google.protobuf.message import Message
from google.protobuf.descriptor import FieldDescriptor
from receiver_utils import (timestamp_to_string, 
                            print_at_indent, 
                            bytes_to_string,
                            INDENT) 

###############################################################################
# GPB compilation and initialisation
###############################################################################

def compile_proto_file(input_files, output_path, include_path):
    """
    Compile a .proto file using protoc
    """
    for file in input_files.split(','):
        if not os.path.isfile(file):
            print("ERROR: file {} does not exist".format(file))
            return
    command = ["protoc","--python_out", output_path, "-I", include_path] + input_files.split(',')
    try:
        call(command)
        print("Compiled {}".format(input_files))
    except OSError as e:
        print("ERROR: unable to run command '{}'. Make sure protoc is "
              "present in your path".format(" ".join(command)))
        raise e

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

def gpb_decoder_init(args):
    """
    Compile the necesary telemetry proto files if they don't already exist and
    create a mapping between policy paths and proto files specified on the 
    command line.
    """
    # Build any proto files not already available
    proto_files = ["descriptor", "cisco", "telemetry"]

    for file in proto_files:
        if not os.path.isfile("{}/{}_pb2.py".format(args.tmp_dir, file)):
            compile_proto_file("{}.proto".format(file), args.tmp_dir, 
                               args.include_path)

    global telemetry_pb2
    import telemetry_pb2


    # Key-value protobuf cannot be compiled using the old version of protoc 
    # available so use a local pre-compiled version.
    global telemetry_kv_pb2
    import telemetry_kv_pb2

    #
    # Create a dictionary for storing mapping from schema paths to
    # decoder objects
    #
    global decoder_dict
    decoder_dict = {}

    #
    # For each proto file specified on the command line
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
            else:
                print("Using existing compiled protobuf file {}".format(compiled_filename))

        try:
            decoder = imp.load_source(module, compiled_filename)
            (schema_path, msg_name) = parse_schema_from_proto(proto)
            decoder_dict[schema_path] = getattr(decoder, msg_name)
        except Exception as e:
            print("Failed to load {}: {}".format(compiled_filename, e))
            sys.exit(1)

###############################################################################
# Protobuf to dict conversion
###############################################################################

DECODE_FN_MAP = {
    FieldDescriptor.TYPE_DOUBLE: float,
    FieldDescriptor.TYPE_FLOAT: float,
    FieldDescriptor.TYPE_INT32: int,
    FieldDescriptor.TYPE_INT64: long,
    FieldDescriptor.TYPE_UINT32: int,
    FieldDescriptor.TYPE_UINT64: long,
    FieldDescriptor.TYPE_SINT32: int,
    FieldDescriptor.TYPE_SINT64: long,
    FieldDescriptor.TYPE_FIXED32: int,
    FieldDescriptor.TYPE_FIXED64: long,
    FieldDescriptor.TYPE_SFIXED32: int,
    FieldDescriptor.TYPE_SFIXED64: long,
    FieldDescriptor.TYPE_BOOL: bool,
    FieldDescriptor.TYPE_STRING: unicode,
    FieldDescriptor.TYPE_BYTES: lambda b: bytes_to_string(b),
    FieldDescriptor.TYPE_ENUM: int,
}


def field_type_to_fn(msg, field):
    if field.type == FieldDescriptor.TYPE_MESSAGE:
        # For embedded messages recursively call this function. If it is
        # a repeated field return a list
        result = lambda msg: proto_to_dict(msg)
    elif field.type in DECODE_FN_MAP:
        result = DECODE_FN_MAP[field.type]
    else:
        raise TypeError("Field %s.%s has unrecognised type id %d" % (
                         msg.__class__.__name__, field.name, field.type))
    return result

def proto_to_dict(msg):
    result_dict = {}
    extensions = {}
    for field, value in msg.ListFields():
        conversion_fn = field_type_to_fn(msg, field)
        
        # Skip extensions
        if not field.is_extension:
            # Repeated fields result in an array, otherwise just call the 
            # conversion function to store the value
            if field.label == FieldDescriptor.LABEL_REPEATED:
                result_dict[field.name] = [conversion_fn(v) for v in value]
            else:
                result_dict[field.name] = conversion_fn(value)
    return result_dict

###############################################################################
# GPB Decoding
###############################################################################

def print_gpb_compact_msg (field, indent, args):
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
                    print_gpb_compact_msg(item, indent+1, args)
                    print_at_indent("}", indent)
                    if not args.print_all:
                        # Stop after the first item unless all have been
                        # requested
                        break
                print_at_indent("]", indent)
            else:
                print_at_indent("{} {{".format(descriptor.name), indent)
                print_gpb_compact_msg(value, indent + 1, args)
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

def decode_gpb_compact (message, args):
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
    json_dict = {}
    if args.json_dump:
        # Convert the protobuf into a dictionary in preparation for dumping
        # it as JSON.
        json_dict = proto_to_dict(header)
    else:
        print_gpb_compact_hdr(header)

    # Loop over the tables within the message, printing either just the first 
    # row or all rows depending on the args specified

    for t, entry in enumerate(header.tables):
        schema_path = entry.policy_path
        if not args.json_dump:
            print(INDENT + "Schema Path:{}".format(schema_path))
            warning = ""
            if not args.print_all:
                warning = "(Only first row displayed)"
            print(INDENT + "# Rows:{} {}".format(len(entry.row), warning))

        if not schema_path in decoder_dict.keys():
            print(INDENT + "No decoder available")
            if args.json_dump:
                json_dict["tables"][t]["row"][0] = "<No decoder available>"
        else:
            for i, row in enumerate(entry.row):
                row_msg = decoder_dict[schema_path]()
                try:
                    row_msg.ParseFromString(row)
                    if args.json_dump:
                        # Replace the bytes in the 'row' field with a decoded
                        # dict
                        table = json_dict["tables"][t]
                        table["row"][i] = proto_to_dict(row_msg)
                    else:
                        print(INDENT * 2 + "Row {}:".format(i))
                        print_gpb_compact_msg(row_msg, 2, args)
                        print("")
                except Exception as e:
                    print("ERROR decoding row. Not a valid GPB message. Full "
                          "message dump below: {}".format(e))
                    print(bytes_to_string(row))
                    
                if not args.print_all and not args.json_dump:
                    break

    if args.json_dump:
        print(json.dumps(json_dict))

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
Collection ID:   {}
Base Path:       {}
Subscription ID: {}
Model Version:   {}""".format(header.collection_id,
           header.base_path,
           header.subscription_identifier,
           header.model_version))
    # start and end time are not always present
    if header.collection_start_time > 0:
        print("Start Time:      {}".format(timestamp_to_string(header.collection_start_time)))
    print("Msg Timestamp:   {}".format(timestamp_to_string(header.msg_timestamp)))
    if header.collection_end_time > 0:
        print("End Time:      {}".format(timestamp_to_string(header.collection_end_time)))
    print("Fields: {}".format(len(header.fields))) 

    

def decode_gpb_kv (message, args):
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

    if args.json_dump:
        print(json.dumps(proto_to_dict(header)))
    else:
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
