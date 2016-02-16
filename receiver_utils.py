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

import time

###############################################################################
# Helper functions
###############################################################################

INDENT = "  "

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
