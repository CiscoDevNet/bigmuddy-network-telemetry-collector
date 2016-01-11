# bigmuddy-network-telemetry-collector

This repository contains a simple collector for receiving and pretty-printing telemetry data streamed from XR routers. It can be used for testing by viewing the data being streamed and the source code can form a basis for other collectors which make use of the resulting data.

The collector process can be run using the following invocation:

    telemetry_receiver.py --ip-address <addr> --port <port> 

This will cause it to listen on the specified address and port and print the received messages. Where the data is tabular it will by default display only the first row in each table. The following options can be used to change this behavior:
     --brief - display only the message headers. No data
     --print-all - display all data (can be very verbose)

## GPB support

XR supports streaming data in either JSON or GPB format and the collector handles both. However in order to decode and print the data in GPB messages it is necessary to provide the .proto file(s) used to encode it using the option below. The collector will use protoc to compile these into the necessary python code.
     --protos <proto1> <proto2> ...

Alternatively, if protoc is not available locally but the .proto files have been compiled elsewhere then you can specify a directory in which the compiled .py files reside using:
     --tmp-dir <path_to_py_files>
    

## Using telemetry

See https://github.com/cisco/logstash-codec-bigmuddy-network-telemetry-gpb/tree/master/resources/xr6.0.0 for instructions for streaming XR telemetry data.
