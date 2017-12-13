#!/usr/bin/env bash

protoc --go_out=plugins=grpc:. job.proto
protoc --go_out=plugins=grpc:. completion.proto
protoc --cpp_out=. completion.proto

mv *.cc ../../src
mv *.h ../../src
