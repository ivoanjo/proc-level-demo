#!/bin/bash

# Compile the Java files
javac *.java

# Run the example
java -version
java ExampleCtx "$@"
