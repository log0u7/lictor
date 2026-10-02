#!/bin/sh
# Serve the binary for acquisition (augure-profiler) + the vulnerable
# service itself. Both in one container, two processes.
cd /opt/target
python3 -m http.server 8000 --bind 0.0.0.0 &
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/opt/target/vuln_service,stderr
