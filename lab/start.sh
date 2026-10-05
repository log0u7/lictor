#!/bin/sh
# Serve the four binaries over http (acquisition) + the four services.
cd /opt/target
python3 -m http.server 8000 --bind 0.0.0.0 &
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/opt/target/ret2func,stderr &
socat TCP-LISTEN:9998,reuseaddr,fork EXEC:/opt/target/ret2plt,stderr &
socat TCP-LISTEN:9997,reuseaddr,fork EXEC:/opt/target/shellcode,stderr &
socat TCP-LISTEN:9996,reuseaddr,fork EXEC:/opt/target/fmtstr,stderr &
socat TCP-LISTEN:9995,reuseaddr,fork EXEC:/opt/target/uaf_heap,stderr &
# the hardened variants (the purple demo watches the decisions die)
socat TCP-LISTEN:8899,reuseaddr,fork EXEC:/opt/target/ret2func_h,stderr &
socat TCP-LISTEN:8898,reuseaddr,fork EXEC:/opt/target/ret2plt_h,stderr &
socat TCP-LISTEN:8897,reuseaddr,fork EXEC:/opt/target/shellcode_h,stderr &
setarch -R socat TCP-LISTEN:9994,reuseaddr,fork EXEC:/opt/target/orw,stderr &
wait
