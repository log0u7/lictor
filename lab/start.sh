#!/bin/sh
# Serve the six binaries (+3 hardened) over http (acquisition) + the listeners.
cd /opt/target
python3 -m http.server 8000 --bind 0.0.0.0 &
socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/opt/target/ret2func,stderr &
socat TCP-LISTEN:9998,reuseaddr,fork EXEC:/opt/target/ret2plt,stderr &
socat TCP-LISTEN:9997,reuseaddr,fork EXEC:/opt/target/shellcode,stderr &
socat TCP-LISTEN:9996,reuseaddr,fork EXEC:/opt/target/fmtstr,stderr &
socat TCP-LISTEN:9995,reuseaddr,fork EXEC:/opt/target/uaf_heap,stderr &
# the ROP Emporium targets: wrapper scripts (the lib needs
# LD_LIBRARY_PATH, the encrypted flag + keys need the right cwd)
socat TCP-LISTEN:9993,reuseaddr,fork EXEC:/opt/target/emporium/callme.sh,stderr &
socat TCP-LISTEN:9992,reuseaddr,fork EXEC:/opt/target/emporium/ret2csu.sh,stderr &
# the hardened variants (the purple demo watches the decisions die)
socat TCP-LISTEN:8899,reuseaddr,fork EXEC:/opt/target/ret2func_h,stderr &
socat TCP-LISTEN:8898,reuseaddr,fork EXEC:/opt/target/ret2plt_h,stderr &
socat TCP-LISTEN:8897,reuseaddr,fork EXEC:/opt/target/shellcode_h,stderr &
setarch -R socat TCP-LISTEN:9994,reuseaddr,fork EXEC:/opt/target/orw,stderr &
wait
