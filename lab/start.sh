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
# the MR5 bench targets (ten more fact bases; the orw-002 chain aims
# .data anchors offline, no setarch needed)
socat TCP-LISTEN:9982,reuseaddr,fork EXEC:/opt/target/ret2libc-001,stderr &
socat TCP-LISTEN:9983,reuseaddr,fork EXEC:/opt/target/ret2libc-002,stderr &
socat TCP-LISTEN:9984,reuseaddr,fork EXEC:/opt/target/fmtstr-002,stderr &
socat TCP-LISTEN:9985,reuseaddr,fork EXEC:/opt/target/ret2func-002,stderr &
socat TCP-LISTEN:9986,reuseaddr,fork EXEC:/opt/target/shellcode-002,stderr &
socat TCP-LISTEN:9987,reuseaddr,fork EXEC:/opt/target/uaf_heap-002,stderr &
socat TCP-LISTEN:9988,reuseaddr,fork EXEC:/opt/target/orw-002,stderr &
socat TCP-LISTEN:9989,reuseaddr,fork EXEC:/opt/target/callme-002,stderr &
socat TCP-LISTEN:9990,reuseaddr,fork EXEC:/opt/target/ret2plt-002,stderr &
socat TCP-LISTEN:9991,reuseaddr,fork EXEC:/opt/target/srop-001,stderr &
# the MR6 training twins (the uaf capability class; the eval targets stay unseen)
socat TCP-LISTEN:19991,reuseaddr,fork EXEC:/opt/target/uaf_train_a,stderr &
socat TCP-LISTEN:19992,reuseaddr,fork EXEC:/opt/target/uaf_train_b,stderr &
wait
