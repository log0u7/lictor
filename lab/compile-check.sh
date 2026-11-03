#!/bin/sh
# Compile-verify the 10 new bench targets with the EXACT flags the
# Dockerfile will use. Fails on the first error.
set -e
cd "$(dirname "$0")"
mkdir -p /tmp/compile-check
ok=1
build() {
	name=$1
	flags=$2
	gcc "targets/$name/service.c" -o "/tmp/compile-check/$name" $flags 2>"/tmp/compile-check/$name.err" || {
		echo "FAIL: $name"
		cat "/tmp/compile-check/$name.err"
		ok=0
		return 1
	}
	echo "OK: $name"
}
build ret2libc-001 "-fno-stack-protector -pie -fPIE -O0"
build ret2libc-002 "-fno-stack-protector -no-pie -O0 -static"
build fmtstr-002 "-fno-stack-protector -pie -fPIE -O0"
build ret2func-002 "-fstack-protector-strong -no-pie -O0"
build shellcode-002 "-fno-stack-protector -pie -fPIE -z execstack -O0"
build uaf_heap-002 "-fno-stack-protector -no-pie -O0"
build orw-002 "-fno-stack-protector -no-pie -O0"
build callme-002 "-fno-stack-protector -no-pie -O0"
build ret2plt-002 "-fno-stack-protector -pie -fPIE -O0 -Wl,-z,now"
build srop-001 "-fno-stack-protector -no-pie -O0"
build uaf_train_a "-fno-stack-protector -no-pie -O0"
build uaf_train_b "-fno-stack-protector -pie -fPIE -O0"
[ "$ok" -eq 1 ]
