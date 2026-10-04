# The demo lab: four vulnerable services, four different fact bases,
# four different decisions from the same engine.
#
#   ret2func   9999  no-PIE, no canary, NX ON, win() present
#   ret2plt    9998  no-PIE, NX ON, system@plt, NO win()
#   shellcode  9997  no-PIE, NX OFF (execstack), no win()
#   fmtstr     9996  printf(input) - the format IS the weapon
#
# Each binary is served over http (port 8000) for acquisition.
FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev socat python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/target
COPY targets/ret2func/flag.txt /opt/target/ret2func.flag
# The services open flag.txt relative to their shared cwd (/opt/target):
# without it the win path prints "no flag file" and a ronin exit code
# still lies about the success.
COPY targets/ret2func/flag.txt /opt/target/flag.txt
COPY targets/ret2plt/flag.txt  /opt/target/ret2plt.flag
COPY targets/shellcode/flag.txt /opt/target/shellcode.flag
COPY targets/fmtstr/flag.txt  /opt/target/fmtstr.flag
COPY targets/ret2func/service.c /opt/target/ret2func.c
COPY targets/ret2plt/service.c  /opt/target/ret2plt.c
COPY targets/shellcode/service.c /opt/target/shellcode.c
COPY targets/fmtstr/service.c   /opt/target/fmtstr.c

# ret2func + ret2plt: NX ON (default), no canary, no PIE.
RUN gcc ret2func.c  -o ret2func  -fno-stack-protector -no-pie -O0 \
    && gcc ret2plt.c   -o ret2plt   -fno-stack-protector -no-pie -O0 \
    && gcc shellcode.c -o shellcode -fno-stack-protector -no-pie -z execstack -O0 \
    && gcc fmtstr.c    -o fmtstr    -fno-stack-protector -no-pie -O0 \
    && chmod 755 ret2func ret2plt shellcode fmtstr \
    && chmod 644 *.flag

EXPOSE 8000 9996 9997 9998 9999

COPY start.sh .
CMD ["./start.sh"]
