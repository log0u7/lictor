# The demo target: a CTF-style service with an unbounded copy.
#
# Protections, chosen for an HONEST demo:
#   - no PIE (win() is at a fixed address, announced in the banner)
#   - no stack canary (the overflow reaches the return address)
#   - NX ON (shellcode impossible: the decision layer must pick ret2func,
#     not shellcode - the anti-reflex discipline)
#
# The service announces the win address in the banner (a classic CTF
# convenience) so the exploit never hardcodes a build-dependent address.
FROM debian:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev socat python3 make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/target
COPY vuln_service.c flag.txt ./

# Protections at build time: no canary, no PIE, NX ON (default).
RUN gcc vuln_service.c -o vuln_service -fno-stack-protector -no-pie -O0 \
    && chmod 755 vuln_service \
    && chmod 644 flag.txt

# The binary is served for acquisition (augure-profiler profiles the ELF).
EXPOSE 8000 9999

COPY start.sh .
CMD ["./start.sh"]
