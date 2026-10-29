#!/bin/sh
# The ROP Emporium callme target: the companion library resolves via
# LD_LIBRARY_PATH and the lib opens encrypted_flag.dat + key*.dat
# relative to the cwd, so the service runs from its own directory.
cd /opt/target/emporium/callme
exec env LD_LIBRARY_PATH=/opt/target/emporium/callme ./callme
