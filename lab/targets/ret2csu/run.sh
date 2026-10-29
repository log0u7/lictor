#!/bin/sh
# The ROP Emporium ret2csu target: same layout as callme - the lib via
# LD_LIBRARY_PATH, the encrypted flag + key opened from the cwd.
cd /opt/target/emporium/ret2csu
exec env LD_LIBRARY_PATH=/opt/target/emporium/ret2csu ./ret2csu
