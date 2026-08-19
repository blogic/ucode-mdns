#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 John Crispin <john@phrozen.org>
"""Run a protocol test with captured transport and deterministic timers."""
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
test = sys.argv[3] if len(sys.argv) > 3 else 'test_protocol.uc'
with tempfile.TemporaryDirectory(prefix='mdns-protocol-') as temporary:
    pathlib.Path(temporary, 'native_mdns.so').symlink_to(pathlib.Path(sys.argv[1]).resolve() / 'mdns.so')
    subprocess.run([sys.argv[2], '-L', str(root / 'tests/mocks/*.uc'), '-L', temporary,
                    '-L', str(root / 'ucode/*.uc'), str(root / 'tests' / test)], check=True)
