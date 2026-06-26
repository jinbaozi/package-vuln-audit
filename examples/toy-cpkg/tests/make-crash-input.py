#!/usr/bin/env python3
from pathlib import Path
Path('oversized-record.bin').write_bytes(bytes([64]) + b'A' * 64)
print('wrote oversized-record.bin')
