#!/usr/bin/python3
"""Launch the vanguards add-on on modern Python.

vanguards 0.3.1 (the version Debian/Ubuntu ship) imports
configparser.SafeConfigParser, which was removed in Python 3.12. The class was a
deprecated alias of ConfigParser, so restoring the alias is behaviour-preserving.
"""
import configparser
import sys

sys.path.insert(0, "/opt/vanguards")   # hash-verified vanguards + stem (see Dockerfile)

if not hasattr(configparser, "SafeConfigParser"):
    configparser.SafeConfigParser = configparser.ConfigParser  # type: ignore[attr-defined]
# readfp() was also removed in Python 3.12; vanguards uses it to load --config.
if not hasattr(configparser.RawConfigParser, "readfp"):
    configparser.RawConfigParser.readfp = configparser.RawConfigParser.read_file  # type: ignore[attr-defined]

from vanguards.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
