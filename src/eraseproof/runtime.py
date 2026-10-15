"""Environment boundaries between bundled libraries and Linux system tools."""
import os
import sys


def system_environment():
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    if getattr(sys, "frozen", False):
        original = environment.get("LD_LIBRARY_PATH_ORIG")
        if original is None:
            environment.pop("LD_LIBRARY_PATH", None)
        else:
            environment["LD_LIBRARY_PATH"] = original
    return environment
