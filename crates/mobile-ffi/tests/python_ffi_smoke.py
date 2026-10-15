#!/usr/bin/env python3
"""Exercise UniFFI's generated ctypes binding against a built shared library."""

from __future__ import annotations

import argparse
import importlib
import pathlib
import shutil
import sys
import tempfile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("library", type=pathlib.Path)
    args = parser.parse_args()

    binding = pathlib.Path(__file__).parents[1] / "generated/python/annoda_mobile_ffi.py"
    if not args.library.is_file():
        parser.error(f"shared library does not exist: {args.library}")
    if not binding.is_file():
        parser.error(f"generated UniFFI binding does not exist: {binding}")

    with tempfile.TemporaryDirectory(prefix="annoda-ffi-") as temporary:
        directory = pathlib.Path(temporary)
        shutil.copy2(binding, directory / binding.name)
        shutil.copy2(args.library, directory / "libannoda_mobile_ffi.so")
        sys.path.insert(0, temporary)
        try:
            ffi = importlib.import_module("annoda_mobile_ffi")
            assert ffi.api_version() == "0.1.0"
            model = ffi.LocalPreferenceModel(2, 1)
            initial = model.score(1, [0.3, 0.4]).probability
            model.record_feedback(1, [0.3, 0.4], True)
            learned = model.score(1, [0.3, 0.4]).probability
            assert initial == 0.5 and learned > initial
            model.reset()
            assert model.score(1, [0.3, 0.4]).probability == 0.5

            try:
                ffi.LocalPreferenceModel(0, 1)
            except ffi.FfiError.InvalidInput:
                pass
            else:
                raise AssertionError("invalid constructor input did not cross the ABI as typed error")

            try:
                model.score(1, [0.3])
            except ffi.FfiError.IncompatibleModel:
                pass
            else:
                raise AssertionError("dimension mismatch did not cross the ABI as typed error")
        finally:
            sys.path.remove(temporary)
            sys.modules.pop("annoda_mobile_ffi", None)

    print("UniFFI Python ABI smoke test passed")


if __name__ == "__main__":
    main()
