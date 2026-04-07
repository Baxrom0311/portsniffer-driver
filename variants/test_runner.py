"""
Test runner for PortSniffer wcslen bug fix.
Tests the multi-SZ iteration logic that was fixed.
"""
import subprocess
import os
import sys

GCC = r"C:\msys64\mingw64\bin\gcc.exe"
SRC = r"C:\PortSnifferTest\test_wcslen_fix.c"
EXE = r"C:\PortSnifferTest\test_fix.exe"

def main():
    # Step 1: Compile
    print("=" * 50)
    print("  Step 1: Compiling test...")
    print("=" * 50)

    result = subprocess.run(
        [GCC, "-Wall", "-o", EXE, SRC],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        print(f"COMPILE FAILED (exit {result.returncode})")
        print(result.stderr)
        return 1

    print("  Compile OK!")
    print()

    # Step 2: Run test
    print("=" * 50)
    print("  Step 2: Running test...")
    print("=" * 50)
    print()

    result = subprocess.run(
        [EXE],
        capture_output=True, text=True
    )

    print(result.stdout)
    if result.stderr:
        print(result.stderr)

    print()
    print("=" * 50)
    if result.returncode == 0:
        print("  ALL TESTS PASSED!")
    else:
        print(f"  SOME TESTS FAILED (exit {result.returncode})")
    print("=" * 50)

    return result.returncode

if __name__ == "__main__":
    sys.exit(main())
