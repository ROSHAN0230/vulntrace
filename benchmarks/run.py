"""
Backward-compatibility forwarding wrapper for legacy benchmarks runner.
Delegates to the canonical Spec §4.15 package runner in bench.run.
"""
import sys
from bench.run import main_cli

if __name__ == "__main__":
    sys.exit(main_cli(sys.argv[1:]))
