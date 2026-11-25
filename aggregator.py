"""Entry point: ``python aggregator.py [options]`` (see ``--help``)."""

import sys

from ipblocklist.pipeline import main

if __name__ == "__main__":
    sys.exit(main())
