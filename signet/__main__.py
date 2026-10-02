"""``python -m signet`` — open the window; with an argument, run the CLI."""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) > 1:
        from .cli import main as cli_main
        return cli_main(sys.argv[1:])
    from .app import main as app_main
    return app_main(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
