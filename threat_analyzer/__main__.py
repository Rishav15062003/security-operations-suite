from __future__ import annotations

import sys


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "cli":
        from .cli import main as cli_main

        return cli_main(argv[1:])
    initial = argv[0] if len(argv) == 1 else None
    from .app_ui import launch

    launch(initial_log=initial)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
