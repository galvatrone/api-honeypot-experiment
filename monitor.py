"""Local monitor. No public dashboard or network calls."""
import argparse
import json
import os
import time
from honeypot import State


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    state = State(args.state_dir)
    try:
        while True:
            started = time.monotonic()
            print(json.dumps(state.export(), ensure_ascii=False, indent=2), flush=True)
            if args.once:
                break
            time.sleep(max(0, 60 - (time.monotonic() - started)))
    except KeyboardInterrupt:
        pass
    finally:
        state.db.close()


if __name__ == '__main__':
    main()
