import json
import sys


class Logger:
    """
    Simple logging abstraction

    Over at rust side, there's a spawned task reading stderr line by line.
    On each line there should be <level><json> on a single line.
    """

    def error(self, message):
        self._log(0, message)

    def warn(self, message):
        self._log(1, message)

    def info(self, message):
        self._log(2, message)

    def debug(self, message):
        self._log(3, message)

    def trace(self, message):
        self._log(4, message)

    def _log(self, level, message):
        print(f"{level}{json.dumps(message)}", file=sys.stderr, flush=True)
