"""A redirect for the one URL nobody can be expected to type.

A Freenet web container lives at `/v1/contract/web/<44 characters>/`, which is
correct and unshareable. The obvious fix -- pointing the hostname's root at the
node -- publishes the node's ADMIN DASHBOARD, which is served at `/` and is the
one thing that must not be on the internet.

So the tunnel sends the app's two paths to the node and everything else here,
and this sends everything else to the app. Twenty lines, no dependencies, and
it holds nothing: it cannot read the node, cannot see a key, and knows only a
contract address that is public anyway.
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FrontDoor(BaseHTTPRequestHandler):
    target = "/"

    def do_GET(self) -> None:  # noqa: N802 - the stdlib chooses this name
        self.send_response(302)
        self.send_header("Location", self.target)
        # A permanent redirect would be cached by browsers forever, and this
        # target changes whenever the site is republished under a new key.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    do_HEAD = do_GET

    def log_message(self, *args) -> None:
        """Silent. This sits behind a tunnel that already logs every request."""


def serve(port: int, contract: str) -> None:
    FrontDoor.target = f"/v1/contract/web/{contract}/"
    ThreadingHTTPServer(("127.0.0.1", port), FrontDoor).serve_forever()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: frontdoor.py <port> <website contract key>")
    serve(int(sys.argv[1]), sys.argv[2])
