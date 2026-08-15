"""Session-scoped fixtures: spin up the flawed demo server once for all tests."""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from websec_auditor import fixgen  # noqa: E402


@pytest.fixture(scope="session")
def demo_server():
    try:
        fixgen.reset_demo_fix()
    except OSError:
        pass
    from websec_auditor.demo import flawed_server
    srv = None
    for attempt in range(30):
        try:
            from http.server import HTTPServer
            srv = HTTPServer(("127.0.0.1", 8099), flawed_server.Handler)
            break
        except OSError:
            time.sleep(0.2)
    if srv is None:
        pytest.skip("demo server port 8099 unavailable")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    yield "http://127.0.0.1:8099"
    srv.shutdown()
    srv.server_close()
