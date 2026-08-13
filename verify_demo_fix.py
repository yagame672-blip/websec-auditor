import sys, time, threading, json
sys.path.insert(0, r"D:\websec-auditor")
from websec_auditor.demo import flawed_server
import websec_auditor.fixgen as fixgen
from websec_auditor.scanner import engine
from websec_auditor.analyzer.analyze import analyze, summarize
import urllib.request

# ensure flawed default
open(r"D:\websec-auditor\data\demo_fixstate.json", "w").write(json.dumps({"hardened": False}))

t = threading.Thread(target=flawed_server.serve, daemon=True)
t.start()
time.sleep(1.5)

def scan_demo():
    return summarize(analyze(engine.scan("http://127.0.0.1:8099")))

print("=== FLAWED  ===", scan_demo())
fixgen.apply_demo_fix()
time.sleep(0.3)
print("=== HARDENED===", scan_demo())
try:
    r = urllib.request.urlopen("http://127.0.0.1:8099/.env", timeout=5)
    print("==> /.env status after fix:", r.status)
except Exception as e:
    print("==> /.env after fix:", type(e).__name__, getattr(e, "code", ""))
