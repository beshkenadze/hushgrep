"""Consumer acceptance test for report generation, masking and source coordinates."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys

root=Path(os.environ["RUNNER_TEMP"])/"canary-repo"
plain="MaskTestFixture7Q"
decoded="MaskTestFixture8P"
escaped="".join("%%%02X"%b for b in decoded.encode())
basic="MaskTestFixture9K"
token=base64.b64encode(("fixture:"+basic).encode()).decode()
fixtures=sorted([(plain, f'uri = "https://fixture:{plain}@example.invalid/"', plain),
                 (decoded, f'uri = "https://fixture:{escaped}@example.invalid/"', escaped),
                 (basic, f'header = "Basic {token}"', token)])
if sys.argv[1]=="prepare":
    root.mkdir()
    subprocess.run(["git","init","-q",root],check=True)
    for filename,line,_ in fixtures:
        (root/(filename+".txt")).write_bytes(("// sample\r\n// тест · "+line+"\r\n").encode())
elif sys.argv[1]=="check":
    d=Path(os.environ["REPORT_DIR"])
    for filename in ["report.json","report.html"]:
        text=(d/filename).read_text()
        if any(v in text for v in (plain,decoded,escaped,basic,token)):
            raise SystemExit("A fixture value escaped masking")
    report=json.loads((d/"report.json").read_text())
    assert report["status"]=="complete" and report["scanned_files"]==3
    expected={(i,2,("// тест · "+line).index(spelling)+1,2,("// тест · "+line).index(spelling)+1+len(spelling))
              for i,(_,line,spelling) in enumerate(fixtures)}
    got=set()
    for r in report["findings"]:
        assert r["path"]=="[REDACTED PATH]" and r["value"]=="[REDACTED]"
        got.add(tuple(r[k] for k in ("file_id","line","column","end_line","end_column")))
    assert expected<=got
    print("URI, percent-encoded URI, HTTP Basic, filenames and Unicode coordinates verified.")
else:
    raise SystemExit("Unknown smoke test operation")
