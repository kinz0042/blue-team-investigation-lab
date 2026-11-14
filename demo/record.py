"""Record actual project command output as an offline HTML demonstration."""
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
commands = [
    ["investigate.py", "--output", "/tmp/blue-team-demo"],
    ["inspect_public_rdp.py"],
    ["investigate_public_rdp.py"],
    ["-m", "unittest", "discover", "-s", "tests", "-v"],
]
steps = []
for arguments in commands:
    start = time.monotonic()
    result = subprocess.run([sys.executable, *arguments], cwd=ROOT,
                            capture_output=True, text=True)
    steps.append({"command": "python3 " + " ".join(arguments),
                  "output": result.stdout + result.stderr,
                  "exit_code": result.returncode,
                  "duration_seconds": round(time.monotonic() - start, 3)})
    if result.returncode:
        raise RuntimeError(steps[-1])
(ROOT / "demo/recording.json").write_text(json.dumps(steps, indent=2)+"\n")
data = json.dumps(steps).replace("<", "\\u003c")
page = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Blue team investigation demonstration</title>
<style>body{background:#101820;color:#e4edf4;max-width:1000px;margin:40px auto;padding:20px;font:17px system-ui}
button{padding:12px 18px;cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#172632;padding:22px;font:14px monospace}
h1{color:#84d9cf}</style>
<h1>Blue team investigation demonstration</h1>
<p>Recorded command output from Linux. The first case uses synthetic events. The second uses the original OTRF public Windows capture.</p>
<button id="next">Show next command</button> <button id="reset">Restart</button><p id="position"></p><pre id="output" aria-live="polite"></pre>
<script>const steps=DATA;let position=0;
const output=document.getElementById("output");
function show(){if(position>=steps.length)return;const s=steps[position++];
output.textContent+="$ "+s.command+"\n"+s.output+"\nExit "+s.exit_code+" · "+s.duration_seconds+"s\n\n";
document.getElementById("position").textContent=position+" of "+steps.length+" commands";
document.getElementById("next").disabled=position===steps.length;}
document.getElementById("next").onclick=show;
document.getElementById("reset").onclick=()=>{position=0;output.textContent="";document.getElementById("next").disabled=false;show();};
show();</script></html>"""
# JavaScript newline escape sequences must survive Python string decoding.
page = page.replace('"\n"', '"\\n"').replace('"\nExit ', '"\\nExit ').replace('s\n\n"', 's\\n\\n"')
(ROOT / "demo/index.html").write_text(page.replace("DATA", data))
print("Recorded", len(steps), "successful commands.")
