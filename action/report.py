"""Render only redacted scanner output. No repository content is opened by this program."""
import html
import json
import math
import os
from pathlib import Path
import platform
import sys
from collections import defaultdict


def read(path):
    return json.loads(path.read_text(encoding="utf8"))


def groups(report):
    result = defaultdict(list)
    for row in report["findings"]:
        if (row["value"] != "[REDACTED]" or
            any(type(row[k]) is not int or row[k] < 1 for k in ("line","column","end_line","end_column")) or
            type(row["file_id"]) is not int or row["file_id"] < 0 or not isinstance(row["path"], str)):
            raise ValueError("unexpected finding schema")
        result[row["file_id"]].append(row)
    if sum(map(len,result.values())) != report["finding_count"]:
        raise ValueError("finding count mismatch")
    return sorted(result.items(),key=lambda item:(-len(item[1]),item[0]))


def memory_total():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1])
    return None


def write_html(directory, report, metrics, by_file):
    status = report["status"]
    cards = [
        ("Findings",f'{report["finding_count"]:,}'),
        ("Files with findings",f'{len(by_file):,}'),
        ("Files scanned",f'{report["scanned_files"]:,}'),
        ("Lines scanned",f'{report["scanned_lines"]:,}'),
    ]
    def safe(value):
        return html.escape(value,quote=True)
    def locations(rows):
        return "".join(f'<tr><td>{r["line"]:,}</td><td>{r["column"]:,}</td>'
                       f'<td>{r["end_line"]:,}</td><td>{r["end_column"]:,}</td><td><code>[REDACTED]</code></td></tr>'
                       for r in rows)
    sections = []
    for i,(file_id,rows) in enumerate(by_file):
        path = rows[0]["path"]
        label = f"File {file_id} · path masked" if path == "[REDACTED PATH]" else path
        sections.append(f'<details {"open" if i==0 else ""}><summary><bdi>{safe(label)}</bdi>'
                        f'<span>{len(rows):,} findings</span></summary><div class="scroll"><table>'
                        '<thead><tr><th>Line</th><th>Column</th><th>End line</th><th>End column</th><th>Value</th></tr></thead>'
                        f'<tbody>{locations(rows)}</tbody></table></div></details>')
    skips=report["skipped_files"]
    coverage = (f'{sum(skips.values()):,} skipped files · '
                f'{report["unlocalized_native_candidates"]:,} unlocalized candidates · '
                f'{report["native_coverage_mismatch_batches"]:,} batches with incomplete coverage')
    page = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';base-uri 'none'">
<title>Hushgrep · Scan report</title><style>
*{box-sizing:border-box}body{margin:0;background:#f4f5f0;color:#192c30;font:16px/1.55 system-ui,sans-serif}
main{max-width:1040px;margin:auto;padding:48px 24px}header{background:#123738;color:#f4fff6;border-radius:16px;padding:32px 36px}
header p{margin:0;color:#c5dcd6}header h1{margin:4px 0 14px;font-size:clamp(32px,5vw,52px);line-height:1.12}
.state{display:inline-block;font-weight:650;background:#d0f4d5;color:#164b38;padding:2px 12px;border-radius:99px}.partial{background:#ffdf98;color:#5e3904}
.cards{margin:20px 0 10px;display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px}
.card,details{background:#fff;border:1px solid #d2ddd6;border-radius:10px}.card{padding:16px 20px}
.card strong{display:block;font-size:34px;font-variant-numeric:tabular-nums}.muted,.card small{color:#415b57}
h2{margin:28px 0 10px}details{margin:8px 0;overflow:hidden}summary{cursor:pointer;padding:12px 16px;font-weight:650;overflow-wrap:anywhere}
summary span{font-weight:450;font-size:.9em;color:#415b57;margin-left:12px}.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;text-align:left;font-variant-numeric:tabular-nums}th,td{padding:8px 16px;border-top:1px solid #dce5dd}
th{color:#405853;background:#f1f5ef}code{font-size:.82em;color:#28534c}
@media(max-width:500px){main{padding:16px 12px}header{padding:20px}.cards{grid-template-columns:1fr 1fr}th,td{padding:6px 9px}}
</style><main><header><p>Hushgrep · v10 INT8</p><h1>Credential scan</h1>"""
    page+=f'<span class="state {status}">{status.capitalize()}</span></header><div class="cards">'
    page+="".join(f'<div class="card"><small>{k}</small><strong>{v}</strong></div>' for k,v in cards)+'</div>'
    page+=(f'<p class="muted">{metrics["wall_seconds"]:.2f} s scan time · {metrics["peak_rss_kib"]/1048576:.2f} GiB peak RSS'
           f'<br>{coverage}</p><h2>Findings by file</h2>')
    if sections:
        page+='<p>Lines and columns start at 1. End columns are exclusive. Files are ordered by finding count.</p>'+"".join(sections)
    else:
        page+='<p>No candidate ranges were reported.</p>'
    (directory/"report.html").write_text(page+"</main></html>",encoding="utf8")


def render(directory, measurement, timing_file, exit_code):
    report=read(directory/"report.json")
    status=report["status"]
    if (int(exit_code),status) not in {(0,"complete"),(2,"partial")}:
        raise ValueError("inconsistent scan status")
    by_file=groups(report)
    seconds,peak=measurement.read_text().strip().splitlines()[-1].split()
    wall=float(seconds);rss=int(peak)
    if not math.isfinite(wall) or wall<0 or rss<=0:
        raise ValueError("invalid scanner measurements")
    timings=read(timing_file)
    metrics=dict(wall_seconds=wall,peak_rss_kib=rss,model_load_seconds=float(timings["model_load_seconds"]),
                 runner_memory_kib=memory_total(),architecture=platform.machine(),
                 cpu_count=len(os.sched_getaffinity(0)),runner_environment=os.getenv("RUNNER_ENVIRONMENT","local"),
                 image=os.getenv("ImageOS",""),image_version=os.getenv("ImageVersion",""))
    (directory/"metrics.json").write_text(json.dumps(metrics,indent=2)+"\n")
    write_html(directory,report,metrics,by_file)
    with open(os.environ["GITHUB_OUTPUT"],"a",encoding="utf8") as output:
        print(f"findings={report['finding_count']}\nstatus={status}\ndirectory={directory}",file=output)


def summary(directory):
    from urllib.parse import urlsplit
    r=read(directory/"report.json");m=read(directory/"metrics.json");files=groups(r)
    print("## Hushgrep · Credential scan\n")
    print(f"**{r['status'].capitalize()}** · {r['finding_count']:,} masked findings in {len(files):,} files.\n")
    print("| Files scanned | Lines scanned | Scan time | Peak RSS |\n| ---: | ---: | ---: | ---: |")
    print(f"| {r['scanned_files']:,} | {r['scanned_lines']:,} | {m['wall_seconds']:.2f} s | {m['peak_rss_kib']/1048576:.2f} GiB |\n")
    print(f"Skipped files: {sum(r['skipped_files'].values()):,}. "
          f"Unlocalized candidates: {r['unlocalized_native_candidates']:,}. "
          f"Coverage mismatches: {r['native_coverage_mismatch_batches']:,}.\n")
    url=os.getenv("ARTIFACT_URL","")
    if url and urlsplit(url).scheme=="https" and not any(c.isspace() or c in "()<>" for c in url):
        print(f"[Download the HTML and JSON reports]({url})")


if __name__=="__main__":
    if sys.argv[1]=="render":
        render(Path(sys.argv[2]),Path(sys.argv[3]),Path(sys.argv[4]),sys.argv[5])
    elif sys.argv[1]=="summary":
        summary(Path(sys.argv[2]))
    else:
        raise SystemExit("Unknown operation")
