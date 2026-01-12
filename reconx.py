#!/usr/bin/env python3
import os
import subprocess
import yaml
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from jinja2 import Template
from colorama import Fore, Style
from tqdm import tqdm

OUTPUT = "output"
SCOPE = "scope.txt"
GO_BIN = os.path.expanduser("~/go/bin")

# -----------------------------
# Core command runner
# -----------------------------
def run(cmd, outfile=None):
    result = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )
    if outfile:
        with open(outfile, "w") as f:
            f.write(result.stdout)
    return result.stdout


# -----------------------------
# Tool & dependency checks
# -----------------------------
def check_tools():
    with open("tools.yaml") as f:
        data = yaml.safe_load(f)

    # System dependencies
    for dep in data.get("system_dependencies", []):
        if subprocess.call(dep["check"], shell=True) != 0:
            print(Fore.YELLOW + f"[!] Installing system dependency: {dep['name']}" + Style.RESET_ALL)
            subprocess.call(dep["install"], shell=True)
        else:
            print(Fore.GREEN + f"[✔] {dep['name']} found" + Style.RESET_ALL)

    # Tools
    for tool in data["tools"]:
        name = tool["name"]
        check_cmd = tool.get(
            "check",
            f"command -v {name} || test -x {GO_BIN}/{name}"
        )

        if subprocess.call(check_cmd + " >/dev/null 2>&1", shell=True) != 0:
            print(Fore.YELLOW + f"[!] Installing {name}" + Style.RESET_ALL)
            subprocess.call(tool["install"], shell=True)
        else:
            print(Fore.GREEN + f"[✔] {name} found" + Style.RESET_ALL)


# -----------------------------
# Parallel execution engine
# -----------------------------
def task(name, cmd, outfile=None):
    start = time.time()
    run(cmd, outfile)
    duration = round(time.time() - start, 2)
    return name, duration


def run_parallel(tasks, workers=4, desc="Running"):
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(task, *t): t[0] for t in tasks}

        for future in tqdm(
            as_completed(futures),
            total=len(futures),
            desc=desc,
            unit="task"
        ):
            name, duration = future.result()
            results.append((name, duration))

    return results


# -----------------------------
# Recon pipeline
# -----------------------------
def recon():
    os.makedirs(OUTPUT, exist_ok=True)

    print(Fore.MAGENTA + "\n[1/10] Subdomain Discovery" + Style.RESET_ALL)
    sub_tasks = [
        ("subfinder", "subfinder -dL scope.txt -silent", f"{OUTPUT}/sub1.txt"),
        ("assetfinder", "assetfinder --subs-only $(cat scope.txt)", f"{OUTPUT}/sub2.txt"),
        ("amass", "amass enum -passive -df scope.txt", f"{OUTPUT}/sub3.txt"),
    ]
    run_parallel(sub_tasks, desc="Subdomain tools")

    run(f"cat {OUTPUT}/sub*.txt | sort -u", f"{OUTPUT}/subdomains.txt")

    print(Fore.MAGENTA + "\n[2/10] DNS Resolution" + Style.RESET_ALL)
    run(f"dnsx -l {OUTPUT}/subdomains.txt -silent", f"{OUTPUT}/resolved.txt")

    print(Fore.MAGENTA + "\n[3/10] HTTP Probing" + Style.RESET_ALL)
    run(
        f"httpx -l {OUTPUT}/resolved.txt -status-code -title -tech-detect",
        f"{OUTPUT}/alive.txt"
    )

    print(Fore.MAGENTA + "\n[4/10] Port Scanning" + Style.RESET_ALL)
    run(
        f"naabu -l {OUTPUT}/resolved.txt -top-ports 1000 -silent",
        f"{OUTPUT}/ports.txt"
    )

    print(Fore.MAGENTA + "\n[5/10] Technology Fingerprinting" + Style.RESET_ALL)
    run(f"whatweb -i {OUTPUT}/alive.txt", f"{OUTPUT}/tech.txt")

    print(Fore.MAGENTA + "\n[6/10] URL Discovery" + Style.RESET_ALL)
    url_tasks = [
        ("gau", f"gau < {OUTPUT}/resolved.txt", f"{OUTPUT}/urls1.txt"),
        ("waybackurls", f"waybackurls < {OUTPUT}/resolved.txt", f"{OUTPUT}/urls2.txt"),
        ("katana", f"katana -list {OUTPUT}/resolved.txt -silent", f"{OUTPUT}/urls3.txt"),
    ]
    run_parallel(url_tasks, desc="URL discovery")

    run(f"cat {OUTPUT}/urls*.txt | sort -u", f"{OUTPUT}/urls.txt")

    print(Fore.MAGENTA + "\n[7/10] JavaScript Recon" + Style.RESET_ALL)
    js_tasks = [
        ("subjs", f"subjs -i {OUTPUT}/alive.txt", f"{OUTPUT}/js.txt"),
    ]
    run_parallel(js_tasks, desc="JS recon")

    print(Fore.MAGENTA + "\n[8/10] Parameter Mining" + Style.RESET_ALL)

    if not os.path.exists("ParamSpider"):
        run("git clone https://github.com/devanshbatham/ParamSpider.git")

    param_tasks = [
        ("paramspider", f"python3 ParamSpider/paramspider.py -l {OUTPUT}/resolved.txt", f"{OUTPUT}/params1.txt"),
        ("arjun", f"arjun -i {OUTPUT}/alive.txt -oT {OUTPUT}/params2.txt"),
    ]
    run_parallel(param_tasks, desc="Parameter mining")

    run(f"cat {OUTPUT}/params*.txt | sort -u", f"{OUTPUT}/params.txt")

    print(Fore.MAGENTA + "\n[9/10] Vulnerability Scanning (Nuclei)" + Style.RESET_ALL)
    run(
        f"nuclei -l {OUTPUT}/alive.txt -severity low,medium,high -silent",
        f"{OUTPUT}/nuclei.txt"
    )


# -----------------------------
# Report generation
# -----------------------------
def report():
    print(Fore.MAGENTA + "\n[10/10] Report Generation" + Style.RESET_ALL)

    with open(f"{OUTPUT}/report.txt", "w") as f:
        for file in sorted(os.listdir(OUTPUT)):
            f.write(f"\n===== {file} =====\n")
            f.write(open(f"{OUTPUT}/{file}").read())

    html = Template("""
    <html>
    <head>
        <title>ReconX Report</title>
        <style>
            body { font-family: monospace; background: #0f172a; color: #e5e7eb; }
            h1, h2 { color: #38bdf8; }
            pre { background: #020617; padding: 10px; overflow-x: auto; }
        </style>
    </head>
    <body>
    <h1>ReconX Report</h1>
    {% for file in files %}
      <h2>{{file}}</h2>
      <pre>{{content[file]}}</pre>
    {% endfor %}
    </body>
    </html>
    """)

    files = sorted(os.listdir(OUTPUT))
    content = {f: open(f"{OUTPUT}/{f}").read() for f in files}

    with open(f"{OUTPUT}/report.html", "w") as f:
        f.write(html.render(files=files, content=content))


# -----------------------------
# Entry point
# -----------------------------
if __name__ == "__main__":
    start_time = time.time()
    check_tools()
    recon()
    report()
    elapsed = round(time.time() - start_time, 2)
    print(Fore.GREEN + f"\n[✔] Recon Complete in {elapsed}s" + Style.RESET_ALL)
