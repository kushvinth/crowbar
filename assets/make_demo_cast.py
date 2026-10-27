#!/usr/bin/env python3
"""Generate website/static/demo.cast - the crowbar intro demo (asciinema v2).

The output blocks below are REAL `crowbar` output captured against the full
index (log4shell triage, nginx version-matching, Exploit-DB lookup), only
trimmed for length. Re-capture with:
    crowbar cve CVE-2021-44228
    crowbar product nginx --version 1.18.0
    crowbar exploit log4j
Run: python3 assets/make_demo_cast.py  ->  writes website/static/demo.cast
"""

from __future__ import annotations
import json
import pathlib
import time

G, C, Y, R, DIM, RST, BOLD = (
    "\x1b[32m",
    "\x1b[36m",
    "\x1b[33m",
    "\x1b[31m",
    "\x1b[2m",
    "\x1b[0m",
    "\x1b[1m",
)
PROMPT = f"{G}❯{RST} "

# (command, [output lines]) - real output, trimmed.
STEPS = [
    (
        "crowbar cve CVE-2021-44228",
        [
            f"{BOLD}CVE-2021-44228{RST}  {R}CRIT 10.0{RST}  {R}KEV{RST} epss {R}1.00{RST}",
            "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints…",
            "",
            f"  {DIM}published{RST} 2021-12-10   {DIM}modified{RST} 2026-08-11   {DIM}status{RST} Analyzed",
            f"  {DIM}vector{RST}    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            f"  {DIM}epss{RST}      1.0000  (percentile 1.00)",
            f"  {DIM}weakness{RST}  CWE-20, CWE-400, CWE-502, CWE-917",
            f"  {DIM}affects{RST}   apache:log4j >=2.0.1 <2.3.1, >=2.13.0 <2.15.0 … (+40 ranges)",
            f"  {DIM}ssvc{RST}      exploitation={R}active{RST} automatable=yes impact=total",
            "",
            f"{Y}▌ CISA KEV{RST}  added 2021-12-10  due 2021-12-24  ransomware=Known",
            "  Apache Log4j2 Remote Code Execution Vulnerability",
            "",
            f"{Y}▌ Exploit-DB (3){RST}",
            f"   {C}50592{RST}  java   remote   Apache Log4j 2 - Remote Code Execution (RCE)",
            f"   {C}50590{RST}  java   remote   Apache Log4j2 2.14.1 - Information Disclosure",
            "",
            f"{Y}▌ Nuclei (44){RST}   {Y}▌ Metasploit (4){RST}",
        ],
    ),
    (
        "crowbar product nginx --version 1.18.0",
        [
            f"{BOLD}CVEs affecting 'nginx' version 1.18.0{RST}",
            "",
            f"{R}CVE-2021-23017{RST} HIGH 7.7 epss 0.53  2021-06-01",
            f"  {DIM}matched{RST} f5:nginx >=0.6.18 <1.20.1",
            "  nginx resolver issue - attacker who can forge UDP responses may trigger memory corruption.",
            "CVE-2019-15517 MED  5.5 epss 0.01  2019-08-23",
            f"  {DIM}matched{RST} jc21:nginx_proxy_manager <2.0.13",
        ],
    ),
    (
        "crowbar exploit log4j",
        [
            f"   {C}50592{RST} 2021-12-14 java   Apache Log4j 2 - Remote Code Execution (RCE)",
            f"        {DIM}CVE-2021-44228{RST}",
            f"   {C}50590{RST} 2021-12-14 java   Apache Log4j2 2.14.1 - Information Disclosure",
            f"        {DIM}CVE-2021-44228{RST}",
        ],
    ),
]


def main() -> None:
    ev: list = []
    t = 0.0

    def out(s: str):
        nonlocal t
        ev.append([round(t, 3), "o", s])

    # intro
    out(PROMPT)
    t += 0.6
    for cmd, lines in STEPS:
        for ch in cmd:  # type the command
            out(ch)
            t += 0.045
        t += 0.25
        out("\r\n")  # Enter
        for ln in lines:  # stream output
            out(ln + "\r\n")
            t += 0.06
        t += 1.9  # read pause
        out("\r\n" + PROMPT)
        t += 0.5
    out(f"{DIM}# offline. reproducible. every answer grounded in the local index.{RST}\r\n")
    t += 2.2

    header = {
        "version": 2,
        "width": 92,
        "height": 32,
        "timestamp": int(time.time()),
        "title": "crowbar - pry it open",
        "env": {"SHELL": "/bin/zsh", "TERM": "xterm-256color"},
    }
    dst = pathlib.Path(__file__).resolve().parents[1] / "website" / "demo.cast"
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("w") as f:
        f.write(json.dumps(header) + "\n")
        for e in ev:
            f.write(json.dumps(e) + "\n")
    print(f"wrote {dst} ({len(ev)} events, ~{t:.0f}s)")


if __name__ == "__main__":
    main()
