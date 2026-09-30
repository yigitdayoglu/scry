"""nuclei ile aktif CVE doğrulama: kanıtlanan CVE ID kümesini döner."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

try:
    import config
except ModuleNotFoundError:
    from .. import config  # type: ignore


def is_available() -> bool:
    return shutil.which("nuclei") is not None


def _target_urls(host: str, services) -> list[str]:
    https_ports = {443, 8443, 4443}
    http_ports = {80, 8080, 8000, 8888, 8081}
    urls: set[str] = set()
    for svc in services:
        port = svc.port
        name = (svc.name or "").lower()
        if port in https_ports or "https" in name or "ssl" in name:
            urls.add(f"https://{host}:{port}")
        elif port in http_ports or "http" in name:
            urls.add(f"http://{host}" if port == 80 else f"http://{host}:{port}")
    if not urls:
        urls.add(host)
    return sorted(urls)


def verify(host: str, services, cve_ids: list[str],
           timeout: int | None = None) -> set[str]:
    if not cve_ids or not is_available():
        return set()

    timeout = timeout or config.NUCLEI_TIMEOUT
    ids = sorted({c.strip().upper() for c in cve_ids if c.strip()})
    targets = _target_urls(host, services)

    confirmed: set[str] = set()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets))
        target_file = tf.name

    try:
        cmd = [
            "nuclei",
            "-l", target_file,
            "-id", ",".join(ids),
            "-jsonl", "-silent", "-nc",
            "-timeout", "8", "-retries", "1",
            "-disable-update-check",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        confirmed = _parse_confirmed(proc.stdout)
    except subprocess.TimeoutExpired:
        pass
    finally:
        Path(target_file).unlink(missing_ok=True)

    return confirmed & set(ids)


def _parse_confirmed(stdout: str) -> set[str]:
    found: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = str(obj.get("template-id", "")).upper()
        if tid.startswith("CVE-"):
            found.add(tid)
        cls = (obj.get("info", {}) or {}).get("classification", {}) or {}
        for cve in (cls.get("cve-id") or []):
            found.add(str(cve).upper())
    return found


# --- CLI test: python -m scanner.nuclei_verifier ---
if __name__ == "__main__":
    print("nuclei mevcut mu?:", is_available())
    if is_available():
        import subprocess as sp
        print(sp.run(["nuclei", "-version"], capture_output=True, text=True).stderr.strip())
