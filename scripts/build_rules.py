#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "PROCESS-NAME",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
}


class SourceFetchError(RuntimeError):
    pass


def _fetch_once(url: str, timeout: int, user_agent: str) -> bytes:
    req = Request(url, headers={"User-Agent": user_agent})
    with urlopen(req, timeout=timeout) as resp:  # nosec B310
        return resp.read()


def _derive_mirror_urls(url: str) -> List[str]:
    mirrors: List[str] = []

    m = re.match(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$", url)
    if m:
        owner, repo, ref, path = m.groups()
        mirrors.append(f"https://github.com/{owner}/{repo}/raw/{ref}/{path}")
        return mirrors

    m = re.match(r"^https://github\.com/([^/]+)/([^/]+)/raw/refs/heads/([^/]+)/(.+)$", url)
    if m:
        owner, repo, ref, path = m.groups()
        mirrors.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}")
        mirrors.append(f"https://github.com/{owner}/{repo}/raw/{ref}/{path}")
        return mirrors

    m = re.match(r"^https://github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.+)$", url)
    if m:
        owner, repo, ref, path = m.groups()
        mirrors.append(f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}")
        return mirrors

    return mirrors


def _expand_urls(source_conf: Dict) -> List[str]:
    configured = source_conf.get("urls")
    if configured is not None:
        if not isinstance(configured, list) or not configured or not all(isinstance(x, str) and x for x in configured):
            raise ValueError("urls must be a non-empty string array")
        base_urls = configured
    else:
        url = source_conf.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError("source must define url or urls")
        base_urls = [url]

    out: List[str] = []
    seen: Set[str] = set()
    for url in base_urls:
        for candidate in [url, *_derive_mirror_urls(url)]:
            if candidate and candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
    return out


def fetch_bytes(
    source_conf: Dict,
    timeout: int,
    user_agent: str,
    retries: int,
    retry_backoff: float,
) -> Tuple[bytes, str]:
    urls = _expand_urls(source_conf)
    last_error: Optional[Exception] = None

    for url in urls:
        for attempt in range(1, retries + 1):
            try:
                return _fetch_once(url, timeout=timeout, user_agent=user_agent), url
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                last_error = exc
                print(
                    f"[WARN] fetch failed: {url} (attempt {attempt}/{retries}): {exc}",
                    file=sys.stderr,
                )
                if attempt < retries and retry_backoff > 0:
                    time.sleep(retry_backoff * attempt)

    raise SourceFetchError(
        f"all fetch attempts failed for {', '.join(urls)}; last error: {last_error}"
    )


def fetch_text(
    source_conf: Dict,
    timeout: int,
    user_agent: str,
    retries: int,
    retry_backoff: float,
) -> Tuple[str, str]:
    data, used_url = fetch_bytes(
        source_conf,
        timeout=timeout,
        user_agent=user_agent,
        retries=retries,
        retry_backoff=retry_backoff,
    )
    return data.decode("utf-8", errors="replace"), used_url


def write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f".{path.name}.tmp"
    tmp_path.write_bytes(data)
    tmp_path.replace(path)


def write_text_atomic(path: Path, text: str) -> None:
    write_bytes_atomic(path, text.encode("utf-8"))


def _clean_line(line: str) -> str:
    line = line.strip().replace("\ufeff", "")
    if not line or line.startswith("#"):
        return ""
    return line


def parse_plain_rules(text: str) -> List[str]:
    return [line for raw in text.splitlines() if (line := _clean_line(raw))]


def parse_plain_domain_list(text: str) -> List[str]:
    out: List[str] = []
    for raw in text.splitlines():
        line = _clean_line(raw)
        if line:
            out.append(f"DOMAIN-SUFFIX,{line.lower()}")
    return out


def parse_dnsmasq_conf(text: str) -> List[str]:
    out: List[str] = []
    for raw in text.splitlines():
        line = _clean_line(raw)
        if not line.startswith("server=/"):
            continue
        m = re.match(r"server=/([^/]+)/", line)
        if m:
            out.append(f"DOMAIN-SUFFIX,{m.group(1).strip().lower()}")
    return out


def parse_clash_yaml_payload(text: str) -> List[str]:
    out: List[str] = []
    in_payload = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if re.match(r"^\s*payload\s*:\s*$", line):
            in_payload = True
            continue
        if not in_payload:
            continue

        # payload list item: "  - DOMAIN-SUFFIX,example.com"
        m = re.match(r"^\s*-\s*(.+?)\s*$", line)
        if not m:
            # stop when another top-level key appears
            if line and not line.startswith(" ") and not line.startswith("\t"):
                break
            continue
        item = m.group(1).strip().strip('"').strip("'")
        item = _clean_line(item)
        if item:
            out.append(item)
    return out


def parse_source(text: str, source_type: str) -> List[str]:
    if source_type == "plain_rules":
        return parse_plain_rules(text)
    if source_type == "plain_domain_list":
        return parse_plain_domain_list(text)
    if source_type == "dnsmasq_conf":
        return parse_dnsmasq_conf(text)
    if source_type == "clash_yaml_payload":
        return parse_clash_yaml_payload(text)
    raise ValueError(f"Unsupported source type: {source_type}")


def normalize_rule(line: str) -> Optional[str]:
    line = _clean_line(line)
    if not line:
        return None

    if "," not in line:
        return f"DOMAIN-SUFFIX,{line.lower()}"

    rtype, value = [x.strip() for x in line.split(",", 1)]
    rtype = rtype.upper()
    if rtype not in RULE_TYPES:
        return None

    if rtype in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}:
        value = value.lower()
    elif rtype in {"IP-CIDR", "IP-CIDR6"}:
        try:
            net = ipaddress.ip_network(value, strict=False)
            value = str(net)
            rtype = "IP-CIDR6" if net.version == 6 else "IP-CIDR"
        except ValueError:
            return None
    elif rtype == "IP-ASN":
        value = value.removeprefix("AS").strip()
        if not value.isdigit():
            return None

    return f"{rtype},{value}"


def dedupe_rules(rules: Iterable[str]) -> List[str]:
    seen: Set[Tuple[str, str]] = set()
    domain_suffixes: Set[str] = set()
    normalized: List[Tuple[str, str]] = []

    for line in rules:
        n = normalize_rule(line)
        if not n:
            continue
        rtype, value = n.split(",", 1)
        key = (rtype, value.lower() if rtype == "PROCESS-NAME" else value)
        if key in seen:
            continue
        seen.add(key)
        normalized.append((rtype, value))
        if rtype == "DOMAIN-SUFFIX":
            domain_suffixes.add(value)

    out: List[str] = []
    for rtype, value in normalized:
        if rtype == "DOMAIN":
            if any(value == s or value.endswith(f".{s}") for s in domain_suffixes):
                continue
        out.append(f"{rtype},{value}")
    return out


def apply_custom(rules: List[str], add_file: Optional[Path], del_file: Optional[Path]) -> List[str]:
    result = list(rules)
    if add_file and add_file.exists():
        result.extend(parse_plain_rules(add_file.read_text(encoding="utf-8")))

    if del_file and del_file.exists():
        del_items = {normalize_rule(x) for x in parse_plain_rules(del_file.read_text(encoding="utf-8"))}
        del_items.discard(None)
        result = [r for r in result if normalize_rule(r) not in del_items]

    return dedupe_rules(result)


def build_target(name: str, conf: Dict, globals_conf: Dict, repo_root: Path) -> None:
    timeout = int(globals_conf.get("request_timeout", 30))
    user_agent = str(globals_conf.get("user_agent", "OClash Rules Auto Builder/1.0"))
    retries = int(globals_conf.get("request_retries", 3))
    retry_backoff = float(globals_conf.get("request_retry_backoff_seconds", 1.5))

    output_list = conf.get("output_list")
    if output_list:
        all_rules: List[str] = []
        seeded_from_current_output = False

        if conf.get("seed_from_current_output"):
            seed_file = repo_root / output_list
            if seed_file.exists():
                all_rules.extend(parse_plain_rules(seed_file.read_text(encoding="utf-8")))
                seeded_from_current_output = True

        successful_sources = 0
        for src in conf.get("list_sources", []):
            try:
                text, used_url = fetch_text(
                    src,
                    timeout=timeout,
                    user_agent=user_agent,
                    retries=retries,
                    retry_backoff=retry_backoff,
                )
                parsed = parse_source(text, src["type"])
                all_rules.extend(parsed)
                successful_sources += 1
                print(
                    f"[OK] {name}: fetched {src.get('name', used_url)} via {used_url} ({len(parsed)} rules)"
                )
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, SourceFetchError) as exc:
                print(
                    f"[WARN] {name}: list source {src.get('name', '<unnamed>')} unavailable: {exc}",
                    file=sys.stderr,
                )

        if conf.get("list_sources") and successful_sources == 0 and not seeded_from_current_output:
            raise RuntimeError(
                f"{name}: no list source succeeded and no seeded {output_list} exists"
            )

        add_file = repo_root / conf["add_file"] if conf.get("add_file") else None
        del_file = repo_root / conf["del_file"] if conf.get("del_file") else None
        final_rules = apply_custom(all_rules, add_file, del_file)

        write_text_atomic(repo_root / output_list, "\n".join(final_rules) + "\n")
        print(f"[OK] {name}: wrote {output_list} ({len(final_rules)} rules)")

    output_mrs = conf.get("output_mrs")
    mrs_source = conf.get("mrs_source")
    if output_mrs and mrs_source and (mrs_source.get("url") or mrs_source.get("urls")):
        required = bool(mrs_source.get("required", True))
        preserve_existing = bool(mrs_source.get("preserve_existing_on_failure", False))
        output_path = repo_root / output_mrs

        try:
            data, used_url = fetch_bytes(
                mrs_source,
                timeout=timeout,
                user_agent=user_agent,
                retries=retries,
                retry_backoff=retry_backoff,
            )
            if not data:
                raise RuntimeError(f"{name}: empty mrs from {used_url}")
            write_bytes_atomic(output_path, data)
            print(f"[OK] {name}: wrote {output_mrs} ({len(data)} bytes) via {used_url}")
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError, SourceFetchError) as exc:
            if preserve_existing and output_path.exists() and output_path.stat().st_size > 0:
                print(
                    f"[WARN] {name}: failed to refresh {output_mrs}; keeping existing file: {exc}",
                    file=sys.stderr,
                )
            elif not required:
                print(
                    f"[WARN] {name}: optional mrs {output_mrs} unavailable: {exc}",
                    file=sys.stderr,
                )
            else:
                raise RuntimeError(f"{name}: failed to build {output_mrs}: {exc}") from exc


def load_config(path: Path) -> Dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Invalid config format")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Build OClash rule outputs")
    parser.add_argument("--config", default="rules-config.json")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    conf = load_config(root / args.config)

    globals_conf = conf.get("globals", {})
    targets = conf.get("targets", {})

    failed = []
    for name, tconf in targets.items():
        required = bool(tconf.get("required", True))
        try:
            build_target(name, tconf, globals_conf, root)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError, SourceFetchError) as exc:
            level = "ERR" if required else "WARN"
            print(f"[{level}] {name}: {exc}", file=sys.stderr)
            if required:
                failed.append(name)

    if failed:
        print(f"Build failed targets: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
