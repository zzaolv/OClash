#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


class SourceFetchError(RuntimeError):
    pass


REJECT_ACTIONS = {
    "reject": "reject",
    "reject-200": "reject-200",
    "reject-204": "reject-204",
    "reject-dict": "reject-dict",
    "reject-array": "reject-array",
    "reject-img": "reject-img",
    "reject-tinygif": "reject-tinygif",
    "reject-drop": "reject-drop",
    "reject-no-drop": "reject",
}

# PCRE features not supported by Rust's `regex` crate
UNSUPPORTED_RUST_REGEX_RE = re.compile(
    r"\(\?[=!]"          # (?=...) or (?!...)
    r"|\(\?<[=!]"        # (?<=...) or (?<!...)
    r"|\(\?>"            # atomic group (?>...)
    r"|(?<!\\)\\[1-9]"   # backreference \1 .. \9
)


def is_valid_rust_regex(pattern: str) -> bool:
    if not pattern or UNSUPPORTED_RUST_REGEX_RE.search(pattern):
        return False
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def try_simplify_lookaround_regex(pattern: str) -> Optional[str]:
    """
    Attempt safe simplifications for common PCRE patterns used in Surge/QX rules
    so they compile cleanly in Rust's `regex` crate.
    """
    if is_valid_rust_regex(pattern):
        return pattern

    cand = pattern
    # Common trailing `(?=$|&)` or `(?=&|$)` -> `(&|$)`
    cand = re.sub(r"\(\?=(?:\$\|&|&\|\$)\)", r"(&|$)", cand)
    # Common trailing `(?=\?)` -> `\?`
    cand = re.sub(r"\(\?=\\\?\)", r"\?", cand)
    # Common trailing `(?=/|$)` -> `(/|$)`
    cand = re.sub(r"\(\?=/\|\$\)", r"(/|$)", cand)

    if cand != pattern and is_valid_rust_regex(cand):
        return cand
    return None


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
        base_urls = [u for u in configured if isinstance(u, str) and u]
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
            except HTTPError as exc:
                last_error = exc
                print(
                    f"[WARN] fetch failed: {url} (attempt {attempt}/{retries}): {exc}",
                    file=sys.stderr,
                )
                if exc.code == 404:
                    break
                if attempt < retries and retry_backoff > 0:
                    time.sleep(retry_backoff * attempt)
            except (URLError, TimeoutError, OSError) as exc:
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


def tokenize_line(line: str) -> List[str]:
    """Matches adstop/src/rule/parser.rs `tokenize_line` exactly."""
    tokens: List[str] = []
    current: List[str] = []
    in_quotes = False
    quoted = False
    chars = list(line)
    i = 0
    n = len(chars)

    while i < n:
        ch = chars[i]
        if ch == '"':
            in_quotes = not in_quotes
            quoted = True
        elif ch in (" ", "\t") and not in_quotes:
            if current or quoted:
                tokens.append("".join(current))
                current = []
                quoted = False
        elif ch == "\\":
            if i + 1 < n and chars[i + 1] in ('"', "\\"):
                current.append(chars[i + 1])
                i += 1
            else:
                current.append("\\")
        elif (
            not in_quotes
            and ch in ("#", ";")
            and (i == 0 or chars[i - 1] in (" ", "\t"))
        ):
            break
        elif (
            not in_quotes
            and ch == "/"
            and i + 1 < n
            and chars[i + 1] == "/"
            and (i == 0 or chars[i - 1] in (" ", "\t"))
        ):
            break
        else:
            current.append(ch)
        i += 1

    if current or quoted:
        tokens.append("".join(current))

    return tokens


def format_token(token: str) -> str:
    r"""
    Exact inverse of `tokenize_line` in adstop/src/rule/parser.rs:
    - `tokenize_line` only unescapes `\\` -> `\` and `\"` -> `"`.
    - Quotes are only needed when token is empty, contains whitespace, or could trigger inline comment.
    """
    if token == "":
        return '""'
    needs_quotes = (
        any(c in token for c in (" ", "\t", "#", ";"))
        or token.startswith("//")
    )
    out: List[str] = []
    n = len(token)
    for i, ch in enumerate(token):
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            # In tokenize_line, `\` followed by `"` or `\` is consumed as an escape
            if i + 1 < n and token[i + 1] in ('"', "\\"):
                out.append("\\\\")
            elif needs_quotes and i + 1 == n:
                out.append("\\\\")
            else:
                out.append("\\")
        else:
            out.append(ch)
    escaped = "".join(out)
    return f'"{escaped}"' if needs_quotes else escaped


def split_params(s: str) -> List[Tuple[str, str]]:
    """Matches adstop/src/rule/parser.rs `split_params`."""
    segments: List[str] = []
    current: List[str] = []
    in_quotes = False
    for ch in s:
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == "," and not in_quotes:
            segments.append("".join(current))
            current = []
        else:
            current.append(ch)
    segments.append("".join(current))

    out: List[Tuple[str, str]] = []
    for seg in segments:
        stripped = seg.lstrip()
        kv = None
        if "=" in stripped:
            k, v = stripped.split("=", 1)
            k_clean = k.strip()
            if k_clean and all(c.isalnum() or c in ("-", "_") for c in k_clean):
                kv = (k_clean.lower(), v)
        if kv is not None:
            out.append(kv)
        elif out:
            prev_k, prev_v = out[-1]
            out[-1] = (prev_k, f"{prev_v},{seg}")
    return out


def param_value(params: List[Tuple[str, str]], key: str) -> Optional[str]:
    for k, v in params:
        if k == key:
            v = v.strip()
            # strip inline comments if unquoted
            if not (v.startswith('"') and v.endswith('"')):
                for comment_sep in (" #", " ;", " //", "\t#", "\t;", "\t//"):
                    idx = v.find(comment_sep)
                    if idx != -1:
                        v = v[:idx].strip()
            if len(v) >= 2 and v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            return v
    return None


def scan_kv(s: str) -> List[Tuple[str, str]]:
    """Matches adstop/src/rule/parser.rs `scan_kv` for [Map Local]."""
    out: List[Tuple[str, str]] = []
    n = len(s)
    i = 0
    while i < n:
        while i < n and s[i].isspace():
            i += 1
        if i >= n:
            break
        if s[i] in ("#", ";") or s[i : i + 2] == "//":
            break
        eq_pos = s.find("=", i)
        if eq_pos == -1:
            break
        key = s[i:eq_pos].strip().lower()
        i = eq_pos + 1
        if not key or any(c.isspace() for c in key):
            break
        if i < n and s[i] == '"':
            i += 1
            val_chars: List[str] = []
            while i < n:
                if s[i] == "\\" and i + 1 < n:
                    val_chars.append(s[i + 1])
                    i += 2
                elif s[i] == '"':
                    # Handle unescaped JSON quotes inside data="{"code":0}"
                    rest_after_quote = s[i + 1 :]
                    if (
                        key == "data"
                        and val_chars
                        and val_chars[0] == "{"
                        and not re.match(r"^\s*(?:$|status-code=|header=|data-type=|#|;|//)", rest_after_quote)
                    ):
                        val_chars.append('"')
                        i += 1
                        continue
                    i += 1
                    break
                else:
                    val_chars.append(s[i])
                    i += 1
            out.append((key, "".join(val_chars)))
        else:
            start = i
            while i < n and not s[i].isspace():
                i += 1
            out.append((key, s[start:i]))
    return out


def script_file_name(path: str) -> str:
    no_query = re.split(r"[?#]", path, maxsplit=1)[0]
    name = no_query.rsplit("/", 1)[-1]
    return name or "script.js"


@dataclass(frozen=True)
class ScriptRule:
    name: str
    kind: str  # "http-response" | "http-request"
    pattern: str
    script_path: str
    requires_body: bool = False
    timeout: int = 0
    max_size: int = 0
    argument: Optional[str] = None

    def format_surge(self, resolved_script_path: Optional[str] = None) -> str:
        spath = resolved_script_path or self.script_path
        safe_name = re.sub(r"[=,]+", "_", self.name).strip() or script_file_name(spath)
        parts = [
            f"{safe_name} = type={self.kind}",
            f'pattern="{self.pattern}"' if "," in self.pattern else f"pattern={self.pattern}",
            f"script-path={spath}",
        ]
        if self.requires_body:
            parts.append("requires-body=1")
        if self.max_size > 0:
            parts.append(f"max-size={self.max_size}")
        if self.timeout > 0:
            parts.append(f"timeout={self.timeout}")
        if self.argument is not None and self.argument != "":
            escaped_arg = self.argument.replace('"', '\\"')
            if "," in self.argument or " " in self.argument or '"' in self.argument:
                parts.append(f'argument="{escaped_arg}"')
            else:
                parts.append(f"argument={self.argument}")
        return ", ".join(parts)


@dataclass
class RuleCollector:
    # (rtype, value) where rtype in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
    domain_rules: List[Tuple[str, str]] = field(default_factory=list)
    # (pattern, target, rtype) where rtype in REJECT_ACTIONS or {"302", "307"}
    url_rewrites: List[Tuple[str, str, str]] = field(default_factory=list)
    # (pattern, op, header_name, header_val)
    header_rewrites: List[Tuple[str, str, str, str]] = field(default_factory=list)
    # (direction, pattern, find_regex, replace_str)
    body_rewrites: List[Tuple[str, str, str, str]] = field(default_factory=list)
    # (pattern, data_type, data, status_code, header)
    map_locals: List[Tuple[str, str, str, int, str]] = field(default_factory=list)
    # ScriptRule items
    scripts: List[ScriptRule] = field(default_factory=list)
    # MITM hostnames
    mitm_hosts: List[str] = field(default_factory=list)

    skipped_unsupported: int = 0
    skipped_invalid_regex: int = 0

    def add_regex_checked(self, pattern: str, allow_non_ascii: bool = False) -> Optional[str]:
        if not allow_non_ascii and any(ord(c) > 127 for c in pattern):
            self.skipped_invalid_regex += 1
            return None
        simplified = try_simplify_lookaround_regex(pattern)
        if simplified is None:
            self.skipped_invalid_regex += 1
            return None
        return simplified

    def parse_document(self, text: str) -> None:
        current_section = "none"
        for raw_line in text.splitlines():
            line = raw_line.strip().replace("\ufeff", "")
            if not line or line.startswith("#") or line.startswith(";") or line.startswith("//") or line.startswith("!"):
                continue

            if line.startswith("[") and line.endswith("]"):
                sec_name = line[1:-1].strip().lower()
                if sec_name in ("url rewrite",):
                    current_section = "url_rewrite"
                elif sec_name in ("rewrite",):
                    current_section = "rewrite"
                elif sec_name in ("header rewrite",):
                    current_section = "header_rewrite"
                elif sec_name in ("body rewrite",):
                    current_section = "body_rewrite"
                elif sec_name in ("rewrite_local",):
                    current_section = "rewrite_local"
                elif sec_name in ("mitm",):
                    current_section = "mitm"
                elif sec_name in ("map local", "map_local"):
                    current_section = "map_local"
                elif sec_name in ("script", "script_local"):
                    current_section = "script"
                elif sec_name in ("rule", "filter_local"):
                    current_section = "rule"
                else:
                    current_section = "unknown"
                continue

            if current_section == "unknown":
                continue

            if current_section == "mitm" or self._is_hostname_line(line):
                self._parse_mitm_line(line)
                continue

            if current_section == "rule":
                self._parse_domain_rule_line(line)
            elif current_section == "script":
                self._parse_script_line(line)
            elif current_section == "map_local":
                self._parse_map_local_line(line)
            elif current_section == "body_rewrite":
                self._parse_body_rewrite_section_line(line)
            elif current_section == "header_rewrite":
                self._parse_header_rewrite_section_line(line)
            elif current_section == "url_rewrite":
                self._parse_url_rewrite_section_line(line)
            elif current_section == "rewrite":
                self._parse_loon_rewrite_section_line(line)
            elif current_section == "rewrite_local":
                self._parse_quanx_rewrite_line(line)
            else:
                # Auto-detect outside sections
                self._parse_autodetect_line(line)

    @staticmethod
    def _is_hostname_line(line: str) -> bool:
        if "=" not in line:
            return False
        left, _ = line.split("=", 1)
        return left.strip().lower() == "hostname"

    def _parse_mitm_line(self, line: str) -> None:
        if "=" in line:
            left, right = line.split("=", 1)
            if left.strip().lower() != "hostname":
                return
            content = right
        else:
            content = line

        # Strip trailing comment if any
        for sep in (" #", " ;", " //", "\t#", "\t;", "\t//"):
            idx = content.find(sep)
            if idx != -1:
                content = content[:idx]

        for part in content.split(","):
            item = part.strip()
            while item.startswith("%"):
                if "% " in item:
                    item = item.split("% ", 1)[1].strip()
                else:
                    m = re.match(r"^%[A-Za-z0-9_]+%\s*(.*)$", item)
                    if m:
                        item = m.group(1).strip()
                    else:
                        break
            if not item:
                continue
            item = item.lower()
            if item.endswith("hostname") and len(item) > 8:
                item = item[:-8]
            # Validate basic hostname characters (allow leading '-', '*', '.', ':', alphanumeric, '-')
            if any(c.isspace() for c in item) or any(ord(c) > 127 for c in item):
                continue
            self.mitm_hosts.append(item)

    def _parse_domain_rule_line(self, line: str) -> None:
        # Strip inline comment
        for sep in (" //", " #", " ;", "\t//", "\t#", "\t;"):
            idx = line.find(sep)
            if idx != -1:
                line = line[:idx].strip()

        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            self.skipped_unsupported += 1
            return

        kind = parts[0].upper()
        if kind == "URL-REGEX":
            # In Surge [Rule], URL-REGEX may have commas inside the regex and optional quotes
            policy_Idx = len(parts) - 1
            # Sometimes trailing options like `no-resolve` or `extended-matching` exist; find REJECT policy
            reject_pol = None
            pattern_end = len(parts) - 1
            for i in range(len(parts) - 1, 1, -1):
                if parts[i].upper().startswith("REJECT"):
                    reject_pol = parts[i].upper()
                    pattern_end = i
                    break
            if not reject_pol:
                self.skipped_unsupported += 1
                return
            raw_pattern = ",".join(parts[1:pattern_end]).strip()
            if len(raw_pattern) >= 2 and raw_pattern[0] in ('"', "'") and raw_pattern[-1] == raw_pattern[0]:
                raw_pattern = raw_pattern[1:-1]
            checked = self.add_regex_checked(raw_pattern)
            if not checked:
                return
            rtype = self._map_reject_policy(reject_pol)
            self.url_rewrites.append((checked, "-", rtype))
            return

        mapped_kind = {
            "DOMAIN": "DOMAIN",
            "HOST": "DOMAIN",
            "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
            "HOST-SUFFIX": "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
            "HOST-KEYWORD": "DOMAIN-KEYWORD",
        }.get(kind)

        if not mapped_kind:
            self.skipped_unsupported += 1
            return

        if not parts[2].upper().startswith("REJECT"):
            self.skipped_unsupported += 1
            return

        value = parts[1].strip().lower()
        if mapped_kind == "DOMAIN-SUFFIX":
            value = value.lstrip(".")
        if not value:
            return
        self.domain_rules.append((mapped_kind, value))

    @staticmethod
    def _map_reject_policy(policy: str) -> str:
        p = policy.strip().lower()
        if p in REJECT_ACTIONS:
            return REJECT_ACTIONS[p]
        if p.startswith("reject"):
            return "reject"
        return "reject"

    def _parse_script_line(self, line: str) -> None:
        first = line.split(None, 1)[0].lower() if line.split(None, 1) else ""
        if first in ("http-response", "http-request"):
            # Loon style: http-response <pattern> script-path=..., requires-body=1, tag=...
            rest = line[len(first) :].lstrip()
            parts = rest.split(None, 1)
            if len(parts) < 2:
                return
            pattern, param_str = parts[0].strip('"'), parts[1]
            params = split_params(param_str)
            name = param_value(params, "tag") or ""
            kind = first
        elif first in ("cron", "generic", "network-changed", "event", "dns"):
            self.skipped_unsupported += 1
            return
        else:
            if "=" not in line:
                return
            name_part, param_str = line.split("=", 1)
            params = split_params(param_str)
            kind = (param_value(params, "type") or "").lower()
            if kind not in ("http-response", "http-request"):
                self.skipped_unsupported += 1
                return
            pattern_opt = param_value(params, "pattern")
            if not pattern_opt:
                return
            pattern = pattern_opt
            name = name_part.strip()

        script_path = param_value(params, "script-path")
        if not script_path:
            return

        checked_pattern = self.add_regex_checked(pattern)
        if not checked_pattern:
            return

        if not name:
            name = script_file_name(script_path)

        req_body_val = (param_value(params, "requires-body") or "").lower()
        requires_body = req_body_val in ("1", "true")

        timeout_s = 0
        timeout_val = param_value(params, "timeout")
        if timeout_val:
            try:
                t_float = float(timeout_val)
                if t_float > 0:
                    timeout_s = max(1, int(round(t_float)))
            except ValueError:
                pass

        max_size = 0
        max_size_val = param_value(params, "max-size")
        if max_size_val and max_size_val.isdigit():
            max_size = int(max_size_val)

        argument = param_value(params, "argument")

        self.scripts.append(
            ScriptRule(
                name=name,
                kind=kind,
                pattern=checked_pattern,
                script_path=script_path,
                requires_body=requires_body,
                timeout=timeout_s,
                max_size=max_size,
                argument=argument,
            )
        )

    def _parse_map_local_line(self, line: str) -> None:
        parts = line.split(None, 1)
        if len(parts) < 2:
            return
        pattern, rest = parts[0], parts[1]
        params = dict(scan_kv(rest))
        data_type = params.get("data-type", "text").lower()
        data = params.get("data")

        if data_type == "tiny-gif":
            data_str = ""
        elif data_type in ("gif", "base64"):
            if not data:
                if data_type == "gif":
                    data_str = ""
                else:
                    return
            elif data.startswith(("http://", "https://", "file://", "/")):
                self.skipped_unsupported += 1
                return
            else:
                data_str = data
        elif data_type in ("text", "json"):
            if data is None:
                return
            if data.startswith(("http://", "https://", "file://", "/")):
                self.skipped_unsupported += 1
                return
            data_str = data
        else:
            self.skipped_unsupported += 1
            return

        status_code = 200
        if "status-code" in params:
            try:
                status_code = int(params["status-code"])
            except ValueError:
                return

        header = params.get("header", "")
        checked = self.add_regex_checked(pattern)
        if not checked:
            return

        self.map_locals.append((checked, data_type, data_str, status_code, header))

    def _parse_body_rewrite_section_line(self, line: str) -> None:
        tokens = tokenize_line(line)
        if len(tokens) < 2:
            return

        first = tokens[0].lower()
        if first in ("http-response-jq", "http-request-jq"):
            self.skipped_unsupported += 1
            return

        if first in ("http-response", "http-request"):
            # Surge 5 format: http-response <url_regex> <find> <replace> [<find> <replace> ...]
            if len(tokens) < 4 or len(tokens) % 2 == 1:
                return
            checked_url = self.add_regex_checked(tokens[1])
            if not checked_url:
                return
            for i in range(2, len(tokens), 2):
                find_pat = tokens[i]
                rep_str = tokens[i + 1]
                if rep_str.lower() in ("response-body", "request-body", "response-body-regex", "request-body-regex"):
                    self.skipped_unsupported += 1
                    continue
                checked_find = self.add_regex_checked(find_pat, allow_non_ascii=True)
                if not checked_find:
                    continue
                self.body_rewrites.append((first, checked_url, checked_find, rep_str))
            return

        # Older Surge format: <url_regex> [response-body] <find> <replace>
        checked_url = self.add_regex_checked(tokens[0])
        if not checked_url:
            return
        rest = tokens[1:]
        if rest[0].lower() == "response-body" and len(rest) >= 3:
            find_pat = rest[1]
            rep_tokens = rest[2:]
            if rep_tokens and rep_tokens[0].lower() == "response-body":
                rep_tokens = rep_tokens[1:]
            if not rep_tokens:
                return
            rep_str = " ".join(rep_tokens)
        elif len(rest) >= 2:
            find_pat, rep_str = rest[0], " ".join(rest[1:])
        else:
            return
        if rep_str.lower() in ("response-body", "request-body"):
            self.skipped_unsupported += 1
            return
        checked_find = self.add_regex_checked(find_pat, allow_non_ascii=True)
        if not checked_find:
            return
        self.body_rewrites.append(("http-response", checked_url, checked_find, rep_str))

    def _parse_header_rewrite_section_line(self, line: str) -> None:
        tokens = tokenize_line(line)
        if len(tokens) < 3:
            return

        first = tokens[0].lower()
        # Handle Surge 5 `http-request <pattern> header-del <name>` and `http-response <pattern> header-add <name> <val>`
        if first in ("http-request", "http-response"):
            if len(tokens) < 4:
                return
            prefix = "request" if first == "http-request" else "response"
            pattern = tokens[1]
            raw_op = tokens[2].lower()
            rest = tokens[3:]
            if raw_op in ("header-del", "request-header-del", "response-header-del"):
                op = f"{prefix}-header-del"
                header_name = rest[0]
                header_val = ""
            elif raw_op in ("header-add", "request-header-add", "response-header-add") and len(rest) >= 2:
                op = f"{prefix}-header-add"
                header_name = rest[0]
                header_val = " ".join(rest[1:])
            elif raw_op in ("header-replace", "request-header-replace", "response-header-replace") and len(rest) >= 2:
                op = f"{prefix}-header-replace"
                header_name = rest[0]
                header_val = " ".join(rest[1:])
            else:
                self.skipped_unsupported += 1
                return
        else:
            pattern = tokens[0]
            raw_op = tokens[1].lower()
            rest = tokens[2:]
            if raw_op in ("request-header-del", "header-del"):
                op = "request-header-del"
                header_name = rest[0]
                header_val = ""
            elif raw_op in ("request-header-add", "header-add") and len(rest) >= 2:
                op = "request-header-add"
                header_name = rest[0]
                header_val = " ".join(rest[1:])
            elif raw_op in ("request-header-replace", "header-replace") and len(rest) >= 2:
                op = "request-header-replace"
                header_name = rest[0]
                header_val = " ".join(rest[1:])
            elif raw_op == "response-header-del":
                op = "response-header-del"
                header_name = rest[0]
                header_val = ""
            elif raw_op == "response-header-add" and len(rest) >= 2:
                op = "response-header-add"
                header_name = rest[0]
                header_val = " ".join(rest[1:])
            elif raw_op == "response-header-replace" and len(rest) >= 2:
                op = "response-header-replace"
                header_name = rest[0]
                header_val = " ".join(rest[1:])
            else:
                self.skipped_unsupported += 1
                return

        checked = self.add_regex_checked(pattern)
        if not checked:
            return
        header_name = header_name.strip().strip("'").strip('"')
        header_val = header_val.strip().strip("'").strip('"')
        self.header_rewrites.append((checked, op, header_name, header_val))

    def _parse_url_rewrite_section_line(self, line: str, allow_fallback: bool = True) -> None:
        tokens = tokenize_line(line)
        if len(tokens) < 2:
            return
        pattern = tokens[0]
        rest = tokens[1:]

        if len(rest) == 1:
            act = rest[0].lower()
            if act in REJECT_ACTIONS:
                checked = self.add_regex_checked(pattern)
                if checked:
                    self.url_rewrites.append((checked, "-", REJECT_ACTIONS[act]))
                return
        elif len(rest) == 2:
            target, kind = rest[0], rest[1].lower()
            if kind in ("302", "307", "header") and target.startswith(("http://", "https://")):
                checked = self.add_regex_checked(pattern)
                if checked:
                    norm_kind = "302" if kind == "header" else kind
                    self.url_rewrites.append((checked, target, norm_kind))
                return
            if kind in REJECT_ACTIONS:
                checked = self.add_regex_checked(pattern)
                if checked:
                    self.url_rewrites.append((checked, "-", REJECT_ACTIONS[kind]))
                return

        if allow_fallback:
            self._parse_autodetect_line(line, from_url_rewrite=True)
        else:
            self.skipped_unsupported += 1

    def _parse_loon_rewrite_section_line(self, line: str, allow_fallback: bool = True) -> None:
        tokens = tokenize_line(line)
        if len(tokens) < 2:
            return
        pattern = tokens[0]
        rest = tokens[1:]
        kw = rest[0].lower()

        if kw in REJECT_ACTIONS and len(rest) == 1:
            checked = self.add_regex_checked(pattern)
            if checked:
                self.url_rewrites.append((checked, "-", REJECT_ACTIONS[kw]))
            return
        if kw in ("302", "307") and len(rest) == 2 and rest[1].startswith(("http://", "https://")):
            checked = self.add_regex_checked(pattern)
            if checked:
                self.url_rewrites.append((checked, rest[1], kw))
            return
        if kw.startswith(("header-", "request-header-", "response-header-")):
            self._parse_header_rewrite_section_line(line)
            return
        if kw == "response-body" and len(rest) >= 3:
            self._parse_body_rewrite_section_line(line)
            return
        if kw.startswith(("response-body-json-", "request-body-json-", "echo-response", "mock-response-body")):
            self.skipped_unsupported += 1
            return

        if allow_fallback:
            self._parse_url_rewrite_section_line(line, allow_fallback=False)
        else:
            self.skipped_unsupported += 1

    def _parse_quanx_rewrite_line(self, line: str) -> None:
        tokens = tokenize_line(line)
        if len(tokens) < 2:
            return
        pattern = tokens[0]
        rest = tokens[1:]
        if rest[0].lower() == "url":
            rest = rest[1:]
        if not rest:
            return

        act = rest[0].lower()
        if act in REJECT_ACTIONS:
            checked = self.add_regex_checked(pattern)
            if checked:
                self.url_rewrites.append((checked, "-", REJECT_ACTIONS[act]))
            return

        if act in ("302", "307") and len(rest) >= 2 and rest[1].startswith(("http://", "https://")):
            checked = self.add_regex_checked(pattern)
            if checked:
                self.url_rewrites.append((checked, rest[1], act))
            return

        if act in ("response-body", "response-body-regex", "request-body", "request-body-regex") and len(rest) >= 3:
            checked_url = self.add_regex_checked(pattern)
            if not checked_url:
                return
            find_pat = rest[1]
            rep_tokens = rest[2:]
            if rep_tokens and rep_tokens[0].lower() in (
                "response-body",
                "response-body-regex",
                "request-body",
                "request-body-regex",
            ):
                rep_tokens = rep_tokens[1:]
            if not rep_tokens:
                return
            rep_str = " ".join(rep_tokens)
            checked_find = self.add_regex_checked(find_pat, allow_non_ascii=True)
            if not checked_find:
                return
            direction = "http-response" if act.startswith("response") else "http-request"
            self.body_rewrites.append((direction, checked_url, checked_find, rep_str))
            return

        if act in (
            "script-response-body",
            "script-request-body",
            "script-response-header",
            "script-request-header",
        ) and len(rest) >= 2:
            checked_url = self.add_regex_checked(pattern)
            if not checked_url:
                return
            script_path = rest[1]
            kind = "http-response" if "response" in act else "http-request"
            requires_body = act.endswith("-body")
            self.scripts.append(
                ScriptRule(
                    name=script_file_name(script_path),
                    kind=kind,
                    pattern=checked_url,
                    script_path=script_path,
                    requires_body=requires_body,
                )
            )
            return

        if act in ("request-header", "response-header") and len(rest) >= 3:
            # Check if QX regex header deletion: e.g. `(\r\n)If-None-Match:.+(\r\n) request-header $1`
            # or setting empty value `(\r\n)Cookie:.+(\r\n) request-header $1Cookie:$2`
            raw_find = rest[1]
            raw_rep = " ".join(rest[2:])
            prefix = "request" if act == "request-header" else "response"
            m = re.match(r"^\(\\r\\n\)([A-Za-z0-9_-]+):\.\+\(\\r\\n\)$", raw_find)
            if m:
                h_name = m.group(1)
                if raw_rep in (
                    f"{act} $1$2",
                    f"{act} $1",
                    f"{act} $1{h_name}:$2",
                    "$1$2",
                    "$1",
                ):
                    checked_url = self.add_regex_checked(pattern)
                    if checked_url:
                        self.header_rewrites.append((checked_url, f"{prefix}-header-del", h_name, ""))
                    return
            self.skipped_unsupported += 1
            return

        self.skipped_unsupported += 1

    def _parse_autodetect_line(self, line: str, from_url_rewrite: bool = False) -> None:
        if re.match(
            r"^(?:DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|HOST|HOST-SUFFIX|HOST-KEYWORD|IP-CIDR|IP-CIDR6|IP-ASN|GEOIP|USER-AGENT|URL-REGEX)\s*,",
            line,
            re.IGNORECASE,
        ):
            self._parse_domain_rule_line(line)
            return
        tokens = tokenize_line(line)
        if len(tokens) < 2:
            return
        if tokens[1].lower() == "url":
            self._parse_quanx_rewrite_line(line)
        elif tokens[0].lower() in ("http-response", "http-request"):
            self._parse_body_rewrite_section_line(line)
        elif tokens[1].lower() == "response-body":
            self._parse_body_rewrite_section_line(line)
        else:
            self._parse_loon_rewrite_section_line(line, allow_fallback=not from_url_rewrite)


def parse_del_patterns(del_file: Optional[Path]) -> Tuple[Set[str], List[re.Pattern]]:
    substrings: Set[str] = set()
    regexes: List[re.Pattern] = []
    if not del_file or not del_file.exists():
        return substrings, regexes

    for raw in del_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip().replace("\ufeff", "")
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if len(line) >= 2 and line.startswith("/") and line.endswith("/"):
            try:
                regexes.append(re.compile(line[1:-1], re.IGNORECASE))
            except re.error:
                pass
        else:
            substrings.add(line.lower())
    return substrings, regexes


def is_excluded(text: str, substrings: Set[str], regexes: List[re.Pattern]) -> bool:
    low = text.lower()
    if any(sub in low for sub in substrings):
        return True
    if any(rx.search(text) for rx in regexes):
        return True
    return False


def dedupe_and_filter(
    collector: RuleCollector,
    del_substrings: Set[str],
    del_regexes: List[re.Pattern],
) -> RuleCollector:
    out = RuleCollector(
        skipped_unsupported=collector.skipped_unsupported,
        skipped_invalid_regex=collector.skipped_invalid_regex,
    )

    # 1. Domain rules: deduplicate & prune subdomains covered by DOMAIN-SUFFIX
    seen_domains: Set[Tuple[str, str]] = set()
    suffixes: Set[str] = set()
    temp_domains: List[Tuple[str, str]] = []
    for rtype, val in collector.domain_rules:
        line_repr = f"{rtype},{val},REJECT"
        if is_excluded(line_repr, del_substrings, del_regexes):
            continue
        key = (rtype, val)
        if key in seen_domains:
            continue
        seen_domains.add(key)
        temp_domains.append(key)
        if rtype == "DOMAIN-SUFFIX":
            suffixes.add(val)

    for rtype, val in temp_domains:
        if rtype == "DOMAIN":
            if any(val == s or val.endswith(f".{s}") for s in suffixes):
                continue
        elif rtype == "DOMAIN-SUFFIX":
            if any(val != s and val.endswith(f".{s}") for s in suffixes):
                continue
        out.domain_rules.append((rtype, val))

    # 2. URL Rewrites: deduplicate by pattern, preferring more specific reject types over plain `reject`
    # Priority: 302/307 > reject-dict/reject-array/reject-img/reject-200/reject-204 > reject
    def url_action_priority(target: str, rtype: str) -> int:
        if rtype in ("302", "307"):
            return 3
        if rtype in ("reject-dict", "reject-array", "reject-img", "reject-tinygif", "reject-200", "reject-204"):
            return 2
        return 1

    url_by_pattern: Dict[str, Tuple[str, str, str]] = {}
    for pattern, target, rtype in collector.url_rewrites:
        line_repr = f"{pattern} {target} {rtype}"
        if is_excluded(line_repr, del_substrings, del_regexes):
            continue
        existing = url_by_pattern.get(pattern)
        if existing is None or url_action_priority(target, rtype) > url_action_priority(existing[1], existing[2]):
            url_by_pattern[pattern] = (pattern, target, rtype)
    out.url_rewrites = list(url_by_pattern.values())

    # 3. Header Rewrites: deduplicate by (pattern, op, header_name.lower(), header_val)
    seen_headers: Set[Tuple[str, str, str, str]] = set()
    for pattern, op, hname, hval in collector.header_rewrites:
        line_repr = f"{pattern} {op} {hname} {hval}".strip()
        if is_excluded(line_repr, del_substrings, del_regexes):
            continue
        key = (pattern, op, hname.lower(), hval)
        if key not in seen_headers:
            seen_headers.add(key)
            out.header_rewrites.append((pattern, op, hname, hval))

    # 4. Body Rewrites: deduplicate by (direction, pattern, find, replace)
    seen_bodies: Set[Tuple[str, str, str, str]] = set()
    for direction, pattern, find_pat, rep_str in collector.body_rewrites:
        line_repr = f"{direction} {pattern} {find_pat} {rep_str}"
        if is_excluded(line_repr, del_substrings, del_regexes):
            continue
        key = (direction, pattern, find_pat, rep_str)
        if key not in seen_bodies:
            seen_bodies.add(key)
            out.body_rewrites.append(key)

    # 5. Map Local: deduplicate by pattern
    seen_map_local: Set[str] = set()
    for item in collector.map_locals:
        pattern, data_type, data_str, status_code, header = item
        line_repr = f'{pattern} data-type={data_type} data="{data_str}"'
        if is_excluded(line_repr, del_substrings, del_regexes):
            continue
        if pattern not in seen_map_local:
            seen_map_local.add(pattern)
            out.map_locals.append(item)

    # 6. Scripts: deduplicate by (kind, pattern, script_path)
    seen_scripts: Dict[Tuple[str, str, str], ScriptRule] = {}
    for s in collector.scripts:
        line_repr = s.format_surge()
        if is_excluded(line_repr, del_substrings, del_regexes):
            continue
        key = (s.kind, s.pattern, s.script_path)
        existing = seen_scripts.get(key)
        if existing is None:
            seen_scripts[key] = s
        else:
            # Prefer entry that has argument/timeout/requires_body
            if (s.argument and not existing.argument) or (s.requires_body and not existing.requires_body):
                seen_scripts[key] = s
    out.scripts = list(seen_scripts.values())

    # 7. MITM Hostnames: deduplicate & filter exclusions
    seen_hosts: Set[str] = set()
    neg_hosts: List[str] = []
    pos_hosts: List[str] = []
    for h in collector.mitm_hosts:
        if is_excluded(h, del_substrings, del_regexes):
            continue
        if h in seen_hosts:
            continue
        seen_hosts.add(h)
        if h.startswith("-"):
            neg_hosts.append(h)
        else:
            pos_hosts.append(h)
    out.mitm_hosts = neg_hosts + pos_hosts

    return out


def mirror_scripts(
    scripts: List[ScriptRule],
    scripts_out_dir: Path,
    mirror_base_url: str,
    seed_scripts_dir: Optional[Path],
    timeout: int,
    user_agent: str,
    retries: int,
    retry_backoff: float,
) -> Tuple[Dict[str, str], int, int]:
    """
    Download and mirror referenced JS scripts into `scripts_out_dir`.
    Returns (url_to_mirrored_url_map, mirrored_count, fallback_count).
    """
    scripts_out_dir.mkdir(parents=True, exist_ok=True)
    unique_urls: List[str] = []
    seen_u: Set[str] = set()
    for s in scripts:
        if s.script_path.startswith(("http://", "https://")) and s.script_path not in seen_u:
            seen_u.add(s.script_path)
            unique_urls.append(s.script_path)

    used_filenames: Dict[str, str] = {}  # filename -> sha256
    url_map: Dict[str, str] = {}
    mirrored_ok = 0
    fallback_cnt = 0

    def _download_one(url: str) -> Tuple[str, str, Optional[bytes]]:
        base_name = script_file_name(url)
        if not base_name.endswith(".js"):
            base_name = f"{base_name}.js"
        base_name = re.sub(r"[^A-Za-z0-9._-]", "_", base_name)
        try:
            data, _ = fetch_bytes(
                {"url": url},
                timeout=timeout,
                user_agent=user_agent,
                retries=retries,
                retry_backoff=retry_backoff,
            )
            return url, base_name, data
        except SourceFetchError as exc:
            print(f"[WARN] script mirror fetch failed for {url}: {exc}", file=sys.stderr)
            if seed_scripts_dir and (seed_scripts_dir / base_name).exists():
                return url, base_name, (seed_scripts_dir / base_name).read_bytes()
            return url, base_name, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_download_one, unique_urls))

    for url, base_name, data in results:
        if not data:
            fallback_cnt += 1
            continue

        sha = hashlib.sha256(data).hexdigest()[:8]
        final_name = base_name
        if final_name in used_filenames and used_filenames[final_name] != sha:
            stem = final_name[:-3] if final_name.endswith(".js") else final_name
            final_name = f"{stem}-{sha}.js"
        used_filenames[final_name] = sha

        write_bytes_atomic(scripts_out_dir / final_name, data)
        if mirror_base_url:
            url_map[url] = f"{mirror_base_url.rstrip('/')}/{final_name}"
        else:
            url_map[url] = url
        mirrored_ok += 1

    return url_map, mirrored_ok, fallback_cnt


def render_sgmodule(
    collector: RuleCollector,
    url_map: Dict[str, str],
    source_names: List[str],
) -> str:
    now_str = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S CST")
    total_rewrites = (
        len(collector.url_rewrites)
        + len(collector.header_rewrites)
        + len(collector.body_rewrites)
        + len(collector.map_locals)
        + len(collector.scripts)
    )

    lines: List[str] = [
        "#!name=OClash AdStop Merged Rules",
        f"#!desc=AdStop 去广告重写/脚本/MITM 聚合模块 | 更新时间: {now_str} | 重写与脚本: {total_rewrites} 条 | 域名规则: {len(collector.domain_rules)} 条 | MITM 域名: {len(collector.mitm_hosts)} 个",
        f"# Upstream sources ({len(source_names)}): {', '.join(source_names)}",
        "",
    ]

    if collector.domain_rules:
        lines.append("[Rule]")
        for rtype, val in collector.domain_rules:
            lines.append(f"{rtype},{val},REJECT")
        lines.append("")

    if collector.url_rewrites:
        lines.append("[URL Rewrite]")
        for pattern, target, rtype in collector.url_rewrites:
            lines.append(f"{format_token(pattern)} {format_token(target)} {rtype}")
        lines.append("")

    if collector.header_rewrites:
        lines.append("[Header Rewrite]")
        for pattern, op, hname, hval in collector.header_rewrites:
            if hval:
                lines.append(f"{format_token(pattern)} {op} {format_token(hname)} {format_token(hval)}")
            else:
                lines.append(f"{format_token(pattern)} {op} {format_token(hname)}")
        lines.append("")

    if collector.body_rewrites:
        lines.append("[Body Rewrite]")
        for direction, pattern, find_pat, rep_str in collector.body_rewrites:
            lines.append(
                f"{direction} {format_token(pattern)} {format_token(find_pat)} {format_token(rep_str)}"
            )
        lines.append("")

    if collector.map_locals:
        lines.append("[Map Local]")
        for pattern, data_type, data_str, status_code, header in collector.map_locals:
            parts = [pattern, f"data-type={data_type}"]
            if data_type != "tiny-gif" and (data_str or data_type in ("text", "json")):
                escaped_data = data_str.replace("\\", "\\\\").replace('"', '\\"')
                parts.append(f'data="{escaped_data}"')
            if status_code != 200:
                parts.append(f"status-code={status_code}")
            if header:
                escaped_hdr = header.replace("\\", "\\\\").replace('"', '\\"')
                parts.append(f'header="{escaped_hdr}"')
            lines.append(" ".join(parts))
        lines.append("")

    if collector.scripts:
        lines.append("[Script]")
        for s in collector.scripts:
            resolved = url_map.get(s.script_path, s.script_path)
            lines.append(s.format_surge(resolved))
        lines.append("")

    if collector.mitm_hosts:
        lines.append("[MITM]")
        lines.append(f"hostname = %APPEND% {', '.join(collector.mitm_hosts)}")
        lines.append("")

    return "\n".join(lines)


def validate_output_sgmodule(text: str) -> None:
    """
    Verify that the rendered .sgmodule has 0 skipped and 0 unsupported lines
    according to AdStop's RuleParser (adstop/src/rule/parser.rs).
    """
    check = RuleCollector()
    check.parse_document(text)
    if check.skipped_unsupported > 0 or check.skipped_invalid_regex > 0:
        raise RuntimeError(
            f"Generated sgmodule failed self-validation: "
            f"skipped_unsupported={check.skipped_unsupported}, "
            f"skipped_invalid_regex={check.skipped_invalid_regex}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build OClash AdStop merged sgmodule and mirror scripts")
    parser.add_argument("--config", default="adstop/sources.json", help="Path to sources.json")
    parser.add_argument("--output-dir", default="dist/adstop", help="Output directory for adstop.sgmodule and scripts/")
    parser.add_argument("--seed-scripts-dir", default="", help="Optional directory of previously mirrored scripts")
    parser.add_argument("--no-mirror-scripts", action="store_true", help="Skip downloading and mirroring JS scripts")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    conf_path = repo_root / args.config
    conf = json.loads(conf_path.read_text(encoding="utf-8"))

    globals_conf = conf.get("globals", {})
    timeout = int(globals_conf.get("request_timeout", 30))
    user_agent = str(globals_conf.get("user_agent", "OClash AdStop Rules Auto Builder/1.0"))
    retries = int(globals_conf.get("request_retries", 3))
    retry_backoff = float(globals_conf.get("request_retry_backoff_seconds", 1.5))
    mirror_base_url = str(globals_conf.get("script_mirror_base_url", ""))

    collector = RuleCollector()
    successful_sources: List[str] = []
    failed_required: List[str] = []

    for src in conf.get("sources", []):
        name = src.get("name", src.get("url", "<unnamed>"))
        required = bool(src.get("required", False))
        try:
            text, used_url = fetch_text(
                src,
                timeout=timeout,
                user_agent=user_agent,
                retries=retries,
                retry_backoff=retry_backoff,
            )
            before_counts = (
                len(collector.domain_rules),
                len(collector.url_rewrites),
                len(collector.header_rewrites),
                len(collector.body_rewrites),
                len(collector.map_locals),
                len(collector.scripts),
                len(collector.mitm_hosts),
            )
            collector.parse_document(text)
            after_counts = (
                len(collector.domain_rules),
                len(collector.url_rewrites),
                len(collector.header_rewrites),
                len(collector.body_rewrites),
                len(collector.map_locals),
                len(collector.scripts),
                len(collector.mitm_hosts),
            )
            deltas = [a - b for a, b in zip(after_counts, before_counts)]
            successful_sources.append(name)
            print(
                f"[OK] {name}: domain={deltas[0]}, url={deltas[1]}, header={deltas[2]}, "
                f"body={deltas[3]}, map_local={deltas[4]}, script={deltas[5]}, mitm={deltas[6]}"
            )
        except Exception as exc:
            level = "ERR" if required else "WARN"
            print(f"[{level}] {name}: {exc}", file=sys.stderr)
            if required:
                failed_required.append(name)

    if failed_required or not successful_sources:
        print(f"Failed required sources: {failed_required}", file=sys.stderr)
        return 1

    # Apply custom additions
    add_file = repo_root / globals_conf["add_file"] if globals_conf.get("add_file") else None
    if add_file and add_file.exists():
        collector.parse_document(add_file.read_text(encoding="utf-8"))

    # Deduplicate and apply custom deletions
    del_file = repo_root / globals_conf["del_file"] if globals_conf.get("del_file") else None
    del_substrings, del_regexes = parse_del_patterns(del_file)
    final_collector = dedupe_and_filter(collector, del_substrings, del_regexes)

    out_dir = repo_root / args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    seed_dir = Path(args.seed_scripts_dir) if args.seed_scripts_dir else None

    if args.no_mirror_scripts:
        url_map = {s.script_path: s.script_path for s in final_collector.scripts}
        mirrored_ok = 0
        fallback_cnt = 0
    else:
        url_map, mirrored_ok, fallback_cnt = mirror_scripts(
            final_collector.scripts,
            scripts_out_dir=out_dir / "scripts",
            mirror_base_url=mirror_base_url,
            seed_scripts_dir=seed_dir,
            timeout=timeout,
            user_agent=user_agent,
            retries=retries,
            retry_backoff=retry_backoff,
        )
        # Drop any script rules whose remote script was 404/unreachable
        final_collector.scripts = [s for s in final_collector.scripts if s.script_path in url_map]

    sgmodule_text = render_sgmodule(final_collector, url_map, successful_sources)
    validate_output_sgmodule(sgmodule_text)
    output_file = out_dir / "adstop.sgmodule"
    write_text_atomic(output_file, sgmodule_text)

    stats = {
        "sources_ok": len(successful_sources),
        "domain_rules": len(final_collector.domain_rules),
        "url_rewrites": len(final_collector.url_rewrites),
        "header_rewrites": len(final_collector.header_rewrites),
        "body_rewrites": len(final_collector.body_rewrites),
        "map_locals": len(final_collector.map_locals),
        "scripts": len(final_collector.scripts),
        "mitm_hosts": len(final_collector.mitm_hosts),
        "mirrored_scripts": mirrored_ok,
        "fallback_scripts": fallback_cnt,
        "skipped_unsupported": final_collector.skipped_unsupported,
        "skipped_invalid_regex": final_collector.skipped_invalid_regex,
    }
    write_text_atomic(out_dir / "stats.json", json.dumps(stats, ensure_ascii=False, indent=2) + "\n")
    print(f"[OK] Wrote {output_file} -> {json.dumps(stats, ensure_ascii=False)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
