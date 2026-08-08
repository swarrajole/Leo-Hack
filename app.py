from __future__ import annotations

import os
import re
import socket
import ssl
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", "change-this-secret-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{INSTANCE_DIR / 'security_command_center.db'}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "show_login"
login_manager.init_app(app)

SIGNAL_LIBRARY: List[Dict[str, object]] = [
    {
        "label": "Credential Attack",
        "tokens": ["failed login", "password spray", "invalid password", "account locked"],
        "weight": 18,
        "finding": "Authentication telemetry suggests credential abuse.",
        "response": "Enable MFA, rate limiting, and geo-anomaly alerts.",
    },
    {
        "label": "SQL Injection",
        "tokens": ["union select", "or 1=1", "information_schema", "drop table"],
        "weight": 28,
        "finding": "Input pattern matches common SQL injection probes.",
        "response": "Inspect application logs, parameterize queries, and tighten WAF rules.",
    },
    {
        "label": "Command Injection",
        "tokens": ["cmd=", "powershell", "bash -c", "; cat /etc/passwd"],
        "weight": 26,
        "finding": "Payload includes command execution indicators.",
        "response": "Review server-side input handling and isolate impacted service nodes.",
    },
    {
        "label": "Reconnaissance",
        "tokens": ["nmap", "masscan", "banner grab", "whatweb"],
        "weight": 16,
        "finding": "Reconnaissance behavior is present in the event stream.",
        "response": "Throttle source IPs and review perimeter exposure.",
    },
    {
        "label": "Web Exploitation",
        "tokens": ["<script>", "xss", "../../", "/etc/passwd"],
        "weight": 18,
        "finding": "Web request contains traversal or script-injection indicators.",
        "response": "Validate request encoding, harden templates, and add payload sanitization.",
    },
    {
        "label": "Obfuscation",
        "tokens": ["base64", "fromcharcode", "invoke-expression", "certutil"],
        "weight": 14,
        "finding": "The content shows signs of encoded or obfuscated execution.",
        "response": "Decode samples in a sandbox and increase endpoint telemetry capture.",
    },
]

EVENT_BASELINES = {
    "auth": 10,
    "network": 12,
    "endpoint": 14,
    "web": 12,
    "cloud": 11,
    "email": 10,
    "general": 6,
}

IOC_PATTERNS: Dict[str, str] = {
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "url": r"\bhttps?://[^\s'\"<>]+",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
}

TACTIC_HINTS: Dict[str, List[str]] = {
    "Credential Attack": ["Credential Access", "Initial Access"],
    "SQL Injection": ["Initial Access", "Execution"],
    "Command Injection": ["Execution", "Privilege Escalation"],
    "Reconnaissance": ["Reconnaissance"],
    "Web Exploitation": ["Initial Access"],
    "Obfuscation": ["Defense Evasion"],
}

ATTACK_KNOWLEDGE_BASE: List[Dict[str, object]] = [
    {
        "name": "Phishing",
        "summary": "A social engineering attack that tricks users into revealing credentials or running malicious actions.",
        "warning_signs": [
            "Urgent language asking for immediate action",
            "Sender/domain mismatch",
            "Unexpected attachment or login link",
            "Requests for OTP, password, or banking details",
        ],
        "example_patterns": [
            "Email subject style: 'Action Required: Account Suspension Notice'",
            "URL pattern check: login-company-security.example instead of the official domain",
            "Credential-harvesting indicator: link redirects through unrelated tracking hosts",
        ],
        "defenses": [
            "Enable MFA for all user accounts",
            "Use DMARC, SPF, and DKIM",
            "Run user awareness drills with simulated phishing",
            "Deploy secure email gateway with URL rewriting/sandboxing",
        ],
    },
    {
        "name": "SQL Injection",
        "summary": "Malicious input attempts to alter SQL query behavior and access or modify database content.",
        "warning_signs": [
            "Requests containing SQL keywords in parameters",
            "Unexpected database syntax errors in logs",
            "Authentication bypass anomalies",
        ],
        "example_patterns": [
            "Suspicious token sequence: union select",
            "Injected boolean pattern: or 1=1",
            "Schema probing indicator: information_schema",
        ],
        "defenses": [
            "Use parameterized queries/ORM methods",
            "Apply strict input validation and output encoding",
            "Limit database account privileges",
            "Monitor and block anomalous query patterns via WAF",
        ],
    },
    {
        "name": "Cross-Site Scripting (XSS)",
        "summary": "Injection of browser-executable scripts into web pages viewed by other users.",
        "warning_signs": [
            "Unexpected script-like payloads in request params",
            "User session anomalies after viewing shared content",
            "DOM-modification errors in browser telemetry",
        ],
        "example_patterns": [
            "Tag injection marker: <script>",
            "Event-handler style payload marker: onerror=",
            "Encoded script indicators in URL/query strings",
        ],
        "defenses": [
            "Escape/encode untrusted output",
            "Use CSP with strict script-src",
            "Sanitize rich text input",
            "Set HttpOnly and SameSite on session cookies",
        ],
    },
    {
        "name": "Command Injection",
        "summary": "Attacker-controlled input reaches shell/system command execution paths.",
        "warning_signs": [
            "Application parameters containing shell separators",
            "Unexpected process spawns from web application user",
            "Output containing system account or filesystem artifacts",
        ],
        "example_patterns": [
            "Parameter style marker: cmd=",
            "Shell chaining tokens in logs: ; && |",
            "Unexpected interpreter references: powershell / bash",
        ],
        "defenses": [
            "Avoid shell invocation; use safe library APIs",
            "Use allowlists and strict input validation",
            "Run services with least privilege and syscall restrictions",
            "Add runtime detection for suspicious child processes",
        ],
    },
    {
        "name": "Password Attacks",
        "summary": "Attempts to guess or reuse credentials via brute force, spraying, or credential stuffing.",
        "warning_signs": [
            "High login failure volume across many accounts",
            "Many accounts targeted from one source",
            "Burst traffic patterns during odd hours",
        ],
        "example_patterns": [
            "Repeated failed login events from same IP",
            "Multiple usernames tested with one password",
            "Login attempts against disabled/inactive accounts",
        ],
        "defenses": [
            "Enable MFA and adaptive authentication",
            "Implement account lockouts/rate limits",
            "Block known breached-password usage",
            "Detect impossible-travel and behavior anomalies",
        ],
    },
    {
        "name": "Denial of Service (DoS)",
        "summary": "Traffic/resource exhaustion attacks that degrade or interrupt service availability.",
        "warning_signs": [
            "Sudden spikes in requests per second",
            "High error rates and elevated latency",
            "Infrastructure saturation (CPU, memory, bandwidth)",
        ],
        "example_patterns": [
            "Large volumes of repetitive requests to a narrow endpoint set",
            "Traffic from bot-like or spoofed source ranges",
            "Connection flood patterns in load balancer logs",
        ],
        "defenses": [
            "Use CDN/WAF and upstream DDoS protections",
            "Apply rate limiting and autoscaling",
            "Cache aggressively and isolate critical paths",
            "Maintain incident playbooks for traffic scrubbing",
        ],
    },
    {
        "name": "Man-in-the-Middle (MitM)",
        "summary": "Interception or alteration of data in transit between endpoints.",
        "warning_signs": [
            "Certificate warnings or trust-chain anomalies",
            "Unexpected DNS/gateway changes",
            "Session hijack indicators",
        ],
        "example_patterns": [
            "TLS downgrade attempts",
            "Unexpected proxy insertion in request path",
            "Certificate fingerprint mismatch alerts",
        ],
        "defenses": [
            "Enforce TLS 1.2+ with HSTS",
            "Use certificate pinning where appropriate",
            "Secure Wi-Fi and internal network segmentation",
            "Monitor DNS and routing integrity",
        ],
    },
]


def ai_chat_response(message: str) -> str:
    text = message.strip()
    lowered = text.lower()
    if not text:
        return "Please enter a question so I can help."

    blocked_keywords = [
        "exploit",
        "payload",
        "malware",
        "ransomware",
        "phishing kit",
        "sql injection attack",
        "ddos",
        "bruteforce",
        "credential stuffing",
        "reverse shell",
        "bypass authentication",
        "xss attack",
    ]
    if any(keyword in lowered for keyword in blocked_keywords):
        return (
            "I can help with defensive security and secure coding, but I cannot provide offensive attack instructions. "
            "If you share your legitimate security goal, I can provide detection logic, hardening steps, and safe remediation code."
        )

    if "python" in lowered:
        return (
            "Python secure coding checklist:\n"
            "1. Validate all external input with strict schemas.\n"
            "2. Use parameterized database queries only.\n"
            "3. Store passwords with salted hash functions (Werkzeug/Argon2/Bcrypt).\n"
            "4. Handle exceptions centrally and avoid leaking internals.\n"
            "5. Add unit tests for auth and permission boundaries."
        )

    if "javascript" in lowered or "node" in lowered:
        return (
            "JavaScript/Node security basics:\n"
            "1. Sanitize and encode untrusted output.\n"
            "2. Use helmet-like hardening for HTTP headers.\n"
            "3. Validate request bodies with schema validators.\n"
            "4. Avoid eval/new Function and insecure deserialization.\n"
            "5. Pin dependencies and run audit checks in CI."
        )

    if "c++" in lowered or "cpp" in lowered or " c " in f" {lowered} ":
        return (
            "C/C++ security basics:\n"
            "1. Prefer bounds-checked containers and safer string APIs.\n"
            "2. Enable compiler protections (ASLR, stack canaries, FORTIFY, UBSan/ASan in testing).\n"
            "3. Validate lengths before memory operations.\n"
            "4. Use static analysis and fuzz testing for risky parsers.\n"
            "5. Treat all network input as untrusted."
        )

    if "flask" in lowered or "api" in lowered:
        return (
            "Flask API hardening plan:\n"
            "1. Enforce authentication and role-based authorization.\n"
            "2. Add CSRF/session protections and secure cookie flags.\n"
            "3. Rate-limit login and high-risk endpoints.\n"
            "4. Return generic errors while logging detailed diagnostics server-side.\n"
            "5. Add security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)."
        )

    return (
        "I can help with Python, JavaScript, C, C++, web security posture checks, and secure architecture design. "
        "Ask me for code reviews, defensive patterns, bug fixes, or implementation guidance."
    )


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class SecurityAssessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    event_type = db.Column(db.String(64), nullable=False)
    payload = db.Column(db.Text, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    severity = db.Column(db.String(16), nullable=False)
    primary_category = db.Column(db.String(64), nullable=False)
    findings = db.Column(db.Text, nullable=False)
    recommendations = db.Column(db.Text, nullable=False)
    matched_signals = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return db.session.get(User, int(user_id))


def normalize_lines(payload: str) -> List[str]:
    return [line.strip() for line in payload.splitlines() if line.strip()]


def score_to_severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def extract_iocs(payload: str) -> Dict[str, List[str]]:
    iocs: Dict[str, List[str]] = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = sorted(set(re.findall(pattern, payload, flags=re.IGNORECASE)))
        if ioc_type == "ipv4":
            # Ignore impossible IPv4 octets.
            filtered = []
            for ip in matches:
                octets = ip.split(".")
                if all(0 <= int(octet) <= 255 for octet in octets):
                    filtered.append(ip)
            matches = filtered
        if matches:
            iocs[ioc_type] = matches
    return iocs


def infer_kill_chain_stage(severity: str, has_recon: bool, tactics: List[str]) -> str:
    if has_recon:
        return "Reconnaissance"
    if "Initial Access" in tactics:
        return "Initial Access"
    if "Execution" in tactics:
        return "Execution"
    if severity in {"critical", "high"}:
        return "Actions on Objectives"
    return "Monitoring"


def looks_like_url(payload: str) -> bool:
    candidate = payload.strip()
    return candidate.startswith("http://") or candidate.startswith("https://")


def passive_url_security_assessment(target_url: str) -> Dict[str, object]:
    findings: List[str] = []
    recommendations: List[str] = []
    observed: List[str] = []
    score = 8

    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {
            "risk_boost": 12,
            "findings": ["Payload looks like a URL but is not valid."],
            "recommendations": ["Use a full URL starting with http:// or https://."],
            "matched_signals": ["invalid-url-format"],
            "observed": [],
        }

    if parsed.scheme == "http":
        score += 16
        findings.append("Site is using HTTP instead of HTTPS.")
        recommendations.append("Force HTTPS and enable HSTS.")

    request = Request(
        target_url,
        method="GET",
        headers={"User-Agent": "SentinelOps-DefensiveScanner/1.0"},
    )

    try:
        with urlopen(request, timeout=7) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            status = getattr(response, "status", 0)
            observed.append(f"http-status:{status}")
            server = headers.get("server")
            if server:
                observed.append(f"server:{server}")
                score += 6
                findings.append("Server header is exposed and may leak stack/version details.")
                recommendations.append("Reduce server fingerprinting by removing detailed Server headers.")

            if "x-frame-options" not in headers:
                score += 8
                findings.append("Missing X-Frame-Options header (clickjacking risk).")
                recommendations.append("Set X-Frame-Options to DENY or SAMEORIGIN.")

            if "x-content-type-options" not in headers:
                score += 8
                findings.append("Missing X-Content-Type-Options header.")
                recommendations.append("Set X-Content-Type-Options: nosniff.")

            csp = headers.get("content-security-policy", "")
            if not csp:
                score += 10
                findings.append("Content-Security-Policy header is missing.")
                recommendations.append("Deploy a restrictive Content-Security-Policy.")

            hsts = headers.get("strict-transport-security", "")
            if parsed.scheme == "https" and not hsts:
                score += 8
                findings.append("HSTS header missing on HTTPS endpoint.")
                recommendations.append("Enable Strict-Transport-Security with an appropriate max-age.")

            cookies = response.headers.get_all("Set-Cookie") or []
            for cookie in cookies:
                cname = cookie.split("=", 1)[0].strip()
                flags = cookie.lower()
                if "secure" not in flags:
                    score += 8
                    findings.append(f"Cookie '{cname}' is missing Secure flag.")
                    recommendations.append("Set Secure flag on cookies to prevent plaintext transport.")
                if "httponly" not in flags:
                    score += 8
                    findings.append(f"Cookie '{cname}' is missing HttpOnly flag.")
                    recommendations.append("Set HttpOnly flag to reduce XSS cookie theft risk.")
                if "samesite" not in flags:
                    score += 6
                    findings.append(f"Cookie '{cname}' is missing SameSite attribute.")
                    recommendations.append("Set SameSite=Lax or Strict for session cookies.")
                observed.append(f"cookie:{cname}")

    except Exception as exc:
        score += 20
        findings.append(f"URL check failed: {exc.__class__.__name__}.")
        recommendations.append("Confirm target reachability and certificate/network path health.")

    if parsed.scheme == "https":
        hostname = parsed.hostname
        port = parsed.port or 443
        if hostname:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                        cert = tls_sock.getpeercert()
                        protocol = tls_sock.version() or "unknown"
                        observed.append(f"tls-version:{protocol}")
                        if cert.get("notAfter"):
                            observed.append(f"cert-not-after:{cert.get('notAfter')}")
            except Exception as exc:
                score += 12
                findings.append(f"TLS handshake validation failed: {exc.__class__.__name__}.")
                recommendations.append("Inspect certificate chain, hostname validation, and TLS configuration.")

    if not findings:
        findings.append("No high-risk web misconfiguration was identified through passive checks.")
        recommendations.append("Continue periodic scanning and add authenticated DAST in a controlled environment.")

    return {
        "risk_boost": min(score, 55),
        "findings": findings,
        "recommendations": list(dict.fromkeys(recommendations)),
        "matched_signals": ["passive-web-posture-check"],
        "observed": observed,
    }


def ai_defensive_assessment(event_type: str, payload: str) -> Dict[str, object]:
    text = payload.lower()
    findings: List[str] = []
    recommendations: List[str] = []
    matched_signals: List[str] = []
    mitre_tactics: List[str] = []
    category_scores: Counter[str] = Counter()
    score = EVENT_BASELINES.get(event_type, EVENT_BASELINES["general"])
    observed_artifacts: List[str] = []

    if looks_like_url(payload):
        url_assessment = passive_url_security_assessment(payload)
        score += int(url_assessment["risk_boost"])
        findings.extend([str(item) for item in url_assessment["findings"]])
        recommendations.extend([str(item) for item in url_assessment["recommendations"]])
        matched_signals.extend([str(item) for item in url_assessment["matched_signals"]])
        observed_artifacts.extend([str(item) for item in url_assessment["observed"]])
        category_scores["Web Security Posture"] += int(url_assessment["risk_boost"])

    for signal in SIGNAL_LIBRARY:
        signal_tokens = signal["tokens"]
        if any(token in text for token in signal_tokens):
            score += int(signal["weight"])
            signal_label = str(signal["label"])
            category_scores[signal_label] += int(signal["weight"])
            findings.append(str(signal["finding"]))
            recommendations.append(str(signal["response"]))
            matched_signals.extend(token for token in signal_tokens if token in text)
            mitre_tactics.extend(TACTIC_HINTS.get(signal_label, []))

    if len(payload) > 1500:
        score += 8
        findings.append("Oversized payload detected; review for staged or concatenated attack attempts.")
        recommendations.append("Correlate this record with surrounding events and inspect raw request capture.")

    unique_tokens = len(set(text.split()))
    if unique_tokens > 80:
        score += 6
        findings.append("High token diversity suggests a complex or multi-step attack chain.")

    score = min(score, 100)
    severity = score_to_severity(score)
    primary_category = category_scores.most_common(1)[0][0] if category_scores else "Unclassified"
    iocs = extract_iocs(payload)
    ioc_count = sum(len(values) for values in iocs.values())
    confidence = min(100, int((score * 0.78) + (len(set(matched_signals)) * 4) + (ioc_count * 3)))
    if ioc_count >= 3:
        score = min(100, score + 6)
        severity = score_to_severity(score)
        findings.append("Multiple indicators of compromise were extracted from this event.")
        recommendations.append("Block or sinkhole flagged indicators and run endpoint containment checks.")

    if not findings:
        findings.append("No high-confidence threat signature matched the current payload.")
        recommendations.append("Keep monitoring and enrich the event with source IP, asset, and user context.")

    if severity in {"critical", "high"}:
        recommendations.append("Open an incident ticket and preserve audit logs for forensic review.")

    unique_tactics = sorted(set(mitre_tactics))
    kill_chain_stage = infer_kill_chain_stage(
        severity=severity,
        has_recon="Reconnaissance" in unique_tactics,
        tactics=unique_tactics,
    )

    return {
        "risk_score": score,
        "confidence": confidence,
        "severity": severity,
        "primary_category": primary_category,
        "findings": findings,
        "recommendations": list(dict.fromkeys(recommendations)),
        "matched_signals": sorted(set(matched_signals)),
        "iocs": iocs,
        "mitre_tactics": unique_tactics,
        "kill_chain_stage": kill_chain_stage,
        "observed": observed_artifacts,
    }


def serialize_assessment(record: SecurityAssessment) -> Dict[str, object]:
    return {
        "id": record.id,
        "event_type": record.event_type,
        "payload": record.payload,
        "risk_score": record.risk_score,
        "severity": record.severity,
        "primary_category": record.primary_category,
        "findings": record.findings.split(" | "),
        "recommendations": record.recommendations.split(" | "),
        "matched_signals": [token for token in record.matched_signals.split(" | ") if token],
        "created_at": record.created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def build_dashboard_stats(user_id: int) -> Dict[str, object]:
    records = (
        SecurityAssessment.query.filter_by(user_id=user_id)
        .order_by(SecurityAssessment.created_at.desc())
        .all()
    )
    severity_counter = Counter(record.severity for record in records)
    category_counter = Counter(record.primary_category for record in records)
    average_risk = round(sum(record.risk_score for record in records) / len(records), 1) if records else 0

    return {
        "total": len(records),
        "critical": severity_counter.get("critical", 0),
        "high": severity_counter.get("high", 0),
        "medium": severity_counter.get("medium", 0),
        "average_risk": average_risk,
        "top_category": category_counter.most_common(1)[0][0] if category_counter else "No data yet",
    }


@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("show_login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        if len(username) < 3 or len(password) < 8:
            return jsonify({"success": False, "message": "Username must be 3+ chars and password 8+ chars."}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({"success": False, "message": "Username already exists."}), 409

        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"success": True, "message": "User registered."})

    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def show_login():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"success": False, "message": "Invalid username or password."}), 401

        login_user(user)
        return jsonify({"success": True, "message": "Logged in."})

    return render_template("auth.html", mode="login")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"success": True})


@app.route("/dashboard")
@login_required
def dashboard():
    assessments = (
        SecurityAssessment.query.filter_by(user_id=current_user.id)
        .order_by(SecurityAssessment.created_at.desc())
        .limit(25)
        .all()
    )
    return render_template(
        "dashboard.html",
        user=current_user,
        assessments=assessments,
        stats=build_dashboard_stats(current_user.id),
    )


@app.route("/info")
@login_required
def info_page():
    return render_template("info.html", attacks=ATTACK_KNOWLEDGE_BASE)


@app.route("/ai")
@login_required
def ai_page():
    return render_template("ai.html")


@app.route("/api/ai-chat", methods=["POST"])
@login_required
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message") or "").strip()
    if not message:
        return jsonify({"success": False, "message": "message is required"}), 400
    if len(message) > 2500:
        return jsonify({"success": False, "message": "message is too long"}), 400

    return jsonify({"success": True, "response": ai_chat_response(message)})


@app.route("/api/analyze", methods=["POST"])
@login_required
def analyze_event():
    data = request.get_json(silent=True) or {}
    event_type = (data.get("event_type") or "general").strip().lower()
    payload = (data.get("payload") or "").strip()
    batch_mode = bool(data.get("batch_mode"))

    if not payload:
        return jsonify({"success": False, "message": "payload is required"}), 400

    payload_items = normalize_lines(payload) if batch_mode else [payload]
    created_reports: List[SecurityAssessment] = []
    results: List[Dict[str, object]] = []

    for item in payload_items:
        result = ai_defensive_assessment(event_type=event_type, payload=item)
        report = SecurityAssessment(
            user_id=current_user.id,
            event_type=event_type,
            payload=item,
            risk_score=int(result["risk_score"]),
            severity=str(result["severity"]),
            primary_category=str(result["primary_category"]),
            findings=" | ".join(result["findings"]),
            recommendations=" | ".join(result["recommendations"]),
            matched_signals=" | ".join(result["matched_signals"]),
        )
        db.session.add(report)
        created_reports.append(report)
        results.append(result)

    db.session.commit()

    max_risk = max(int(result["risk_score"]) for result in results)
    summary = {
        "events_processed": len(results),
        "max_risk": max_risk,
        "critical_events": sum(1 for result in results if result["severity"] == "critical"),
        "high_events": sum(1 for result in results if result["severity"] == "high"),
        "top_categories": Counter(str(result["primary_category"]) for result in results).most_common(3),
    }

    return jsonify(
        {
            "success": True,
            "summary": summary,
            "results": results,
            "report_ids": [report.id for report in created_reports],
        }
    )


@app.route("/api/assessments")
@login_required
def list_assessments():
    records = (
        SecurityAssessment.query.filter_by(user_id=current_user.id)
        .order_by(SecurityAssessment.created_at.desc())
        .limit(50)
        .all()
    )
    return jsonify({"success": True, "items": [serialize_assessment(record) for record in records]})


@app.route("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
    )


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
