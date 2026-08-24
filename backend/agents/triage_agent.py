"""
backend/agents/triage_agent.py
-------------------------------
Autonomous SOC AI Triage Agent utilizing Tavily Threat Intel and Groq LLM (llama-3.3-70b-versatile).
"""

import json
import os
import re
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from integrations.tavily_client import search_threat_intel

load_dotenv()


class TriageReport(BaseModel):
    threat_level: str = Field(
        ...,
        description="Assessed threat severity level (critical, high, medium, low, info)",
    )
    confidence_score: float = Field(
        ...,
        description="Confidence score between 0.0 and 1.0 (or 0-100)",
    )
    mitre_tactic: str = Field(
        ...,
        description="Primary MITRE ATT&CK Tactic (e.g., Initial Access, Credential Access)",
    )
    mitre_technique: str = Field(
        ...,
        description="Specific MITRE ATT&CK Technique ID & Name (e.g., T1003 - OS Credential Dumping)",
    )
    cve_references: List[str] = Field(
        default_factory=list,
        description="Associated CVE references if applicable",
    )
    reasoning: str = Field(
        ...,
        description="Detailed technical reasoning and contextual analysis of the threat",
    )
    recommended_action: str = Field(
        ...,
        description="Actionable mitigation, containment, or remediation recommendations",
    )


def is_valid_api_key(key: Optional[str]) -> bool:
    """Check if the provided API key is valid and not a placeholder."""
    if not key:
        return False
    clean = key.strip()
    placeholder_keys = {"your_groq_api_key", "groq_api_key", "none", "placeholder"}
    if not clean or clean.lower() in placeholder_keys:
        return False
    return True


def get_deterministic_triage(source_ip: str, payload: dict) -> dict:
    """
    Generate deterministic threat classification when LLM API key is unavailable.
    Provides signature heuristics based on common threat indicators.
    """
    payload_str = json.dumps(payload).lower()

    # Rule: Sensitive file access / Credential dumping / Path traversal
    if "/etc/passwd" in payload_str or "/etc/shadow" in payload_str or "win.ini" in payload_str or "cmd.exe" in payload_str:
        return {
            "threat_level": "high",
            "confidence_score": 0.92,
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1003 - OS Credential Dumping",
            "cve_references": ["CVE-2021-41773", "CVE-2021-42013"],
            "reasoning": (
                f"Deterministic signature heuristic: Detected unauthorized attempt to access sensitive system files "
                f"({payload}) originating from source IP {source_ip}. Indicates potential directory traversal or credential harvesting."
            ),
            "recommended_action": (
                f"Immediately block source IP {source_ip} on perimeter firewalls and WAF. "
                f"Inspect web server logs for URI traversal attempts and verify file system permissions."
            ),
        }

    # Rule: SQL Injection
    if any(sqli in payload_str for sqli in ["union select", "or 1=1", "--", "information_schema", "sleep("]):
        return {
            "threat_level": "high",
            "confidence_score": 0.90,
            "mitre_tactic": "Initial Access",
            "mitre_technique": "T1190 - Exploit Public-Facing Application",
            "cve_references": [],
            "reasoning": (
                f"Deterministic signature heuristic: SQL injection pattern detected in payload from {source_ip}."
            ),
            "recommended_action": (
                f"Block source IP {source_ip}, review database queries, and enable parameterized queries."
            ),
        }

    # Rule: Remote Code Execution / Command Injection
    if any(cmd in payload_str for cmd in ["/bin/bash", "/bin/sh", "curl ", "wget ", "powershell", "whoami"]):
        return {
            "threat_level": "critical",
            "confidence_score": 0.95,
            "mitre_tactic": "Execution",
            "mitre_technique": "T1059 - Command and Scripting Interpreter",
            "cve_references": [],
            "reasoning": (
                f"Deterministic signature heuristic: Command execution or shell spawning pattern detected in payload from {source_ip}."
            ),
            "recommended_action": (
                f"Isolate targeted host, terminate suspicious processes, block IP {source_ip}, and initiate incident response."
            ),
        }

    # Generic Fallback Triage
    return {
        "threat_level": "medium",
        "confidence_score": 0.70,
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "cve_references": [],
        "reasoning": (
            f"Deterministic heuristic: Security telemetry event received from source IP {source_ip}. "
            f"No critical exploit signature matched; flagged for standard SOC analyst review."
        ),
        "recommended_action": (
            f"Monitor traffic from {source_ip} for escalating patterns or anomaly thresholds."
        ),
    }


def analyze_security_event(source_ip: str, payload: dict) -> dict:
    """
    Analyze a security event by combining Tavily real-time threat intelligence
    and Groq LLM (llama-3.3-70b-versatile) classification.

    Falls back to deterministic signature heuristics if GROQ_API_KEY is missing or invalid.

    Args:
        source_ip: Source IP of the suspicious activity.
        payload: Event payload details (e.g. path, method, headers, raw text).

    Returns:
        dict: Validated TriageReport dictionary.
    """
    # 1. Real-time Threat Intelligence lookup via Tavily
    intel_query = f"Threat intelligence IOC source IP {source_ip} security event {json.dumps(payload)}"
    threat_intel = search_threat_intel(query=intel_query)

    # 2. Check for Groq API Key
    groq_key = os.getenv("GROQ_API_KEY")
    if not is_valid_api_key(groq_key):
        report = get_deterministic_triage(source_ip=source_ip, payload=payload)
        return TriageReport(**report).model_dump()

    # 3. Query Groq LLM (llama-3.3-70b-versatile)
    try:
        from groq import Groq

        client = Groq(api_key=groq_key)

        system_prompt = (
            "You are an elite Autonomous SOC Security Analyst. Your task is to analyze incoming security "
            "events and real-time threat intelligence to produce a comprehensive, structured threat triage report.\n\n"
            "You MUST output ONLY a valid JSON object strictly matching the following schema:\n"
            "{\n"
            '  "threat_level": "critical" | "high" | "medium" | "low" | "info",\n'
            '  "confidence_score": float (0.0 to 1.0),\n'
            '  "mitre_tactic": "string (e.g. Credential Access, Initial Access, Execution, Discovery)",\n'
            '  "mitre_technique": "string (e.g. T1003 - OS Credential Dumping, T1190 - Exploit Public-Facing Application)",\n'
            '  "cve_references": ["CVE-YYYY-XXXX"],\n'
            '  "reasoning": "string (clear, rigorous analytical explanation)",\n'
            '  "recommended_action": "string (concrete containment and remediation steps)"\n'
            "}\n"
            "Do not wrap in markdown codeblocks (no ```json). Output raw JSON only."
        )

        user_content = (
            f"Security Event Data:\n"
            f"- Source IP: {source_ip}\n"
            f"- Event Payload: {json.dumps(payload, indent=2)}\n\n"
            f"Threat Intelligence Feed:\n"
            f"{json.dumps(threat_intel, indent=2)}\n\n"
            f"Analyze the event and provide the triage report."
        )

        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            model="llama-3.3-70b-versatile",
            temperature=0.1,
            response_format={"type": "json_object"},
        )

        response_text = chat_completion.choices[0].message.content
        if not response_text:
            raise ValueError("Empty response from Groq LLM")

        # Parse and validate with Pydantic
        parsed_json = json.loads(response_text)
        validated_report = TriageReport(**parsed_json)
        return validated_report.model_dump()

    except Exception as exc:
        print(f"[triage_agent] Warning: Groq triage failed ({exc}). Falling back to deterministic triage.")
        report = get_deterministic_triage(source_ip=source_ip, payload=payload)
        return TriageReport(**report).model_dump()
