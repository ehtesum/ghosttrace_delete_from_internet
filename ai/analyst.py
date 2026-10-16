"""
Claude-powered privacy analyst.
Streams a JSON analysis of all scan results and returns:
  risk_score, risk_level, executive_summary, key_findings,
  immediate_actions, deletion_email_template, exposure_breakdown
"""
import json

from anthropic import Anthropic

_SYSTEM = (
    "You are a digital privacy and OSINT expert. "
    "Analyse exposure data and return ONLY valid JSON — no markdown, no prose. "
    "Be specific, direct, and actionable."
)

_SCHEMA = """{
  "risk_score": <0-100 integer>,
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "executive_summary": "<2-3 sentence overview of the exposure>",
  "key_findings": ["<finding 1>", "<finding 2>", "<finding 3>"],
  "immediate_actions": [
    {"priority": 1, "action": "<short title>", "detail": "<steps>", "urgency": "<critical|high|medium|low>"},
    {"priority": 2, "action": "<short title>", "detail": "<steps>", "urgency": "<critical|high|medium|low>"},
    {"priority": 3, "action": "<short title>", "detail": "<steps>", "urgency": "<critical|high|medium|low>"}
  ],
  "deletion_email_template": "<full email body for GDPR/CCPA erasure request>",
  "exposure_breakdown": {
    "social_media": <count of found social accounts>,
    "services": <count of found service accounts>,
    "breaches": <count of breach findings>,
    "deep_web": <count of deep-web findings>
  }
}"""


class AIAnalyst:
    def __init__(self, api_key: str):
        self.client = Anthropic(api_key=api_key)

    def stream(self, email: str, surface: list, deep: list):
        """Yields raw text chunks from the Claude response."""
        found_s = [r for r in surface if r.get("status") == "found"]
        found_d = [r for r in deep if r.get("status") == "found"]

        summary = [
            {
                "platform": r.get("name", ""),
                "status": r.get("status", ""),
                "category": r.get("category", ""),
                "layer": r.get("layer", "surface"),
                "details": r.get("details", "")[:120],
            }
            for r in surface + deep
        ]

        prompt = f"""Analyse this OSINT privacy scan for email: {email}

SURFACE WEB — {len(found_s)} found out of {len(surface)} checked:
{json.dumps(found_s, indent=2)}

DEEP WEB — {len(found_d)} found out of {len(deep)} checked:
{json.dumps(found_d, indent=2)}

ALL RESULTS SUMMARY:
{json.dumps(summary, indent=2)}

Respond with ONLY valid JSON matching this exact schema:
{_SCHEMA}"""

        with self.client.messages.stream(
            model="claude-haiku-4-5-20251001",
            max_tokens=2500,
            system=_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            for chunk in stream.text_stream:
                yield chunk
