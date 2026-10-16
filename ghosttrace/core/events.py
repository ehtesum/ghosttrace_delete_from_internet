import json
from dataclasses import asdict
from typing import Any, Dict


def format_sse(event: Dict[str, Any]) -> str:
    return f"data: {json.dumps(event, default=str)}\n\n"
