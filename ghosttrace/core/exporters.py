import csv
import json
from io import StringIO
from typing import Dict, Iterable, List


def export_json(data: Dict[str, object]) -> str:
    return json.dumps(data, indent=2, sort_keys=False)


def export_csv(rows: Iterable[Dict[str, object]], fieldnames: List[str]) -> str:
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def flatten_result(result: Dict[str, object]) -> Dict[str, object]:
    return {
        "id": result.get("id", ""),
        "name": result.get("name", ""),
        "status": result.get("status", ""),
        "category": result.get("category", ""),
        "confidence": result.get("confidence", 0.0),
        "details": result.get("details", ""),
        "delete_url": result.get("delete_url", ""),
    }
