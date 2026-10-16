from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class CheckResult:
    status: str = "unknown"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)
    details: str = ""
    delete_url: str = ""


class BaseChecker(abc.ABC):
    id: str = ""
    name: str = ""
    category: str = "other"
    layer: str = "surface"
    tags: List[str] = []
    privacy: str = "api"
    requires_auth: bool = False
    supports_proxy: bool = True
    timeout: float = 15.0
    retries: int = 2

    def __init__(self) -> None:
        pass

    @abc.abstractmethod
    async def scan(self, query: str, session: Any, config: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def result(self, **kwargs: Any) -> Dict[str, Any]:
        return CheckResult(**kwargs).__dict__
