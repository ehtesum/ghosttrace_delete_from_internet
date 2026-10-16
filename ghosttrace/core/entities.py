from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import hashlib
import re
from .normalization import normalize_alias, is_bengali


def _normalize_email(raw: str) -> str:
    return raw.strip().lower()


def _normalize_username(raw: str) -> str:
    return raw.strip().lstrip('@').lower()


def _normalize_phone(raw: str) -> str:
    # naive: remove non-digits, keep leading + if present
    s = raw.strip()
    s = re.sub(r"[^\d+]", "", s)
    return s


def _image_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Entity:
    id: str
    type: str
    raw: str
    normalized: str
    aliases: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class EntityStore:
    def __init__(self) -> None:
        self._entities: Dict[str, Entity] = {}

    def add(self, type: str, raw: str, metadata: Optional[Dict[str, Any]] = None) -> Entity:
        metadata = metadata or {}
        if type == 'email':
            norm = _normalize_email(raw)
            eid = f'email:{norm}'
        elif type == 'username':
            norm = _normalize_username(raw)
            eid = f'username:{norm}'
        elif type == 'phone':
            norm = _normalize_phone(raw)
            eid = f'phone:{norm}'
        elif type == 'image':
            if isinstance(raw, (bytes, bytearray)):
                norm = _image_hash(raw)
            else:
                norm = str(raw)
            eid = f'image:{norm}'
        else:
            norm = raw.strip()
            eid = f'{type}:{norm}'

        if eid in self._entities:
            ent = self._entities[eid]
            ent.metadata.update({k: v for k, v in (metadata or {}).items() if k not in ent.metadata})
            return ent

        # produce normalized variants for aliases/names
        variants: List[str] = []
        if type in ('alias', 'display_name', 'username', 'social_handle', 'multilingual_alias'):
            variants = normalize_alias(raw)
            # prefer transliterated variant if bangla
            if is_bengali(raw) and variants:
                norm = variants[1] if len(variants) > 1 else variants[0]

        ent = Entity(id=eid, type=type, raw=raw, normalized=norm, aliases=variants, metadata=metadata or {})
        self._entities[eid] = ent
        return ent

    def get_all(self) -> List[Entity]:
        return list(self._entities.values())

    def find_by_normalized(self, type: str, normalized: str) -> Optional[Entity]:
        key = f'{type}:{normalized}'
        return self._entities.get(key)

    def merge_alias(self, target_id: str, alias_raw: str) -> None:
        ent = self._entities.get(target_id)
        if not ent:
            return
        if alias_raw not in ent.aliases:
            ent.aliases.append(alias_raw)
