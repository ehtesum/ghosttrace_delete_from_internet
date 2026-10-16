from __future__ import annotations

import re
from typing import List

# Basic Bangla (Bengali) Unicode block detection
_BENGALI_RANGE = (0x0980, 0x09FF)


def is_bengali(text: str) -> bool:
    if not text:
        return False
    for ch in text:
        if _BENGALI_RANGE[0] <= ord(ch) <= _BENGALI_RANGE[1]:
            return True
    return False


# A very small transliteration map for common Bangla letters to Latin approximations.
# This is intentionally lightweight — a production system should use a proper
# transliteration library or rule set.
_TRANSLIT = {
    'আ': 'a', 'অ': 'o', 'ই': 'i', 'ঈ': 'i', 'উ': 'u', 'ঊ': 'u',
    'ক': 'k', 'খ': 'kh', 'গ': 'g', 'ঘ': 'gh', 'ঙ': 'ng',
    'চ': 'ch', 'ছ': 'chh', 'জ': 'j', 'ঝ': 'jh', 'ঞ': 'n',
    'ট': 't', 'ঠ': 'th', 'ড': 'd', 'ঢ': 'dh', 'ণ': 'n',
    'ত': 't', 'থ': 'th', 'দ': 'd', 'ধ': 'dh', 'ন': 'n',
    'প': 'p', 'ফ': 'ph', 'ব': 'b', 'ভ': 'bh', 'ম': 'm',
    'য': 'y', 'র': 'r', 'ল': 'l', 'শ': 'sh', 'ষ': 'sh', 'স': 's', 'হ': 'h',
    'ঁ': '', 'ং': 'ng', 'ঃ': '', '্': '',
    'া': 'a', 'ি': 'i', 'ী': 'i', 'ু': 'u', 'ূ': 'u', 'ে': 'e', 'ৈ': 'oi', 'ো': 'o', 'ৌ': 'ou',
}


def transliterate_bengali_to_latin(text: str) -> str:
    out = []
    for ch in text:
        if ch in _TRANSLIT:
            out.append(_TRANSLIT[ch])
        else:
            out.append(ch)
    return ''.join(out)


def normalize_alias(raw: str) -> List[str]:
    """Return normalized variants for a given alias/display name.

    - trims and lowercases
    - strips punctuation and diacritics
    - if Bangla text detected, also return a transliterated Latin variant
    """
    if not raw:
        return []
    s = raw.strip()
    s = re.sub(r"[\u2000-\u206F\u2E00-\u2E7F\'\"\(\)\[\]\{\},:;.!?\\/\\\\<>\-]+", '', s)
    s = s.lower()
    variants = [s]
    if is_bengali(s):
        tr = transliterate_bengali_to_latin(s)
        tr = re.sub(r"[^a-z0-9_ ]+", '', tr).strip().lower()
        if tr and tr not in variants:
            variants.append(tr)
    # also add underscore/dot variants
    slug = re.sub(r"\s+", '_', s)
    if slug not in variants:
        variants.append(slug)
    dot = re.sub(r"\s+", '.', s)
    if dot not in variants:
        variants.append(dot)
    return variants
