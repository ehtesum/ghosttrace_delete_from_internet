from __future__ import annotations

from typing import Any, Dict, List, Tuple
from .entities import Entity, EntityStore
from .scoring import ScoringEngine
from .normalization import is_bengali
import difflib
import math


class Correlator:
    def __init__(self) -> None:
        self.scorer = ScoringEngine()

    def score_name_similarity(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        seq = difflib.SequenceMatcher(a=a, b=b)
        return seq.ratio()

    def _collect_pair_evidence(self, a: Entity, b: Entity, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        evidences: List[Dict[str, Any]] = []

        # exact normalized equality
        if a.normalized and b.normalized and a.normalized == b.normalized:
            evidences.append(self.scorer.make_evidence('exact_email', 'internal', f'{a.normalized}=={b.normalized}'))

        # name similarity
        sim = self.score_name_similarity(a.normalized or '', b.normalized or '')
        if sim > 0.6:
            evidences.append(self.scorer.make_evidence('username_similarity', 'internal', f'sim={sim:.2f}', value=sim))

        # transliteration hint
        if is_bengali(a.raw) or is_bengali(b.raw):
            # if one normalized contains the other's ascii form
            try:
                if a.normalized and b.normalized and (a.normalized in b.normalized or b.normalized in a.normalized):
                    evidences.append(self.scorer.make_evidence('transliteration_match', 'internal', 'transliteration heuristic'))
            except Exception:
                pass

        # scan records: look for links or metadata that reference the other entity
        for rec in records:
            try:
                r_entity = rec.get('entity')
                checker = rec.get('id') or rec.get('name') or 'checker'
                links = rec.get('links') or []
                metadata = rec.get('metadata') or {}
                status = rec.get('status')

                # if this record belongs to a and mentions b in links
                if r_entity == a.id and links:
                    for l in links:
                        if isinstance(l, str) and (b.normalized and b.normalized in l or b.raw and str(b.raw) in l):
                            evidences.append(self.scorer.make_evidence('same_profile_url', checker, f'{l} mentions {b.id}'))

                # same for reverse
                if r_entity == b.id and links:
                    for l in links:
                        if isinstance(l, str) and (a.normalized and a.normalized in l or a.raw and str(a.raw) in l):
                            evidences.append(self.scorer.make_evidence('same_profile_url', checker, f'{l} mentions {a.id}'))

                # avatar hash in metadata
                av_a = a.metadata.get('avatar_hash')
                av_b = b.metadata.get('avatar_hash')
                if av_a and av_b and av_a == av_b:
                    evidences.append(self.scorer.make_evidence('avatar_hash', checker, f'{av_a}'))

                # found status contributes weaker evidence
                if status == 'found' and (r_entity == a.id or r_entity == b.id):
                    evidences.append(self.scorer.make_evidence('found_status', checker, f'status found on {r_entity}'))

                # bio similarity / metadata text
                bio = metadata.get('bio') or metadata.get('description') or ''
                if bio and (a.normalized in bio or b.normalized in bio):
                    evidences.append(self.scorer.make_evidence('same_bio', checker, f'bio mentions normalized'))

            except Exception:
                continue

        return evidences

    def build_graph(self, entities: List[Entity], evidence: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        evidence = evidence or []
        nodes = {e.id: {'id': e.id, 'type': e.type, 'normalized': e.normalized, 'aliases': e.aliases, 'metadata': e.metadata} for e in entities}
        edges: List[Dict[str, Any]] = []

        # produce pairwise evidence and score
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                a = entities[i]
                b = entities[j]
                evidences = self._collect_pair_evidence(a, b, evidence)
                if not evidences:
                    continue
                confidence = self.scorer.score_from_evidence(evidences)
                if confidence <= 0:
                    continue
                edges.append({'source': a.id, 'target': b.id, 'score': confidence, 'evidence': evidences})

        return {'nodes': list(nodes.values()), 'edges': edges, 'evidence': evidence}

    def cluster(self, graph: Dict[str, Any]) -> List[List[str]]:
        # simple connected-component clustering
        nodes = {n['id'] for n in graph.get('nodes', [])}
        adj = {n: set() for n in nodes}
        for e in graph.get('edges', []):
            adj[e['source']].add(e['target'])
            adj[e['target']].add(e['source'])

        visited = set()
        clusters: List[List[str]] = []
        for n in nodes:
            if n in visited:
                continue
            stack = [n]
            comp = []
            while stack:
                cur = stack.pop()
                if cur in visited:
                    continue
                visited.add(cur)
                comp.append(cur)
                for nb in adj.get(cur, []):
                    if nb not in visited:
                        stack.append(nb)
            clusters.append(comp)
        return clusters