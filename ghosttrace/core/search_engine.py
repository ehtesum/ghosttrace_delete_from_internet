"""
Advanced Search Engine with Indexing & Caching for Billion-scale Registry Lookups.

Features:
- Inverted Index: Fast text search O(1) lookups
- Bloom Filters: Existence checks with minimal memory
- LRU Caching: Recent queries cached
- Batch Processing: Handle thousands of queries simultaneously
- Ranking: Relevance scoring for results
- Pagination: Memory-efficient large result sets
"""

from __future__ import annotations

import hashlib
import heapq
import logging
import time
from collections import defaultdict, deque
from functools import lru_cache
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class BloomFilter:
    """Memory-efficient existence checker."""

    def __init__(self, size: int = 1_000_000, hash_functions: int = 3):
        self.size = size
        self.hash_functions = hash_functions
        self.bits = [False] * size

    def add(self, item: str) -> None:
        """Add item to filter."""
        for i in range(self.hash_functions):
            h = self._hash(item, i) % self.size
            self.bits[h] = True

    def contains(self, item: str) -> bool:
        """Check if item likely exists."""
        for i in range(self.hash_functions):
            h = self._hash(item, i) % self.size
            if not self.bits[h]:
                return False
        return True

    def _hash(self, item: str, seed: int) -> int:
        return int(hashlib.md5(f"{item}{seed}".encode()).hexdigest(), 16)


class InvertedIndex:
    """Inverted index for fast full-text search."""

    def __init__(self):
        self.index: Dict[str, Set[int]] = defaultdict(set)
        self.documents: Dict[int, Dict[str, Any]] = {}
        self.doc_counter = 0

    def add_document(self, doc_id: int, content: Dict[str, Any]) -> None:
        """Index a document with unique ID."""
        self.documents[doc_id] = content
        self.doc_counter = max(self.doc_counter, doc_id + 1)

        # Index all text fields
        for key, value in content.items():
            if isinstance(value, str):
                tokens = self._tokenize(value)
                for token in tokens:
                    self.index[token].add(doc_id)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    if isinstance(item, str):
                        tokens = self._tokenize(item)
                        for token in tokens:
                            self.index[token].add(doc_id)

    def search(self, query: str, limit: int = 100) -> List[Tuple[int, Dict[str, Any], float]]:
        """Search with relevance scoring. Returns (doc_id, doc, score)."""
        tokens = self._tokenize(query)
        if not tokens:
            return []

        # AND query: find docs containing all tokens
        matching_docs = None
        for token in tokens:
            doc_set = self.index.get(token, set())
            if matching_docs is None:
                matching_docs = doc_set.copy()
            else:
                matching_docs &= doc_set

        if not matching_docs:
            return []

        # Score by frequency
        scores = []
        for doc_id in matching_docs:
            doc = self.documents[doc_id]
            score = sum(len(self.index.get(token, set())) for token in tokens) / len(tokens)
            scores.append((doc_id, doc, score))

        # Sort by score descending
        scores.sort(key=lambda x: -x[2])
        return scores[:limit]

    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization."""
        return [t.lower() for t in text.split() if len(t) > 1]


class SearchCache:
    """LRU cache for recent searches."""

    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, List[Tuple[int, Dict[str, Any], float]]] = {}
        self.access_order: deque = deque(maxlen=max_size)
        self.max_size = max_size

    def get(self, key: str) -> Optional[List[Tuple[int, Dict[str, Any], float]]]:
        """Get cached result."""
        if key in self.cache:
            self.access_order.append(key)
            return self.cache[key]
        return None

    def put(self, key: str, value: List[Tuple[int, Dict[str, Any], float]]) -> None:
        """Cache a result."""
        if len(self.cache) >= self.max_size and key not in self.cache:
            # Evict oldest
            if self.access_order:
                oldest = self.access_order[0]
                del self.cache[oldest]
        self.cache[key] = value
        self.access_order.append(key)

    def clear(self) -> None:
        """Clear cache."""
        self.cache.clear()
        self.access_order.clear()


class SearchEngine:
    """Fast registry search with caching, indexing, and ranking."""

    def __init__(self, cache_size: int = 5000, bloom_size: int = 10_000_000):
        self.inverted_index = InvertedIndex()
        self.cache = SearchCache(max_size=cache_size)
        self.bloom_filter = BloomFilter(size=bloom_size)
        self.registry_size = 0
        self.last_update = time.time()

    def index_registry(self, checkers: List[Dict[str, Any]]) -> None:
        """Index a batch of checkers."""
        start = time.time()
        for idx, checker in enumerate(checkers):
            self.inverted_index.add_document(idx, checker)
            self.bloom_filter.add(checker.get("name", ""))
            self.bloom_filter.add(checker.get("id", ""))

        self.registry_size = len(checkers)
        self.last_update = time.time()
        elapsed = time.time() - start
        logger.info("Indexed %d checkers in %.3fs", self.registry_size, elapsed)

    def search(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Fast search with optional filters.

        Args:
            query: Search string
            filters: Dict of {field: value} to filter by
            limit: Max results
            offset: Pagination offset

        Returns:
            {
                "total": int,
                "results": [(id, doc, score), ...],
                "query_time_ms": float,
                "cached": bool
            }
        """
        start = time.time()
        cache_key = f"{query}|{filters}|{limit}|{offset}"

        # Check cache
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            elapsed = (time.time() - start) * 1000
            logger.debug("Cache hit for query: %s (%.2fms)", query, elapsed)
            return {
                "total": len(cached_result),
                "results": cached_result[offset : offset + limit],
                "query_time_ms": elapsed,
                "cached": True,
            }

        # Search inverted index
        results = self.inverted_index.search(query, limit=10000)

        # Apply filters
        if filters:
            results = self._apply_filters(results, filters)

        # Cache full results
        self.cache.put(cache_key, results)

        elapsed = (time.time() - start) * 1000
        return {
            "total": len(results),
            "results": results[offset : offset + limit],
            "query_time_ms": elapsed,
            "cached": False,
        }

    def exists(self, name: str) -> bool:
        """Fast existence check using Bloom filter."""
        return self.bloom_filter.contains(name)

    def batch_search(
        self, queries: List[str], limit: int = 50
    ) -> Dict[str, Dict[str, Any]]:
        """Batch search for multiple queries."""
        start = time.time()
        results = {}
        for query in queries:
            results[query] = self.search(query, limit=limit)
        elapsed = (time.time() - start) * 1000
        logger.info("Batch search %d queries in %.2fms", len(queries), elapsed)
        return results

    def _apply_filters(
        self, results: List[Tuple[int, Dict[str, Any], float]], filters: Dict[str, Any]
    ) -> List[Tuple[int, Dict[str, Any], float]]:
        """Apply field filters to results."""
        filtered = []
        for doc_id, doc, score in results:
            match = True
            for key, value in filters.items():
                if key not in doc:
                    match = False
                    break
                if isinstance(value, list):
                    if doc[key] not in value:
                        match = False
                        break
                else:
                    if doc[key] != value:
                        match = False
                        break
            if match:
                filtered.append((doc_id, doc, score))
        return filtered

    def get_stats(self) -> Dict[str, Any]:
        """Get search engine stats."""
        return {
            "indexed_checkers": self.registry_size,
            "cache_size": len(self.cache.cache),
            "last_update": self.last_update,
            "uptime_seconds": time.time() - self.last_update,
        }

    def clear_cache(self) -> None:
        """Clear search cache."""
        self.cache.clear()


# Global search engine instance
search_engine = SearchEngine()
