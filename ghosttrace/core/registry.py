from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import time
from types import ModuleType
from typing import Any, Dict, Iterable, List, Optional, Type, Union

from .base_checker import BaseChecker
from .search_engine import search_engine

logger = logging.getLogger(__name__)


class CheckerRegistry:
    def __init__(self) -> None:
        self._checkers: Dict[str, BaseChecker] = {}
        self._by_layer: Dict[str, List[BaseChecker]] = {}
        self._by_category: Dict[str, List[BaseChecker]] = {}
        self._by_tag: Dict[str, List[BaseChecker]] = {}
        self._discovered: bool = False
        self._discover_target: Optional[str] = None
        self._search_enabled: bool = True

    def register(self, checker: BaseChecker) -> None:
        checker_id = self._checker_id(checker)
        if checker_id in self._checkers:
            logger.warning("Duplicate checker skipped: %s", checker_id)
            return

        self._checkers[checker_id] = checker
        self._by_layer.setdefault(checker.layer, []).append(checker)
        self._by_category.setdefault(checker.category, []).append(checker)
        for t in getattr(checker, 'tags', []) or []:
            self._by_tag.setdefault(t, []).append(checker)
        logger.info("Registered checker %s (layer=%s, category=%s)", checker_id, checker.layer, checker.category)

    def discover_plugins(self, package: Union[str, ModuleType]) -> None:
        if isinstance(package, str):
            package = importlib.import_module(package)

        if self._discovered and self._discover_target == getattr(package, "__name__", None):
            logger.debug("Plugin discovery already completed for %s", self._discover_target)
            return

        if not hasattr(package, "__path__"):
            raise ValueError("Package required for plugin discovery")

        package_name = package.__name__
        start_time = time.perf_counter()
        loaded = 0

        for finder, name, ispkg in pkgutil.walk_packages(package.__path__, prefix=package_name + "."):
            try:
                module = importlib.import_module(name)
            except Exception as exc:
                logger.exception("Failed to import plugin module %s", name)
                continue

            loaded += self._register_checkers_from_module(module)

        self._discovered = True
        self._discover_target = package_name
        logger.info("Discovered %s plugin checker(s) in %s in %.3fs", loaded, package_name, time.perf_counter() - start_time)
        
        # Rebuild search index
        if self._search_enabled:
            self._rebuild_search_index()

    def _register_checkers_from_module(self, module: ModuleType) -> int:
        registered = 0
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj is BaseChecker:
                continue
            if not issubclass(obj, BaseChecker):
                continue
            if getattr(obj, "__module__", None) != module.__name__:
                continue

            try:
                checker = obj()
            except Exception:
                logger.exception("Failed to instantiate checker %s from %s", obj.__name__, module.__name__)
                continue

            self.register(checker)
            registered += 1

        return registered

    def _checker_id(self, checker: BaseChecker) -> str:
        if checker.id:
            return checker.id
        if checker.name:
            return checker.name.lower().replace(" ", "_")
        raise ValueError("Checker must define an id or name")

    def get(self, layer: str) -> List[BaseChecker]:
        return list(self._by_layer.get(layer, []))

    def get_by_id(self, checker_id: str) -> Optional[BaseChecker]:
        return self._checkers.get(checker_id)

    def list_all(self) -> Dict[str, List[BaseChecker]]:
        return {layer: list(checkers) for layer, checkers in self._by_layer.items()}

    def list_by_category(self, category: str) -> List[BaseChecker]:
        return list(self._by_category.get(category, []))

    def get_by_tag(self, tag: str) -> List[BaseChecker]:
        return list(self._by_tag.get(tag, []))

    def list_all_tags(self) -> List[str]:
        return list(self._by_tag.keys())

    def search(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Fast search across registry using indexed search engine.
        
        Args:
            query: Search string (name, category, tags, etc.)
            filters: Optional field filters {field: value}
            limit: Max results to return
            offset: Pagination offset
            
        Returns:
            Dict with total count, results, and query time
        """
        if not self._search_enabled:
            return {"total": 0, "results": [], "error": "Search disabled"}
        
        return search_engine.search(query, filters=filters, limit=limit, offset=offset)

    def batch_search(self, queries: List[str], limit: int = 50) -> Dict[str, Dict[str, Any]]:
        """Batch search for multiple queries efficiently."""
        if not self._search_enabled:
            return {}
        return search_engine.batch_search(queries, limit=limit)

    def get_search_stats(self) -> Dict[str, Any]:
        """Get search engine statistics."""
        return search_engine.get_stats()

    def _rebuild_search_index(self) -> None:
        """Rebuild search index from current checkers."""
        if not self._search_enabled:
            return
            
        checkers_data = []
        for checker_id, checker in self._checkers.items():
            checkers_data.append({
                "id": checker_id,
                "name": getattr(checker, "name", ""),
                "category": getattr(checker, "category", ""),
                "layer": getattr(checker, "layer", ""),
                "tags": getattr(checker, "tags", []) or [],
                "description": getattr(checker, "description", ""),
            })
        
        search_engine.index_registry(checkers_data)
        logger.debug("Rebuilt search index with %d checkers", len(checkers_data))


registry = CheckerRegistry()
