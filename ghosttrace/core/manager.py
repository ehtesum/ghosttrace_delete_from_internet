import asyncio
import logging
from typing import Any, AsyncGenerator, Dict, List, Optional

from .events import format_sse
from .proxies import ProxyClientSession, ProxyConfig
from .registry import registry
from .base_checker import BaseChecker
from .entities import EntityStore
from .correlation import Correlator


def _import_aiohttp():
    try:
        import aiohttp
        from aiohttp import ClientSession, ClientTimeout, TCPConnector
    except ImportError as exc:
        raise RuntimeError("aiohttp is required for async scanning. Install it from requirements.txt") from exc
    return ClientSession, ClientTimeout, TCPConnector

logging.getLogger("aiohttp").setLevel(logging.WARNING)

DEFAULT_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": "GhostTrace/4.0 (+https://example.local)"
}


class AsyncScannerManager:
    def __init__(self, max_workers: int = 16) -> None:
        self.max_workers = max_workers
        self.correlator = Correlator()

    async def scan_email(
        self,
        email: str,
        layer: str = "surface",
        config: Optional[Dict[str, Any]] = None,
        include_tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        config = config or {}
        checkers = registry.get(layer)
        # apply tag filters (include/exclude)
        if include_tags or exclude_tags:
            def _keep(ch):
                tags = getattr(ch, 'tags', []) or []
                if exclude_tags and any(t in tags for t in exclude_tags):
                    return False
                if include_tags and not any(t in tags for t in include_tags):
                    return False
                return True

            checkers = [c for c in checkers if _keep(c)]
        total = len(checkers)
        yield {"type": "progress", "current": 0, "total": total, "checking": "Preparing scan…"}

        async with self._create_session(config, timeout_total=45) as session:
            tasks = [self._run_checker(checker, email, session, config) for checker in checkers]
            semaphore = asyncio.Semaphore(self.max_workers)

            async def bound(task):
                async with semaphore:
                    return await task

            wrapped = [bound(task) for task in tasks]
            done = 0
            for future in asyncio.as_completed(wrapped):
                result = await future
                done += 1
                yield {"type": "progress", "current": done, "total": total, "checking": result.get("name", "unknown")}
                yield {"type": "result", **result}

        yield {"type": "done"}

    async def scan_username(self, username: str, config: Optional[Dict[str, Any]] = None) -> AsyncGenerator[Dict[str, Any], None]:
        config = config or {}
        checkers = registry.get("username")
        # support tag filtering for username hunts via config keys
        include_tags = (config.get('include_tags') if isinstance(config, dict) else None)
        exclude_tags = (config.get('exclude_tags') if isinstance(config, dict) else None)
        if include_tags or exclude_tags:
            def _keep(ch):
                tags = getattr(ch, 'tags', []) or []
                if exclude_tags and any(t in tags for t in exclude_tags):
                    return False
                if include_tags and not any(t in tags for t in include_tags):
                    return False
                return True

            checkers = [c for c in checkers if _keep(c)]
        total = len(checkers)
        yield {"type": "progress", "current": 0, "total": total, "checking": "Preparing username hunt…"}

        async with self._create_session(config, timeout_total=45) as session:
            tasks = [self._run_checker(checker, username, session, config) for checker in checkers]
            semaphore = asyncio.Semaphore(self.max_workers)
            wrapped = [self._bound(task, semaphore) for task in tasks]
            done = 0
            for future in asyncio.as_completed(wrapped):
                result = await future
                done += 1
                yield {"type": "progress", "current": done, "total": total, "checking": result.get("name", "unknown")}
                yield {"type": "result", **result}

        yield {"type": "done"}

    async def scan_image(self, image_bytes: bytes, filename: str = "upload.jpg", config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run image checkers against an uploaded image and return aggregated JSON.

        Returns a dict with at least `metadata` and `search_links` keys expected
        by the frontend. Image checkers should accept the raw bytes as the
        `query` parameter and may return metadata in their result.
        """
        config = config or {}
        # Ensure plugins are discovered (app typically does this at startup)
        try:
            registry.discover_plugins("ghosttrace.checkers")
        except Exception:
            # discovery errors already logged by registry; continue
            pass

        image_checkers = registry.get("image")
        # config-driven filtering
        include_tags = (config.get('include_tags') if isinstance(config, dict) else None)
        exclude_tags = (config.get('exclude_tags') if isinstance(config, dict) else None)
        if include_tags or exclude_tags:
            def _keep(ch):
                tags = getattr(ch, 'tags', []) or []
                if exclude_tags and any(t in tags for t in exclude_tags):
                    return False
                if include_tags and not any(t in tags for t in include_tags):
                    return False
                return True

            image_checkers = [c for c in image_checkers if _keep(c)]

        results = []
        aggregated_metadata: Dict[str, Any] = {}
        aggregated_links: List[str] = []

        async with self._create_session(config, timeout_total=60) as session:
            tasks = [self._run_checker(checker, image_bytes, session, config) for checker in image_checkers]
            semaphore = asyncio.Semaphore(self.max_workers)

            async def bound(task):
                async with semaphore:
                    return await task

            wrapped = [bound(task) for task in tasks]
            for future in asyncio.as_completed(wrapped):
                try:
                    r = await future
                except Exception:
                    continue
                results.append(r)
                # merge metadata and links conservatively
                meta = r.get("metadata") or {}
                if isinstance(meta, dict):
                    aggregated_metadata.update({k: v for k, v in meta.items() if k not in aggregated_metadata})
                links = r.get("links") or []
                if isinstance(links, list):
                    aggregated_links.extend([l for l in links if l not in aggregated_links])

        return {"metadata": {"filename": filename, **aggregated_metadata}, "search_links": aggregated_links, "results": results}

    async def orchestrate_entities(self, inputs: List[Dict[str, Any]], mode: str = "comprehensive", config: Optional[Dict[str, Any]] = None) -> AsyncGenerator[Dict[str, Any], None]:
        """Orchestrate scans for a list of normalized inputs (entities).

        `inputs` is a list of dicts: {'type': 'email'|'username'|'image'|'phone'|..., 'value': raw}
        Streams SSE-style dicts: progress/result/done and final 'graph' payload.
        """
        config = config or {}
        store = EntityStore()
        # normalize and deduplicate inputs
        for itm in inputs:
            etype = itm.get('type') or 'username'
            val = itm.get('value')
            if not val:
                continue
            store.add(etype, val, metadata=itm.get('metadata'))

        entities = store.get_all()
        total_entities = len(entities)
        yield {"type": "progress", "current": 0, "total": total_entities, "checking": "Preparing correlation scan…"}

        # simple orchestration: for each entity, run layer-appropriate checkers
        done = 0
        all_results = []
        for ent in entities:
            # choose checkers based on entity.type mapped to layer
            # simple mapping: email->surface, username->username, image->image, phone->surface
            layer = 'surface'
            if ent.type == 'username':
                layer = 'username'
            elif ent.type == 'image':
                layer = 'image'

            checkers = registry.get(layer)
            yield {"type": "progress", "current": done, "total": total_entities, "checking": f'Running {len(checkers)} checks for {ent.id}'}

            async with self._create_session(config, timeout_total=45) as session:
                tasks = [self._run_checker(checker, ent.raw, session, config) for checker in checkers]
                semaphore = asyncio.Semaphore(self.max_workers)

                async def bound(task):
                    async with semaphore:
                        return await task

                wrapped = [bound(task) for task in tasks]
                for future in asyncio.as_completed(wrapped):
                    result = await future
                    all_results.append({"entity": ent.id, **result})
                    yield {"type": "result", **result, "entity": ent.id}

            done += 1
            yield {"type": "progress", "current": done, "total": total_entities, "checking": f'Finished {ent.id}'}

        # correlation
        graph = self.correlator.build_graph(entities, evidence=all_results)
        clusters = self.correlator.cluster(graph)
        yield {"type": "done", "graph": graph, "clusters": clusters}

    async def _bound(self, task: asyncio.Task, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        async with semaphore:
            return await task

    def _get_proxy_config(self, config: Optional[Dict[str, Any]]) -> ProxyConfig:
        if not isinstance(config, dict):
            return ProxyConfig()
        proxy = config.get("proxy")
        if isinstance(proxy, ProxyConfig):
            return proxy
        if isinstance(proxy, dict):
            return ProxyConfig(**proxy)
        return ProxyConfig(
            use_tor=bool(config.get("use_tor", False)),
            proxy_url=config.get("proxy_url"),
        )

    def _create_session(self, config: Optional[Dict[str, Any]] = None, timeout_total: int = 45) -> ProxyClientSession:
        ClientSession, ClientTimeout, TCPConnector = _import_aiohttp()
        proxy_config = self._get_proxy_config(config)
        connector = TCPConnector(ssl=False, limit=self.max_workers)
        timeout = ClientTimeout(total=timeout_total)
        proxy_url = proxy_config.as_aiohttp_proxy()
        raw_session = ClientSession(connector=connector, headers=DEFAULT_HEADERS, timeout=timeout)
        return ProxyClientSession(raw_session, proxy_url)

    async def _run_checker(
        self,
        checker: BaseChecker,
        query: str,
        session: Any,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        try:
            result = await checker.scan(query, session, config)
        except Exception as exc:
            return self._normalize_result(
                checker,
                status="error",
                details=str(exc),
                raw={"exception": repr(exc)},
            )
        return self._normalize_result(checker, **result)

    def _normalize_result(self, checker: BaseChecker, **data: Any) -> Dict[str, Any]:
        return {
            "id": getattr(checker, "id", checker.name.lower().replace(" ", "_")),
            "name": checker.name,
            "category": checker.category,
            "privacy": checker.privacy,
            "layer": getattr(checker, "layer", "surface"),
            "status": data.get("status", "unknown"),
            "confidence": float(data.get("confidence", 0.0)),
            "evidence": data.get("evidence", []),
            "links": data.get("links", []),
            "details": data.get("details", ""),
            "metadata": data.get("metadata", {}),
            "raw": data.get("raw", {}),
            "delete_url": data.get("delete_url", getattr(checker, "delete_url", "")),
        }
