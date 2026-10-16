"""
Search API endpoints for GhostTrace v4.

These endpoints integrate the optimized search engine for handling billion-scale registry queries.
Add these routes to the Flask app in app.py.
"""

from flask import Flask, request, jsonify
from ghosttrace.core.registry import registry
from ghosttrace.core.search_engine import search_engine

def register_search_routes(app: Flask) -> None:
    """Register search API endpoints."""
    
    @app.route("/api/search", methods=["GET"])
    def search():
        """
        Fast registry search endpoint.
        
        Query params:
        - q: Search query (name, category, tags, description)
        - filters: JSON-encoded field filters {field: value}
        - limit: Results limit (default 100)
        - offset: Pagination offset (default 0)
        
        Returns: {total, results, query_time_ms, cached}
        """
        query = request.args.get("q", "").strip()
        if not query:
            return jsonify({"error": "Query required"}), 400
        
        filters_json = request.args.get("filters")
        filters = None
        if filters_json:
            try:
                import json
                filters = json.loads(filters_json)
            except:
                filters = None
        
        limit = min(int(request.args.get("limit", 100)), 1000)
        offset = int(request.args.get("offset", 0))
        
        result = registry.search(query, filters=filters, limit=limit, offset=offset)
        return jsonify(result)

    @app.route("/api/search/batch", methods=["POST"])
    def batch_search():
        """
        Batch search multiple queries efficiently.
        
        JSON body: {"queries": ["query1", "query2", ...], "limit": 50}
        
        Returns: {query: search_result, ...}
        """
        data = request.get_json(silent=True) or {}
        queries = data.get("queries", [])
        limit = min(data.get("limit", 50), 500)
        
        if not queries:
            return jsonify({"error": "Queries required"}), 400
        
        results = registry.batch_search(queries, limit=limit)
        return jsonify(results)

    @app.route("/api/search/stats", methods=["GET"])
    def search_stats():
        """Get search engine statistics."""
        stats = registry.get_search_stats()
        return jsonify(stats)

    @app.route("/api/search/checkers", methods=["GET"])
    def list_checkers():
        """
        List all checkers with optional filtering.
        
        Query params:
        - layer: Filter by layer (surface, deep, username, etc.)
        - category: Filter by category
        - tag: Filter by tag
        
        Returns: {layer: [checkers], ...} or filtered list
        """
        layer = request.args.get("layer")
        category = request.args.get("category")
        tag = request.args.get("tag")
        
        if layer:
            checkers = registry.get(layer)
            return jsonify({"layer": layer, "count": len(checkers), "checkers": [
                {
                    "id": c.id or c.name,
                    "name": c.name,
                    "category": c.category,
                    "layer": c.layer,
                    "tags": getattr(c, 'tags', []) or [],
                }
                for c in checkers
            ]})
        
        if category:
            checkers = registry.list_by_category(category)
            return jsonify({"category": category, "count": len(checkers), "checkers": [
                {
                    "id": c.id or c.name,
                    "name": c.name,
                    "category": c.category,
                    "layer": c.layer,
                    "tags": getattr(c, 'tags', []) or [],
                }
                for c in checkers
            ]})
        
        if tag:
            checkers = registry.get_by_tag(tag)
            return jsonify({"tag": tag, "count": len(checkers), "checkers": [
                {
                    "id": c.id or c.name,
                    "name": c.name,
                    "category": c.category,
                    "layer": c.layer,
                    "tags": getattr(c, 'tags', []) or [],
                }
                for c in checkers
            ]})
        
        # Return overview
        all_checkers = registry.list_all()
        return jsonify({
            "layers": {
                layer: len(checkers)
                for layer, checkers in all_checkers.items()
            },
            "total": sum(len(checkers) for checkers in all_checkers.values()),
            "tags": registry.list_all_tags()
        })

    @app.route("/api/search/clear-cache", methods=["POST"])
    def clear_search_cache():
        """Clear the search engine cache."""
        search_engine.clear_cache()
        return jsonify({"status": "cache cleared"})
