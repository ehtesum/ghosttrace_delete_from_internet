import importlib
import sys
from pathlib import Path

import pytest

from ghosttrace.core.base_checker import BaseChecker
from ghosttrace.core.registry import CheckerRegistry, registry


def test_import_safe_without_plugin_discovery():
    import ghosttrace
    import ghosttrace.app

    assert "ghosttrace.checkers.surface.example_checker" not in sys.modules
    assert "ghosttrace.checkers.username.example_username" not in sys.modules
    assert hasattr(ghosttrace, "create_app")


def test_registry_discover_plugins_registers_example_checkers():
    registry = CheckerRegistry()
    registry.discover_plugins("ghosttrace.checkers")

    surface_checkers = registry.get("surface")
    username_checkers = registry.get("username")

    assert any(checker.id == "example_surface" for checker in surface_checkers)
    assert any(checker.id == "example_username" for checker in username_checkers)
    assert registry.get_by_id("example_surface").category == "testing"
    assert "surface" in registry.list_all()
    assert "username" in registry.list_all()


def test_registry_duplicate_prevention():
    registry = CheckerRegistry()

    class DuplicateChecker(BaseChecker):
        id = "duplicate"
        name = "Duplicate Checker"
        category = "testing"
        layer = "surface"

        async def scan(self, query, session, config):
            return {
                "status": "ok",
                "confidence": 1.0,
                "evidence": [],
                "links": [],
                "metadata": {},
                "raw": {},
            }

    registry.register(DuplicateChecker())
    registry.register(DuplicateChecker())

    assert len(registry.get("surface")) == 1
    assert registry.get_by_id("duplicate") is not None


def test_broken_plugin_isolated(tmp_path, monkeypatch):
    package_dir = tmp_path / "fake_plugins"
    package_dir.mkdir()
    (package_dir / "__init__.py").write_text("# fake plugin package\n")
    (package_dir / "good.py").write_text(
        "from ghosttrace.core.base_checker import BaseChecker\n"
        "\n"
        "class GoodChecker(BaseChecker):\n"
        "    id = 'good'\n"
        "    name = 'Good Checker'\n"
        "    category = 'testing'\n"
        "    layer = 'surface'\n"
        "\n"
        "    async def scan(self, query, session, config):\n"
        "        return {'status': 'ok', 'confidence': 1.0, 'evidence': [], 'links': [], 'metadata': {}, 'raw': {}}\n"
    )
    (package_dir / "broken.py").write_text("raise RuntimeError('boom')\n")

    monkeypatch.syspath_prepend(str(tmp_path))

    registry = CheckerRegistry()
    registry.discover_plugins("fake_plugins")

    assert registry.get_by_id("good") is not None
    assert registry.get("surface")
    assert registry.get_by_id("good").name == "Good Checker"
