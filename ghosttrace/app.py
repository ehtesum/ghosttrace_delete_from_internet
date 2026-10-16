import logging
import pathlib
import time
import asyncio
from typing import Any

from flask import Flask, Response, render_template, request, stream_with_context, jsonify
from flask_cors import CORS

from .core.events import format_sse
from .core.manager import AsyncScannerManager
from .core.proxies import ProxyConfig
from .core.registry import registry

logger = logging.getLogger(__name__)
logging.disable(logging.CRITICAL)

BASE_DIR = pathlib.Path(__file__).resolve().parent


def create_app() -> Flask:
    app = Flask(__name__, template_folder=str(BASE_DIR.parent / "templates"))
    CORS(app, origins=["http://127.0.0.1:5000", "http://localhost:5000"])

    registry.discover_plugins("ghosttrace.checkers")
    manager = AsyncScannerManager()

    @app.after_request
    def _privacy(response: Response) -> Response:
        response.headers.pop("Server", None)
        response.headers["Cache-Control"] = "no-store, no-cache, private"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/scan")
    def scan():
        email = request.args.get("email", "").strip().lower()
        layer = request.args.get("layer", "surface")
        hibp_key = request.args.get("hibp_key", "").strip()
        emailrep_key = request.args.get("emailrep_key", "").strip()
        use_tor = request.args.get("tor", "0") == "1"

        if not email or "@" not in email or "." not in email:
            return jsonify({"error": "Invalid email address"}), 400

        config = {
            "hibp_key": hibp_key,
            "emailrep_key": emailrep_key,
            "proxy": ProxyConfig(use_tor=use_tor),
            "timestamp": int(time.time()),
        }

        async def generate():
            async for event in manager.scan_email(email, layer=layer, config=config):
                yield format_sse(event)

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route("/api/username-scan")
    def username_scan():
        username = request.args.get("username", "").strip()
        use_tor = request.args.get("tor", "0") == "1"

        if not username or len(username) > 64:
            return jsonify({"error": "Username required (max 64 chars)"}), 400

        config = {"proxy": ProxyConfig(use_tor=use_tor), "timestamp": int(time.time())}

        async def generate():
            async for event in manager.scan_username(username, config=config):
                yield format_sse(event)

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route("/api/image-scan", methods=["POST"])
    def image_scan():
        # Accept multipart form uploads with a file field named 'image'
        if "image" not in request.files:
            return jsonify({"error": "No image uploaded"}), 400

        f = request.files["image"]
        if not f or f.filename == "":
            return jsonify({"error": "Invalid image upload"}), 400

        data = f.read()
        use_tor = request.form.get("tor", request.args.get("tor", "0")) == "1"
        config = {"proxy": ProxyConfig(use_tor=use_tor), "timestamp": int(time.time())}

        try:
            result = asyncio.run(manager.scan_image(data, filename=f.filename, config=config))
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify(result)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
