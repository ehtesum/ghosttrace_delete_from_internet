"""
Reverse image search — provides links to external services and an optional
automated Yandex upload (sends image to yandex.com servers, user-initiated).
"""


def get_search_services() -> list:
    return [
        {
            "name": "Google Lens",
            "url": "https://lens.google.com/",
            "icon": "🔍",
            "description": "General matching, text/objects, similar scenes",
            "free": True,
            "faces": False,
        },
        {
            "name": "Yandex Images",
            "url": "https://yandex.com/images/",
            "icon": "🔎",
            "description": "Best face recognition & finding similar photos",
            "free": True,
            "faces": True,
        },
        {
            "name": "TinEye",
            "url": "https://tineye.com/",
            "icon": "👁",
            "description": "Find exact copies, track where image appeared",
            "free": True,
            "faces": False,
        },
        {
            "name": "Bing Visual Search",
            "url": "https://www.bing.com/visualsearch",
            "icon": "🌐",
            "description": "Microsoft — products, scenes, similar images",
            "free": True,
            "faces": False,
        },
        {
            "name": "FaceCheck.ID",
            "url": "https://facecheck.id/",
            "icon": "👤",
            "description": "Face search across social media & public sites",
            "free": True,
            "faces": True,
        },
        {
            "name": "PimEyes",
            "url": "https://pimeyes.com/en",
            "icon": "👁️",
            "description": "Most powerful face recognition across the web",
            "free": False,
            "faces": True,
        },
        {
            "name": "Karma Decay",
            "url": "https://karmadecay.com/",
            "icon": "📋",
            "description": "Find image reposts on Reddit",
            "free": True,
            "faces": False,
        },
        {
            "name": "Berify",
            "url": "https://berify.com/",
            "icon": "🛡",
            "description": "Reverse image search + copyright protection",
            "free": False,
            "faces": False,
        },
    ]


def try_yandex_upload(image_bytes: bytes) -> dict:
    """
    Upload image to Yandex reverse image search.
    NOTE: This sends the image to yandex.com servers. Only call when the user
    explicitly initiates this action.
    """
    import requests
    import re

    result = {
        "success": False,
        "search_url": None,
        "message": "",
        "service": "Yandex Images",
    }

    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://yandex.com/images/",
        })

        upload_resp = session.post(
            "https://yandex.com/images/search",
            params={
                "rpt": "imageview",
                "format": "json",
                "request": '{"blocks":[{"block":"b-page_type_search-by-image__link"}]}',
            },
            files={"upfile": ("image.jpg", image_bytes, "image/jpeg")},
            timeout=20,
        )

        if upload_resp.status_code == 200:
            try:
                data = upload_resp.json()
                for block in data.get("blocks", []):
                    html = block.get("html", "")
                    m = re.search(r'href="(/images/search\?[^"]+)"', html)
                    if m:
                        result["search_url"] = "https://yandex.com" + m.group(1).replace("&amp;", "&")
                        result["success"] = True
                        result["message"] = "Upload successful — click to view results"
                        break
                if not result["success"]:
                    result["message"] = "Upload succeeded but could not extract result URL"
            except Exception as je:
                result["message"] = f"Parse error: {str(je)[:80]}"
        else:
            result["message"] = f"HTTP {upload_resp.status_code}"

    except requests.exceptions.Timeout:
        result["message"] = "Request timed out"
    except Exception as e:
        result["message"] = f"Error: {str(e)[:100]}"

    return result
