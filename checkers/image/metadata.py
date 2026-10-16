"""
EXIF and image metadata extraction — fully local, no network requests.
Extracts GPS, device fingerprint, timestamps, authorship, and serial numbers.
"""
import io


def extract_metadata(image_bytes: bytes, filename: str = "") -> dict:
    result = {
        "filename": filename,
        "file_size": len(image_bytes),
        "file_size_human": _human_size(len(image_bytes)),
        "format": _detect_format(image_bytes, filename),
        "gps": None,
        "device": {},
        "timestamps": {},
        "software": None,
        "dimensions": None,
        "color_mode": None,
        "exif_fields": {},
        "findings": [],
        "risk_indicators": [],
    }

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        img = Image.open(io.BytesIO(image_bytes))
        result["dimensions"] = {
            "width": img.width,
            "height": img.height,
            "mpx": round(img.width * img.height / 1_000_000, 2),
        }
        result["color_mode"] = img.mode

        exif_data = None
        try:
            exif_data = img._getexif()
        except AttributeError:
            pass  # PNG, GIF, etc.

        if not exif_data:
            result["findings"].append(
                "No EXIF data found — metadata was stripped or format doesn't support it"
            )
            return result

        # Decode all EXIF tags into flat string dict
        parsed = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, f"Tag_{tag_id}")
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    value = f"<binary {len(value)} bytes>"
            parsed[tag] = value

        result["exif_fields"] = {
            k: str(v)[:200]
            for k, v in parsed.items()
            if not isinstance(v, dict)
        }

        # Device fingerprinting
        for field in ("Make", "Model", "LensModel", "LensMake"):
            if field in parsed and str(parsed[field]).strip():
                result["device"][field] = str(parsed[field]).strip()

        if result["device"]:
            camera = f"{result['device'].get('Make', '')} {result['device'].get('Model', '')}".strip()
            if camera:
                result["findings"].append(f"Camera: {camera}")
                result["risk_indicators"].append({
                    "type": "device_fingerprint",
                    "severity": "medium",
                    "label": "Camera Model",
                    "value": camera,
                    "detail": "Device make/model reveals your equipment and can link multiple photos to the same owner",
                })

        # Serial numbers — uniquely identify a specific camera body
        for field in ("BodySerialNumber", "CameraSerialNumber", "SerialNumber", "InternalSerialNumber"):
            if field in parsed and str(parsed[field]).strip():
                serial = str(parsed[field]).strip()
                result["risk_indicators"].append({
                    "type": "serial_number",
                    "severity": "high",
                    "label": "Camera Serial Number",
                    "value": serial,
                    "detail": f"{field}: uniquely identifies your specific camera — links all photos from this body",
                })
                result["findings"].append(f"Serial: {serial}")

        # Software
        if "Software" in parsed and str(parsed["Software"]).strip():
            sw = str(parsed["Software"]).strip()
            result["software"] = sw
            result["findings"].append(f"Software: {sw}")
            if any(x in sw.lower() for x in ("adobe", "lightroom", "photoshop", "instagram", "snapchat", "facetune", "vsco")):
                result["risk_indicators"].append({
                    "type": "software",
                    "severity": "low",
                    "label": "Editing Software",
                    "value": sw,
                    "detail": "Reveals which app was used to capture or edit the image",
                })

        # Authorship fields — may directly name you
        for field in ("Artist", "Copyright", "XPAuthor", "XPComment", "XPTitle", "ImageDescription"):
            if field in parsed and str(parsed[field]).strip():
                val = str(parsed[field]).strip()
                result["risk_indicators"].append({
                    "type": "authorship",
                    "severity": "high",
                    "label": field,
                    "value": val,
                    "detail": f"{field} may directly identify you by name or copyright notice",
                })
                result["findings"].append(f"{field}: {val}")

        # Timestamps
        for ts_field in ("DateTime", "DateTimeOriginal", "DateTimeDigitized"):
            if ts_field in parsed:
                result["timestamps"][ts_field] = str(parsed[ts_field])

        if result["timestamps"]:
            result["findings"].append(f"Photo taken: {list(result['timestamps'].values())[0]}")

        # GPS — the most sensitive metadata
        gps_tag_id = next((k for k, v in TAGS.items() if v == "GPSInfo"), None)
        if gps_tag_id and gps_tag_id in exif_data:
            gps_raw = exif_data[gps_tag_id]
            gps = {GPSTAGS.get(k, k): gps_raw[k] for k in gps_raw}

            if "GPSLatitude" in gps and "GPSLongitude" in gps:
                try:
                    lat = _dms_to_dd(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
                    lon = _dms_to_dd(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
                    alt = None
                    if "GPSAltitude" in gps:
                        try:
                            av = gps["GPSAltitude"]
                            alt = round(float(av.numerator) / float(av.denominator), 1)
                        except Exception:
                            pass

                    result["gps"] = {
                        "lat": round(lat, 7),
                        "lon": round(lon, 7),
                        "alt_m": alt,
                        "maps_url": f"https://maps.google.com/?q={lat:.7f},{lon:.7f}",
                        "osm_url": f"https://www.openstreetmap.org/?mlat={lat:.7f}&mlon={lon:.7f}&zoom=17",
                        "street_view": f"https://maps.google.com/?q=&layer=c&cbll={lat:.7f},{lon:.7f}",
                    }
                    result["findings"].append(f"GPS: {lat:.5f}, {lon:.5f}")
                    result["risk_indicators"].append({
                        "type": "gps_location",
                        "severity": "critical",
                        "label": "GPS Location",
                        "value": f"{lat:.5f}, {lon:.5f}",
                        "detail": "Exact GPS coordinates embedded in image — reveals precisely where photo was taken",
                    })
                except Exception as e:
                    result["findings"].append(f"GPS data present but unreadable: {e}")

        if not result["findings"]:
            result["findings"].append("EXIF data found but no sensitive information detected")

    except ImportError:
        result["findings"].append("Pillow not installed — run: pip install Pillow")
    except Exception as e:
        result["findings"].append(f"Metadata extraction error: {str(e)[:200]}")

    return result


def _dms_to_dd(dms, ref: str) -> float:
    d = float(dms[0].numerator) / float(dms[0].denominator)
    m = float(dms[1].numerator) / float(dms[1].denominator)
    s = float(dms[2].numerator) / float(dms[2].denominator)
    dd = d + m / 60 + s / 3600
    if str(ref).upper() in ("S", "W"):
        dd = -dd
    return dd


def _detect_format(data: bytes, filename: str) -> str:
    sigs = {
        b"\xff\xd8\xff": "JPEG",
        b"\x89PNG\r\n": "PNG",
        b"GIF8": "GIF",
        b"RIFF": "WebP",
        b"MM\x00*": "TIFF",
        b"II*\x00": "TIFF",
    }
    for sig, fmt in sigs.items():
        if data[: len(sig)] == sig:
            return fmt
    if b"ftyp" in data[:12]:
        return "HEIC/MP4"
    ext = filename.rsplit(".", 1)[-1].upper() if "." in filename else ""
    return ext or "Unknown"


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"
