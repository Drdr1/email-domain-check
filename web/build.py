#!/usr/bin/env python3
"""Builds web/dist/email-check.html: inlines src/emailcheck.js and the settings in web/site.json."""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
site = json.loads((ROOT / "web/site.json").read_text())
core = (ROOT / "src/emailcheck.js").read_text()
if "</script" in core.lower():
    raise SystemExit("emailcheck.js contains '</script' and cannot be inlined")

html = (ROOT / "web/email-check.template.html").read_text()
html = (html.replace("{{CORE_JS}}", core)
            .replace("{{UPWORK_OFFER_URL}}", site.get("upwork_offer", ""))
            .replace("{{UPWORK_PROFILE_URL}}", site.get("upwork_profile", ""))
            .replace("{{OFFERS_JSON}}", json.dumps(site.get("offers", []))))
assert "{{" not in html, "unreplaced placeholder"

out = ROOT / "web/dist/email-check.html"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(html)
print(f"wrote {out} ({len(html):,} bytes)")
