"""
Stage 19 - Capture screenshots of the running analyst console for the Milestone 2 document.

A marker reading the PDF should be able to see that the prototype exists and what it does,
without installing anything. This script starts the Streamlit app on a spare port, drives it
with headless Chromium, and saves one screenshot per view into outputs/figures/.

Run it on its own with:  python src/s19_app_screenshots.py
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import OUT_FIGS, ROOT, get_logger

LOG = get_logger("s19_shots")
PORT = 8613

# (tab label, output file, extra scroll in pixels before the shot)
VIEWS = [
    ("Overview", "fig27_console_overview.png", 0),
    ("Accounts & risk", "fig28_console_accounts.png", 0),
    ("Investigation", "fig29_console_investigation.png", 0),
    ("Simulation", "fig30_console_simulation.png", 120),
]


def main() -> None:
    proc = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", str(ROOT / "app" / "app.py"),
         "--server.headless", "true", "--server.port", str(PORT),
         "--browser.gatherUsageStats", "false"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    time.sleep(15)

    script = f"""
import time
from playwright.sync_api import sync_playwright
views = {VIEWS!r}
with sync_playwright() as pw:
    b = pw.chromium.launch()
    pg = b.new_page(viewport={{"width": 1500, "height": 1000}}, device_scale_factor=2)
    pg.goto("http://localhost:{PORT}", timeout=90000)
    pg.wait_for_selector('[data-testid="stTab"]', timeout=90000)
    pg.wait_for_timeout(9000)
    for label, out, scroll in views:
        tab = pg.locator('[data-testid="stTab"]', has_text=label).first
        tab.click()
        pg.wait_for_timeout(6500)
        if scroll:
            pg.mouse.wheel(0, scroll)
            pg.wait_for_timeout(2500)
        pg.screenshot(path=r"{OUT_FIGS}/" + out)
        print("captured", out)
    b.close()
"""
    try:
        res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True,
                             timeout=400)
        LOG.info("%s", res.stdout.strip() or res.stderr.strip()[-400:])
    finally:
        proc.terminate()

    for _label, out, _s in VIEWS:
        p = OUT_FIGS / out
        LOG.info("%-34s %s", out, f"{p.stat().st_size/1e3:.0f} kB" if p.exists() else "MISSING")


if __name__ == "__main__":
    main()
