"""Records the README demo: starts the engine, drives the dashboard with Playwright, and
produces docs/media/demo.mp4, docs/media/demo.gif and screenshots.

    pip install -r scripts/requirements-demo.txt && python -m playwright install chromium
    python scripts/record_demo.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import imageio_ffmpeg
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
MEDIA = ROOT / "docs" / "media"
PORT = 8011
URL = f"http://127.0.0.1:{PORT}"
W, H = 1600, 1000


def wait_ready(timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(URL + "/api/health", timeout=1)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError("engine did not start")


def post(path):
    urllib.request.urlopen(urllib.request.Request(URL + path, method="POST"), timeout=3)


def smooth_scroll(page, dy, steps=12, pause=0.06):
    for _ in range(steps):
        page.mouse.wheel(0, dy / steps)
        time.sleep(pause)


def main():
    MEDIA.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp())
    env = {**os.environ, "THREATPULSE_DB": str(tmp / "demo.db")}
    server = subprocess.Popen(
        [sys.executable, "-m", "threatpulse.cli", "run", "--port", str(PORT), "--speed", "2.5",
         "--intensity", "1.6", "--seed", "21"],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        wait_ready()
        time.sleep(22)  # let the Half-Space-Trees model finish warming up on benign traffic

        with sync_playwright() as p:
            browser = p.chromium.launch()
            ctx = browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=1,
                                      record_video_dir=str(tmp), record_video_size={"width": W, "height": H})
            page = ctx.new_page()
            page.goto(URL)
            page.wait_for_selector(".kpi-value")
            time.sleep(5)

            page.get_by_role("button", name="Full kill chain").click()
            time.sleep(7)
            page.get_by_role("button", name="ioc contact").click()
            time.sleep(6)
            page.get_by_role("button", name="syn flood").click()
            time.sleep(8)
            page.screenshot(path=str(MEDIA / "dashboard.png"))

            smooth_scroll(page, 640)
            time.sleep(3)
            rows = page.locator(".alert-row")
            if rows.count():
                rows.nth(0).click()
            time.sleep(5)
            smooth_scroll(page, 520)
            time.sleep(6)
            page.screenshot(path=str(MEDIA / "graph.png"))
            smooth_scroll(page, -1160, steps=16)
            time.sleep(4)

            # Wait for the kill chain to reach lateral movement and exfiltration
            deadline = time.time() + 70
            while time.time() < deadline:
                if page.locator(".incident-title", has_text="Multi-stage").count() and \
                        page.locator(".incident-bottom", has_text="6 tactics").count():
                    break
                time.sleep(1)
            time.sleep(3)
            page.screenshot(path=str(MEDIA / "killchain.png"))

            smooth_scroll(page, 640)
            time.sleep(2)
            page.locator(".incident-title", has_text="Multi-stage").first.click()
            time.sleep(4)
            page.screenshot(path=str(MEDIA / "incident.png"))
            drawer = page.locator(".drawer")
            for _ in range(6):
                drawer.evaluate("el => el.scrollBy({top: 130, behavior: 'smooth'})")
                time.sleep(0.7)
            time.sleep(2)
            page.locator(".actions .danger").first.click()
            time.sleep(3)
            for _ in range(6):
                drawer.evaluate("el => el.scrollBy({top: 160, behavior: 'smooth'})")
                time.sleep(0.6)
            time.sleep(2)
            page.locator(".close").click()
            time.sleep(1)
            smooth_scroll(page, 520)
            time.sleep(5)
            smooth_scroll(page, -1200, steps=16)
            time.sleep(4)

            video = page.video.path()
            ctx.close()
            browser.close()

        ff = imageio_ffmpeg.get_ffmpeg_exe()
        mp4 = MEDIA / "demo.mp4"
        subprocess.run([ff, "-y", "-loglevel", "error", "-i", video, "-c:v", "libx264", "-pix_fmt", "yuv420p",
                        "-crf", "26", "-preset", "slow", "-movflags", "+faststart", str(mp4)], check=True)
        palette = tmp / "palette.png"
        vf = "setpts=PTS/2.2,fps=5,scale=920:-1:flags=lanczos"
        subprocess.run([ff, "-y", "-loglevel", "error", "-i", str(mp4), "-vf", f"{vf},palettegen=max_colors=96:stats_mode=diff",
                        str(palette)], check=True)
        subprocess.run([ff, "-y", "-loglevel", "error", "-i", str(mp4), "-i", str(palette), "-lavfi",
                        f"{vf} [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle",
                        str(MEDIA / "demo.gif")], check=True)
        for f in ("demo.mp4", "demo.gif"):
            print(f, f"{(MEDIA / f).stat().st_size / 1e6:.1f} MB")
    finally:
        server.terminate()
        server.wait(10)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
