#!/usr/bin/env python3
"""Open a (headed) browser so a human can log in, then save Playwright storage state
(cookies + localStorage) for use with mapper.py --storage-state / replay.py --storage-state.

Usage: login.py URL --out state.json [--wait-seconds N] [--headless]
  - default: waits until you press Enter in this terminal (or the window is closed)
  - --wait-seconds N: save automatically after N seconds (for non-interactive use)
  - --wait-url REGEX: save as soon as the page URL matches (e.g. a post-login dashboard)
Needs a display for headed mode (DISPLAY is set on the box desktop).
"""
import argparse
import asyncio
import re
import sys

from playwright.async_api import async_playwright


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url")
    ap.add_argument("--out", required=True, help="storage-state JSON to write (contains secrets; keep private)")
    ap.add_argument("--wait-seconds", type=float, default=0)
    ap.add_argument("--wait-url", help="regex; save once page URL matches")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--user-agent")
    a = ap.parse_args()
    async with async_playwright() as pw:
        b = await pw.chromium.launch(headless=a.headless)
        ctx = await b.new_context(**({"user_agent": a.user_agent} if a.user_agent else {}))
        page = await ctx.new_page()
        await page.goto(a.url)
        if a.wait_url:
            print(f"waiting for URL matching {a.wait_url!r} ...", file=sys.stderr)
            await page.wait_for_url(re.compile(a.wait_url), timeout=0)
        elif a.wait_seconds:
            await page.wait_for_timeout(a.wait_seconds * 1000)
        else:
            print("Log in in the browser window, then press Enter here to save the session...", file=sys.stderr)
            await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline)
        await ctx.storage_state(path=a.out)
        print(f"saved storage state -> {a.out}", file=sys.stderr)
        await b.close()


if __name__ == "__main__":
    asyncio.run(main())
