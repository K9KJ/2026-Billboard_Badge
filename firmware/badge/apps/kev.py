"""CISA KEV badge app. Wi-Fi credentials stay in /data/kev-wifi.json."""

import asyncio as aio
import json
import os
import time
import network
import ntptime
import lvgl

from apps.base_app import BaseApp
from lib.button import UserA, UserB
from lib.epd import display
from lib.kev_client import date_string, fetch_recent

CACHE = "/data/kev-cache.json"
REFRESH_MS = 6 * 60 * 60 * 1000
RETRY_MS = 15 * 60 * 1000


class KevApp(BaseApp):
    def __init__(self):
        super().__init__("CISA KEV")
        self.page = 0
        self.data = None
        self.status = "Not checked"
        self.next_check = time.ticks_ms()
        self.screen = None
        try:
            with open(CACHE) as file:
                cached = json.load(file)
            if not isinstance(cached.get("entries"), list) or "checked" not in cached:
                raise ValueError("Invalid cache")
            self.data = cached
            self.status = "Saved result - refresh pending"
        except (OSError, ValueError):
            pass

    async def refresh(self):
        self.status = "Connecting to Wi-Fi..."
        self.draw()
        # Let the display task consume this frame before networking starts.
        await aio.sleep_ms(200)
        while not display.is_done_updating():
            await aio.sleep_ms(100)
        try:
            wlan = network.WLAN(network.STA_IF)
            if not wlan.isconnected():
                try:
                    with open("/data/kev-wifi.json") as file:
                        config = json.load(file)
                except (OSError, ValueError):
                    raise ValueError("Set up /data/kev-wifi.json first")
                if not config.get("ssid"):
                    raise ValueError("Set Wi-Fi SSID in kev-wifi.json")
                wlan.active(True)
                wlan.connect(config["ssid"], config.get("password", ""))
                deadline = time.ticks_add(time.ticks_ms(), 20000)
                while not wlan.isconnected():
                    if wlan.status() < 0 or time.ticks_diff(time.ticks_ms(), deadline) >= 0:
                        wlan.disconnect()
                        raise OSError("Wi-Fi connection failed")
                    await aio.sleep_ms(200)
            try:
                ntptime.settime()
            except OSError:
                # With a valid RTC, TLS can still verify CISA. Its authenticated
                # HTTP Date sets the exact UTC window before filtering.
                if time.gmtime()[0] < 2025:
                    raise ValueError("Set badge clock or allow NTP, then retry")
            result = fetch_recent()
            # Replace the cache only after a complete, validated download.
            with open(CACHE + ".tmp", "w") as file:
                json.dump(result, file)
            os.rename(CACHE + ".tmp", CACHE)
            self.data = result
            self.page = 0
            self.status = "Live CISA feed"
            print("KEV updated:", [entry["cveID"] for entry in result["entries"]])
            self.next_check = time.ticks_add(time.ticks_ms(), REFRESH_MS)
        except Exception as error:
            print("KEV refresh failed:", error)
            self.status = ("Saved result / " if self.data else "") + "Refresh failed - " + str(error)[:80]
            self.next_check = time.ticks_add(time.ticks_ms(), RETRY_MS)
        self.draw()

    def label(self, text, y, font, color=0x000000, height=None):
        label = lvgl.label(self.screen)
        label.set_text(text)
        label.set_width(896)
        if height is not None:
            label.set_height(height)
        label.set_pos(32, y)
        label.set_style_text_font(font, 0)
        label.set_style_text_color(lvgl.color_hex(color), 0)

    def draw(self):
        old_screen = self.screen
        self.screen = lvgl.obj()
        self.screen.remove_style_all()
        self.screen.set_size(960, 672)
        self.screen.set_style_bg_color(lvgl.color_hex(0xFFFFFF), 0)
        self.screen.set_style_bg_opa(lvgl.OPA.COVER, 0)
        self.label("CISA / KNOWN EXPLOITED", 18, lvgl.font_montserrat_36, 0xFF0000)
        window = ("Added %s to %s (UTC)" % (self.data["yesterday"], self.data["today"])
                  if self.data else "Today + yesterday (UTC)")
        self.label(window, 63, lvgl.font_montserrat_24)
        entries = self.data["entries"] if self.data else []
        if self.data:
            checked = self.data["checked"]
            clock = time.gmtime(checked)
            checked_text = "%s %02d:%02d UTC" % (date_string(checked), clock[3], clock[4])
            self.label("Checked " + checked_text, 100, lvgl.font_montserrat_24)
        if entries:
            self.page %= len(entries)
            entry = entries[self.page]
            self.label(entry["cveID"] + "   (%d/%d)" % (self.page + 1, len(entries)),
                       146, lvgl.font_montserrat_36, 0xFF0000)
            product = entry["vendorProject"] + " / " + entry["product"]
            self.label(product[:100], 195, lvgl.font_montserrat_28, height=70)
            self.label(entry["shortDescription"][:300], 275, lvgl.font_montserrat_24, height=150)
            self.label("Action: " + entry["requiredAction"][:165],
                       432, lvgl.font_montserrat_24, height=90)
            self.label("Added %s | Due %s | Ransomware: %s" %
                       (entry["dateAdded"], entry["dueDate"], entry["knownRansomwareCampaignUse"]),
                       531, lvgl.font_montserrat_16)
        else:
            message = "No additions in this date window" if self.data else "Wi-Fi setup required"
            self.label(message, 210, lvgl.font_montserrat_36)
            detail = ("Window: %s to %s UTC" % (self.data["yesterday"], self.data["today"])
                      if self.data else "Fill in kev-wifi.json, then press B to refresh.")
            self.label(detail, 278, lvgl.font_montserrat_24, height=100)
        self.label(self.status, 573, lvgl.font_montserrat_16, 0xFF0000, height=42)
        self.label("A: Next CVE    B: Refresh    Menu +/-: Apps", 630, lvgl.font_montserrat_16)
        lvgl.screen_load(self.screen)
        lvgl.refr_now(display.lv_display)
        display.update()
        if old_screen is not None:
            old_screen.delete()

    async def arun(self):
        if self.launched:
            self.draw()
        if display.is_done_updating():
            if UserA.pressed() and self.data and self.data["entries"]:
                self.page = (self.page + 1) % len(self.data["entries"])
                self.draw()
            elif UserB.pressed() or time.ticks_diff(time.ticks_ms(), self.next_check) >= 0:
                await self.refresh()
        await aio.sleep_ms(100)
