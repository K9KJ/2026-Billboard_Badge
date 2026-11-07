# CISA KEV badge app

The CISA KEV menu app connects directly to CISA's public JSON catalog over verified HTTPS. No API key or computer relay is required.

CISA publishes dateAdded as YYYY-MM-DD, so the app displays additions dated today or either of the previous two dates in UTC. This window can include more than 48 hours. Each page lists up to five CVE IDs and vulnerability titles. Titles wrap across two lines. The compact cache keeps only the CVE ID, title and date added. CISA's endpoint supplies the full catalog, which the badge filters as it streams the download.

## Wi-Fi setup

Fill in the ssid and password strings in kev-wifi.json locally, then copy that file to /data/kev-wifi.json on the badge. Use a 2.4 GHz network with a normal personal password or an open network. Captive portals and enterprise authentication require additional implementation. Keep the real configuration out of GitHub.

Upload firmware/badge/apps/kev.py to /apps/kev.py, firmware/badge/lib/kev_client.py to /lib/kev_client.py and firmware/badge/data/kev-ca.pem to /data/kev-ca.pem.

The optional "startup_app": "CISA KEV" field in /data/panel_config.json makes the dashboard launch automatically at power-on. main.py supports this setting by app name. Without it, normal menu startup is used.

Restart the badge, select CISA KEV with Menu +/- and press A or B to launch it. A advances to the next page when more than five CVEs match, B refreshes, and Menu +/- returns to app selection. While the app is selected it refreshes every six hours and retries failures after fifteen minutes.

The clock attempts NTP before each fetch. If NTP is blocked and the RTC already has a usable date, verified HTTPS still works. The authenticated HTTP Date from CISA then sets the UTC clock and date window. After complete power loss, NTP or a one-time clock setup may be needed. The app checks CISA's certificate and hostname against the included DigiCert Global Root G3 CA. If CISA changes its certificate chain, the trust file may need updating.

A complete successful result replaces /data/kev-cache.json. Failed refreshes retain the previous result and show an error alongside the original check time and date window. No additions produces an explicit empty view. Downloads parse one vulnerability at a time to bound memory use. DNS, NTP and HTTPS operations can briefly pause button handling.

On this badge's LVGL firmware, repeated MicroPython soft resets can cause display initialization failures. A hardware reset restores normal initialization. File uploads should be followed by a hardware reset.

## Display performance

The full-color driver incorporates the hardware SPI, Viper pixel conversion, framebuffer preparation and queued-refresh fixes from Hack-a-Day/2026-Billboard_Badge PR #3 by FacioErgoSum (reviewed at 67fd7b8183b70fe6f327ab1af5a7f809ed994b47). BUSY polling has a timeout that raises an error. The display task records failures in display.last_error and logs them.

The KEV app refreshes its screen after the fetch completes. It shows the saved result at startup and prints connection progress to serial.

On this badge, the initial optimized dashboard render took 618 ms, image transfer took 204 ms (previously about 5,303 ms), and the full-color panel phase took 32,795 ms. Full-color waveforms remain in use. Optional short-waveform refresh is a separate future step requiring image-quality checks.
