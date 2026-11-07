# CISA KEV badge app

The CISA KEV menu app connects directly to CISA's public JSON catalog over verified HTTPS. No API key or computer relay is required.

CISA publishes dateAdded as YYYY-MM-DD, so the app displays additions dated today or yesterday in UTC. This window can include more than 24 hours. Each page shows the CVE, vendor/product, description, required action, due date and CISA's ransomware-use flag. Long text is shortened to fit.

## Wi-Fi setup

Fill in the ssid and password strings in kev-wifi.json locally, then copy that file to /data/kev-wifi.json on the badge. Use a 2.4 GHz network with a normal personal password or an open network. Captive portals and enterprise authentication require additional implementation. Keep the real configuration out of GitHub.

Upload firmware/badge/apps/kev.py to /apps/kev.py, firmware/badge/lib/kev_client.py to /lib/kev_client.py and firmware/badge/data/kev-ca.pem to /data/kev-ca.pem.

The optional "startup_app": "CISA KEV" field in /data/panel_config.json makes the dashboard launch automatically at power-on. main.py supports this setting by app name. Without it, normal menu startup is used.

Restart the badge, select CISA KEV with Menu +/- and press A or B to launch it. A advances to the next CVE, B refreshes, and Menu +/- returns to app selection. While the app is selected it refreshes every six hours and retries failures after fifteen minutes.

The clock synchronizes using NTP before each fetch. The app checks CISA's certificate and hostname against the included DigiCert Global Root G3 CA. If CISA changes its certificate chain, the trust file may need updating.

A complete successful result replaces /data/kev-cache.json. Failed refreshes retain the previous result and show an error alongside the original check time and date window. No additions produces an explicit empty view. Downloads parse one vulnerability at a time to bound memory use. DNS, NTP and HTTPS operations can briefly pause button handling.

On this badge's LVGL firmware, repeated MicroPython soft resets can cause display initialization failures. A hardware reset restores normal initialization. File uploads should be followed by a hardware reset.
