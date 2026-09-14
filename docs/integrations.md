# Notifications, backups and sharing

[Home](../README.md) · [Documentation](../README.md#documentation)

## Telegram

In Settings, enter a BotFather token and the receiving Chat ID. Send `/start`
to the bot from the receiving account before using a private chat. Use the
receiver's chat ID, not the bot's own numeric ID. In groups/channels, give the
bot membership and permission to post.

Enable notifications for engine lifecycle events, successful subscription
refreshes with counts and active-node health failures. The optional health
monitor checks the active configuration every five minutes and suppresses
repeated failures until recovery. Notifications use a bounded queue and timeout;
a delivery failure does not stop routing.

**Send Telegram through proxy** OFF connects directly from the Debian host and ignores
HTTP proxy environment variables. ON uses an isolated sing-box process with
Global Default or a pinned configuration. Global Default follows the active
choice, using a saved healthy candidate when automatic selection is offline.
An unavailable explicit choice fails without route fallback. Groups use their
first saved member. This does not change LAN routes.

**Save & send test message** saves settings and starts a test even if automatic
notifications are disabled. Errors show the API description and delivery path.
A bot-to-bot 403 means the destination ID must be corrected. HTML/non-API
rejections call for inspecting the network path. Never publish tokens; revoke
exposed tokens in BotFather. [Telegram API](https://core.telegram.org/bots/api).

## Backup and restore

Download Backup streams a ZIP containing `nodes.json`, `state.json`, `tproxy.conf`
and `devices.json`. It includes proxy credentials and Telegram secrets. Store
it privately.

Restore Backup validates archive names, sizes, state references and configuration
before replacing managed settings. It reconciles the engine with the saved
ON/OFF intent. The archive does not include the executable, systemd unit,
UFW/NAT rules, engine cache or downloaded rule-set payloads. Preserve host setup
separately and redownload rule sets as needed.

## Speed tests

Speed Test starts a bounded fixed-payload download through an isolated sing-box
process for that node and its detours, using a loopback SOCKS client. The result
is measured Mbps, not a latency-derived estimate. Remote download endpoints can
refuse traffic or time out; an HTTP 403 from a speed endpoint is independent of
Telegram permissions. Tests consume real data and share host bandwidth.

## QR sharing

QR Code requests an explicit share link for a supported single node. Links and
QR images contain credentials. Rendering happens in the browser; HooLAN permits
a pinned qrcode.js CDN resource for this purpose. The link is not sent to the
renderer host. If the renderer cannot load, copy the link from the dialog.
Multi-hop chains and distribution groups cannot be exported as one ordinary
node URL.
