# HooLAN dashboard

[Home](../README.md) · [Documentation](../README.md#documentation)

Sign in using `HOOLAN_TOKEN`. Browser authentication uses an HttpOnly session
cookie and CSRF protection. The header provides engine ON/OFF, theme, language
and sign-out controls. Status cards show the process, interception rules,
configuration count and selected outbound.

## Configurations

**Add & create** contains Add a configuration, Add a subscription, Chain Builder
and Load balancing. Manual configurations and subscriptions use separate cards;
subscription lists collapse from their headers. Row selections drive each
card's Bulk Ping and Bulk Delete actions. Click Configuration, Protocol, Server,
Latency or Checked to sort that card; click again to reverse. Untested latency
and missing timestamps stay at the bottom.

The global automatic-selection switch lives in Load balancing. It selects an
ordinary configuration by measured latency. Activate a saved group to use that
group's strategy. Explicit manual selection stops the global background URLTest
sweep; tests requested from the UI remain available.

See [configuration management](configurations.md) and [group strategies](load-balancing.md).

## Usage

Click a column heading to sort; click it again to reverse the direction. The
arrow shows the current order, which is kept during automatic refreshes. Node
and device tables support names, upload and download; device tables also support
IP address, route and speed limits. Nodes with zero usage stay hidden. A device's **Speed set** column shows its saved limits;
**Settings** edits its alias, outbound and four limit fields. Reset limits clears
all four inputs; Save device settings applies the reset.

Counters are payload measurements from sing-box. Per-node, direct and per-device
attribution is estimated from one-second connection samples, so short flows can
be missed. [Device and usage details](devices.md).

## Settings

The cards are Routing & DNS, Telegram notifications, then Backup & restore.
Routing includes DNS, update scheduling, the Iran preset, custom rule sets and
custom match rules. Configure **Tunneled DoH Server**, **Direct DNS Server** and
**DNS listen address** using the [DNS & FakeDNS guide](dns.md). The TCP/UDP
listener on port 1053 works independently of the FakeDNS
switch. The listen-address controls are shown only when FakeDNS is switched on;
hiding them does not clear the saved address or stop split DNS. To change this
address while keeping FakeDNS off, switch it on in the form, edit the address,
switch it off again, then save. Both resolver fields remain editable in either mode. Save settings
applies these edits; follow the guide before changing DNS clients or turning the
engine off. Telegram has separate notification and proxy-delivery
switches, a proxy selector and an explicit test button. Error messages appear
separately from field descriptions.

## Live logs

Turn the SSE stream on to see recent and incoming service/engine logs. Turn it
off to pause the browser stream. The view retains at most 500 lines; scrolling
up pauses automatic scrolling. Clear view affects only the browser display.
The service keeps a bounded replay buffer and supports Last-Event-ID reconnects.
Use journald for persistent operational history.

## Appearance and accessibility

The red-accent UI supports dark/light themes, English/Persian text and RTL
layout. The logo and browser-tab icon follow the theme. Preferences live in
`hoolan-theme` and `hoolan-language` in browser storage. Node names and other
user content are not translated. Keyboard focus outlines and reduced-motion
preferences are supported.
