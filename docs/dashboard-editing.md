# Dashboard editing, themes and Persian localization

Rebuild and deploy the Go binary to update both the backend and embedded assets.
No npm build, external fonts or frontend framework is needed.

## File-by-file changes

| File | Responsibility |
| --- | --- |
| `internal/api/devices.go` | Accept the reserved `direct` device target alongside a node ID or the empty global default |
| `internal/engine/singbox.go` | Render a source-IP rule whose outbound is `direct` for that target |
| `internal/api/edit.go` | Read/edit manual nodes and saved chains; validate edits and update ID references with rollback |
| `internal/api/handlers.go` | Add `chain_id` to node views so the dashboard chooses the correct editor |
| `internal/api/handlers_dashboard.go` | Register the new editor and expanded chain routes |
| `internal/api/web/index.html` | Header controls, manual editing dialog and chain editing/cancel state |
| `internal/api/web/app.js` | Direct option, collapsible subscription groups, credential-preserving editor and editable hop order |
| `internal/api/web/preferences.js` | Apply stored theme/language before rendering and wire the header buttons |
| `internal/api/web/i18n.js` | Embedded English/Persian catalog, static/dynamic label translation and restoration of original English text |
| `internal/api/web/style.css` | Shared form styles, theme variables, dropdown arrows, focus outlines, responsive editor and RTL layout |
| `internal/api/web/login.html` | Apply the same stored theme/language to sign-in |
| `internal/api/edit_test.go` | Editing, ownership isolation, rekeying, secret redaction, API/CSRF, persistence rollback and direct assignment tests |
| `internal/engine/devices_test.go`, `internal/api/static_test.go` | Direct rule generation and embedding of the new scripts |

## Direct device routing

```http
PUT /api/devices
Content-Type: application/json

{"ip":"192.168.3.141","node_id":"direct"}
```

Use `"node_id":""` for Global Default, or a stored node ID for a proxy. `direct`
is a reserved route target, not an inventory node, and survives subscription
pruning and node deletion. The source matcher and existing rule precedence stay
unchanged: safety/DNS/private/custom/Iran rules precede device rules, and the
proxy selector remains the final fallback. Thus Direct changes ordinary device
traffic without overriding earlier routing rules. This does not alter nftables.

## Collapsible subscription groups

Subscription cards use native `<details>` and `<summary>` with the full heading
as the toggle. They start collapsed. Open/closed state and checked nodes survive
inventory polling during the page session. Source URL, Refresh and group bulk
actions appear inside the expanded card. Manual configurations remain visible.
Keyboard users can toggle a focused summary with Enter or Space.

## Edit a manual configuration

```http
GET /api/nodes/edit?node_id=existing-id
```

Returns editable fields, including `name`, `server`, `port`, `protocol`, `sni`,
`security`, `transport`, `path`, `host`, `service_name`, `method`, `flow`,
`public_key`, `short_id`, `fingerprint` and `insecure`. It never returns stored
UUIDs or passwords. The dialog presents the credential field appropriate to the
protocol and leaves it blank; blank fields are omitted on save.

```http
PUT /api/nodes/edit
Content-Type: application/json

{"node_id":"existing-id","name":"My server","server":"new.example.com","port":443}
```

This is a partial update: omitted fields are preserved. `password` and `uuid`
can be explicitly supplied to replace credentials. Identity, ownership, protocol
and detour are not writable through this endpoint. Chains have their own editor.
The response contains the resulting `node_id`, which can change when endpoint
identity changes. Selections, device assignments and stored ID-based detour
references follow the edited configuration. Historical usage entries retain
their original IDs.

If a manually added node is also subscription-owned, editing makes an independent
manual copy and preserves the provider-owned original. Subsequent subscription
refreshes cannot overwrite that manual edit. Editing a subscription-only node is
rejected; manually import its link first if you need a separately editable copy.

## Edit a saved chain

```http
GET /api/chains?node_id=chain-exit-id
```

Returns its `name`, `node_id`, and ordered `hops` with `id`, `tag`, and `server`.
These IDs refer to the saved chain's private copies, so editing remains possible
even after the original provider nodes disappear.

```http
PUT /api/chains
Content-Type: application/json

{"node_id":"chain-exit-id","name":"Updated chain","node_ids":["retained-hop-id","new-single-hop-id","retained-exit-id"]}
```

Choose 2–8 distinct IDs in traversal order. Each must be a current hop of this
chain or an enabled original single-hop configuration. Hops from another saved
chain and nested chains are rejected. The backend reconstructs the private
copies, removes replaced hops and retargets selections/device assignments to the
new exit ID. The response returns that ID. Existing `POST /api/chains` still
creates new chains. Original nodes and other chains are unchanged.

Both editing operations serialize with other manager mutations and reject an
active refresh. Invalid edits and persistence failures restore the previous
inventory/state. Engine application failures also roll back the edited records
and managed routing configuration; the existing fail-safe may leave the engine
stopped with interception removed. Successful edits briefly restart an active
engine through the existing managed reload. When OFF, edits apply at next enable.
All editor routes use existing authentication and CSRF protection.

## Themes and language

Header controls switch Dark/Light and English/Persian immediately. Preferences
are stored only in `proxy-manager-theme` and `proxy-manager-language` in browser
localStorage; failure or denial of storage does not disable the controls. Theme
initialization runs before the stylesheet to avoid a flash of the other theme.
The initial theme follows the system preference when no explicit choice exists.
English is the initial language. Sign-in follows the same saved preferences.

Persian sets `<html lang="fa" dir="rtl">`. Forms, tables, navigation and switches
mirror, while addresses, credentials and raw log lines remain left-to-right.
The embedded catalog covers static dashboard copy and common generated UI labels.
A MutationObserver translates newly rendered text and accessible attributes;
switching back restores original English without rebuilding forms or losing
unsaved input. Provider names, user input and raw logs are preserved. Backend
error details remain their original diagnostic text.

The locale layer changes presentation only: option values (`direct`, node IDs,
rule actions, etc.), API field names, credentials and saved data stay unchanged.
