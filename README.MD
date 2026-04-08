# Sub House

[English](./README.MD) | [Simplified Chinese](./README.zh-CN.md)

Sub House is a Cloudflare Workers based subscription management and config generation system.
It lets you manage nodes, collections, templates, rules, admin settings, and user access in one place, then export subscriptions for different clients.

## What It Does

- Manage proxy nodes and group them into collections
- Generate 3 subscription outputs:
  - `base` link subscription
  - `clash` YAML config
  - `singbox` JSON config
- Maintain templates and route rules for Clash and Sing-box generation
- Import built-in DustinWin rule presets
- Provide admin login, user login, collection credentials, and session handling
- Serve a web UI for both admins and end users

## Current Highlights

- Session-based admin login
- Collection-level user credentials and expiry
- Template manager with built-in presets
- Rule manager with DustinWin preset import
- Hover QR codes on collection subscription buttons
- Settings panel for admin credentials and "other link"
- Best-effort subscription naming headers:
  - `Profile-Title`
  - `Content-Disposition`

## Subscription Routes

```text
/api/share/:collectionId/base
/api/share/:collectionId/clash
/api/share/:collectionId/singbox
```

User entry:

```text
/user
```

Admin entry:

```text
/
```

## Protocol Support

### Base Export

Currently supported in `subscription/base.js`:

- `vmess`
- `vless`
- `trojan`
- `ss`
- `ssr`
- `hysteria`
- `hysteria2`
- `tuic`
- `anytls`
- `socks5`
- `http`

### Clash Export

Currently supported in `subscription/clash.js`:

- `vmess`
- `vless`
- `trojan`
- `ss`
- `hysteria`
- `hysteria2`
- `tuic`
- `socks5`
- `http`
- `anytls`

### Sing-box Export

Sing-box export supports the common protocols that can be represented safely in current project logic, but intentionally skips incompatible node types.

Sing-box export currently skips:

- `xhttp` transport nodes
- `ssr`
- `ss` nodes with plugin requirements
- `mieru`
- other unsupported or unimplemented node types

## Known Limitations

- Sing-box export does not output native `xhttp`. `xhttp` nodes are skipped.
- Clash / Mihomo support for `xhttp` depends on kernel version and server mode.
- Shadowrocket may still use the subscription URL domain as the subscription name, even when `Profile-Title` is present.
- Remote rule sets are downloaded from GitHub Releases by default. If the runtime environment cannot reach GitHub, remote rule-set initialization may fail.
- Very old Sing-box clients may still have compatibility issues with newer DNS and inbound structures.

## Architecture Notes

- Nodes are stored as raw input links.
- Parsing happens at subscription generation time.
- `subscription/parser_v2.js` is the active parser path.
- Remote sources can be parsed from:
  - plain link subscriptions
  - Clash YAML `proxies`
  - Sing-box JSON `outbounds`

## Project Structure

```text
sub_house-main/
- _worker.js
- config.js
- management.js
- services.js
- user.js
- middleware.js
- utils.js
- subscription/
  - parser.js
  - parser_v2.js
  - base.js
  - clash.js
  - singbox.js
- wrangler.jsonc
```

## Data Storage

The project uses Cloudflare KV.

Main keys and namespaces:

- `NODE_STORE`
  - `nodes`
  - `collections`
  - `app_settings`
  - `user_tokens`
  - `user_sessions`
  - `session:<token>`
- `TEMPLATE_CONFIG`
- `RULE_CONFIG`

## Deployment

Recommended deployment target: Cloudflare Workers with Wrangler.

### Prerequisites

- Node.js
- Wrangler
- Cloudflare account
- 3 KV namespaces:
  - `NODE_STORE`
  - `TEMPLATE_CONFIG`
  - `RULE_CONFIG`

### Install Wrangler

```bash
npm install -g wrangler
wrangler login
```

### Configure Wrangler

This repository now includes two Wrangler config patterns:

- `wrangler.jsonc`
  - minimal public config
  - intended for Cloudflare Git-based automatic deployments
  - keeps only the Worker name, entry file, and compatibility date
- `wrangler.example.jsonc`
  - full example file
  - intended for local setup reference

```text
wrangler.jsonc
wrangler.example.jsonc
```

Recommended setup:

1. If you use Cloudflare Git sync, keep the committed `wrangler.jsonc` in the repo.
2. Configure KV bindings and runtime variables in the Cloudflare Dashboard for that Worker.
3. If you want a richer local config, copy `wrangler.example.jsonc` to `wrangler.local.jsonc` or your own private file.
4. Do not commit private deployment secrets or private local overrides.

Example KV binding structure:

```jsonc
{
  "kv_namespaces": [
    { "binding": "NODE_STORE", "id": "..." },
    { "binding": "TEMPLATE_CONFIG", "id": "..." },
    { "binding": "RULE_CONFIG", "id": "..." }
  ]
}
```

### Important Variables

| Variable | Required | Description |
| --- | --- | --- |
| `DEFAULT_USERNAME` | Yes | Initial admin username |
| `DEFAULT_PASSWORD` | Yes | Initial admin password |
| `DEFAULT_TEMPLATE_URL` | Recommended | Default template URL |
| `SUB_WORKER_URL` | No | External subscription converter URL |
| `SUBSCRIBER_URL` | No | Legacy field, no longer primary in current UI |
| `QUICK_SUB_URL` | No | Legacy field, no longer primary in current UI |

Notes:

- After first deployment, log in and change admin credentials in the settings panel.
- If `SUB_WORKER_URL` is empty, internal conversion is used.
- If `SUB_WORKER_URL` is set, external conversion is preferred unless the request contains `?internal=1`.

### Local Development

```bash
wrangler dev
```

### Deploy

```bash
wrangler deploy
```

### Cloudflare Dashboard Git Sync Deployment

You can also deploy this project without running local `wrangler deploy`.

Recommended flow:

1. Connect the GitHub repository to your Cloudflare Worker in the Dashboard.
2. Keep `wrangler.jsonc` in the repository so Cloudflare can read:
   - `name`
   - `main`
   - `compatibility_date`
3. Make sure the Worker name in the Dashboard matches the `name` field in `wrangler.jsonc`.
4. Configure KV bindings and environment variables manually in the Cloudflare Dashboard.
5. Push to the configured branch and let Cloudflare build and deploy automatically.

Notes:

- This is the recommended option if you prefer Git-based deployment.
- The repository keeps `wrangler.jsonc` minimal on purpose.
- Secrets and private local overrides should stay outside the public repository.

## Basic Usage Flow

### Admin

1. Open `/`
2. Log in with the admin account
3. Add nodes and create collections
4. Manage templates and set the active template
5. Import or maintain rules
6. Maintain admin settings and external links

### End User

1. Open `/user`
2. Log in with collection credentials
3. Copy or scan the `base`, `singbox`, or `clash` subscription

## Templates and Rules

### Templates

Templates control:

- groups
- rule references
- final outbound selection
- Clash / Sing-box routing layout

Current template manager supports:

- create template
- save template
- delete template
- activate current template
- open current default subscription config
- insert rule references
- insert group rules
- load built-in template presets

### Rules

Rules can come from:

- direct URL
- alias reference such as `@ads`

Built-in DustinWin presets are included for:

- Clash `rule-providers`
- Sing-box `rule_set`

## Subscription Naming

The service now adds collection-name related response headers:

- `Profile-Title`
- `Content-Disposition`

This is best effort only. Whether the client displays the collection name depends on the client implementation.

Known behavior:

- some Clash / Mihomo style clients may use these headers
- Shadowrocket may still prefer the subscription URL domain

## GitHub Release Checklist

Before publishing this repository, check at least the following:

- replace all KV IDs in `wrangler.jsonc`
- change any weak default admin credentials
- verify `DEFAULT_TEMPLATE_URL`
- confirm whether built-in DustinWin presets should stay enabled
- make sure no real user data or private node links are committed
- review screenshots, example URLs, and deployment notes

## Suggested Next Steps

- add skipped-node statistics for Sing-box export
- add client compatibility badges in the admin UI
- continue improving Mihomo / Sing-box transport compatibility
- add frontend tests for template, rule, and collection flows

## References

- [Troywww/Subhub](https://github.com/Troywww/Subhub)
- [DustinWin/ruleset_geodata](https://github.com/DustinWin/ruleset_geodata)
