# Sub House

[English](./README.MD) | [简体中文](./README.zh-CN.md)

Sub House is a Cloudflare Workers based subscription management panel for nodes, collections, templates, rules, and end-user subscription delivery.

It provides:

- Admin management UI at `/`
- End-user subscription UI at `/user`
- Collection-based subscription export for:
  - `base`
  - `clash`
  - `singbox`

## Features

- Manage proxy nodes and organize them into collections
- Create collection credentials with optional expiry
- Generate `base`, `clash`, and `singbox` subscription outputs
- Maintain internal templates for Clash / Sing-box generation
- Maintain remote rule definitions and import built-in DustinWin presets
- Hover QR preview and one-click copy for subscription links
- Session-based admin login and user login

## Admin Initialization

This project no longer uses built-in default admin credentials.

On first visit, if `app_settings` in `NODE_STORE` does not contain:

- `adminUsername`
- `adminPassword`

the admin UI will enter setup mode and require you to create the first admin account before normal login becomes available.

## Routes

Admin:

```text
/
```

User:

```text
/user
```

Subscription outputs:

```text
/api/share/:collectionId/base
/api/share/:collectionId/clash
/api/share/:collectionId/singbox
```

## Templates

Templates are stored internally in `TEMPLATE_CONFIG`.

- The active template is the one saved in app settings as `activeTemplateUrl`
- Only the currently selected internal template is used
- If no active template is set, `singbox` and `clash` exports run without a `template` parameter
- There is no longer a default remote template URL fallback

## Supported Protocols

### Base

Implemented in `subscription/base.js`:

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

### Clash

Implemented in `subscription/clash.js`:

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

### Sing-box

Sing-box export supports the common node types currently handled safely by project logic.

Known skips:

- `xhttp`
- `ssr`
- `ss` nodes that require plugins
- `mieru`
- other unsupported or unimplemented node types

## Data Storage

The project uses Cloudflare KV.

Namespaces:

- `NODE_STORE`
- `TEMPLATE_CONFIG`
- `RULE_CONFIG`

Main keys inside `NODE_STORE`:

- `nodes`
- `collections`
- `app_settings`
- `user_tokens`
- `user_sessions`
- `session:<token>`
- `admin_session:<token>`

## Project Structure

```text
sub_house/
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
- wrangler.example.jsonc
```

## Deployment

### Requirements

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

Use the included example file:

```text
wrangler.example.jsonc
```

Copy it to `wrangler.jsonc` and replace the Worker name and KV namespace IDs with your own values.

Example:

```jsonc
{
  "name": "your-worker-name",
  "main": "_worker.js",
  "compatibility_date": "2026-04-07",
  "kv_namespaces": [
    { "binding": "NODE_STORE", "id": "..." },
    { "binding": "TEMPLATE_CONFIG", "id": "..." },
    { "binding": "RULE_CONFIG", "id": "..." }
  ]
}
```

No initial default admin credentials or default template variables are required.

### Local Development

```bash
wrangler dev
```

### Deploy

```bash
wrangler deploy
```

## Basic Usage

### Admin

1. Open `/`
2. If this is the first run, create the initial admin account
3. Add nodes and create collections
4. Manage templates and set the active template when needed
5. Maintain rules
6. Update admin settings and optional "other link"

### End User

1. Open `/user`
2. Log in with collection credentials
3. Copy or scan the `base`, `singbox`, or `clash` subscription

## Notes

- Admin login is session-based
- User access is collection-based
- Rule presets are imported from DustinWin remote sources
- Subscription naming tries to set headers such as `Profile-Title` and `Content-Disposition`
