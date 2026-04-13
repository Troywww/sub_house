# Sub House

[English](./README.MD) | [简体中文](./README.zh-CN.md)

Sub House is a Cloudflare-based subscription management panel for nodes, collections, templates, rules, and end-user subscription delivery.

It provides:

- Admin UI at `/`
- End-user subscription UI at `/user`
- Collection-based subscription outputs for:
  - `base`
  - `clash`
  - `singbox`

## Features

- Manage proxy nodes and organize them into collections
- Create collection credentials with optional expiry
- Generate `base`, `clash`, and `singbox` subscription outputs
- Maintain internal templates for Clash / Sing-box generation
- Maintain remote rule definitions and import built-in DustinWin presets
- QR preview and one-click copy for subscription links
- Session-based admin login and user login

## Admin Initialization

This project no longer uses built-in default admin credentials.

On first visit, if `app_settings` in `NODE_STORE` does not contain:

- `adminUsername`
- `adminPassword`

the admin UI enters setup mode and requires you to create the first admin account before normal login becomes available.

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

- The active template is stored in app settings as `activeTemplateUrl`
- Only the currently selected internal template is used automatically
- If no active template is set, `singbox` and `clash` exports run without a `template` parameter
- There is no default remote template fallback anymore

### Template Subscription Link Format

The current active template is appended automatically for `clash` and `singbox` when it exists.

Manual formats are:

Internal subscription route with an internal template:

```text
/api/share/:collectionId/singbox?internal=1&template=https%3A%2F%2Finner.template.secret%2Fid-<templateId>
/api/share/:collectionId/clash?internal=1&template=https%3A%2F%2Finner.template.secret%2Fid-<templateId>
```

Internal subscription route with an external template URL:

```text
/api/share/:collectionId/singbox?internal=1&template=https%3A%2F%2Fexample.com%2Fcustom-template.txt
/api/share/:collectionId/clash?internal=1&template=https%3A%2F%2Fexample.com%2Fcustom-template.txt
```

If you are using an external converter through `SUB_WORKER_URL`, the same idea becomes:

```text
https://your-converter.example.com/singbox?url=<encoded-share-url>&template=<encoded-template-url>
https://your-converter.example.com/clash?url=<encoded-share-url>&template=<encoded-template-url>
```

Notes:

- `base` does not use the `template` parameter
- To use another internal template that is not the current one, copy its internal template address from the template manager and place it in the `template=` parameter manually
- The internal template URL format is:

```text
https://inner.template.secret/id-<templateId>
```

## Supported Input Formats

The parser can ingest both single-node links and remote subscription/configuration content.

### Single-node links

Each line can be a single node link such as:

- `vmess://...`
- `vless://...`
- `trojan://...`
- `ss://...`
- `ssr://...`
- `hysteria://...`
- `hysteria2://...`
- `hy2://...`
- `tuic://...`
- `anytls://...`
- `socks5://...`
- `socks://...`
- `http://...`
- `https://...`

Examples:

```text
vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQiLCJwcyI6Ik5vZGUifQ==
vless://uuid@example.com:443?security=tls&type=ws#My-VLESS
trojan://password@example.com:443?security=tls#My-Trojan
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#My-SS
```

### Plain subscription text

The parser also supports plain-text subscriptions where each line is:

- a node link, or
- another remote subscription URL

This allows nested subscriptions within the recursion limit.

### Base64 subscriptions

If a remote subscription body is plain Base64 text and the decoded result contains node schemes such as `vmess://` or `trojan://`, it is treated as a standard base subscription and decoded automatically.

In practice, this usually means:

- the subscription response body itself is Base64
- the decoded content becomes multiple node links separated by line breaks

### Clash YAML subscriptions

Clash-style YAML is supported when the content contains a top-level `proxies:` section. The parser reads proxy entries from that section and normalizes them into internal nodes.

### sing-box JSON subscriptions

sing-box style JSON is supported when the content contains an `outbounds` array. The parser reads supported outbound entries from `outbounds` and converts them into internal nodes.

### Internal collection subscription

The project also supports its own internal collection link format:

```text
http://inner.nodes.secret/id-<collectionId>
```

This is resolved from KV and expanded into the nodes inside that collection.

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

### Deploy as a Worker

This is the recommended deployment mode for this repository.

1. Copy `wrangler.example.jsonc` to `wrangler.jsonc`
2. Fill in your Worker name and KV namespace IDs
3. Keep your real `wrangler.jsonc` local only
4. Start local development:

```bash
wrangler dev
```

5. Deploy:

```bash
wrangler deploy
```

Minimal example:

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

### Deploy on Cloudflare Pages

This project can also run on Cloudflare Pages in advanced mode because it already uses `_worker.js`.

Recommended Pages setup:

1. Create a Pages project
2. Use advanced mode with `_worker.js`
3. Set the build output directory to the repository root `.` so `_worker.js` and its imported modules are included
4. Bind the same KV namespaces in Pages:
   - `NODE_STORE`
   - `TEMPLATE_CONFIG`
   - `RULE_CONFIG`

Git integration:

- Connect the GitHub repository
- Use the repository root as the output directory
- This project does not require a frontend build step

Direct Upload / Wrangler:

```bash
npx wrangler pages project create
npx wrangler pages deploy .
```

Notes for Pages:

- Cloudflare Pages advanced mode supports `_worker.js` officially
- If you later add static assets, your `_worker.js` must explicitly forward asset requests with `env.ASSETS.fetch(request)`
- For the current project structure, Worker deployment is still the simpler and recommended path

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
