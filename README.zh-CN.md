# Sub House

[English](./README.MD) | [简体中文](./README.zh-CN.md)

Sub House 是一个基于 Cloudflare 的订阅管理面板，用来统一管理节点、集合、模板、规则，以及终端用户的订阅分发。

它提供：

- 管理后台：`/`
- 用户订阅页：`/user`
- 集合级别的 3 种订阅输出：
  - `base`
  - `clash`
  - `singbox`

## 功能概览

- 管理代理节点，并按集合组织
- 为集合生成用户名、密码和可选到期时间
- 生成 `base`、`clash`、`singbox` 三类订阅输出
- 维护 Clash / Sing-box 的内部模板
- 维护远程规则，并支持导入内置 DustinWin 规则预置
- 支持订阅链接一键复制和二维码预览
- 提供管理员登录和用户登录

## 管理员初始化

项目已经不再内置默认管理员账号密码。

首次访问后台时，如果 `NODE_STORE` 中的 `app_settings` 还没有保存：

- `adminUsername`
- `adminPassword`

系统就会进入初始化模式，要求先创建第一个管理员账号，之后才可以正常登录。

## 路由

管理后台：

```text
/
```

用户页面：

```text
/user
```

订阅输出：

```text
/api/share/:collectionId/base
/api/share/:collectionId/clash
/api/share/:collectionId/singbox
```

## 模板逻辑

模板保存在 `TEMPLATE_CONFIG` 中。

- 当前生效模板来自 `app_settings.activeTemplateUrl`
- 只会自动使用当前选中的内部模板
- 如果没有设置当前模板，`singbox` 和 `clash` 输出不会附加 `template` 参数
- 项目已经不再使用默认远程模板 URL 作为兜底

### 模板订阅链接格式

当前模板存在时，后台和用户页会自动把它附加到 `clash` / `singbox` 订阅链接中。

如果你想手动指定模板，可以使用下面的格式。

使用内部模板：

```text
/api/share/:collectionId/singbox?internal=1&template=https%3A%2F%2Finner.template.secret%2Fid-<templateId>
/api/share/:collectionId/clash?internal=1&template=https%3A%2F%2Finner.template.secret%2Fid-<templateId>
```

使用外部模板 URL：

```text
/api/share/:collectionId/singbox?internal=1&template=https%3A%2F%2Fexample.com%2Fcustom-template.txt
/api/share/:collectionId/clash?internal=1&template=https%3A%2F%2Fexample.com%2Fcustom-template.txt
```

如果你启用了外部订阅转换器 `SUB_WORKER_URL`，对应格式会变成：

```text
https://your-converter.example.com/singbox?url=<encoded-share-url>&template=<encoded-template-url>
https://your-converter.example.com/clash?url=<encoded-share-url>&template=<encoded-template-url>
```

补充说明：

- `base` 不使用 `template` 参数
- 如果想使用“非当前模板”的内部模板，可以先在模板管理里复制它的内部模板地址，再手动填入 `template=` 参数
- 内部模板地址格式为：

```text
https://inner.template.secret/id-<templateId>
```

## 可解析的输入格式

解析器既支持单节点链接，也支持远程订阅内容或配置内容。

### 单节点链接

每一行都可以是一个单独的节点链接，例如：

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

示例：

```text
vmess://eyJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6InV1aWQiLCJwcyI6Ik5vZGUifQ==
vless://uuid@example.com:443?security=tls&type=ws#My-VLESS
trojan://password@example.com:443?security=tls#My-Trojan
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#My-SS
```

### 纯文本订阅

也支持普通文本形式的订阅内容，其中每一行可以是：

- 一个节点链接
- 一个远程订阅 URL

因此可以在递归深度限制内继续展开嵌套订阅。

### Base64 订阅

如果远程订阅返回的正文本身是一段 Base64 文本，并且解码后包含 `vmess://`、`trojan://` 等节点协议前缀，系统会自动把它识别为常见的 base 订阅并解码。

通常可以理解为：

- 订阅响应体本身是 Base64
- 解码后的内容是多行节点链接

### Clash YAML 订阅

如果内容中包含顶层 `proxies:` 段，系统会按 Clash 风格 YAML 处理，并从 `proxies` 中提取节点。

### sing-box JSON 订阅

如果内容中包含 `outbounds` 数组，系统会按 sing-box 风格 JSON 处理，并从 `outbounds` 中提取受支持的节点。

### 内部集合订阅

项目也支持自己的内部集合链接格式：

```text
http://inner.nodes.secret/id-<collectionId>
```

这类链接会从 KV 中解析出对应集合，再展开集合内的节点。

## 协议支持

### Base

实现位置：`subscription/base.js`

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

实现位置：`subscription/clash.js`

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

Sing-box 导出支持当前项目中可以安全表示的常见节点类型。

当前会跳过：

- `xhttp`
- `ssr`
- 依赖插件的 `ss`
- `mieru`
- 其它未支持或未实现的节点类型

## 数据存储

项目使用 Cloudflare KV。

命名空间：

- `NODE_STORE`
- `TEMPLATE_CONFIG`
- `RULE_CONFIG`

`NODE_STORE` 中的主要 key：

- `nodes`
- `collections`
- `app_settings`
- `user_tokens`
- `user_sessions`
- `session:<token>`
- `admin_session:<token>`

## 项目结构

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

## 部署

### 前置要求

- Node.js
- Wrangler
- Cloudflare 账号
- 3 个 KV Namespace：
  - `NODE_STORE`
  - `TEMPLATE_CONFIG`
  - `RULE_CONFIG`

### 安装 Wrangler

```bash
npm install -g wrangler
wrangler login
```

### 作为 Worker 部署

这是当前仓库最推荐的部署方式。

1. 复制 `wrangler.example.jsonc` 为 `wrangler.jsonc`
2. 填入你自己的 Worker 名称和 KV ID
3. 真实 `wrangler.jsonc` 建议只保留在本地
4. 本地开发：

```bash
wrangler dev
```

5. 正式部署：

```bash
wrangler deploy
```

最小示例：

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

现在不再需要配置：

- 默认管理员用户名
- 默认管理员密码
- 默认模板 URL

### 作为 Cloudflare Pages 部署

这个项目也可以通过 Cloudflare Pages 的 advanced mode 运行，因为它已经使用 `_worker.js` 作为入口。

推荐做法：

1. 创建一个 Pages 项目
2. 启用 `_worker.js` 的 advanced mode
3. 将输出目录设置为仓库根目录 `.`，确保 `_worker.js` 和它依赖的模块都被包含进去
4. 在 Pages 项目里绑定同样的 KV：
   - `NODE_STORE`
   - `TEMPLATE_CONFIG`
   - `RULE_CONFIG`

如果使用 Git 集成：

- 直接连接 GitHub 仓库
- 输出目录填写仓库根目录
- 这个项目本身不需要单独的前端构建步骤

如果使用 Wrangler / Direct Upload：

```bash
npx wrangler pages project create
npx wrangler pages deploy .
```

Pages 部署补充说明：

- Cloudflare Pages 官方支持 `_worker.js` advanced mode
- 如果后续你加入静态资源，需要在 `_worker.js` 中显式转发静态资源请求给 `env.ASSETS.fetch(request)`
- 对当前这个项目来说，直接作为 Worker 部署仍然是更简单、更推荐的方案

## 基本使用流程

### 管理员

1. 打开 `/`
2. 如果是首次运行，先创建管理员账号
3. 添加节点并创建集合
4. 管理模板，并在需要时设置当前模板
5. 维护规则
6. 在配置面板中维护管理员信息和可选的“其他链接”

### 普通用户

1. 打开 `/user`
2. 使用集合凭据登录
3. 复制或扫码使用 `base`、`singbox`、`clash` 订阅

## 说明

- 管理员登录使用会话机制
- 用户访问基于集合凭据
- 规则预置来源于 DustinWin 远程规则集
- 订阅响应会尽量附带 `Profile-Title`、`Content-Disposition` 等命名头信息
