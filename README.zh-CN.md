# Sub House

[English](./README.MD) | [简体中文](./README.zh-CN.md)

Sub House 是一个基于 Cloudflare Workers 的订阅管理面板，用来统一管理节点、集合、模板、规则，以及终端用户的订阅分发。

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
- 只使用当前选中的内部模板
- 如果没有设置当前模板，`singbox` 和 `clash` 输出不会附加 `template` 参数
- 项目已经不再使用默认远程模板 URL 作为兜底

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

### 配置 Wrangler

项目自带示例文件：

```text
wrangler.example.jsonc
```

复制为 `wrangler.jsonc` 后，替换成你自己的 Worker 名称和 KV ID 即可。

示例：

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

### 本地开发

```bash
wrangler dev
```

### 正式部署

```bash
wrangler deploy
```

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
