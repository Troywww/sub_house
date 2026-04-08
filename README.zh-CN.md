# Sub House

[English](./README.MD) | [简体中文](./README.zh-CN.md)

Sub House 是一个基于 Cloudflare Workers 的订阅管理与配置生成系统。
它可以集中管理节点、集合、模板、规则、管理员设置和用户访问，并按不同客户端输出不同格式的订阅。

## 项目能力

- 管理代理节点，并按集合分组
- 生成 3 类订阅输出：
  - `base` 通用链接订阅
  - `clash` YAML 配置
  - `singbox` JSON 配置
- 通过模板和规则控制 Clash / Sing-box 的分组与分流结构
- 导入内置 DustinWin 规则预置
- 提供管理员登录、用户登录、集合凭据与会话管理
- 提供管理员页面和用户订阅页面

## 当前特性

- 基于会话的管理员登录
- 集合级用户名、密码和有效期管理
- 带内置预置的模板管理器
- 支持导入 DustinWin 规则预置的规则管理器
- 集合订阅按钮支持悬停二维码
- 配置面板支持维护管理员信息和“其他链接”
- 订阅响应会尽量附带集合名相关头信息：
  - `Profile-Title`
  - `Content-Disposition`

## 订阅路径

```text
/api/share/:collectionId/base
/api/share/:collectionId/clash
/api/share/:collectionId/singbox
```

用户入口：

```text
/user
```

管理员入口：

```text
/
```

## 协议支持

### Base 导出

`subscription/base.js` 当前支持：

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

### Clash 导出

`subscription/clash.js` 当前支持：

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

### Sing-box 导出

Sing-box 导出会优先保留当前项目能安全表示的节点类型，并主动跳过已知不兼容节点。

当前会跳过：

- `xhttp` 传输节点
- `ssr`
- 带插件要求的 `ss`
- `mieru`
- 其它 sing-box 不支持或当前项目未实现的节点类型

## 已知限制

- Sing-box 导出不会原生输出 `xhttp`，遇到 `xhttp` 节点会直接跳过。
- Clash / Mihomo 对 `xhttp` 的兼容性取决于内核版本和服务端模式。
- Shadowrocket 可能仍然优先使用订阅 URL 的域名作为名称，即使响应头里已经附带 `Profile-Title`。
- 远程规则集默认从 GitHub Releases 下载；如果运行环境无法访问 GitHub，远程规则集初始化可能失败。
- 很旧的 Sing-box 客户端可能仍然无法完全兼容较新的 DNS 和 inbound 结构。

## 设计说明

- 节点以原始输入链接为主存储，不在入库阶段做强制规范化。
- 解析发生在订阅生成阶段，而不是节点创建阶段。
- `subscription/parser_v2.js` 是当前主解析链路。
- 远程来源支持解析：
  - 普通链接订阅
  - Clash YAML 中的 `proxies`
  - Sing-box JSON 中的 `outbounds`

## 目录结构

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

## 数据存储

项目使用 Cloudflare KV。

主要键和值命名空间包括：

- `NODE_STORE`
  - `nodes`
  - `collections`
  - `app_settings`
  - `user_tokens`
  - `user_sessions`
  - `session:<token>`
- `TEMPLATE_CONFIG`
- `RULE_CONFIG`

## 部署方式

推荐使用 Cloudflare Workers + Wrangler 部署。

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

仓库中已经包含两个配置方案：

- `wrangler.jsonc`
  - 公开仓库可提交的最小配置
  - 适合 Cloudflare Worker 直接同步 Git 自动部署
  - 仅保留 Worker 名称、入口文件和兼容日期
- `wrangler.example.jsonc`
  - 更完整的示例配置
  - 适合本地参考和私有扩展

```text
wrangler.jsonc
wrangler.example.jsonc
```

建议做法：

1. 如果你使用 Cloudflare Git 同步部署，保留仓库中的 `wrangler.jsonc`。
2. 在 Cloudflare Dashboard 中手动配置 KV 绑定和环境变量。
3. 如果你需要更完整的本地私有配置，可以复制 `wrangler.example.jsonc` 为 `wrangler.local.jsonc` 或其它私有文件。
4. 不要把私有密钥、私有变量和本地覆盖配置提交到公开仓库。

示例 KV 绑定结构：

```jsonc
{
  "kv_namespaces": [
    { "binding": "NODE_STORE", "id": "..." },
    { "binding": "TEMPLATE_CONFIG", "id": "..." },
    { "binding": "RULE_CONFIG", "id": "..." }
  ]
}
```

### 重要环境变量

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `DEFAULT_USERNAME` | 是 | 初始管理员用户名 |
| `DEFAULT_PASSWORD` | 是 | 初始管理员密码 |
| `DEFAULT_TEMPLATE_URL` | 建议 | 默认模板 URL |
| `SUB_WORKER_URL` | 否 | 外部订阅转换服务地址 |
| `SUBSCRIBER_URL` | 否 | 旧字段，当前 UI 不再主用 |
| `QUICK_SUB_URL` | 否 | 旧字段，当前 UI 不再主用 |

补充说明：

- 首次部署后，建议登录后台，在配置面板中修改管理员账号和密码。
- `SUB_WORKER_URL` 为空时，系统使用内部转换逻辑。
- `SUB_WORKER_URL` 不为空时，默认优先使用外部转换器，除非请求带 `?internal=1`。

### 本地开发

```bash
wrangler dev
```

### 正式部署

```bash
wrangler deploy
```

### Cloudflare Dashboard Git 同步部署

如果你不想在本地手动执行 `wrangler deploy`，也可以直接使用 Cloudflare Dashboard 的 Git 同步部署。

推荐流程：

1. 在 Cloudflare Dashboard 中把这个 GitHub 仓库连接到目标 Worker。
2. 保留仓库中的 `wrangler.jsonc`，让 Cloudflare 能读取以下最小信息：
   - `name`
   - `main`
   - `compatibility_date`
3. 确保 Dashboard 中的 Worker 名称与 `wrangler.jsonc` 里的 `name` 一致。
4. 在 Cloudflare Dashboard 中手动配置 KV 绑定和环境变量。
5. 推送到配置好的分支后，由 Cloudflare 自动构建和部署。

补充说明：

- 如果你偏好 Git 驱动部署，这种方式更方便。
- 仓库中的 `wrangler.jsonc` 故意保持为最小公开配置。
- 私有密钥、私有变量和本地覆盖配置不要提交到公开仓库。

## 使用流程

### 管理员

1. 打开 `/`
2. 使用管理员账号登录
3. 添加节点并创建集合
4. 管理模板并设置当前模板
5. 导入或维护规则
6. 在配置面板中维护管理员设置和外部链接

### 普通用户

1. 打开 `/user`
2. 使用集合凭据登录
3. 复制或扫码获取 `base`、`singbox`、`clash` 订阅

## 模板与规则

### 模板

模板负责控制：

- 分组
- 规则引用
- 默认出站
- Clash / Sing-box 配置中的分流结构

当前模板管理支持：

- 新建模板
- 保存模板
- 删除模板
- 启用当前模板
- 查看当前默认订阅配置
- 插入规则引用
- 插入分组规则
- 加载内置模板预置

### 规则

规则可以来自：

- 直接 URL
- 别名引用，例如 `@ads`

当前内置了 DustinWin 规则预置，可用于：

- Clash `rule-providers`
- Sing-box `rule_set`

## 订阅名称说明

系统会尽量把“集合名称”写入订阅响应头：

- `Profile-Title`
- `Content-Disposition`

这是 best effort 行为，最终是否显示为集合名取决于客户端实现。

已知情况：

- 部分 Clash / Mihomo / 通用订阅客户端会读取这些头
- Shadowrocket 可能仍优先使用订阅 URL 的域名

## GitHub 发布前检查

发布前建议至少检查以下内容：

- 把 `wrangler.jsonc` 中的真实 KV ID 替换或仅保留在本地
- 修改弱默认密码
- 检查 `DEFAULT_TEMPLATE_URL`
- 确认是否保留 DustinWin 规则预置
- 确认没有把真实用户数据、真实节点、真实私有链接提交到仓库
- 检查 README、示例链接和截图是否适合公开

## 后续建议

- 为 Sing-box 导出增加“跳过节点统计与提示”
- 在管理页面给节点增加客户端兼容性标记
- 继续补强 Mihomo / Sing-box 传输兼容性
- 为模板、规则和集合交互补充前端测试

## 参考项目

- [Troywww/Subhub](https://github.com/Troywww/Subhub)
- [DustinWin/ruleset_geodata](https://github.com/DustinWin/ruleset_geodata)

