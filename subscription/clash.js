import Parser from './parser.js';
import { CONFIG } from '../config.js';

// 定义节点协议列表
const NODE_PROTOCOLS = ['vless:', 'vmess:', 'trojan:', 'ss:', 'ssr:', 'hysteria:', 'tuic:', 'hy2:', 'hysteria2:'];

// 使用基础配置
const BASE_CONFIG = CONFIG.CLASH_BASE_CONFIG;

// 设置默认模板URL和环境变量处理
const getTemplateUrl = (env) => {
    return env?.c || CONFIG.DEFAULT_TEMPLATE_URL;
};

export async function handleClashRequest(request, env) {
    try {
        // 从路径中获取集合ID
        const path = new URL(request.url).pathname;
        const collectionId = path.split('/').slice(-2)[0];
        
        // 直接通过Parser从KV读取节点数据
        const nodes = await Parser.parse(`http://inner.nodes.secret/id-${collectionId}`, env);

        if (!nodes || nodes.length === 0) {
            return new Response('No valid nodes found', { status: 400 });
        }

        // 获取模板配置
        const url = new URL(request.url);
        const templateUrl = url.searchParams.get('template') || getTemplateUrl(env);
        
        // 获取模板内容
        let templateContent;
        if (templateUrl.startsWith('https://inner.template.secret/id-')) {
            const templateId = templateUrl.replace('https://inner.template.secret/id-', '');
            const templateData = await env.TEMPLATE_CONFIG.get(templateId);
            if (!templateData) {
                return new Response('Template not found', { status: 404 });
            }
            const templateInfo = JSON.parse(templateData);
            templateContent = templateInfo.content;
        } else {
            const templateResponse = await fetch(templateUrl);
            if (!templateResponse.ok) {
                return new Response('Failed to fetch template', { status: 500 });
            }
            templateContent = await templateResponse.text();
        }

        // 生成配置
        const config = await generateClashConfig(templateContent, nodes);

        return new Response(config, {
            headers: {
                'Content-Type': 'text/yaml',
                'Content-Disposition': 'attachment; filename=config.yaml'
            }
        });
    } catch (error) {
        console.error('Clash convert error:', error);
        return new Response('Internal Server Error: ' + error.message, { status: 500 });
    }
}

// 判断规则内容是否全为 IP 规则
function isAllIpRules(rulesText) {
    const ipRuleTypes = [
        'IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'SRC-IP-CIDR6', 'GEOIP'
    ];
    return rulesText
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'))
        .every(line => ipRuleTypes.some(type => line.startsWith(type + ',')));
}

// 精简 getProviderInfo 函数，只保留 provider、path、format
async function getProviderInfo(url) {
    let fileName = '';
    try {
        const urlObj = new URL(url);
        fileName = urlObj.pathname.split('/').pop().split('?')[0];
    } catch {
        fileName = url.split('/').pop().split('?')[0];
    }
    const ext = fileName.split('.').pop().toLowerCase();
    const provider = fileName;
    const path = `./ruleset/${fileName}`;
    let format = 'text';
    if (ext === 'srs') format = 'srs';
    else if (ext === 'mrs') format = 'mrs';
    else if (ext === 'yaml' || ext === 'yml') format = 'yaml';
    else if (ext === 'list' || ext === 'txt') format = 'text';
    return { provider, path, format };
}

async function generateClashConfig(templateContent, nodes) {
    let config = BASE_CONFIG + '\n';
    
    // 添加代理节点（压缩为一行）
    config += '\nproxies:\n';
    const proxies = nodes.map(node => {
        const converted = convertNodeToClash(node);
        return converted;
    }).filter(Boolean);
    
    // 将节点配置压缩为一行
    proxies.forEach(proxy => {
        config += '  - ';
        const proxyStr = Object.entries(proxy)
            .filter(([_, value]) => value !== undefined && value !== null)
            .map(([key, value]) => {
                if (typeof value === 'string') {
                    return `${key}: "${value}"`;
                } else if (typeof value === 'boolean' || typeof value === 'number') {
                    return `${key}: ${value}`;
                } else if (Array.isArray(value)) {
                    return `${key}: [${value.map(v => typeof v === 'string' ? `"${v}"` : v).join(', ')}]`;
                } else if (typeof value === 'object') {
                    const objStr = Object.entries(value)
                        .filter(([_, v]) => v !== undefined && v !== null)
                        .map(([k, v]) => {
                            if (typeof v === 'string') {
                                return `${k}: "${v}"`;
                            } else if (typeof v === 'boolean' || typeof v === 'number') {
                                return `${k}: ${v}`;
                            } else if (Array.isArray(v)) {
                                return `${k}: [${v.map(item => typeof item === 'string' ? `"${item}"` : item).join(', ')}]`;
                            } else if (typeof v === 'object') {
                                const nestedObjStr = Object.entries(v)
                                    .filter(([_, nestedV]) => nestedV !== undefined && nestedV !== null)
                                    .map(([nestedK, nestedV]) => `${nestedK}: ${typeof nestedV === 'string' ? `"${nestedV}"` : nestedV}`)
                                    .join(', ');
                                return `${k}: {${nestedObjStr}}`;
                }
                            return `${k}: "${v}"`;
                        })
                        .join(', ');
                    return `${key}: {${objStr}}`;
                }
                return `${key}: "${value}"`;
            })
            .join(', ');
        config += `{${proxyStr}}\n`;
    });

    // 处理分组（压缩为一行）
    config += '\nproxy-groups:\n';
    const groupLines = templateContent.split('\n')
        .filter(line => line.startsWith('custom_proxy_group='));
    
    groupLines.forEach(line => {
        const [groupName, ...rest] = line.slice('custom_proxy_group='.length).split('`');
        const groupType = rest[0];
        const options = rest.slice(1);
        
        // 构建分组配置对象
        const groupConfig = {
            name: groupName,
            type: groupType === 'url-test' ? 'url-test' : 'select'
        };
        
        // 处理 url-test 类型的特殊配置
        if (groupType === 'url-test') {
            const testUrl = options.find(opt => opt.startsWith('http')) || 'http://www.gstatic.com/generate_204';
            const interval = 300;
            const tolerance = groupName.includes('欧美') ? 150 : 50;
            
            groupConfig.url = testUrl;
            groupConfig.interval = interval;
            groupConfig.tolerance = tolerance;
        }
        
        // 收集代理列表
        const proxyList = [];
        let hasProxies = false;
        
        // 处理分组选项
        options.forEach(option => {
            if (option.startsWith('[]')) {
                hasProxies = true;
                const groupRef = option.slice(2);
                proxyList.push(groupRef);
            } else if (option === 'DIRECT' || option === 'REJECT') {
                hasProxies = true;
                proxyList.push(option);
            } else if (!option.startsWith('http')) {
                try {
                    let matchedCount = 0;
                    // 处理正则表达式过滤
                    let pattern = option;
                    
                    // 处理否定查找
                    if (pattern.includes('(?!')) {
                        const [excludePattern, includePattern] = pattern.split(')).*$');
                        const exclude = excludePattern.substring(excludePattern.indexOf('.*(') + 3).split('|');
                        const include = includePattern ? includePattern.slice(1).split('|') : [];
                        
                        const matchedProxies = proxies.filter(proxy => {
                            const isExcluded = exclude.some(keyword => 
                                proxy.name.includes(keyword)
                            );
                            if (isExcluded) return false;
                            if (!includePattern || include.length === 0) {
                                return true;
                            }
                            return include.some(keyword => 
                                proxy.name.includes(keyword)
                            );
                        });
                        
                        matchedProxies.forEach(proxy => {
                            hasProxies = true;
                            matchedCount++;
                            proxyList.push(proxy.name);
                        });
                    } else {
                        const filter = new RegExp(pattern);
                        const matchedProxies = proxies.filter(proxy => 
                            filter.test(proxy.name)
                        );
                        matchedProxies.forEach(proxy => {
                            hasProxies = true;
                            matchedCount++;
                            proxyList.push(proxy.name);
                        });
                    }
                } catch (error) {
                    console.error('Error processing proxy group option:', error);
                }
            }
        });

        // 如果分组没有任何节点，添加 DIRECT
        if (!hasProxies) {
            proxyList.push('DIRECT');
        }
        
        groupConfig.proxies = proxyList;
        
        // 将分组配置压缩为一行
        config += '  - ';
        const groupStr = Object.entries(groupConfig)
            .map(([key, value]) => {
                if (key === 'proxies') {
                    return `proxies: [${value.map(v => `"${v}"`).join(', ')}]`;
                } else if (typeof value === 'string') {
                    return `${key}: "${value}"`;
                } else {
                    return `${key}: ${value}`;
                }
            })
            .join(', ');
        config += `{${groupStr}}\n`;
    });

    // 1. 解析 ruleset= 行，严格按模板顺序处理
    const ruleLines = templateContent.split('\n')
        .filter(line => line.startsWith('ruleset='))
        .map(line => line.trim());
    const ruleProviders = {};
    const rulesInOrder = [];
    for (const line of ruleLines) {
        // 新格式：ruleset=分组,tag,链接1,链接2...
        const parts = line.slice('ruleset='.length).split(',');
        const group = parts[0].trim();
        const tag = parts[1] ? parts[1].trim() : '';
        const urls = parts.slice(2).map(x => x.trim()).filter(Boolean);

        // 兜底规则
        if (/^(MATCH|FINAL)$/i.test(tag)) {
            rulesInOrder.push(`  - ${tag.toUpperCase()},${group}`);
            continue;
        }

        // 远程规则集
        const remoteUrls = urls.filter(u => /^https?:\/\//.test(u));
        if (remoteUrls.length > 0 && tag) {
            // 只生成一次 provider
            if (!ruleProviders[tag]) {
                // 只选 Clash 支持的链接（不选 .srs 结尾的）
                const url = pickClashRuleUrl(remoteUrls);
                if (!url || url.endsWith('.srs') || url.includes('#srs')) continue; // 跳过 srs
                const { provider, path, format } = await getProviderInfo(url);
                // path 用 tag
                ruleProviders[tag] = {
                    type: 'http',
                    behavior: 'classical',
                    format,
                    url,
                    path: `./ruleset/${tag}.${format === 'yaml' ? 'yaml' : format === 'srs' ? 'srs' : format === 'mrs' ? 'mrs' : 'txt'}`,
                    interval: 86400
                };
            }
            rulesInOrder.push(`  - RULE-SET,${tag},${group}`);
            continue;
        }
                
        // 本地批量规则等其它情况
        if (urls.length > 0 && tag) {
            const rules = expandRuleLine(group, urls.join(','));
            rules.forEach(rule => rulesInOrder.push(rule));
            continue;
        }
    }
    // 2. 输出 rule-providers
    if (Object.keys(ruleProviders).length > 0) {
        config += '\nrule-providers:\n';
        for (const [name, provider] of Object.entries(ruleProviders)) {
            config += `  ${name}:\n`;
            config += `    type: ${provider.type}\n`;
            config += `    behavior: ${provider.behavior}\n`;
            config += `    format: ${provider.format}\n`;
            config += `    url: "${provider.url}"\n`;
            config += `    path: ${provider.path}\n`;
            config += `    interval: ${provider.interval}\n`;
        }
    }
    // 3. 输出 rules，顺序与模板一致
    config += '\nrules:\n';
    config += rulesInOrder.join('\n') + '\n';
    return config;
}

function convertNodeToClash(node) {
    switch (node.type) {
        case 'vmess':
            return convertVmess(node);
        case 'vless':
            return convertVless(node);
        case 'trojan':
            return convertTrojan(node);
        case 'ss':
            return convertShadowsocks(node);
        case 'ssr':
            return convertShadowsocksR(node);
        case 'hysteria':
            return convertHysteria(node);
        case 'hysteria2':
            return convertHysteria2(node);
        case 'tuic':
            return convertTuic(node);
        default:
            return null;
    }
}

function convertVmess(node) {
    // 基础配置
    const config = {
        name: node.name,
        type: 'vmess',
        server: node.server,
        port: node.port,
        uuid: node.settings.id,
        alterId: node.settings.aid || 0,
        cipher: 'auto',
        udp: true
    };

    // 网络设置
    if (node.settings.net) {
        config.network = node.settings.net;
        
        // ws 配置
        if (node.settings.net === 'ws') {
            config['ws-opts'] = {
                path: node.settings.path || '/',
                headers: {
                    Host: node.settings.host || ''
                }
            };
        }
    }

    // TLS 设置
    if (node.settings.tls === 'tls') {
        config.tls = true;
        if (node.settings.sni) {
            config.servername = node.settings.sni;
        }
        // 添加 allowInsecure 支持
        if (node.settings.allowInsecure === true || node.settings.allowInsecure === '1' || node.settings.allowInsecure === 'true') {
            config['skip-cert-verify'] = true;
        }
    }

    return config;
}

function convertVless(node) {
    const config = {
        name: node.name,
        type: 'vless',
        server: node.server,
        port: node.port,
        uuid: node.settings.id
    };

    // 映射基础参数
    [
        'network',
        'flow',
        'encryption',
        'servername',
        'client-fingerprint'
    ].forEach(key => {
        if (node.settings[key] !== undefined && node.settings[key] !== '') {
            if (key === 'servername') config.servername = node.settings[key];
            else if (key === 'client-fingerprint') config['client-fingerprint'] = node.settings[key];
            else config[key] = node.settings[key];
        }
    });

    // TLS 设置
    if (node.settings.security === 'tls') {
        config.tls = true;
        if (node.settings.sni) {
            config.servername = node.settings.sni;
        }
        if (node.settings.fp) {
            config['client-fingerprint'] = node.settings.fp;
        }
    }

    // Reality
    if (node.settings.security === 'reality') {
        config['reality-opts'] = {};
        if (node.settings.pbk) config['reality-opts']['public-key'] = node.settings.pbk;
        if (node.settings.sid) config['reality-opts']['short-id'] = node.settings.sid;
        if (node.settings.sni) config.servername = node.settings.sni;
        if (node.settings.fp) config['client-fingerprint'] = node.settings.fp;
        config.tls = true; // Reality 节点必须补齐 tls: true
    }

    // ws-opts
    if (node.settings.type === 'ws' || node.settings.network === 'ws') {
        config['ws-opts'] = {};
        if (node.settings.path) config['ws-opts'].path = node.settings.path;
        if (node.settings.host || node.settings.ua) {
            config['ws-opts'].headers = {};
            if (node.settings.host) config['ws-opts'].headers.Host = node.settings.host;
            if (node.settings.ua) config['ws-opts'].headers['User-Agent'] = node.settings.ua;
        }
    }

    // grpc-opts
    if (node.settings.type === 'grpc') {
        if (node.settings.service_name || node.settings.path) {
            config['grpc-opts'] = {
                'grpc-service-name': node.settings.service_name || node.settings.path
            };
        }
    }

    // alpn 处理
    if (node.settings.alpn) {
        config.alpn = [node.settings.alpn];
    }

    // udp 和 xudp 处理
    if (node.settings.udp === 'true' || node.settings.udp === true) {
        config.udp = true;
    }
    if (node.settings.xudp === 'true' || node.settings.xudp === true) {
        config.xudp = true;
    }

    return config;
}

function convertTrojan(node) {
    return {
        name: node.name,
        type: 'trojan',
        server: node.server,
        port: node.port,
        password: node.settings.password,
        udp: true,
        'skip-cert-verify': node.settings.allowInsecure === true || node.settings.allowInsecure === '1' || node.settings.allowInsecure === 'true' || node.settings.insecure === '1' || node.settings.insecure === true,
        network: node.settings.type || 'tcp',
        'ws-opts': node.settings.type === 'ws' ? {
            path: node.settings.path,
            headers: { Host: node.settings.host }
        } : undefined,
        sni: node.settings.sni || undefined,
        alpn: node.settings.alpn ? [node.settings.alpn] : undefined
    };
}

function convertShadowsocks(node) {
    const config = {
        name: node.name,
        type: 'ss',
        server: node.server,
        port: node.port,
        cipher: node.settings.method,
        password: node.settings.password,
        udp: true
    };

    // 添加插件支持（自动拆分 plugin 字符串为 plugin/plugin-opts）
    if (node.settings.plugin) {
        if (node.settings.plugin.includes(';')) {
            const [pluginName, ...optsArr] = node.settings.plugin.split(';');
            config.plugin = pluginName;
            const optsObj = {};
            optsArr.forEach(opt => {
                if (!opt) return;
                const [k, v] = opt.split('=');
                if (v === undefined) {
                    // 处理无等号的布尔参数，如 tls、mux
                    optsObj[k] = true;
                } else {
                    // 处理有等号的参数
                    // 自动识别布尔和数字
                    if (v === 'true') optsObj[k] = true;
                    else if (v === 'false') optsObj[k] = false;
                    else if (!isNaN(Number(v))) optsObj[k] = Number(v);
                    else optsObj[k] = decodeURIComponent(v);
                }
            });
            config['plugin-opts'] = optsObj;
        } else {
        config.plugin = node.settings.plugin;
        if (node.settings.pluginOpts && Object.keys(node.settings.pluginOpts).length > 0) {
            config['plugin-opts'] = node.settings.pluginOpts;
            }
        }
    }

    return config;
}

function convertShadowsocksR(node) {
    return {
        name: node.name,
        type: 'ssr',
        server: node.server,
        port: node.port,
        cipher: node.settings.method,
        password: node.settings.password,
        protocol: node.settings.protocol,
        'protocol-param': node.settings.protocolParam,
        obfs: node.settings.obfs,
        'obfs-param': node.settings.obfsParam,
        udp: true
    };
}

function convertHysteria(node) {
    // up/down 优先，没有则 upmbps/downmbps
    let up = node.settings.up || node.settings.upmbps;
    let down = node.settings.down || node.settings.downmbps;

    // 自动加单位
    if (up && !/mbps/i.test(up)) up = `${up} Mbps`;
    if (down && !/mbps/i.test(down)) down = `${down} Mbps`;

    // alpn 处理为数组
    let alpn = node.settings.alpn;
    if (alpn && !Array.isArray(alpn)) alpn = [alpn];

    return {
        name: node.name,
        type: 'hysteria',
        server: node.server,
        port: node.port,
        auth_str: node.settings.auth,
        up: up,
        down: down,
        'skip-cert-verify': true,
        sni: node.settings.sni,
        alpn: alpn,
        obfs: node.settings.obfs
    };
}

function convertHysteria2(node) {
    return {
        name: node.name,
        type: 'hysteria2',
        server: node.server,
        port: node.port,
        password: node.settings.auth || node.settings.password || node.settings.username,
        'skip-cert-verify': node.settings.insecure === '1' || node.settings.insecure === true,
        sni: node.settings.sni,
        obfs: node.settings.obfs,
        'obfs-password': node.settings.obfsParam
    };
}

// 添加新的转换函数
function convertTuic(node) {
    return {
        name: node.name,
        type: 'tuic',
        server: node.server,
        port: node.port,
        uuid: node.settings.uuid,
        password: node.settings.password,
        'congestion-controller': node.settings.congestion_control || 'bbr',
        'udp-relay-mode': node.settings.udp_relay_mode || 'native',
        'reduce-rtt': node.settings.reduce_rtt || false,
        'skip-cert-verify': true,
        sni: node.settings.sni || undefined,
        alpn: node.settings.alpn ? [node.settings.alpn] : undefined
    };
}

// 修改 yamlStringify 函数以处理数组格式
function yamlStringify(obj, indent = 0) {
    return Object.entries(obj)
        .map(([key, value]) => {
            const spaces = ' '.repeat(indent);
            if (Array.isArray(value)) {
                // 数组项新起一行并正确缩进
                return `${spaces}${key}:\n${value.map(v => `${spaces}  - ${v}`).join('\n')}`;
            }
            if (typeof value === 'object' && value !== null) {
                return `${spaces}${key}:\n${yamlStringify(value, indent + 2)}`;
            }
            return `${spaces}${key}: ${value}`;
        })
        .join('\n');
}

// 修改 pickClashRuleUrl 函数，跳过带 #singbox 的 json 链接
function pickClashRuleUrl(urls) {
    // 优先 mrs
    for (const url of urls) {
        if (url.endsWith('.mrs')) return url;
    }
    // 其次 list
    for (const url of urls) {
        if (url.endsWith('.list')) return url;
    }
    // 其次 txt
    for (const url of urls) {
        if (url.endsWith('.txt')) return url;
    }
    // 其次 yaml/yml
    for (const url of urls) {
        if (url.endsWith('.yaml') || url.endsWith('.yml')) return url;
    }
    // 其次 json（跳过带 #singbox 的 json）
    for (const url of urls) {
        if (url.endsWith('.json') && !url.includes('#singbox')) return url;
    }
    // fallback: 返回第一个非 srs、非 #singbox 的链接
    for (const url of urls) {
        if (!url.endsWith('.srs') && !url.includes('#singbox')) return url;
    }
    // fallback: 全是 srs 或 #singbox，返回空
    return '';
}

// 新增辅助函数：批量展开 rule= 行，支持 (group, ruleString) 或 (line) 两种用法
function expandRuleLine(groupOrLine, maybeRuleString) {
    let group, rest;
    if (maybeRuleString !== undefined) {
        // 新用法：expandRuleLine(group, ruleString)
        group = groupOrLine.trim();
        rest = maybeRuleString.trim();
    } else {
        // 兼容老用法：expandRuleLine('rule=分组,规则块')
        const line = groupOrLine;
        const firstComma = line.indexOf(',');
        if (firstComma === -1) return [];
        group = line.slice(5, firstComma).trim();
        rest = line.slice(firstComma + 1);
    }
    const ruleBlocks = rest.split(';');
    const rules = [];
    for (const block of ruleBlocks) {
        const match = block.match(/^([A-Z0-9\-]+)\{(.+)\}$/i);
        if (match) {
            const type = match[1];
            const values = match[2].split(',').map(v => v.trim()).filter(Boolean);
            for (const val of values) {
                if (val.includes('|')) {
                    const [main, ...params] = val.split('|').map(s => s.trim());
                    rules.push(`  - ${type},${main},${group},${params.join(',')}`);
                } else {
                    rules.push(`  - ${type},${val},${group}`);
                }
            }
        } else {
            // 单条规则
            const parts = block.split(',');
            if (parts.length === 2) {
                rules.push(`  - ${parts[0]},${parts[1]},${group}`);
            }
        }
    }
    return rules;
}
