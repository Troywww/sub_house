import Parser from './parser.js';
import { CONFIG } from '../config.js';

// 在文件顶部添加规则类型定义
const RULE_TYPES = {
    CLASH_MODE: 'clash_mode',
    GEOIP: 'geoip',
    FINAL: 'final',
    PROTOCOL: 'protocol'
};

// 在文件顶部添加常量配置
const URL_TEST_CONFIG = {
    TEST_URL: 'http://www.gstatic.com/generate_204',
    BACKUP_TEST_URL: 'https://cp.cloudflare.com/generate_204',
    INTERVAL: '300s',
    TOLERANCE: 50,
};

// 使用基础配置
const BASE_CONFIG = CONFIG.SINGBOX_BASE_CONFIG;

// 设置默认模板URL和环境变量处理
const getTemplateUrl = (env) => {
    return env?.DEFAULT_TEMPLATE_URL || CONFIG.DEFAULT_TEMPLATE_URL;
};

export async function handleSingboxRequest(request, env) {
    try {
        // 从路径中获取集合ID
        const path = new URL(request.url).pathname;
        const collectionId = path.split('/').slice(-2)[0];
        
        // 直接通Parser从KV读取节点数据
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

        // 检测用户平台
        const userAgent = request.headers.get('User-Agent') || '';
        const isApplePlatform = userAgent.includes('iPhone') || 
                               userAgent.includes('iPad') || 
                               userAgent.includes('Macintosh') ||
                               userAgent.includes('SFI/');

        // 生成配置
        const config = await generateSingboxConfig(templateContent, nodes, isApplePlatform);

        return new Response(JSON.stringify(config, null, 2), {
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (error) {
        console.error('Singbox convert error:', error);
        return new Response('Internal Server Error: ' + error.message, { status: 500 });
    }
}

// 修改 generateSingboxConfig 函数以支持苹果平台参数
async function generateSingboxConfig(templateContent, proxies, isApplePlatform) {
    // 首先将节点转换为 Singbox 格式
    const singboxNodes = proxies.map(node => ({
        ...convertNodeToSingbox(node),
        tag: node.name // 确保保留原始名称作为tag
    }));
    
    // 解析分组规则
    const groups = parseGroups(templateContent);
    
    // 创建分组映射
    const groupOutbounds = {};
    
    // 使用基础配置模板
    const config = {
        ...BASE_CONFIG,  // 展开基础配置
        outbounds: [
            ...singboxNodes, // 直接使用转换好的节点
            ...Object.entries(groups).map(([name, group]) => {
                const outboundsList = [];
                
                // 处理分组选项
                group.patterns.forEach(option => {
                    if (option.startsWith('[]')) {
                        const groupRef = option.slice(2);
                        if (groupRef !== name) {
                            outboundsList.push(groupRef);
                        }
                    } else if (option === 'DIRECT') {
                        outboundsList.push('direct');
                    } else if (option === 'REJECT') {
                        outboundsList.push('block');
                    } else if (!option.includes('http')) { 
                        const matchedNodes = matchProxies(singboxNodes, option);
                        outboundsList.push(...matchedNodes.map(p => p.tag));
                    }
                });
  
                return generateGroupOutbound(name, group, outboundsList);
            }),
            {
                type: 'direct',
                tag: 'direct'
            },
            {
                type: 'block',
                tag: 'block'
            },
            {
                type: 'dns',
                tag: 'dns-out'
            }
        ],
        route: {},
        experimental: {},
    };

    const { rules, finalOutbound } = await generateRules(templateContent, groupOutbounds, isApplePlatform);
    config.route = {
        rules: rules,
        auto_detect_interface: true,
        final: finalOutbound
    };
    config.experimental = {};

    return config;
}

  // 解析分组规则
  function parseGroups(template) {
    const groups = {};
    const lines = template.split('\n');
    
    for (const line of lines) {
        if (line.startsWith('custom_proxy_group=')) {
            const [name, ...parts] = line.slice('custom_proxy_group='.length).split('`');
            const type = parts[0];
            const patterns = parts.slice(1).filter(p => p && !p.includes('http'));
            
            groups[name] = {
                type,
                patterns,
                filter: patterns.map(pattern => {
                    if (pattern === 'DIRECT') return null;
                    if (pattern.startsWith('^') && pattern.endsWith('$')) {
                        return new RegExp(pattern);
                    }
                    if (pattern.startsWith('(') && pattern.endsWith(')')) {
                        return new RegExp(pattern.slice(1, -1));
                    }
                    return pattern;
                }).filter(Boolean)
            };
        }
    }
    
    return groups;
  }
  
  // 对代理进行分组
  function groupProxies(proxies, groups) {
    if (!proxies || !Array.isArray(proxies)) {
        return {};
    }

    if (!groups || typeof groups !== 'object') {
        return {};
    }

    const result = {};
    
    for (const [name, group] of Object.entries(groups)) {
        if (!group || !Array.isArray(group.filter)) {
            result[name] = [];
            continue;
        }

        result[name] = proxies.filter(proxy => {
            if (!proxy || typeof proxy.tag !== 'string') {
                return false;
            }

            return group.filter.some(pattern => {
                if (!pattern) {
                    return false;
                }
                
                if (pattern instanceof RegExp) {
                    return pattern.test(proxy.tag);
                }
                
                if (typeof pattern === 'string') {
                    return proxy.tag.includes(pattern);
                }
                
                return false;
            });
        });
    }
    
    return result;
  }
  
  // 匹配代理节点
  function matchProxies(proxies, pattern) {

    
    // 安全检查
    if (!proxies || !pattern || pattern === 'DIRECT' || pattern.startsWith('[]')) {
        return [];
    }

    // 确保 proxies 是数组
    if (!Array.isArray(proxies)) {
        return [];
    }

    // 过滤掉无效的代理节点
    const validProxies = proxies.filter(proxy => proxy && proxy.tag);

    // 处理否定查找模式 (?!...)
    if (pattern.includes('(?!')) {
        const [excludePattern, includePattern] = pattern.split(')).*$');
        const exclude = excludePattern.substring(excludePattern.indexOf('.*(') + 3).split('|');
        const include = includePattern ? includePattern.slice(1).split('|') : [];
        const result = validProxies.filter(proxy => {
            const isExcluded = exclude.some(keyword => {
                if (!keyword) return false;
                return proxy.tag.indexOf(keyword) !== -1;
            });
            if (isExcluded) return false;
            
            return include.length === 0 || include.some(keyword => {
                if (!keyword) return false;
                return proxy.tag.indexOf(keyword) !== -1;
            });
        });
        return result;
    } 
    // 处理普通正则表达式模式
    else if (pattern.startsWith('(') && pattern.endsWith(')')) {
        const keywords = pattern.slice(1, -1).split('|');
        const result = validProxies.filter(proxy => 
            keywords.some(keyword => proxy.tag.indexOf(keyword) !== -1)
        );
        return result;
    }
    // 处理完整正则表达式
    else if (pattern.startsWith('^') || pattern.endsWith('$')) {
        try {
            const regex = new RegExp(pattern, 'i');
            const result = validProxies.filter(proxy => regex.test(proxy.tag));
            return result;
        } catch (e) {
            console.log('Regex error:', e.message);
            return [];
        }
    }
    // 普通字符串匹配
    else {
        const result = validProxies.filter(proxy => proxy.tag.indexOf(pattern) !== -1);
        return result;
    }
  }

// 修改 generateGroupOutbound 
function generateGroupOutbound(name, group, outbounds) {
    // 如果 outbounds 为空，添加 direct
    if (outbounds.length === 0) {
        outbounds.push('direct');
    }

    // 转换所有出站引用为小写
    const normalizedOutbounds = outbounds.map(out => {
        if (out === 'DIRECT') return 'direct';
        if (out === 'REJECT') return 'block';
        return out;
    });

    const groupConfig = {
        type: group.type === 'url-test' ? 'urltest' : 'selector',
        tag: name,
        outbounds: normalizedOutbounds
    };

    // 如果是 url-test 类型，添优化的测试配置
    if (group.type === 'url-test') {
        Object.assign(groupConfig, {
            url: URL_TEST_CONFIG.TEST_URL,
            interval: URL_TEST_CONFIG.INTERVAL,
            tolerance: URL_TEST_CONFIG.TOLERANCE,
            idle_timeout: URL_TEST_CONFIG.IDLE_TIMEOUT,
            interrupt_exist_connections: true
        });
    }

    return groupConfig;
}

// 修改节点转换函数
function convertNodeToSingbox(node) {
    const tag = node.name || `${node.type}-${node.server}:${node.port}`;
    
    switch (node.type) {
        case 'vmess':
            return {
                type: 'vmess',
                tag,
                server: node.server,
                server_port: node.port,
                uuid: node.settings.id,
                security: 'auto',
                alter_id: node.settings.aid || 0,
                global_padding: false,
                authenticated_length: true,
                multiplex: {
                    enabled: false,
                    protocol: 'smux',
                    max_streams: 32
                },
                tls: {
                    enabled: !!node.settings.tls,
                    server_name: node.settings.sni || node.settings.host || node.server,
                    insecure: true,
                    alpn: node.settings.alpn ? node.settings.alpn.split(',') : undefined
                },
                transport: node.settings.net ? {
                    type: node.settings.net,
                    path: node.settings.path || '/',
                    headers: node.settings.host ? { Host: node.settings.host } : undefined
                } : undefined
            };

        case 'vless':
            const tlsEnabled = node.settings.security === 'tls' || node.settings.tls === 'tls';
            const config = {
                type: 'vless',
                tag,
                server: node.server,
                server_port: node.port,
                uuid: node.settings.id,
                flow: node.settings.flow || '',
                tls: node.settings.security === 'reality' ? {
                    enabled: true,
                    server_name: node.settings.sni,
                    reality: {
                        enabled: true,
                        public_key: node.settings.pbk,
                        short_id: node.settings.sid || '',
                    },
                    utls: {
                        enabled: true,
                        fingerprint: node.settings.fp || 'chrome'
                    }
                } : tlsEnabled ? {
                    enabled: true,
                    server_name: node.settings.sni || node.settings.host || node.server,
                    insecure: false,
                    utls: {
                        enabled: true,
                        fingerprint: node.settings.fp || 'random'
                    }
                } : undefined,
                transport: node.settings.type !== 'tcp' ? {
                    type: node.settings.type || node.settings.net,
                    ...(node.settings.type === 'grpc'
                        ? { service_name: node.settings.path || '' }
                        : { path: node.settings.path || '/' }),
                    headers: node.settings.host ? { Host: node.settings.host } : undefined
                } : undefined
            };
            return config;

        case 'trojan':
            const trojanConfig = {
                tag: node.name,
                type: 'trojan',
                server: node.server,
                server_port: node.port,
                password: node.settings.password,
                tls: {
                    enabled: true,
                    server_name: node.settings.sni,
                    insecure: true
                }
            };
            // 只有非 tcp 时才加 transport 字段
            if (node.settings.type && node.settings.type !== 'tcp') {
                trojanConfig.transport = {
                    type: node.settings.type,
                    path: node.settings.path,
                    headers: node.settings.host ? { Host: node.settings.host } : undefined
                };
            }
            return trojanConfig;

        case 'ss':
            return {
                tag: node.name,
                type: 'shadowsocks',
                server: node.server,
                server_port: node.port,
                method: node.settings.method,
                password: node.settings.password
            };

        case 'ssr':
            return {
                tag: node.name,
                type: 'shadowsocksr',
                server: node.server,
                server_port: node.port,
                method: node.settings.method,
                password: node.settings.password,
                protocol: node.settings.protocol,
                protocol_param: node.settings.protocolParam,
                obfs: node.settings.obfs,
                obfs_param: node.settings.obfsParam
            };

        case 'hysteria':
            return {
                tag: node.name,
                type: 'hysteria',
                server: node.server,
                server_port: node.port,
                auth_str: node.settings.auth,
                up_mbps: parseInt(node.settings.up),
                down_mbps: parseInt(node.settings.down),
                tls: {
                    enabled: true,
                    server_name: node.settings.sni,
                    insecure: true,
                    alpn: node.settings.alpn ? [node.settings.alpn] : undefined
                },
                obfs: node.settings.obfs
            };

        case 'hysteria2':
            return {
                tag: node.name,
                type: 'hysteria2',
                server: node.server,
                server_port: node.port,
                password: node.settings.auth,
                tls: {
                    enabled: true,
                    server_name: node.settings.sni,
                    insecure: true
                },
                obfs: {
                    type: node.settings.obfs,
                    password: node.settings.obfsParam
                }
            };

        case 'tuic':
            return {
                type: 'tuic',
                tag,
                server: node.server,
                server_port: node.port,
                uuid: node.settings.uuid,
                password: node.settings.password,
                congestion_control: node.settings.congestion_control || 'bbr',
                udp_relay_mode: node.settings.udp_relay_mode || 'native',
                zero_rtt_handshake: node.settings.reduce_rtt || false,
                tls: {
                    enabled: true,
                    server_name: node.settings.sni || node.server,
                    alpn: node.settings.alpn || ['h3'],
                    disable_sni: node.settings.disable_sni || false
                }
            };

        default:
            return null;
    }
}

// 修改 generateRules 函数
async function generateRules(template, groupOutbounds, isApplePlatform) {
    // 首先检查参数
    if (!template) {
        return { rules: [], finalOutbound: 'direct' };
    }

    const rules = [
        {
            [RULE_TYPES.CLASH_MODE]: "Global",
            outbound: "🚀 节点选择"
        },
        {
            [RULE_TYPES.CLASH_MODE]: "Direct",
            outbound: "direct"
        },
        {
            [RULE_TYPES.PROTOCOL]: "dns",
            outbound: "dns-out"
        }
    ];

    let finalOutbound = 'direct';

    // 确保模板内容是字符并且包含规则
    const ruleLines = template.split('\n')
        .filter(line => line && typeof line === 'string' && line.startsWith('ruleset='))
        .map(line => line.trim());

    for (const line of ruleLines) {
        // 确保规则行格式正确
        if (!line.includes(',')) {
            continue;
        }

        const [group, ...urlParts] = line.slice('ruleset='.length).split(',');
        const url = urlParts.join(',');
        
        // 确保 group 存在
        if (!group) {
            continue;
        }

        const outbound = group === 'DIRECT' ? 'direct' :
                        group === 'REJECT' ? 'block' :
                        group;

        if (url.startsWith('[]')) {
            const ruleContent = url.slice(2);
            if (!ruleContent) {
                continue;
            }

            if (ruleContent.startsWith('GEOIP,')) {
                const [, geoipValue] = ruleContent.split(',');
                if (geoipValue) {
                    rules.push({
                        geoip: [geoipValue.toLowerCase()],
                        outbound: outbound
                    });
                }
            } else if (ruleContent === 'MATCH' || ruleContent === 'FINAL') {
                finalOutbound = outbound;
            }
        } else {
            try {
                const rulesByType = {
                    domain: new Set(),
                    domain_suffix: new Set(),
                    domain_keyword: new Set(),
                    ip_cidr: new Set(),
                    ...(isApplePlatform ? {} : { process_name: new Set() })
                };

                const response = await fetch(url);
                if (!response.ok) {
                    continue;
                }
                
                const ruleContent = await response.text();
                
                ruleContent.split('\n')
                    .map(rule => rule && rule.trim())
                    .filter(rule => rule && !rule.startsWith('#'))
                    .forEach(rule => {
                        const [type, ...valueParts] = rule.split(',');
                        const value = valueParts.join(',');
                        
                        if (!type || !value) {
                            return;
                        }

                        switch (type) {
                            case 'DOMAIN-SUFFIX':
                                rulesByType.domain_suffix.add(value);
                                break;
                            case 'DOMAIN':
                                rulesByType.domain.add(value);
                                break;
                            case 'DOMAIN-KEYWORD':
                                rulesByType.domain_keyword.add(value);
                                break;
                            case 'IP-CIDR':
                            case 'IP-CIDR6':
                                rulesByType.ip_cidr.add(value.split(',')[0]);
                                break;
                            case 'PROCESS-NAME':
                                if (!isApplePlatform && rulesByType.process_name) {
                                    rulesByType.process_name.add(value);
                                }
                                break;
                        }
                    });
                
                for (const [type, values] of Object.entries(rulesByType)) {
                    if (values.size > 0) {
                        rules.push({
                            [type]: Array.from(values),
                            outbound
                        });
                    }
                }
            } catch (error) {
                console.error(`Error processing rule list ${url}:`, error);
            }
        }
    }

    return { rules, finalOutbound };
}
