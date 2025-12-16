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

async function generateClashConfig(templateContent, nodes) {
    let config = BASE_CONFIG + '\n';
    
    // 添加代理节点
    config += '\nproxies:\n';
    const proxies = nodes.map(node => {
        const converted = convertNodeToClash(node);
        return converted;
    }).filter(Boolean);
    
    proxies.forEach(proxy => {
        config += '  -';
        function writeValue(obj, indent = 4) {
            Object.entries(obj).forEach(([key, value]) => {
                if (value === undefined || value === null) {
                    return;
                }
                const spaces = ' '.repeat(indent);
                if (Array.isArray(value)) {
                    config += `\n${spaces}${key}:`;
                    value.forEach(item => {
                        config += `\n${spaces}  - ${typeof item === 'string' ? `"${item}"` : item}`;
                    });
                } else if (typeof value === 'object') {
                    config += `\n${spaces}${key}:`;
                    writeValue(value, indent + 2);
                } else {
                    const formattedValue = typeof value === 'boolean' || typeof value === 'number'
                        ? value
                        : `"${value}"`;
                    config += `\n${spaces}${key}: ${formattedValue}`;
                }
            });
        }
        writeValue(proxy);
        config += '\n';
    });

    // 处理分组，确保新起一行
    config += '\nproxy-groups:\n';
    const groupLines = templateContent.split('\n')
        .filter(line => line.startsWith('custom_proxy_group='));
    
    groupLines.forEach(line => {
        const [groupName, ...rest] = line.slice('custom_proxy_group='.length).split('`');
        const groupType = rest[0];
        const options = rest.slice(1);
        
        config += `  - name: "${groupName}"\n`;
        config += `    type: ${groupType === 'url-test' ? 'url-test' : 'select'}\n`;
        
        // 处理 url-test 类型的特殊配置
        if (groupType === 'url-test') {
            const testUrl = options.find(opt => opt.startsWith('http')) || 'http://www.gstatic.com/generate_204';
            const interval = 300;
            const tolerance = groupName.includes('欧美') ? 150 : 50;
            
            config += `    url: ${testUrl}\n`;
            config += `    interval: ${interval}\n`;
            config += `    tolerance: ${tolerance}\n`;
        }
        
        config += '    proxies:\n';
        let hasProxies = false;
        
        // 处理分组选项
        options.forEach(option => {
            if (option.startsWith('[]')) {
                hasProxies = true;
                const groupRef = option.slice(2);
                config += `      - ${groupRef}\n`;
            } else if (option === 'DIRECT' || option === 'REJECT') {
                hasProxies = true;
                config += `      - ${option}\n`;
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
                        
                        // 添加调试日志
                        console.log('Pattern processing:', {
                            original: pattern,
                            exclude,
                            include,
                            includePattern
                        });
                        
                        const matchedProxies = proxies.filter(proxy => {
                            const isExcluded = exclude.some(keyword => 
                                proxy.name.includes(keyword)
                            );
                            if (isExcluded) return false;
                            
                            // 如果没有包含模式，则返回所有未被排除的节点
                            if (!includePattern || include.length === 0) {
                                return true;
                            }
                            // 如果有包含模式，则需要匹配包含模式
                            return include.some(keyword => 
                                proxy.name.includes(keyword)
                            );
                        });
                        
                        matchedProxies.forEach(proxy => {
                            hasProxies = true;
                            matchedCount++;
                            config += `      - ${proxy.name}\n`;
                        });
                    } else {
                        const filter = new RegExp(pattern);
                        const matchedProxies = proxies.filter(proxy => 
                            filter.test(proxy.name)
                        );
                        matchedProxies.forEach(proxy => {
                            hasProxies = true;
                            matchedCount++;
                            config += `      - ${proxy.name}\n`;
                        });
                    }
                } catch (error) {
                    console.error('Error processing proxy group option:', error);
                }
            }
        });

        // 如果分组没有任何节点，添加 DIRECT
        if (!hasProxies) {
            config += '      - "DIRECT"\n';
        }
    });

    // 处理规则
    config += '\nrules:\n';
    const ruleLines = templateContent.split('\n')
        .filter(line => line.startsWith('ruleset='))
        .map(line => line.trim());
    
    // 获取并解析所有规则列表
    for (const line of ruleLines) {
        const groupEndIndex = line.indexOf(',');
        const group = line.substring('ruleset='.length, groupEndIndex);
        const url = line.substring(groupEndIndex + 1);
        
        if (url.startsWith('[]')) {
            // 处理内置规则
            const ruleContent = url.slice(2);
            
            if (ruleContent === 'MATCH' || ruleContent === 'FINAL') {
                config += `  - MATCH,${group}\n`;
            } else if (ruleContent.startsWith('GEOIP,')) {
                config += `  - ${ruleContent},${group}\n`;
            } else {
                config += `  - ${ruleContent},${group}\n`;
            }
        } else {
            try {
                // 获取规则列表内容
                const response = await fetch(url);
                if (!response.ok) {
                    console.error(`Failed to fetch rules from ${url}: ${response.status}`);
                    continue;
                }
                
                const ruleContent = await response.text();
                const rules = ruleContent.split('\n')
                    .map(rule => rule.trim())
                    .filter(rule => rule && !rule.startsWith('#'));
                
                // 添加解析后的规则
                rules.forEach(rule => {
                    if (rule.includes(',')) {
                        const parts = rule.split(',');
                        const ruleType = parts[0];
                        const ruleValue = parts[1];
                        
                        // 跳过 USER-AGENT 和 URL-REGEX 规则
                        if (ruleType === 'USER-AGENT' || ruleType === 'URL-REGEX') {
                            return;
                        }
                        
                        // 处理规则
                        if (ruleType === 'IP-CIDR' || ruleType === 'IP-CIDR6') {
                            config += `  - ${ruleType},${ruleValue},${group},no-resolve\n`;
                        } else if (ruleType === 'FINAL') {
                            config += `  - MATCH,${group}\n`;
                        } else {
                            config += `  - ${ruleType},${ruleValue},${group}\n`;
                        }
                    }
                });
            } catch (error) {
                console.error(`Error processing rule list ${url}:`, error);
            }
        }
    }

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
    }

    return config;
}

function convertVless(node) {
    const config = {
        name: node.name,
        type: 'vless',
        server: node.server,
        port: node.port,
        uuid: node.settings.id,
        network: node.settings.type || node.settings.net || 'tcp',
        'skip-cert-verify': false,
        tls: true
    };

    // 基本配置
    if (node.settings.flow) {
        config.flow = node.settings.flow;
    }

    if (node.settings.sni || node.settings.host) {
        config.servername = node.settings.sni || node.settings.host;
    }

    // Reality 配置
    if (node.settings.security === 'reality') {
        config.flow = 'xtls-rprx-vision';
        config['reality-opts'] = {
            'public-key': node.settings.pbk
            'short-id': node.settings.sid
        };
        config['client-fingerprint'] = node.settings.fp || 'chrome';
    }

    // gRPC 配置
    if (node.settings.type === 'grpc') {
        config['grpc-opts'] = {
            'grpc-service-name': node.settings.service_name || node.settings.path || ''
        };
    } else if (node.settings.type === 'ws' || node.settings.net === 'ws') {
        config['ws-opts'] = {
            path: node.settings.path || '/',
            headers: {
                Host: node.settings.host || node.settings.sni || node.server
            }
        };
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

    // 添加插件支持
    if (node.settings.plugin) {
        config.plugin = node.settings.plugin;
        
        if (node.settings.pluginOpts && Object.keys(node.settings.pluginOpts).length > 0) {
            config['plugin-opts'] = node.settings.pluginOpts;
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
