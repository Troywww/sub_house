import Parser from './parser.js';
import { CONFIG } from '../config.js';

/**
 * 处理基础转换请求
 * @param {Request} request
 */
export async function handleConvertRequest(request, env) {
    let path;
    try {
        path = new URL(request.url).pathname;
        const collectionId = path.split('/').slice(-2)[0];
        
        const nodes = await Parser.parse(`http://inner.nodes.secret/id-${collectionId}`, env);

        if (!nodes || nodes.length === 0) {
            return new Response('No valid nodes found', { status: 400 });
        }

        const convertedNodes = nodes.map(node => {
            return convertToLink(node);
        }).filter(Boolean);

        const result = convertedNodes.join('\n');

        return new Response(btoa(result), {
            headers: { 
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        console.error('Convert error:', error.message);
        return new Response(`Error: ${error.message}`, { 
            status: 500,
            headers: { 
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

function convertToLink(node) {
    try {
        switch (node.type) {
            case 'vmess':
                return generateVmessLink(node);
            case 'vless':
                return generateVlessLink(node);
            case 'trojan':
                return generateTrojanLink(node);
            case 'ss':
                return generateSSLink(node);
            case 'ssr':
                return generateSSRLink(node);
            case 'hysteria':
                return generateHysteriaLink(node);
            case 'hysteria2':
                return generateHysteria2Link(node);
            case 'tuic':
                return generateTuicLink(node);
            default:
                return node.url; // 如果无法识别类型，返回原始URL
        }
    } catch (error) {
        console.error('Error converting node:', error);
        return node.url; // 转换失败时返回原始URL
    }
}

// 生成 VMess 链接
function generateVmessLink(node) {
    try {
        const config = {
            v: '2',
            ps: node.name,
            add: node.server,
            port: node.port,
            id: node.settings.id,
            aid: node.settings.aid || 0,
            net: node.settings.net || 'tcp',
            type: node.settings.type || 'none',
            host: node.settings.host || '',
            path: node.settings.path || '',
            tls: node.settings.tls || '',
            sni: node.settings.sni || '',
            alpn: node.settings.alpn || ''
        };
        
        const jsonString = JSON.stringify(config);
        const encoder = new TextEncoder();
        const utf8Bytes = encoder.encode(jsonString);
        
        return 'vmess://' + btoa(String.fromCharCode.apply(null, utf8Bytes));
    } catch (error) {
        console.error('Generate VMess link error:', error);
        return node.url;
    }
}

function generateVlessLink(node) {
    try {
        const params = new URLSearchParams();
        const { settings } = node;

        if (settings.type) params.set('type', settings.type);
        if (settings.security) params.set('security', settings.security);
        if (settings.flow) params.set('flow', settings.flow);
        if (settings.encryption) params.set('encryption', settings.encryption);
        
        // Reality 特有参数
        if (settings.security === 'reality') {
            if (settings.pbk) params.set('pbk', settings.pbk);
            if (settings.fp) params.set('fp', settings.fp);
            if (settings.sid) params.set('sid', settings.sid);
            if (settings.spx) params.set('spx', settings.spx);
        }

        // 通用参数
        if (settings.path) params.set('path', settings.path);
        if (settings.host) params.set('host', settings.host);
        if (settings.sni) params.set('sni', settings.sni);
        if (settings.alpn) params.set('alpn', settings.alpn);

        const url = `vless://${settings.id}@${node.server}:${node.port}`;
        const query = params.toString();
        const hash = node.name ? `#${encodeURIComponent(node.name)}` : '';

        return `${url}${query ? '?' + query : ''}${hash}`;
    } catch (error) {
        console.error('Generate VLESS link error:', error);
        return node.url;
    }
}

function generateTrojanLink(node) {
    try {
        const params = new URLSearchParams();
        const { settings } = node;

        if (settings.type) params.set('type', settings.type);
        if (settings.security) params.set('security', settings.security);
        if (settings.path) params.set('path', settings.path);
        if (settings.host) params.set('host', settings.host);
        if (settings.sni) params.set('sni', settings.sni);
        if (settings.alpn) params.set('alpn', settings.alpn);
        if (settings.allowInsecure) params.set('allowInsecure', '1');

        const url = `trojan://${settings.password}@${node.server}:${node.port}`;
        const query = params.toString();
        const hash = node.name ? `#${encodeURIComponent(node.name)}` : '';

        return `${url}${query ? '?' + query : ''}${hash}`;
    } catch (error) {
        console.error('Generate Trojan link error:', error);
        return node.url;
    }
}

function generateSSLink(node) {
    try {
        // 构建userInfo: method:password
        const userInfo = `${node.settings.method}:${node.settings.password}`;
        console.log('SS userInfo before base64:', userInfo);
        
        // 使用UTF-8安全的base64编码
        const encodedUserInfo = btoa(unescape(encodeURIComponent(userInfo)));
        
        // 构建URL
        let url = `ss://${encodedUserInfo}@${node.server}:${node.port}`;
        
        // 添加插件参数（如果有）
        if (node.settings.plugin) {
            url += `?plugin=${node.settings.plugin}`;
            if (node.settings.pluginOpts) {
                for (const [key, value] of Object.entries(node.settings.pluginOpts)) {
                    url += `&plugin_${key}=${value}`;
                }
            }
        }
        
        // 添加节点名称
        if (node.name && node.name !== 'Unnamed') {
            url += `#${encodeURIComponent(node.name)}`;
        }
        
        return url;
    } catch (error) {
        console.error('Generate SS link error:', error);
        return null;
    }
}

function generateSSRLink(node) {
    try {
        console.log('generateSSRLink:');
        console.log('  node.server:', node.server);
        console.log('  node.port:', node.port);
        console.log('  settings.protocol:', node.settings.protocol);
        console.log('  settings.method:', node.settings.method);
        console.log('  settings.obfs:', node.settings.obfs);
        console.log('  settings.password:', node.settings.password);
        console.log('  settings.protocolParam:', node.settings.protocolParam);
        console.log('  settings.obfsParam:', node.settings.obfsParam);
        console.log('  node.name:', node.name);
        
        // 修复：使用UTF-8安全的base64编码
        const remarks = btoa(unescape(encodeURIComponent(node.name)));
        console.log('  remarks (encoded):', remarks);
        
        // 构建查询参数
        const queryParams = [];
        if (node.settings.protocolParam) {
            queryParams.push(`protoparam=${btoa(node.settings.protocolParam)}`);
        }
        if (node.settings.obfsParam) {
            queryParams.push(`obfsparam=${btoa(node.settings.obfsParam)}`);
        }
        queryParams.push(`remarks=${remarks}`);
        
        const query = queryParams.join('&');
        console.log('  query:', query);
        
        // 构建配置字符串
        const config = `${node.server}:${node.port}:${node.settings.protocol}:${node.settings.method}:${node.settings.obfs}:${btoa(node.settings.password)}/?${query}`;
        console.log('  config (before base64):', config);
        
        const finalSSR = `ssr://${btoa(config)}`;
        console.log('  finalSSR:', finalSSR);
        
        return finalSSR;
    } catch (error) {
        console.error('Error converting node:', error);
        return null;
    }
}

function generateHysteriaLink(node) {
    try {
        const params = new URLSearchParams();
        const { settings } = node;

        // up/down 兼容 upmbps/downmbps
        if (settings.up) params.set('up', settings.up);
        else if (settings.upmbps) params.set('upmbps', settings.upmbps);

        if (settings.down) params.set('down', settings.down);
        else if (settings.downmbps) params.set('downmbps', settings.downmbps);

        // 其它常见参数全部导出
        [
            'alpn', 'auth', 'auth_str', 'protocol', 'obfs', 'obfsParam', 'sni', 'peer', 'delay', 'insecure', 'password', 'username'
        ].forEach(key => {
            if (settings[key] !== undefined && settings[key] !== '') {
                params.set(key, settings[key]);
            }
        });

        // 修正：auth 放在主链接部分
        const authPart = settings.auth ? `${encodeURIComponent(settings.auth)}@` : '';
        const url = `hysteria://${node.server}:${node.port}`;
        const query = params.toString();
        const hash = node.name ? `#${encodeURIComponent(node.name)}` : '';

        return `${url}${query ? '?' + query : ''}${hash}`;
    } catch (error) {
        console.error('Generate Hysteria link error:', error);
        return node.url;
    }
}

function generateHysteria2Link(node) {
    try {
        const params = new URLSearchParams();
        const { settings } = node;

        // 导出所有常见参数
        [
            'sni', 'obfs', 'obfsParam', 'insecure', 'alpn', 'peer', 'delay', 'password', 'username'
        ].forEach(key => {
            if (settings[key] !== undefined && settings[key] !== '') {
                // obfsParam 导出为 obfs-password，其它原样
                if (key === 'obfsParam') {
                    params.set('obfs-password', settings[key]);
                } else {
                    params.set(key, settings[key]);
                }
            }
        });

        const url = `hysteria2://${settings.auth ? encodeURIComponent(settings.auth) + '@' : ''}${node.server}:${node.port}`;
        const query = params.toString();
        const hash = node.name ? `#${encodeURIComponent(node.name)}` : '';

        return `${url}${query ? '?' + query : ''}${hash}`;
    } catch (error) {
        console.error('Generate Hysteria2 link error:', error);
        return node.url;
    }
}

function generateTuicLink(node) {
    try {
        const { settings } = node;
        const params = new URLSearchParams();
        
        if (settings.congestion_control) params.set('congestion_control', settings.congestion_control);
        if (settings.udp_relay_mode) params.set('udp_relay_mode', settings.udp_relay_mode);
        if (settings.alpn && settings.alpn.length) params.set('alpn', settings.alpn.join(','));
        if (settings.reduce_rtt) params.set('reduce_rtt', '1');
        if (settings.sni) params.set('sni', settings.sni);
        if (settings.disable_sni) params.set('disable_sni', '1');

        const url = `tuic://${settings.uuid}:${settings.password}@${node.server}:${node.port}`;
        const query = params.toString();
        const hash = node.name ? `#${encodeURIComponent(node.name)}` : '';

        return `${url}${query ? '?' + query : ''}${hash}`;
    } catch (error) {
        console.error('Generate TUIC link error:', error);
        return node.url;
    }
}

function safeBase64Encode(str) {
    try {
        if (!str) return '';
        // SSR 兼容 Latin1 base64
        return btoa(unescape(encodeURIComponent(str)));
    } catch (error) {
        console.error('Base64 encode error:', error);
        return '';
    }
}
