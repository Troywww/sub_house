// @ts-nocheck

import { CONFIG } from '../config.js';

// 添加名称解码函数
function decodeNodeName(encodedName, fallback = 'Unnamed') {
    if (!encodedName) return fallback;
    
    try {
        let decoded = encodedName;
        
        // 1. 第一次 URL 解码
        try {
            const urlDecoded = decodeURIComponent(decoded);
            decoded = urlDecoded;
        } catch (e) {}
        
        // 2. 第二次 URL 解码（处理双重编码）
        try {
            const urlDecoded2 = decodeURIComponent(decoded);
            decoded = urlDecoded2;
        } catch (e) {}
        
        // 3. 如果看起来是 Base64，尝试 Base64 解码
        if (/^[A-Za-z0-9+/=]+$/.test(decoded)) {
            try {
                const base64Decoded = atob(decoded);
                const bytes = new Uint8Array(base64Decoded.length);
                for (let i = 0; i < base64Decoded.length; i++) {
                    bytes[i] = base64Decoded.charCodeAt(i);
                }
                const text = new TextDecoder('utf-8').decode(bytes);
                if (/^[\x20-\x7E\u4E00-\u9FFF]+$/.test(text)) {
                    decoded = text;
                }
            } catch (e) {}
        }
        
        // 4. 尝试 UTF-8 解码
        try {
            const utf8Decoded = decodeURIComponent(escape(decoded));
            if (utf8Decoded !== decoded) {
                decoded = utf8Decoded;
            }
        } catch (e) {}
        
        return decoded;
    } catch (e) {
        return encodedName || fallback;
    }
}

const config = {
  proxy: {
    http: "http://127.0.0.1:8080",
    https: "http://127.0.0.1:8080",
    socks: "socks5://127.0.0.1:1080"
  }
};

export default class Parser {
    /**
     * 解析订阅内容
     * @param {string} url - 订阅链接或短链ID
     * @param {Env} [env] - KV 环境变量
     */
    static async parse(url, env) {
        try {
            if (url.startsWith('http://inner.nodes.secret/id-')) {
                const collectionId = url.replace('http://inner.nodes.secret/id-', '');
                const collections = await env.NODE_STORE.get(CONFIG.COLLECTIONS_KEY);

                if (!collections) {
                    throw new Error('No collections found');
                }

                const collectionsData = JSON.parse(collections);
                const collection = collectionsData.find(c => c.id === collectionId);

                const nodesData = await env.NODE_STORE.get(CONFIG.KV_KEY);
                if (!nodesData) {
                    throw new Error('No nodes found');
                }

                const nodes = JSON.parse(nodesData);
                const collectionNodes = nodes.filter(node => 
                    collection.nodeIds.includes(node.id)
                );

                let processedNodes = [];
                for (const node of collectionNodes) {
                    if (node.url.startsWith('http')) {
                        try {
                            const response = await fetch(node.url);
                            if (!response.ok) continue;
                            const content = await response.text();
                            const subNodes = await this.parseContent(content);
                            processedNodes = processedNodes.concat(subNodes);
                        } catch (error) {
                            console.error('Error processing subscription:', error);
                        }
                    } else {
                        const parsedNode = this.parseLine(node.url);
                        if (parsedNode) {
                            processedNodes.push(parsedNode);
                        }
                    }
                }

                return processedNodes;
            }

            throw new Error('Invalid URL format');
        } catch (error) {
            console.error('Parser error:', error);
            return [];
        }
    }

    /**
     * 解析订阅内容
     * @param {string} content 
     * @returns {Promise<Array>} 节点列表
     */
    static async parseContent(content, env) {
        try {
            if (!content) return [];

            // 尝试 Base64 解码
            let decodedContent = this.tryBase64Decode(content);
            
            // 分割行
            const lines = decodedContent.split(/[\n\s]+/).filter(line => line.trim());

            let nodes = [];
            for (const line of lines) {
                if (this.isSubscriptionUrl(line)) {
                    // 如果是订阅链接，递归解析
                    const subNodes = await this.parse(line, env);
                    nodes = nodes.concat(subNodes);
                } else {
                    // 解析单个节点
                    const node = this.parseLine(line.trim());
                    if (node) {
                        nodes.push(node);
                    }
                }
            }

            return nodes;
        } catch (error) {
            console.error('Parse error:', error);
            return [];
        }
    }

    /**
     * 判断是否为订阅链接
     * @param {string} line 
     * @returns {boolean}
     */
    static isSubscriptionUrl(line) {
        try {
            // 1. 检查是否是 UUID 格式（跳过 UUID 格式的字符串）
            if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(line)) {
                return false;
            }

            // 2. 检查是否是有效的URL
            const url = new URL(line);
            
            // 3. 必须是 http 或 https 协议
            if (url.protocol !== 'http:' && url.protocol !== 'https:') {
                return false;
            }

            // 4. 排除已知的节点链接协议
            const nodeProtocols = ['vmess://', 'vless://', 'trojan://', 'ss://', 'ssr://', 'hysteria://', 'hysteria2://', 'tuic://'];
            if (nodeProtocols.some(protocol => line.toLowerCase().startsWith(protocol))) {
                return false;
            }

            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * 尝试 Base64 解码
     * @param {string} content 
     * @returns {string}
     */
    static tryBase64Decode(content) {
        try {
            // 1. 检查是否看起来像 Base64
            if (!/^[A-Za-z0-9+/=]+$/.test(content.trim())) {
                return content;
            }

            // 2. 尝试 Base64 解码
            const decoded = atob(content);
            
            // 3. 验证解码结果是否包含有效的协议前缀
            const validProtocols = ['vmess://', 'vless://', 'trojan://', 'ss://', 'ssr://'];
            if (validProtocols.some(protocol => decoded.includes(protocol))) {
                return decoded;
            }

            // 4. 如果解码结果不包含有效协议，返回原内容
            return content;
        } catch {
            // 5. 如果解码失败，返回原内容
            return content;
        }
    }

    /**
     * 解析单行内容
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseLine(line) {
        if (!line) return null;

        try {
            // 添加解析日志
            console.log('Parsing node:', {
                length: line.length,
                protocol: line.split('://')[0],
                sample: line.slice(0, 50) + '...'
            });

            // 解析不同类型的节点
            if (line.startsWith('vmess://')) {
                return this.parseVmess(line);
            } else if (line.startsWith('vless://')) {
                return this.parseVless(line);
            } else if (line.startsWith('trojan://')) {
                return this.parseTrojan(line);
            } else if (line.startsWith('ss://')) {
                return this.parseSS(line);
            } else if (line.startsWith('ssr://')) {
                return this.parseSSR(line);
            } else if (line.startsWith('hysteria://')) {
                return this.parseHysteria(line);
            } else if (line.startsWith('hysteria2://')) {
                return this.parseHysteria2(line);
            } else if (line.startsWith('tuic://')) {
                return this.parseTuic(line);
            }

            // 记录未知协议
            console.log('Unknown protocol:', line.split('://')[0]);
            return null;
        } catch (error) {
            console.error('Parse line error:', error);
            return null;
        }
    }

    /**
     * 解析 VMess 节点
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseVmess(line) {
        try {
            const content = line.slice(8); // 移除 "vmess://"
            // 将 URL 安全的 base64 转换为标准 base64
            const safeContent = content
                .replace(/-/g, '+')
                .replace(/_/g, '/')
                .replace(/\s+/g, '');
            
            // 添加适当的填充
            let paddedContent = safeContent;
            const mod4 = safeContent.length % 4;
            if (mod4) {
                paddedContent += '='.repeat(4 - mod4);
            }

            const config = JSON.parse(atob(paddedContent));
            return {
                type: 'vmess',
                name: decodeNodeName(config.ps || 'Unnamed'),
                server: config.add,
                port: parseInt(config.port),
                settings: {
                    id: config.id,
                    aid: parseInt(config.aid),
                    net: config.net,
                    type: config.type,
                    host: config.host,
                    path: config.path,
                    tls: config.tls,
                    sni: config.sni,
                    alpn: config.alpn
                }
            };
        } catch (error) {
            console.error('Parse VMess error:', error);
            return null;
        }
    }

    /**
     * 解析 VLESS 节点
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseVless(line) {
        try {
            const url = new URL(line);
            const params = new URLSearchParams(url.search);
            
            // 添加解析日志
            console.log('Parsing VLESS node:', {
                server: url.hostname,
                port: url.port,
                uuid: url.username,
                params: Object.fromEntries(params.entries())
            });

            const node = {
                type: 'vless',
                name: decodeNodeName(url.hash.slice(1)),
                server: url.hostname,
                port: parseInt(url.port),
                settings: {
                    id: url.username,
                    flow: params.get('flow') || '',
                    encryption: params.get('encryption') || 'none',
                    type: params.get('type') || 'tcp',
                    security: params.get('security') || '',
                    path: params.get('path') || '',
                    host: params.get('host') || '',
                    sni: params.get('sni') || '',
                    alpn: params.get('alpn') || '',
                    pbk: params.get('pbk') || '',
                    fp: params.get('fp') || '',
                    sid: params.get('sid') || '',
                    spx: params.get('spx') || ''
                }
            };

            // 添加解析结果日志
            console.log('Parsed VLESS node:', node);
            return node;
        } catch (error) {
            console.error('Parse VLESS error:', error);
            return null;
        }
    }

    /**
     * 解析 Trojan 节点
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseTrojan(line) {
        try {
            const url = new URL(line);
            const params = new URLSearchParams(url.search);
            return {
                type: 'trojan',
                name: decodeNodeName(url.hash.slice(1)) || decodeNodeName(params.get('remarks') || ''),
                server: url.hostname,
                port: parseInt(url.port),
                settings: {
                    password: url.username,
                    type: params.get('type') || 'tcp',
                    security: params.get('security') || 'tls',
                    path: params.get('path') || '',
                    host: params.get('host') || '',
                    sni: params.get('sni') || '',
                    alpn: params.get('alpn') || ''
                }
            };
        } catch (error) {
            console.error('Parse Trojan error:', error);
            return null;
        }
    }

    /**
     * 解析 Shadowsocks 节点
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseSS(line) {
        try {
            console.log('Parsing node:', {
                protocol: 'ss',
                length: line.length,
                sample: line.slice(0, 50) + '...'
            });

            // 移除 "ss://" 前缀
            let content = line.slice(5);
            
            // 分离名称部分（如果存在）
            let name = '';
            const hashIndex = content.lastIndexOf('#');
            if (hashIndex !== -1) {
                name = content.slice(hashIndex + 1);
                content = content.slice(0, hashIndex);
            }

            // 检查是否是新版格式（已经 base64 编码的用户信息）
            const atIndex = content.indexOf('@');
            if (atIndex === -1) {
                // 旧版格式，整个内容都是 base64 编码
                const decoded = atob(content);
                const [methodAndPass, serverInfo] = decoded.split('@');
                const [method, password] = methodAndPass.split(':');
                const [server, port] = serverInfo.split(':');
                
                return {
                    type: 'ss',
                    name: decodeNodeName(name),
                    server,
                    port: parseInt(port),
                    settings: {
                        method,
                        password
                    }
                };
            } else {
                // 新版格式，只有用户信息是 base64 编码
                const [userInfo, serverInfo] = content.split('@');
                console.log('Processing userInfo:', userInfo);
                
                // 解码用户信息
                const decodedUserInfo = atob(userInfo);
                console.log('Decoded userInfo:', decodedUserInfo);
                
                const [method, ...passwordParts] = decodedUserInfo.split(':');
                const encodedPassword = passwordParts.join(':');
                
                const [server, port] = serverInfo.split(':');
                
                return {
                    type: 'ss',
                    name: decodeNodeName(name),
                    server,
                    port: parseInt(port),
                    settings: {
                        method,
                        password: encodedPassword  // 保持原始编码格式
                    }
                };
            }
        } catch (error) {
            console.error('Parse Shadowsocks error:', error);
            return null;
        }
    }

    /**
     * 解析 ShadowsocksR 节点
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseSSR(line) {
        try {
            const content = line.slice(6); // 移除 "ssr://"
            const decoded = this.tryBase64Decode(content);
            const [baseConfig, query] = decoded.split('/?');
            const [server, port, protocol, method, obfs, password] = baseConfig.split(':');
            const params = new URLSearchParams(query);
            return {
                type: 'ssr',
                name: decodeNodeName(params.get('remarks') || ''),
                server,
                port: parseInt(port),
                settings: {
                    protocol,
                    method,
                    obfs,
                    password: atob(password),
                    protocolParam: atob(params.get('protoparam') || ''),
                    obfsParam: atob(params.get('obfsparam') || '')
                }
            };
        } catch (error) {
            console.error('Parse ShadowsocksR error:', error);
            return null;
        }
    }

    /**
     * 解析 Hysteria 节点
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseHysteria(line) {
        try {
            const url = new URL(line);
            const params = new URLSearchParams(url.search);
            return {
                type: 'hysteria',
                name: decodeNodeName(url.hash.slice(1)) || decodeNodeName(params.get('remarks') || ''),
                server: url.hostname,
                port: parseInt(url.port),
                settings: {
                    auth: url.username,
                    protocol: params.get('protocol') || '',
                    up: params.get('up') || params.get('upmbps') || '',
                    down: params.get('down') || params.get('downmbps') || '',
                    alpn: params.get('alpn') || '',
                    obfs: params.get('obfs') || '',
                    sni: params.get('sni') || ''
                }
            };
        } catch (error) {
            console.error('Parse Hysteria error:', error);
            return null;
        }
    }

    /**
     * 解析 Hysteria2 节点
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseHysteria2(line) {
        try {
            const url = new URL(line);
            const params = new URLSearchParams(url.search);
            return {
                type: 'hysteria2',
                name: decodeNodeName(url.hash.slice(1)) || decodeNodeName(params.get('remarks') || ''),
                server: url.hostname,
                port: parseInt(url.port),
                settings: {
                    auth: url.username,
                    sni: params.get('sni') || '',
                    obfs: params.get('obfs') || '',
                    obfsParam: params.get('obfs-password') || '',
                    insecure: params.get('insecure') === '1' // 添加 insecure 参数支持
                }
            };
        } catch (error) {
            console.error('Parse Hysteria2 error:', error);
            return null;
        }
    }

    /**
     * 解析 TUIC 节点
     * @param {string} line 
     * @returns {Object|null}
     */
    static parseTuic(line) {
        try {
            const url = new URL(line);
            const params = new URLSearchParams(url.search);
            return {
                type: 'tuic',
                name: decodeNodeName(url.hash.slice(1)),
                server: url.hostname,
                port: parseInt(url.port),
                settings: {
                    uuid: url.username,
                    password: url.password,
                    congestion_control: params.get('congestion_control') || 'bbr',
                    udp_relay_mode: params.get('udp_relay_mode') || 'native',
                    alpn: (params.get('alpn') || '').split(',').filter(Boolean),
                    reduce_rtt: params.get('reduce_rtt') === '1',
                    sni: params.get('sni') || '',
                    disable_sni: params.get('disable_sni') === '1'
                }
            };
        } catch (error) {
            console.error('Parse TUIC error:', error);
            return null;
        }
    }
}
