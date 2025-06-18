import { CONFIG } from './config.js';

// 基础服务类
class BaseService {
    constructor(env, config) {
        this.env = env;
        this.config = config;
    }

    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c == 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    handleOptions() {
        return new Response(null, {
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            }
        });
    }
}

// 节点服务
export class NodesService extends BaseService {
    async getNodes() {
        if (!this.env?.NODE_STORE) {
            return [];
        }
        const data = await this.env.NODE_STORE.get(this.config.KV_KEY);
        return data ? JSON.parse(data) : [];
    }

    async setNodes(nodes) {
        if (!this.env?.NODE_STORE) {
            throw new Error('KV store not available');
        }
        await this.env.NODE_STORE.put(this.config.KV_KEY, JSON.stringify(nodes));
    }

    async handleRequest(request) {
        const method = request.method;
        switch (method) {
            case 'GET': return this.handleGet();
            case 'POST': return this.handlePost(request);
            case 'PUT': return this.handlePut(request);
            case 'DELETE': return this.handleDelete(request);
            case 'OPTIONS': return this.handleOptions();
            default: return new Response('Method not allowed', { status: 405 });
        }
    }

    // 节点服务的处理方法
    async handleGet() {
        const nodes = await this.getNodes();
        return new Response(JSON.stringify(nodes), {
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    async handlePost(request) {
        try {
            const data = await request.json();
            if (!data.name || !data.url) {
                throw new Error('Missing required fields');
            }
            
            const nodes = await this.getNodes();
            const newNode = {
                id: this.generateUUID(),
                name: data.name,
                url: data.url,
                createdAt: new Date().toISOString()
            };
            
            nodes.push(newNode);
            await this.setNodes(nodes);
            
            return new Response(JSON.stringify(newNode), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    async handlePut(request) {
        try {
            const data = await request.json();
            if (!data.id || !data.name || !data.url) {
                throw new Error('Missing required fields');
            }
            
            const nodes = await this.getNodes();
            const nodeIndex = nodes.findIndex(node => node.id === data.id);
            
            if (nodeIndex === -1) {
                throw new Error('Node not found');
            }
            
            nodes[nodeIndex] = {
                ...nodes[nodeIndex],
                name: data.name,
                url: data.url,
                updatedAt: new Date().toISOString()
            };
            
            await this.setNodes(nodes);
            return new Response(JSON.stringify(nodes[nodeIndex]), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    async handleDelete(request) {
        try {
            const { id } = await request.json();
            const nodes = await this.getNodes();
            const newNodes = nodes.filter(node => node.id !== id);
            await this.setNodes(newNodes);
            return new Response(JSON.stringify({ success: true }));
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    // ... 节点的其他处理方法 ...
}

// 集合服务
export class CollectionsService extends BaseService {
    async getCollections() {
        if (!this.env?.NODE_STORE) {
            return [];
        }
        const data = await this.env.NODE_STORE.get(this.config.COLLECTIONS_KEY);
        return data ? JSON.parse(data) : [];
    }

    async setCollections(collections) {
        if (!this.env?.NODE_STORE) {
            throw new Error('KV store not available');
        }
        await this.env.NODE_STORE.put(this.config.COLLECTIONS_KEY, JSON.stringify(collections));
    }

    async handleRequest(request) {
        const method = request.method;
        const url = new URL(request.url);
        const path = url.pathname;

        // 处理获取用户令牌请求
        if (method === 'GET' && path.startsWith('/api/collections/token/')) {
            const collectionId = path.split('/').pop();
            const tokensData = await this.env.NODE_STORE.get(CONFIG.USER_TOKENS_KEY) || '[]';
            const tokens = JSON.parse(tokensData);
            const token = tokens.find(t => t.collectionId === collectionId);
            
            return new Response(JSON.stringify(token || {}), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 处理密码验证路由
        if (method === 'POST' && path.endsWith('/verify')) {
            try {
                const { username, password } = await request.json();
                const userToken = await this.verifyUserAccess(username, password);
                
                if (userToken) {
                    // 创建会话令牌
                    const sessionToken = this.generateUUID();
                    const session = {
                        token: sessionToken,
                        username,
                        collectionId: userToken.collectionId,
                        expiresAt: Date.now() + (CONFIG.USER_SESSION_EXPIRE * 1000)
                    };

                    // 保存会话
                    const sessionsData = await this.env.NODE_STORE.get(CONFIG.USER_SESSION_KEY) || '{}';
                    const sessions = JSON.parse(sessionsData);
                    sessions[sessionToken] = session;
                    await this.env.NODE_STORE.put(CONFIG.USER_SESSION_KEY, JSON.stringify(sessions));

                    return new Response(JSON.stringify({ 
                        success: true,
                        collectionId: userToken.collectionId,
                        sessionToken
                    }), {
                        headers: { 
                            'Content-Type': 'application/json',
                            'Set-Cookie': `session=${sessionToken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${CONFIG.USER_SESSION_EXPIRE}`
                        }
                    });
                } else {
                    return new Response('Invalid credentials', { status: 401 });
                }
            } catch (e) {
                return new Response('Error verifying credentials', { status: 500 });
            }
        }

        // 处理常规请求
        switch (method) {
            case 'GET': return this.handleGet();
            case 'POST': return this.handlePost(request);
            case 'PUT': return this.handlePut(request);
            case 'DELETE': return this.handleDelete(request);
            case 'OPTIONS': return this.handleOptions();
            default: return new Response('Method not allowed', { status: 405 });
        }
    }

    // 集合服务的处理方法
    async handleGet() {
        const collections = await this.getCollections();
        return new Response(JSON.stringify(collections), {
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }

    async handlePost(request) {
        try {
            const data = await request.json();
            if (!data.name || !data.nodeIds || !Array.isArray(data.nodeIds)) {
                throw new Error('Missing required fields');
            }
            
            const collections = await this.getCollections();
            const newCollection = {
                id: this.generateUUID(),
                name: data.name,
                nodeIds: data.nodeIds,
                createdAt: new Date().toISOString(),
                userId: data.userId // 支持用户关联
            };
            
            collections.push(newCollection);
            await this.setCollections(collections);
            
            return new Response(JSON.stringify(newCollection), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    async handlePut(request) {
        try {
            const { id, nodeIds, username, password, expiry, name } = await request.json();
            if (!id) {
                throw new Error('Missing collection id');
            }

            const collections = await this.getCollections();
            const collectionIndex = collections.findIndex(c => c.id === id);
            
            if (collectionIndex === -1) {
                throw new Error('Collection not found');
            }

            // 更新用户令牌
            const tokensData = await this.env.NODE_STORE.get(CONFIG.USER_TOKENS_KEY) || '[]';
            const tokens = JSON.parse(tokensData);
            const tokenIndex = tokens.findIndex(t => t.collectionId === id);
            
            const token = {
                username: username || (tokenIndex >= 0 ? tokens[tokenIndex].username : `user_${id.slice(0, 6)}`),
                password: password || (tokenIndex >= 0 ? tokens[tokenIndex].password : ''),
                collectionId: id,
                expiry: expiry || null,
                createdAt: new Date().toISOString()
            };

            if (tokenIndex >= 0) {
                tokens[tokenIndex] = token;
            } else {
                tokens.push(token);
            }

            await this.env.NODE_STORE.put(CONFIG.USER_TOKENS_KEY, JSON.stringify(tokens));

            // 更新集合信息
            collections[collectionIndex] = {
                ...collections[collectionIndex],
                name: name || collections[collectionIndex].name,
                nodeIds: nodeIds || collections[collectionIndex].nodeIds,
                updatedAt: new Date().toISOString()
            };

            await this.setCollections(collections);
            return new Response(JSON.stringify(collections[collectionIndex]), {
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    async handleDelete(request) {
        try {
            const { id } = await request.json();
            const collections = await this.getCollections();
            const newCollections = collections.filter(collection => collection.id !== id);
            await this.setCollections(newCollections);
            return new Response(JSON.stringify({ success: true }));
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    async setCollectionPassword(id, username, password) {
        const tokensData = await this.env.NODE_STORE.get(CONFIG.USER_TOKENS_KEY) || '[]';
        const tokens = JSON.parse(tokensData);
        
        // 添加或更新户令牌
        const tokenIndex = tokens.findIndex(t => t.collectionId === id);
        const token = {
            username: username || `user_${id.slice(0, 6)}`,  // 如果没有提供用户名，生成一个
            password,
            collectionId: id,
            createdAt: new Date().toISOString()
        };

        if (tokenIndex >= 0) {
            tokens[tokenIndex] = token;
        } else {
            tokens.push(token);
        }

        await this.env.NODE_STORE.put(CONFIG.USER_TOKENS_KEY, JSON.stringify(tokens));
        return token;
    }

    async verifyUserAccess(username, password) {
        const tokensData = await this.env.NODE_STORE.get(CONFIG.USER_TOKENS_KEY) || '[]';
        const tokens = JSON.parse(tokensData);
        return tokens.find(t => t.username === username && t.password === password);
    }

    async verifySession(sessionToken) {
        if (!sessionToken) return null;

        const sessionsData = await this.env.NODE_STORE.get(CONFIG.USER_SESSION_KEY) || '{}';
        const sessions = JSON.parse(sessionsData);
        const session = sessions[sessionToken];

        if (!session || session.expiresAt < Date.now()) {
            return null;
        }

        return session;
    }

    // ... 集合的其他处理方法 ...
}

// 分享服务增强
export class ShareService extends BaseService {
    constructor(env, config, nodesService, collectionsService) {
        super(env, config);
        this.nodesService = nodesService;
        this.collectionsService = collectionsService;
    }

    async handleRequest(request) {
        try {
            const url = new URL(request.url);
            const path = url.pathname;
            const pathParts = path.split('/');
            
            // 检查是否是订阅请求
            if (this.isSubscriptionPath(path)) {
                const id = pathParts[pathParts.length - 2];  // 获取倒数部分作为ID
                return this.handleSubscription(request, id);
            } else {
                const id = pathParts[pathParts.length - 1];  // 获取最后一个部分作为ID
                return this.handleShare(id);
            }
        } catch (e) {
            return new Response('Error processing request', { status: 500 });
        }
    }

    async handleShare(id) {
        try {
            const collection = await this.getCollection(id);
            if (!collection) {
                return new Response('Collection not found', { status: 404 });
            }

            const nodes = await this.getCollectionNodes(collection);
            if (!nodes || nodes.length === 0) {
                return new Response('No nodes found', { status: 404 });
            }

            const urls = nodes.map(node => node.url).join('\n');
            
            return new Response(urls, {
                headers: {
                    'Content-Type': 'text/plain;charset=utf-8',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        } catch (e) {
            return new Response('Internal Server Error', { status: 500 });
        }
    }

    async handleSubscription(request, id) {
        const url = new URL(request.url);
        const collection = await this.getCollection(id);
        
        if (!collection) {
            return new Response('Collection not found', { status: 404 });
        }

        const nodes = await this.getCollectionNodes(collection);
        
        // 检查是否置了外部订阅转换器
        const externalConverter = this.env.SUB_WORKER_URL || this.config.SUB_WORKER_URL;
        const useInternal = url.searchParams.get('internal') === '1';

        if (externalConverter && !useInternal) {
            // 使用外部订阅转换器
            return this.handleExternalSubscription(request, nodes);
        } else {
            // 使用内部订阅转换器
            return this.handleInternalSubscription(request, nodes);
        }
    }

    async handleInternalSubscription(request, nodes) {
        const url = new URL(request.url);
        const path = url.pathname;

        // 创建一个新的 Request 对象但不通过 headers 传递点
        const newRequest = new Request(request.url, {
            ...request,
            // 添加自定义属性来传递点数据
            nodeData: nodes
        });

        try {
            if (path.endsWith('/base')) {
                const { handleConvertRequest } = await import('./subscription/base.js');
                return handleConvertRequest(newRequest, this.env);
            } 
            else if (path.endsWith('/singbox')) {
                const { handleSingboxRequest } = await import('./subscription/singbox.js');
                return handleSingboxRequest(newRequest, this.env);
            } 
            else if (path.endsWith('/clash')) {
                const { handleClashRequest } = await import('./subscription/clash.js');
                return handleClashRequest(newRequest, this.env);
            }

            return new Response('Invalid subscription type', { status: 400 });
        } catch (error) {
            return new Response(`Error: ${error.message}`, { 
                status: 500,
                headers: { 'Content-Type': 'text/plain' }
            });
        }
    }

    async handleExternalSubscription(request, nodes) {
        const url = new URL(request.url);
        const shareUrl = `${url.origin}${url.pathname}`;
        const templateParam = url.searchParams.get('template') ? 
            `&template=${encodeURIComponent(url.searchParams.get('template'))}` : '';
        
        let converterUrl;
        if (url.pathname.endsWith('/base')) {
            converterUrl = `${this.config.SUB_WORKER_URL}/base?url=${encodeURIComponent(shareUrl)}`;
        } else if (url.pathname.endsWith('/singbox')) {
            converterUrl = `${this.config.SUB_WORKER_URL}/singbox?url=${encodeURIComponent(shareUrl)}${templateParam}`;
        } else if (url.pathname.endsWith('/clash')) {
            converterUrl = `${this.config.SUB_WORKER_URL}/clash?url=${encodeURIComponent(shareUrl)}${templateParam}`;
        }

        return fetch(converterUrl);
    }

    async getCollection(id) {
        try {
            const collections = await this.collectionsService.getCollections();
            const collection = collections.find(c => c.id === id);
            return collection;
        } catch (e) {
            return null;
        }
    }

    async getCollectionNodes(collection) {
        try {
            const nodes = await this.nodesService.getNodes();
            const collectionNodes = nodes.filter(node => collection.nodeIds.includes(node.id));
            return collectionNodes;
        } catch (e) {
            return [];
        }
    }

    isSubscriptionPath(path) {
        return ['/base', '/singbox', '/clash'].some(type => path.endsWith(type));
    }
}

// 自定义错误类
export class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ValidationError';
    }
}

export class AuthError extends Error {
    constructor(message = 'Unauthorized') {
        super(message);
        this.name = 'AuthError';
    }
}

// 认证服务
export class AuthService {
    constructor(env, config) {
        this.env = env;
        this.config = config;
    } 

    async handleRequest(request) {
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                    'Access-Control-Max-Age': '86400'
                }
            });
        }

        const auth = request.headers.get('Authorization');
        if (!this.checkAuth(auth)) {
            return new Response(JSON.stringify({
                error: 'Unauthorized',
                code: 'AUTH_ERROR'
            }), {
                status: 401,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'WWW-Authenticate': 'Basic realm="Admin Access"'
                }
            });
        }

        return null;
    }

    checkAuth(auth) {
        if (!auth) return false;
        
        try {
            const [username, password] = atob(auth.split(' ')[1]).split(':');
            const validUsername = this.env.DEFAULT_USERNAME || this.config.DEFAULT_USERNAME || 'admin';
            const validPassword = this.env.DEFAULT_PASSWORD || this.config.DEFAULT_PASSWORD || 'admin';
            
            return username === validUsername && password === validPassword;
        } catch (e) {
            return false;
        }
    }
}

// 错误处理器
export class ErrorHandler {
    static handle(error, request) {
        if (error instanceof ValidationError) {
            return new Response(JSON.stringify({
                error: error.message,
                code: 'VALIDATION_ERROR'
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }

        if (error instanceof AuthError) {
            return new Response(JSON.stringify({
                error: error.message,
                code: 'AUTH_ERROR'
            }), {
                status: 401,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }

        return new Response(JSON.stringify({
            error: 'Internal Server Error',
            code: 'INTERNAL_ERROR'
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// 用户服务
export class UserService extends BaseService {
    // 修改会话有效期为3小时
    SESSION_TTL = 3 * 60 * 60 * 1000;  // 3小时 = 3 * 60分 * 60秒 * 1000毫秒

    async handleLogin(request) {
        try {
            const { username, password } = await request.json();

            // 获浏览器特信息
            const browserInfo = {
                userAgent: request.headers.get('User-Agent'),
                ip: request.headers.get('CF-Connecting-IP'),
                country: request.headers.get('CF-IPCountry'),
                platform: request.headers.get('Sec-CH-UA-Platform'),
                mobile: request.headers.get('Sec-CH-UA-Mobile')
            };

            // 从 KV 获取用户令牌信息
            const tokensData = await this.env.NODE_STORE.get(CONFIG.USER_TOKENS_KEY) || '[]';
            const tokens = JSON.parse(tokensData);
            
            // 查找匹配的用户令牌
            const userToken = tokens.find(t => 
                t.username === username && 
                t.password === password
            );

            if (userToken) {
                // 创建会话
                const sessionToken = this.generateUUID();
                
                // 保存会话信息，使用3小时过期时间
                await this.env.NODE_STORE.put(
                    CONFIG.KV_PREFIX.SESSION + sessionToken,
                    JSON.stringify({
                        username: userToken.username,
                        collectionId: userToken.collectionId,
                        browserInfo,
                        expiresAt: Date.now() + this.SESSION_TTL  // 3小时后过期
                    }),
                    { expirationTtl: this.SESSION_TTL / 1000 }  // 转换为秒
                );

                return new Response(JSON.stringify({
                    success: true,
                    sessionToken,
                    username: userToken.username,
                    collectionId: userToken.collectionId
                }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            return new Response(JSON.stringify({
                success: false,
                error: '用户名或密码错误'
            }), { 
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (error) {
            console.error('Login error:', error);
            return new Response(JSON.stringify({
                success: false,
                error: '登录失败，请重试'
            }), { 
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    async verifySession(sessionToken, request) {
        if (!sessionToken) return null;

        try {
            const data = await this.env.NODE_STORE.get(CONFIG.KV_PREFIX.SESSION + sessionToken);
            if (data) {
                const session = JSON.parse(data);
                if (session.expiresAt > Date.now()) {
                    // 验证浏览器特征
                    const currentBrowser = {
                        userAgent: request.headers.get('User-Agent'),
                        platform: request.headers.get('Sec-CH-UA-Platform')
                    };

                    if (
                        currentBrowser.userAgent === session.browserInfo.userAgent &&
                        currentBrowser.platform === session.browserInfo.platform
                    ) {
                        // 获取用户令牌信息
                        const userToken = await this.getUserToken(session.collectionId);
                        return {
                            ...session,
                            expiry: userToken?.expiry || null
                        };
                    }
                }
            }
            return null;
        } catch (error) {
            console.error('Session verification error:', error);
            return null;
        }
    }

    async deleteSession(sessionToken) {
        if (sessionToken) {
            await this.env.NODE_STORE.delete(CONFIG.KV_PREFIX.SESSION + sessionToken);
        }
    }

    // 新增方法：获取用户令牌信息
    async getUserToken(collectionId) {
        try {
            const tokensData = await this.env.NODE_STORE.get(CONFIG.USER_TOKENS_KEY);
            const tokens = tokensData ? JSON.parse(tokensData) : [];
            return tokens.find(t => t.collectionId === collectionId) || null;
        } catch (error) {
            console.error('Get user token error:', error);
            return null;
        }
    }
}
