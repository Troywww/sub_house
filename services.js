import { CONFIG, RULE_PRESETS } from './config.js';

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

    createRandomString(length = 16) {
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            const bytes = new Uint8Array(length);
            crypto.getRandomValues(bytes);
            return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
        }
        return this.generateUUID().replace(/-/g, '').slice(0, length * 2);
    }

    async sha256(input) {
        const data = new TextEncoder().encode(input);
        const digest = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    }

    async createPasswordRecord(password) {
        const salt = this.createRandomString(16);
        const hash = await this.sha256(`${salt}:${password}`);
        return {
            passwordHash: hash,
            passwordSalt: salt
        };
    }

    async verifyPasswordRecord(token, password) {
        if (!token) return false;
        if (token.passwordHash && token.passwordSalt) {
            const hash = await this.sha256(`${token.passwordSalt}:${password}`);
            return hash === token.passwordHash;
        }
        return token.password === password;
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
        const nodes = (await this.getNodes()).map((node) => ({
            ...node,
            tags: Array.isArray(node.tags) ? node.tags : []
        }));
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
                tags: Array.isArray(data.tags) ? data.tags.map(tag => String(tag).trim()).filter(Boolean) : [],
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
                tags: Array.isArray(data.tags) ? data.tags.map(tag => String(tag).trim()).filter(Boolean) : [],
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
            
            const safeToken = token ? {
                username: token.username || '',
                collectionId: token.collectionId,
                expiry: token.expiry || null,
                hasPassword: !!(token.passwordHash || token.password)
            } : {};

            return new Response(JSON.stringify(safeToken), {
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
            
            const previousToken = tokenIndex >= 0 ? tokens[tokenIndex] : null;
            const token = {
                username: username || previousToken?.username || `user_${id.slice(0, 6)}`,
                collectionId: id,
                expiry: expiry || null,
                createdAt: previousToken?.createdAt || new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };

            if (password) {
                Object.assign(token, await this.createPasswordRecord(password));
            } else if (previousToken?.passwordHash && previousToken?.passwordSalt) {
                token.passwordHash = previousToken.passwordHash;
                token.passwordSalt = previousToken.passwordSalt;
            } else if (previousToken?.password) {
                token.password = previousToken.password;
            }

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
        
        const tokenIndex = tokens.findIndex(t => t.collectionId === id);
        const previousToken = tokenIndex >= 0 ? tokens[tokenIndex] : null;
        const token = {
            username: username || previousToken?.username || `user_${id.slice(0, 6)}`,
            collectionId: id,
            createdAt: previousToken?.createdAt || new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        if (password) {
            Object.assign(token, await this.createPasswordRecord(password));
        } else if (previousToken?.passwordHash && previousToken?.passwordSalt) {
            token.passwordHash = previousToken.passwordHash;
            token.passwordSalt = previousToken.passwordSalt;
        } else if (previousToken?.password) {
            token.password = previousToken.password;
        }

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
        for (const token of tokens) {
            if (token.username !== username) continue;
            if (token.expiry) {
                const expiryTime = new Date(token.expiry).getTime();
                if (!Number.isNaN(expiryTime) && expiryTime < Date.now()) {
                    continue;
                }
            }
            const matched = await this.verifyPasswordRecord(token, password);
            if (!matched) continue;

            if (!token.passwordHash && token.password) {
                Object.assign(token, await this.createPasswordRecord(password));
                delete token.password;
                await this.env.NODE_STORE.put(CONFIG.USER_TOKENS_KEY, JSON.stringify(tokens));
            }

            return token;
        }

        return null;
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
export class TemplatesService extends BaseService {
    getTemplateKeyFromPath(pathname) {
        const base = this.config.API.TEMPLATES;
        if (pathname === base) return null;
        if (!pathname.startsWith(`${base}/`)) return null;
        const key = pathname.slice(base.length + 1);
        return key ? decodeURIComponent(key) : null;
    }

    buildInternalTemplateUrl(id) {
        return `https://inner.template.secret/id-${id}`;
    }

    async ensureTemplateStore() {
        if (!this.env?.TEMPLATE_CONFIG) {
            throw new Error('TEMPLATE_CONFIG binding is not configured');
        }
        return this.env.TEMPLATE_CONFIG;
    }

    async getTemplateRecord(id) {
        const store = await this.ensureTemplateStore();
        const raw = await store.get(id);
        if (!raw) return null;

        const record = JSON.parse(raw);
        return {
            id,
            name: record.name || 'Untitled Template',
            content: record.content || '',
            createdAt: record.createdAt || record.createTime || null,
            updatedAt: record.updatedAt || record.createTime || record.createdAt || null,
            internalUrl: this.buildInternalTemplateUrl(id)
        };
    }

    async listTemplates() {
        const store = await this.ensureTemplateStore();
        const { keys } = await store.list();
        const templates = [];

        for (const key of keys) {
            const record = await this.getTemplateRecord(key.name);
            if (!record) continue;
            templates.push({
                id: record.id,
                name: record.name,
                createdAt: record.createdAt,
                updatedAt: record.updatedAt,
                internalUrl: record.internalUrl
            });
        }

        return templates.sort((a, b) => {
            const left = new Date(b.updatedAt || b.createdAt || 0).getTime();
            const right = new Date(a.updatedAt || a.createdAt || 0).getTime();
            return left - right;
        });
    }

    async saveTemplate(id, data) {
        const store = await this.ensureTemplateStore();
        const now = new Date().toISOString();
        const existing = id ? await this.getTemplateRecord(id) : null;
        const templateId = id || (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : this.generateUUID());
        const record = {
            name: data.name?.trim() || existing?.name || 'Untitled Template',
            content: data.content || existing?.content || '',
            createdAt: existing?.createdAt || now,
            updatedAt: now
        };

        await store.put(templateId, JSON.stringify(record));
        return this.getTemplateRecord(templateId);
    }

    async deleteTemplate(id) {
        const store = await this.ensureTemplateStore();
        await store.delete(id);
    }

    async handleRequest(request) {
        try {
            const url = new URL(request.url);
            const method = request.method;
            const templateId = this.getTemplateKeyFromPath(url.pathname);

            if (method === 'GET' && !templateId) {
                const templates = await this.listTemplates();
                return new Response(JSON.stringify(templates), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'GET' && templateId) {
                const template = await this.getTemplateRecord(templateId);
                if (!template) {
                    return new Response(JSON.stringify({ error: 'Template not found' }), {
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                return new Response(JSON.stringify(template), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'POST' && !templateId) {
                const data = await request.json();
                if (!data?.name?.trim()) {
                    throw new Error('Template name is required');
                }
                const template = await this.saveTemplate(null, data);
                return new Response(JSON.stringify(template), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'PUT' && templateId) {
                const data = await request.json();
                const existing = await this.getTemplateRecord(templateId);
                if (!existing) {
                    return new Response(JSON.stringify({ error: 'Template not found' }), {
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                const template = await this.saveTemplate(templateId, data);
                return new Response(JSON.stringify(template), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'DELETE' && templateId) {
                await this.deleteTemplate(templateId);
                return new Response(JSON.stringify({ success: true }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'OPTIONS') {
                return this.handleOptions();
            }

            return new Response('Method not allowed', { status: 405 });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
}

export class RulesService extends BaseService {
    getRuleIdFromPath(pathname) {
        const base = this.config.API.RULES;
        if (pathname === base) return null;
        if (!pathname.startsWith(`${base}/`)) return null;
        const key = pathname.slice(base.length + 1);
        return key ? decodeURIComponent(key) : null;
    }

    async ensureRuleStore() {
        if (!this.env?.RULE_CONFIG) {
            throw new Error('RULE_CONFIG binding is not configured');
        }
        return this.env.RULE_CONFIG;
    }

    async getRuleRecord(id) {
        const store = await this.ensureRuleStore();
        const raw = await store.get(id);
        if (!raw) return null;

        const record = JSON.parse(raw);
        return {
            id,
            name: record.name || id,
            clash: record.clash || {},
            singbox: record.singbox || {},
            createdAt: record.createdAt || null,
            updatedAt: record.updatedAt || null
        };
    }

    async listRules() {
        const store = await this.ensureRuleStore();
        const { keys } = await store.list();
        const rules = [];

        for (const key of keys) {
            const record = await this.getRuleRecord(key.name);
            if (!record) continue;
            rules.push(record);
        }

        return rules.sort((a, b) => a.name.localeCompare(b.name));
    }

    async saveRule(id, data) {
        const store = await this.ensureRuleStore();
        const now = new Date().toISOString();
        const existing = id ? await this.getRuleRecord(id) : null;
        const ruleId = id || (data.id?.trim() || data.name?.trim() || (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : this.generateUUID()));
        const record = {
            name: data.name?.trim() || existing?.name || ruleId,
            clash: {
                url: data.clash?.url?.trim() || existing?.clash?.url || '',
                format: data.clash?.format?.trim() || existing?.clash?.format || ''
            },
            singbox: {
                url: data.singbox?.url?.trim() || existing?.singbox?.url || '',
                format: data.singbox?.format?.trim() || existing?.singbox?.format || ''
            },
            createdAt: existing?.createdAt || now,
            updatedAt: now
        };

        await store.put(ruleId, JSON.stringify(record));
        return this.getRuleRecord(ruleId);
    }

    async deleteRule(id) {
        const store = await this.ensureRuleStore();
        await store.delete(id);
    }

    async importPresetRules() {
        await this.ensureRuleStore();
        let imported = 0;
        let skipped = 0;
        const records = [];

        for (const preset of RULE_PRESETS) {
            const existing = await this.getRuleRecord(preset.id);
            if (existing) {
                skipped += 1;
                records.push(existing);
                continue;
            }

            const saved = await this.saveRule(preset.id, preset);
            imported += 1;
            records.push(saved);
        }

        return {
            imported,
            skipped,
            total: RULE_PRESETS.length,
            rules: records.sort((a, b) => a.name.localeCompare(b.name))
        };
    }

    async handleRequest(request) {
        try {
            const url = new URL(request.url);
            const method = request.method;
            const ruleId = this.getRuleIdFromPath(url.pathname);

            if (url.pathname === this.config.API.RULES_PRESETS && method === 'POST') {
                const result = await this.importPresetRules();
                return new Response(JSON.stringify(result), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'GET' && !ruleId) {
                const rules = await this.listRules();
                return new Response(JSON.stringify(rules), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'GET' && ruleId) {
                const rule = await this.getRuleRecord(ruleId);
                if (!rule) {
                    return new Response(JSON.stringify({ error: 'Rule not found' }), {
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                return new Response(JSON.stringify(rule), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'POST' && !ruleId) {
                const data = await request.json();
                if (!data?.name?.trim()) throw new Error('Rule name is required');
                const rule = await this.saveRule(null, data);
                return new Response(JSON.stringify(rule), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'PUT' && ruleId) {
                const data = await request.json();
                const existing = await this.getRuleRecord(ruleId);
                if (!existing) {
                    return new Response(JSON.stringify({ error: 'Rule not found' }), {
                        status: 404,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                const rule = await this.saveRule(ruleId, data);
                return new Response(JSON.stringify(rule), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'DELETE' && ruleId) {
                await this.deleteRule(ruleId);
                return new Response(JSON.stringify({ success: true }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            }

            if (method === 'OPTIONS') {
                return this.handleOptions();
            }

            return new Response('Method not allowed', { status: 405 });
        } catch (e) {
            return new Response(JSON.stringify({ error: e.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
}

export class SettingsService extends BaseService {
    async getSettings() {
        if (!this.env?.NODE_STORE) {
            return {};
        }
        const raw = await this.env.NODE_STORE.get(this.config.APP_SETTINGS_KEY);
        if (!raw) return {};
        try {
            return JSON.parse(raw) || {};
        } catch {
            return {};
        }
    }

    async saveSettings(nextSettings) {
        if (!this.env?.NODE_STORE) {
            throw new Error('KV store not available');
        }
        await this.env.NODE_STORE.put(this.config.APP_SETTINGS_KEY, JSON.stringify(nextSettings));
        return nextSettings;
    }

    async handleRequest(request) {
        if (request.method === 'GET') {
            const settings = await this.getSettings();
            const effectiveUsername = settings.adminUsername || this.env.DEFAULT_USERNAME || this.config.DEFAULT_USERNAME || '';
            const effectivePassword = settings.adminPassword || this.env.DEFAULT_PASSWORD || this.config.DEFAULT_PASSWORD || '';
            return new Response(JSON.stringify({
                adminUsername: effectiveUsername,
                hasAdminPassword: Boolean(effectivePassword),
                otherLinkUrl: settings.otherLinkUrl || '',
                activeTemplateUrl: settings.activeTemplateUrl || ''
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        if (request.method === 'PUT') {
            const payload = await request.json();
            const current = await this.getSettings();
            const nextSettings = {
                ...current,
                updatedAt: new Date().toISOString()
            };

            if (Object.prototype.hasOwnProperty.call(payload, 'adminUsername')) {
                nextSettings.adminUsername = String(payload.adminUsername || '').trim();
            }

            if (Object.prototype.hasOwnProperty.call(payload, 'otherLinkUrl')) {
                nextSettings.otherLinkUrl = String(payload.otherLinkUrl || '').trim();
            }

            if (Object.prototype.hasOwnProperty.call(payload, 'activeTemplateUrl')) {
                nextSettings.activeTemplateUrl = String(payload.activeTemplateUrl || '').trim();
            }

            if (Object.prototype.hasOwnProperty.call(payload, 'adminPassword')) {
                const password = String(payload.adminPassword || '').trim();
                if (password) {
                    nextSettings.adminPassword = password;
                } else if (!current.adminPassword) {
                    nextSettings.adminPassword = '';
                }
            }

            await this.saveSettings(nextSettings);
            return new Response(JSON.stringify({
                success: true,
                adminUsername: nextSettings.adminUsername || '',
                hasAdminPassword: Boolean(nextSettings.adminPassword),
                otherLinkUrl: nextSettings.otherLinkUrl || '',
                activeTemplateUrl: nextSettings.activeTemplateUrl || ''
            }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        if (request.method === 'OPTIONS') {
            return this.handleOptions();
        }

        return new Response('Method not allowed', { status: 405 });
    }
}

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
            return this.handleExternalSubscription(request, nodes, externalConverter);
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
                const response = await handleConvertRequest(newRequest, this.env);
                return this.attachSubscriptionMetadataByRequest(response, request);
            } 
            else if (path.endsWith('/singbox')) {
                const { handleSingboxRequest } = await import('./subscription/singbox.js');
                const response = await handleSingboxRequest(newRequest, this.env);
                return this.attachSubscriptionMetadataByRequest(response, request);
            } 
            else if (path.endsWith('/clash')) {
                const { handleClashRequest } = await import('./subscription/clash.js');
                const response = await handleClashRequest(newRequest, this.env);
                return this.attachSubscriptionMetadataByRequest(response, request);
            }

            return new Response('Invalid subscription type', { status: 400 });
        } catch (error) {
            return new Response(`Error: ${error.message}`, { 
                status: 500,
                headers: { 'Content-Type': 'text/plain' }
            });
        }
    }

    async handleExternalSubscription(request, nodes, converterBase) {
        const url = new URL(request.url);
        const shareUrl = `${url.origin}${url.pathname}`;
        const templateParam = url.searchParams.get('template') ? 
            `&template=${encodeURIComponent(url.searchParams.get('template'))}` : '';
        const baseUrl = converterBase || this.env.SUB_WORKER_URL || this.config.SUB_WORKER_URL;
        if (!baseUrl) {
            throw new Error('SUB_WORKER_URL is not configured');
        }
        
        let converterUrl;
        if (url.pathname.endsWith('/base')) {
            converterUrl = `${baseUrl}/base?url=${encodeURIComponent(shareUrl)}`;
        } else if (url.pathname.endsWith('/singbox')) {
            converterUrl = `${baseUrl}/singbox?url=${encodeURIComponent(shareUrl)}${templateParam}`;
        } else if (url.pathname.endsWith('/clash')) {
            converterUrl = `${baseUrl}/clash?url=${encodeURIComponent(shareUrl)}${templateParam}`;
        }

        const response = await fetch(converterUrl);
        return this.attachSubscriptionMetadataByRequest(response, request);
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

    async attachSubscriptionMetadataByRequest(response, request) {
        if (!(response instanceof Response) || !response.ok) {
            return response;
        }

        const url = new URL(request.url);
        const pathParts = url.pathname.split('/').filter(Boolean);
        const collectionId = pathParts.length >= 2 ? pathParts[pathParts.length - 2] : '';
        if (!collectionId) {
            return response;
        }

        const collection = await this.getCollection(collectionId);
        if (!collection) {
            return response;
        }

        const title = String(collection.name || '').trim() || `collection-${collectionId.slice(0, 6)}`;
        const headers = new Headers(response.headers);
        headers.set('Profile-Title', `base64:${this.encodeProfileTitle(title)}`);
        headers.set('Content-Disposition', this.buildSubscriptionDisposition(title, url.pathname));

        const exposeHeaders = headers.get('Access-Control-Expose-Headers');
        const requiredExposeHeaders = 'Profile-Title, Content-Disposition';
        if (!exposeHeaders) {
            headers.set('Access-Control-Expose-Headers', requiredExposeHeaders);
        } else if (!exposeHeaders.toLowerCase().includes('profile-title')) {
            headers.set('Access-Control-Expose-Headers', `${exposeHeaders}, ${requiredExposeHeaders}`);
        }

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers
        });
    }

    encodeProfileTitle(title) {
        const bytes = new TextEncoder().encode(title);
        let binary = '';
        bytes.forEach((byte) => {
            binary += String.fromCharCode(byte);
        });
        return btoa(binary);
    }

    buildSubscriptionDisposition(title, path) {
        const safeAscii = title
            .replace(/[^\x20-\x7E]+/g, '_')
            .replace(/[\\/:*?"<>|]+/g, '_')
            .replace(/\s+/g, ' ')
            .trim() || 'subscription';

        const ext = path.endsWith('/clash')
            ? 'yaml'
            : path.endsWith('/singbox')
                ? 'json'
                : 'txt';

        const utf8Filename = encodeURIComponent(`${title}.${ext}`);
        return `attachment; filename="${safeAscii}.${ext}"; filename*=UTF-8''${utf8Filename}`;
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
export class AuthService extends BaseService {
    constructor(env, config) {
        super(env, config);
    } 

    getAdminSessionKey(token) {
        return `admin_session:${token}`;
    }

    createToken() {
        if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
            return crypto.randomUUID();
        }
        return this.generateUUID();
    }

    async getAdminCredentials() {
        const settingsRaw = await this.env.NODE_STORE.get(this.config.APP_SETTINGS_KEY);
        let settings = {};
        if (settingsRaw) {
            try {
                settings = JSON.parse(settingsRaw) || {};
            } catch {
                settings = {};
            }
        }
        const username = settings.adminUsername || this.env.DEFAULT_USERNAME || this.config.DEFAULT_USERNAME || '';
        const password = settings.adminPassword || this.env.DEFAULT_PASSWORD || this.config.DEFAULT_PASSWORD || '';
        return {
            username,
            password
        };
    }

    async hasConfiguredAdminCredentials() {
        const { username, password } = await this.getAdminCredentials();
        return Boolean(username && password);
    }

    parseCookies(request) {
        const cookieHeader = request.headers.get('Cookie') || '';
        return cookieHeader.split(';').reduce((acc, part) => {
            const [rawKey, ...rest] = part.trim().split('=');
            if (!rawKey) return acc;
            acc[rawKey] = decodeURIComponent(rest.join('=') || '');
            return acc;
        }, {});
    }

    buildSessionCookie(token, maxAge = this.config.COOKIE.MAX_AGE) {
        return `${this.config.COOKIE.ADMIN_SESSION_NAME || 'admin_session'}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
    }

    clearSessionCookie() {
        return `${this.config.COOKIE.ADMIN_SESSION_NAME || 'admin_session'}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
    }

    async createSession(username) {
        const token = this.createToken();
        const session = {
            username,
            createdAt: Date.now(),
            expiresAt: Date.now() + ((this.config.COOKIE.MAX_AGE || 86400) * 1000)
        };
        await this.env.NODE_STORE.put(
            this.getAdminSessionKey(token),
            JSON.stringify(session),
            { expirationTtl: this.config.COOKIE.MAX_AGE || 86400 }
        );
        return { token, session };
    }

    async getSession(token) {
        if (!token) return null;
        const data = await this.env.NODE_STORE.get(this.getAdminSessionKey(token));
        if (!data) return null;
        try {
            const session = JSON.parse(data);
            if (session.expiresAt <= Date.now()) {
                await this.env.NODE_STORE.delete(this.getAdminSessionKey(token));
                return null;
            }
            return session;
        } catch {
            return null;
        }
    }

    async isAuthorized(request) {
        if (!await this.hasConfiguredAdminCredentials()) {
            return false;
        }

        const cookies = this.parseCookies(request);
        const sessionToken = cookies[this.config.COOKIE.ADMIN_SESSION_NAME || 'admin_session'];
        if (sessionToken) {
            const session = await this.getSession(sessionToken);
            if (session) return true;
        }

        const auth = request.headers.get('Authorization');
        return this.checkAuth(auth);
    }

    async handleApiRequest(request) {
        const url = new URL(request.url);
        const path = url.pathname;

        if (request.method === 'OPTIONS') {
            return this.handleOptions();
        }

        if (path === this.config.API.ADMIN.LOGIN && request.method === 'POST') {
            if (!await this.hasConfiguredAdminCredentials()) {
                return new Response(JSON.stringify({
                    success: false,
                    error: 'Admin credentials are not configured'
                }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
                });
            }

            const { username, password } = await request.json();
            const { username: validUsername, password: validPassword } = await this.getAdminCredentials();
            if (username !== validUsername || password !== validPassword) {
                return new Response(JSON.stringify({ success: false, error: 'Invalid username or password' }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
                });
            }

            const { token } = await this.createSession(username);
            return new Response(JSON.stringify({ success: true, username }), {
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Set-Cookie': this.buildSessionCookie(token)
                }
            });
        }

        if (path === this.config.API.ADMIN.SESSION && request.method === 'GET') {
            const cookies = this.parseCookies(request);
            const session = await this.getSession(cookies[this.config.COOKIE.ADMIN_SESSION_NAME || 'admin_session']);
            return new Response(JSON.stringify({
                authenticated: !!session,
                username: session?.username || null
            }), {
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }

        if (path === this.config.API.ADMIN.LOGOUT && request.method === 'POST') {
            const cookies = this.parseCookies(request);
            const token = cookies[this.config.COOKIE.ADMIN_SESSION_NAME || 'admin_session'];
            if (token) {
                await this.env.NODE_STORE.delete(this.getAdminSessionKey(token));
            }
            return new Response(JSON.stringify({ success: true }), {
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Set-Cookie': this.clearSessionCookie()
                }
            });
        }

        return new Response('Not Found', { status: 404 });
    }

    async handleRequest(request) {
        const authorized = await this.isAuthorized(request);
        if (!authorized) {
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
            return this.getAdminCredentials().then(({ username: validUsername, password: validPassword }) => {
                return username === validUsername && password === validPassword;
            }).catch(() => false);
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

            // From KV get user token info
            const collectionsService = new CollectionsService(this.env, this.config);
            const userToken = await collectionsService.verifyUserAccess(username, password);

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
