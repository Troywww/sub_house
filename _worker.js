import { CONFIG } from './config.js';
import { NodesService, CollectionsService, TemplatesService, RulesService, SettingsService, ShareService, AuthService, UserService } from './services.js';
import { generateManagementPage } from './management.js';
import { isSubscriptionPath } from './utils.js';
import { ErrorHandler } from './middleware.js';
import { generateUserPage } from './user.js';

export default {
    async fetch(request, env) {
        try {
            const services = initializeServices(env);
            return await handleRequest(request, env, services);
        } catch (err) {
            return ErrorHandler.handle(err, request);
        }
    }
};

function initializeServices(env) {
    const nodesService = new NodesService(env, CONFIG);
    const collectionsService = new CollectionsService(env, CONFIG);
    const templatesService = new TemplatesService(env, CONFIG);
    const rulesService = new RulesService(env, CONFIG);
    const settingsService = new SettingsService(env, CONFIG);
    const shareService = new ShareService(env, CONFIG, nodesService, collectionsService);
    const userService = new UserService(env, CONFIG);
    const authService = new AuthService(env, CONFIG);

    return {
        nodes: nodesService,
        collections: collectionsService,
        templates: templatesService,
        rules: rulesService,
        settings: settingsService,
        share: shareService,
        user: userService,
        auth: authService
    };
}

async function handleRequest(request, env, services) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
        return handleCORS();
    }

    if (path === '/favicon.ico') {
        return new Response(null, { status: 204 });
    }

    if (path.startsWith(CONFIG.API.USER.PAGE)) {
        try {
            let auth = request.headers.get('Authorization');
            const token = url.searchParams.get('token');
            if (token) {
                auth = `Bearer ${token}`;
            }

            if (auth?.startsWith('Bearer ')) {
                const sessionToken = auth.split(' ')[1];
                const session = await services.user.verifySession(sessionToken, request);
                if (session) {
                    return await generateUserPage(env, 'secret', {
                        username: session.username,
                        collectionId: session.collectionId,
                        expiry: session.expiry,
                        request
                    });
                }
            }

            return await generateUserPage(env);
        } catch (error) {
            return ErrorHandler.handle(error, request);
        }
    }

    if (isPublicPath(path)) {
        if (path.startsWith('/api/')) {
            return handleAPIRequest(request, path, services);
        }
        return null;
    }

    if (path.startsWith('/api/')) {
        return handleAPIRequest(request, path, services);
    }

    return generateManagementPage(env, CONFIG);
}

function isPublicPath(path) {
    return path.startsWith(CONFIG.API.SHARE) ||
        path.startsWith(CONFIG.API.ADMIN.BASE) ||
        isSubscriptionPath(path) ||
        path.startsWith('/user') ||
        path.startsWith(CONFIG.API.USER.BASE) ||
        path === '/favicon.ico';
}

function handleCORS() {
    return new Response(null, {
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Max-Age': '86400'
        }
    });
}

async function handleAPIRequest(request, path, services) {
    if (path.startsWith(CONFIG.API.ADMIN.BASE)) {
        return services.auth.handleApiRequest(request);
    }

    if (path.startsWith(CONFIG.API.SHARE)) {
        return services.share.handleRequest(request);
    }

    if (path.startsWith(CONFIG.API.USER.BASE)) {
        if (path === CONFIG.API.USER.LOGIN) {
            return services.user.handleLogin(request);
        }

        if (path === CONFIG.API.USER.LOGOUT) {
            const urlObj = new URL(request.url);
            const token = urlObj.searchParams.get('token');
            if (token) {
                await services.user.deleteSession(token);
            }
            return new Response(JSON.stringify({ success: true }), {
                headers: { 'Content-Type': 'application/json' }
            });
        }

        return services.user.handleRequest(request);
    }

    if (path.startsWith(CONFIG.API.NODES)) {
        const authResponse = await services.auth.handleRequest(request);
        if (authResponse) return authResponse;
        return services.nodes.handleRequest(request);
    }

    if (path.startsWith(CONFIG.API.COLLECTIONS)) {
        const authResponse = await services.auth.handleRequest(request);
        if (authResponse) return authResponse;
        return services.collections.handleRequest(request);
    }

    if (path.startsWith(CONFIG.API.TEMPLATES)) {
        const authResponse = await services.auth.handleRequest(request);
        if (authResponse) return authResponse;
        return services.templates.handleRequest(request);
    }

    if (path.startsWith(CONFIG.API.RULES)) {
        const authResponse = await services.auth.handleRequest(request);
        if (authResponse) return authResponse;
        return services.rules.handleRequest(request);
    }

    if (path.startsWith(CONFIG.API.SETTINGS)) {
        const authResponse = await services.auth.handleRequest(request);
        if (authResponse) return authResponse;
        return services.settings.handleRequest(request);
    }

    return new Response('Not Found', { status: 404 });
}
