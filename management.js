import { CONFIG, TEMPLATE_PRESETS, getConfig } from './config.js';

// 管理页面生成
export function generateManagementPage(env, CONFIG) {
    const html = `
        <!DOCTYPE html>
        <html>
        <head>
            ${generateConsoleHead()}
        </head>
        <body class="editorial-admin min-h-screen">
            ${generateConsoleHeader(CONFIG, env)}
            ${generateConsoleMainContent(CONFIG)}
            ${generateScripts(env, CONFIG)}
        </body>
        </html>
    `;

    return new Response(html, {
        headers: { 'Content-Type': 'text/html;charset=utf-8' }
    });
}

function generateConsoleHead() {
    return `
        ${generateHead()}
        ${generateEditorialStyleTag()}
    `;
}

// 生成头部
function generateHead() {
    return `
        <title>Sub House Admin Console</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://unpkg.com/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
        <script>
            let adminDialogVisible = false;
            let adminNeedsSetup = false;

            function closeLoginDialog() {
                const dialog = document.getElementById('adminLoginDialog');
                if (dialog) dialog.remove();
                adminDialogVisible = false;
            }

            function buildAdminDialogMarkup(message = '') {
                if (adminNeedsSetup) {
                    return \`
                        <div class="bg-white border border-gray-200 p-6 w-full max-w-md shadow-2xl">
                            <h2 class="text-xl font-bold mb-2 text-gray-900">Create Admin Account</h2>
                            <p class="text-sm text-gray-500 mb-4">No admin account is configured yet. Create one to enter the management console.</p>
                            <div class="space-y-4">
                                <div id="adminLoginError" class="text-sm text-red-600 min-h-[1.25rem]">\${message}</div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Admin Username</label>
                                    <input type="text" id="adminUsername" class="mt-1 block w-full px-3 py-2 border border-gray-300">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">Admin Password</label>
                                    <input type="password" id="adminPassword" class="mt-1 block w-full px-3 py-2 border border-gray-300">
                                </div>
                                <button onclick="setupAdmin()" class="w-full px-4 py-2 bg-black text-white hover:bg-gray-900">Create And Login</button>
                            </div>
                        </div>
                    \`;
                }

                return \`
                    <div class="bg-white border border-gray-200 p-6 w-full max-w-md shadow-2xl">
                        <h2 class="text-xl font-bold mb-4 text-gray-900">Admin Login</h2>
                        <div class="space-y-4">
                            <div id="adminLoginError" class="text-sm text-red-600 min-h-[1.25rem]">\${message}</div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Username</label>
                                <input type="text" id="adminUsername" class="mt-1 block w-full px-3 py-2 border border-gray-300">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Password</label>
                                <input type="password" id="adminPassword" class="mt-1 block w-full px-3 py-2 border border-gray-300">
                            </div>
                            <button onclick="login()" class="w-full px-4 py-2 bg-black text-white hover:bg-gray-900">Login</button>
                        </div>
                    </div>
                \`;
            }

            function showLoginDialog(message = '') {
                if (adminDialogVisible) {
                    const error = document.getElementById('adminLoginError');
                    if (error) error.textContent = message || '';
                    return;
                }

                adminDialogVisible = true;
                const dialog = document.createElement('div');
                dialog.id = 'adminLoginDialog';
                dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
                dialog.innerHTML = buildAdminDialogMarkup(message);
                document.body.appendChild(dialog);

                dialog.querySelectorAll('input').forEach(input => {
                    input.addEventListener('keypress', (e) => {
                        if (e.key === 'Enter') {
                            adminNeedsSetup ? setupAdmin() : login();
                        }
                    });
                });
            }
        </script>
    `;
}

function generateEditorialStyleTag() {
    return `
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Barlow+Condensed:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&family=Noto+Sans+SC:wght@400;500;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --editorial-bg: #f4f4f1;
                --editorial-paper: #ffffff;
                --editorial-panel: #f0f0ec;
                --editorial-ink: #111111;
                --editorial-muted: #666666;
                --editorial-line: rgba(17, 17, 17, 0.14);
                --editorial-line-soft: rgba(17, 17, 17, 0.08);
                --editorial-success: #0d6f3c;
                --editorial-warn: #9b650d;
                --editorial-danger: #b42318;
            }
            body.editorial-admin { background: linear-gradient(180deg, #f7f7f4 0%, #f0f0eb 100%); color: var(--editorial-ink); font-family: 'Noto Sans SC', sans-serif; letter-spacing: -0.01em; }
            .editorial-shell { max-width: 1600px; margin: 0 auto; padding: 0 22px 24px; }
            .editorial-topbar { position: sticky; top: 0; z-index: 40; border-bottom: 1px solid var(--editorial-line); background: rgba(249, 249, 246, 0.92); backdrop-filter: blur(14px); }
            .editorial-topbar-inner { min-height: 62px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
            .editorial-brand { display: flex; align-items: end; gap: 14px; min-width: 0; }
            .editorial-wordmark { font-family: 'Barlow Condensed', sans-serif; font-size: clamp(1.75rem, 2.1vw, 2.4rem); line-height: 0.92; font-weight: 700; letter-spacing: -0.05em; color: var(--editorial-ink); white-space: nowrap; }
            .editorial-kicker, .editorial-label { font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--editorial-muted); }
            .editorial-top-actions { display: flex; align-items: center; gap: 0; flex-wrap: wrap; }
            .editorial-top-actions button { border: 1px solid var(--editorial-line); border-left: none; padding: 9px 14px; background: rgba(255, 255, 255, 0.65); color: var(--editorial-ink); font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; min-height: 40px; }
            .editorial-top-actions button:first-child { border-left: 1px solid var(--editorial-line); }
            .editorial-top-actions .primary { background: var(--editorial-ink); color: #ffffff; border-color: var(--editorial-ink); }
            .editorial-main { padding-top: 16px; }
            .editorial-gate { border: 1px solid var(--editorial-line); background: var(--editorial-paper); padding: 32px 28px; text-align: center; }
            .editorial-tabbar { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 0; border: 1px solid var(--editorial-line); background: rgba(255, 255, 255, 0.72); }
            .editorial-tab { padding: 13px 16px 12px; border-right: 1px solid var(--editorial-line-soft); background: transparent; color: var(--editorial-ink); text-align: left; }
            .editorial-tab:last-child { border-right: none; }
            .editorial-tab.active { background: var(--editorial-ink); color: #ffffff; }
            .editorial-tab .en { display: block; font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: 0.14em; text-transform: uppercase; opacity: 0.6; }
            .editorial-tab .zh { display: block; margin-top: 4px; font-size: 18px; font-weight: 700; letter-spacing: -0.03em; }
            .editorial-page-stack, .editorial-pane-stack { display: flex; flex-direction: column; gap: 16px; }
            .editorial-panel { border: 1px solid var(--editorial-line); background: rgba(255, 255, 255, 0.88); box-shadow: 0 8px 24px rgba(17, 17, 17, 0.03); }
            .editorial-panel.inset { background: rgba(240, 240, 236, 0.92); }
            .editorial-title { font-family: 'Barlow Condensed', sans-serif; font-size: clamp(2.25rem, 3vw, 3.35rem); line-height: 0.92; font-weight: 700; letter-spacing: -0.05em; color: var(--editorial-ink); }
            .editorial-subtle { font-size: 13px; color: var(--editorial-muted); line-height: 1.6; }
            .editorial-hero { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(320px, 0.9fr); gap: 18px; align-items: end; }
            .editorial-stat-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); border: 1px solid var(--editorial-line); background: var(--editorial-panel); }
            .editorial-stat { padding: 14px 16px; border-right: 1px solid var(--editorial-line-soft); border-bottom: 1px solid var(--editorial-line-soft); min-height: 90px; }
            .editorial-stat:nth-child(2n) { border-right: none; }
            .editorial-stat:nth-last-child(-n + 2) { border-bottom: none; }
            .editorial-stat-value { font-family: 'Barlow Condensed', sans-serif; font-size: 2.4rem; line-height: 0.95; font-weight: 700; letter-spacing: -0.05em; }
            .editorial-kpi-warn { color: var(--editorial-warn); }
            .editorial-kpi-danger { color: var(--editorial-danger); }
            .editorial-kpi-success { color: var(--editorial-success); }
            .editorial-divider { border-top: 1px solid var(--editorial-line-soft); }
            .editorial-form-grid { display: grid; gap: 16px; }
            .editorial-form-grid.columns-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .editorial-form-grid.columns-3 { grid-template-columns: 220px minmax(0, 1fr) 220px auto; }
            .editorial-form-grid.columns-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
            .editorial-input, .editorial-select, .editorial-textarea { width: 100%; border: 1px solid var(--editorial-line); background: rgba(255, 255, 255, 0.9); padding: 11px 12px; font-size: 14px; color: var(--editorial-ink); outline: none; }
            .editorial-textarea { min-height: 360px; resize: vertical; font-family: 'IBM Plex Mono', monospace; line-height: 1.6; }
            .editorial-input.mono, .editorial-select.mono { font-family: 'IBM Plex Mono', monospace; }
            .editorial-button { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 16px; border: 1px solid var(--editorial-line); background: rgba(255, 255, 255, 0.92); color: var(--editorial-ink); font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; min-height: 42px; white-space: nowrap; }
            .editorial-button.primary { background: var(--editorial-ink); color: #ffffff; border-color: var(--editorial-ink); }
            .editorial-button.subscription-primary { background: #111111; color: #ffffff; border-color: #111111; }
            .editorial-button.subscription-singbox { color: var(--editorial-success); }
            .editorial-button.subscription-clash { color: #6b46c1; }
            .editorial-chip, .editorial-chip-count, .editorial-badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; border: 1px solid var(--editorial-line-soft); background: rgba(255, 255, 255, 0.72); font-size: 12px; color: var(--editorial-ink); }
            .editorial-chip-count, .editorial-badge { font-family: 'IBM Plex Mono', monospace; color: var(--editorial-muted); }
            .editorial-status-good { color: var(--editorial-success); background: rgba(13, 111, 60, 0.08); border-color: rgba(13, 111, 60, 0.12); }
            .editorial-status-warn { color: var(--editorial-warn); background: rgba(155, 101, 13, 0.08); border-color: rgba(155, 101, 13, 0.12); }
            .editorial-status-danger { color: var(--editorial-danger); background: rgba(180, 35, 24, 0.08); border-color: rgba(180, 35, 24, 0.12); }
            .editorial-card-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
            .editorial-card, .editorial-list-card { border: 1px solid var(--editorial-line); background: rgba(255, 255, 255, 0.88); padding: 18px; }
            .editorial-card-head { display: flex; align-items: start; justify-content: space-between; gap: 12px; }
            .editorial-card-title { font-size: 18px; font-weight: 700; letter-spacing: -0.03em; color: var(--editorial-ink); line-height: 1.2; }
            .editorial-card-meta { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
            .editorial-card-meta-item { background: var(--editorial-panel); padding: 12px; min-height: 72px; }
            .editorial-card-actions, .editorial-subscription-row { display: flex; flex-wrap: wrap; gap: 8px; }
            .editorial-empty { border: 1px dashed var(--editorial-line); background: rgba(255, 255, 255, 0.65); padding: 28px; text-align: center; color: var(--editorial-muted); }
            .editorial-side-layout { display: grid; grid-template-columns: 320px minmax(0, 1fr); gap: 16px; }
            .editorial-side-list, .editorial-structure-list { display: flex; flex-direction: column; gap: 12px; max-height: 34rem; overflow: auto; padding-right: 4px; }
            .editorial-structure-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
            .editorial-structure-box { border: 1px solid var(--editorial-line-soft); background: var(--editorial-panel); padding: 14px; min-height: 220px; }
            .editorial-structure-item { border: 1px solid var(--editorial-line-soft); background: rgba(255, 255, 255, 0.88); padding: 12px; }
            .editorial-hint { background: var(--editorial-panel); border: 1px solid var(--editorial-line-soft); padding: 14px; font-size: 13px; color: var(--editorial-muted); line-height: 1.6; }
            .editorial-modal-backdrop { position: fixed; inset: 0; z-index: 50; background: rgba(17, 17, 17, 0.5); padding: 16px; overflow: auto; }
            .editorial-modal { background: #ffffff; border: 1px solid var(--editorial-line); max-width: 1080px; width: 100%; margin: 0 auto; max-height: calc(100vh - 32px); display: flex; flex-direction: column; box-shadow: 0 24px 64px rgba(17, 17, 17, 0.12); }
            .editorial-modal-head, .editorial-modal-foot { padding: 16px 20px; border-bottom: 1px solid var(--editorial-line-soft); background: rgba(248, 248, 245, 0.96); }
            .editorial-modal-foot { border-top: 1px solid var(--editorial-line-soft); border-bottom: none; display: flex; justify-content: flex-end; gap: 8px; }
            .editorial-modal-body { padding: 20px; overflow: auto; display: flex; flex-direction: column; gap: 16px; }
            .editorial-toast { position: fixed; left: 50%; bottom: 18px; transform: translateX(-50%); background: #111111; color: #ffffff; padding: 10px 14px; font-size: 13px; z-index: 60; box-shadow: 0 10px 30px rgba(17, 17, 17, 0.18); }
            #subscriptionQrPopup .editorial-qr-card { background: rgba(255, 255, 255, 0.95); border: 1px solid var(--editorial-line); padding: 12px; box-shadow: 0 16px 40px rgba(17, 17, 17, 0.08); }
            .editorial-pane > div, #managementPage-collections > div, #managementPage-nodes > div, #managementPage-templates > div, #managementPage-rules > div, #managementPage-settings > div { border: none !important; border-radius: 0 !important; background: transparent !important; box-shadow: none !important; }
            .editorial-pane input, .editorial-pane textarea, .editorial-pane select, #managementPage-collections input, #managementPage-collections textarea, #managementPage-collections select, #managementPage-nodes input, #managementPage-nodes textarea, #managementPage-nodes select, #managementPage-templates input, #managementPage-templates textarea, #managementPage-templates select, #managementPage-rules input, #managementPage-rules textarea, #managementPage-rules select, #managementPage-settings input, #managementPage-settings textarea, #managementPage-settings select { border-radius: 0 !important; }
            @media (max-width: 1279px) {
                .editorial-hero, .editorial-side-layout, .editorial-form-grid.columns-3, .editorial-form-grid.columns-4, .editorial-card-grid, .editorial-structure-grid { grid-template-columns: 1fr; }
            }
            @media (max-width: 900px) {
                .editorial-shell { padding-left: 14px; padding-right: 14px; }
                .editorial-topbar-inner, .editorial-brand { align-items: flex-start; flex-direction: column; }
                .editorial-tabbar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
                .editorial-form-grid.columns-2, .editorial-card-meta { grid-template-columns: 1fr; }
            }
        </style>
    `;
}

function generateConsoleHeader(CONFIG, env) {
    return `
        <header class="editorial-topbar">
            <div class="editorial-shell">
                <div class="editorial-topbar-inner">
                    <div class="editorial-brand">
                        <div class="editorial-wordmark">SUB//HOUSE</div>
                        <div class="editorial-kicker">Cloudflare Worker Subscription Console</div>
                    </div>
                    <div class="editorial-top-actions">
                        <button type="button" onclick="openUserLogin()">User Portal</button>
                        <button type="button" onclick="openOtherLink()">Other Link</button>
                        <button type="button" class="primary" onclick="logoutAdmin()">Logout</button>
                    </div>
                </div>
            </div>
        </header>
    `;
}

function generateConsoleMainContent(CONFIG) {
    return `
        <main class="editorial-shell editorial-main">
            <div id="adminGateHint">
                <section class="editorial-gate">
                    <div class="editorial-kicker mb-3">[ADMIN_ACCESS]</div>
                    <h2 class="editorial-title">Enter The Management Console</h2>
                    <p class="editorial-subtle mt-3 max-w-2xl mx-auto">Sign in to manage collections, nodes, templates, rules, and system settings. The dashboard now uses a collection-first editorial console layout with fast subscription distribution actions.</p>
                    <button onclick="showLoginDialog()" class="editorial-button primary mt-6">Admin Login</button>
                </section>
            </div>
            <div id="managementShell" class="hidden editorial-page-stack">
                <nav class="editorial-tabbar">
                    <button type="button" data-page-tab="collections" onclick="showManagementPage('collections')" class="editorial-tab">
                        <span class="en">collections</span>
                        <span class="zh">Collections</span>
                    </button>
                    <button type="button" data-page-tab="nodes" onclick="showManagementPage('nodes')" class="editorial-tab">
                        <span class="en">nodes</span>
                        <span class="zh">Nodes</span>
                    </button>
                    <button type="button" data-page-tab="templates" onclick="showManagementPage('templates')" class="editorial-tab">
                        <span class="en">templates</span>
                        <span class="zh">Templates</span>
                    </button>
                    <button type="button" data-page-tab="rules" onclick="showManagementPage('rules')" class="editorial-tab">
                        <span class="en">rules</span>
                        <span class="zh">Rules</span>
                    </button>
                    <button type="button" data-page-tab="settings" onclick="showManagementPage('settings')" class="editorial-tab">
                        <span class="en">settings</span>
                        <span class="zh">Settings</span>
                    </button>
                </nav>
                <section id="managementPage-overview" data-page-panel="overview" class="hidden"></section>
                <section id="managementPage-collections" data-page-panel="collections">${generateCollectionManagerV2(CONFIG)}</section>
                <section id="managementPage-nodes" data-page-panel="nodes" class="hidden">${generateNodeManagerV2()}</section>
                <section id="managementPage-templates" data-page-panel="templates" class="hidden editorial-pane">${generateTemplateManager()}</section>
                <section id="managementPage-rules" data-page-panel="rules" class="hidden editorial-pane">${generateRuleManager()}</section>
                <section id="managementPage-settings" data-page-panel="settings" class="hidden editorial-pane">${renderSettingsManager()}</section>
            </div>
            <div id="subscriptionQrPopup" class="hidden fixed z-50 pointer-events-none">
                <div class="editorial-qr-card">
                    <p id="subscriptionQrTitle" class="editorial-kicker mb-2">SUBSCRIPTION QR</p>
                    <div id="subscriptionQrCanvas" class="w-40 h-40 flex items-center justify-center"></div>
                </div>
            </div>
        </main>
    `;
}

function generateHeader(CONFIG, env) {
    return `
        <header class="bg-white shadow-lg rounded-xl mb-3 backdrop-blur-lg bg-opacity-90">
            <div class="max-w-7xl mx-auto py-2.5 px-4 sm:px-5">
                <div class="flex justify-between items-center">
                    <div class="flex items-center">
                        <i class="fas fa-server text-blue-500 text-3xl mr-3"></i>
                        <div>
                            <h1 class="text-2xl md:text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 text-transparent bg-clip-text">
                                节点管理系统
                            </h1>
                            <p class="text-sm text-gray-500 mt-1">Cloudflare Worker 节点与订阅管理</p>
                        </div>
                    </div>
                    <div class="flex items-center space-x-3">
                        <div class="flex space-x-2">
                            <button onclick="openUserLogin()"
                                class="inline-flex items-center px-3.5 py-1.5 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-yellow-500 hover:bg-yellow-600 transition-all duration-200">
                                <i class="fas fa-user text-white mr-2"></i>用户入口
                            </button>
                        </div>
                        <div class="flex space-x-2">
                            <button onclick="logoutAdmin()"
                                class="inline-flex items-center px-3.5 py-1.5 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-red-500 hover:bg-red-600 transition-all duration-200">
                                <i class="fas fa-sign-out-alt text-white mr-2"></i>退出登录
                            </button>
                            <button onclick="openOtherLink()"
                                class="inline-flex items-center px-3.5 py-1.5 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 transition-all duration-200">
                                <i class="fas fa-link text-white mr-2"></i>其他链接
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </header>
    `;
}

// 生成主要内容
function generateMainContent(CONFIG) {
    return `
        <main class="max-w-7xl mx-auto py-3 sm:px-5 lg:px-6">
            <div id="adminGateHint" class="px-4 sm:px-0">
                <div class="bg-white rounded-xl shadow-lg p-10 text-center">
                    <h2 class="text-2xl font-bold text-gray-800">管理员后台</h2>
                    <p class="mt-3 text-gray-500">请先登录后再管理节点、集合、模板和规则。</p>
                    <button onclick="showLoginDialog()" class="mt-6 px-6 py-2.5 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition duration-200">
                        立即登录
                    </button>
                </div>
            </div>
            <div id="managementShell" class="hidden px-4 sm:px-0 space-y-5">
                <div class="bg-white rounded-xl shadow-lg p-1.5">
                    <div class="flex flex-wrap gap-1.5">
                        <button type="button" data-page-tab="overview" onclick="showManagementPage('overview')"
                            class="hidden px-4 py-2 rounded-lg bg-blue-500 text-white">
                            ?????????????????????????????????????????????????????????????????
                        </button>
                        <button type="button" data-page-tab="collections" onclick="showManagementPage('collections')"
                            class="px-3 py-1.5 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200">
                            集合管理
                        </button>
                        <button type="button" data-page-tab="nodes" onclick="showManagementPage('nodes')"
                            class="px-3 py-1.5 rounded-lg bg-blue-500 text-white">
                            节点管理
                        </button>
                        <button type="button" data-page-tab="templates" onclick="showManagementPage('templates')"
                            class="px-3 py-1.5 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200">
                            模板管理
                        </button>
                        <button type="button" data-page-tab="rules" onclick="showManagementPage('rules')"
                            class="px-3 py-1.5 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200">
                            规则目录
                        </button>
                        <button type="button" data-page-tab="settings" onclick="showManagementPage('settings')"
                            class="px-3 py-1.5 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200">
                            配置面板
                        </button>
                    </div>
                </div>
                <section id="managementPage-overview" data-page-panel="overview" class="hidden"></section>
                <section id="managementPage-nodes" data-page-panel="nodes" class="hidden">
                    ${generateNodeManagerV2()}
                </section>
                <section id="managementPage-collections" data-page-panel="collections" class="hidden">
                    ${generateCollectionManagerV2(CONFIG)}
                </section>
                <section id="managementPage-templates" data-page-panel="templates" class="hidden">
                    ${generateTemplateManager()}
                </section>
                <section id="managementPage-rules" data-page-panel="rules" class="hidden">
                    ${generateRuleManager()}
                </section>
                <section id="managementPage-settings" data-page-panel="settings" class="hidden">
                    ${renderSettingsManager()}
                </section>
            </div>
            <div id="subscriptionQrPopup" class="hidden fixed z-50 pointer-events-none">
                <div class="bg-white rounded-2xl shadow-2xl border border-gray-200 p-3">
                    <p id="subscriptionQrTitle" class="text-xs font-medium text-gray-500 mb-2">订阅二维码</p>
                    <div id="subscriptionQrCanvas" class="w-40 h-40 flex items-center justify-center"></div>
                </div>
            </div>
        </main>
    `;
}

// 生成节点管理部分
function generateNodeManager() {
    return `
        <div class="bg-white rounded-xl shadow-lg p-8 hover:shadow-xl transition-all duration-300">
            <h2 class="text-2xl font-bold text-gray-800 mb-6 flex items-center">
                <i class="fas fa-network-wired text-blue-500 mr-3"></i>节点管理
            </h2>
            <div class="space-y-6">
                <div class="flex flex-col md:flex-row gap-4">
                    <div class="flex-1 flex flex-col md:flex-row gap-4">
                        <input type="text" id="nodeName" placeholder="节点名称"
                            class="w-full md:w-1/3 px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200">
                        <input type="text" id="nodeUrl" placeholder="节点URL"
                            class="w-full md:w-2/3 px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200">
                    </div>
                    <button onclick="addNode()"
                        class="whitespace-nowrap px-6 py-2.5 bg-gradient-to-r from-blue-500 to-blue-600 text-white rounded-lg hover:from-blue-600 hover:to-blue-700 transition-all duration-200 shadow-md hover:shadow-lg">
                        <i class="fas fa-plus mr-2"></i>添加节点
                    </button>
                </div>
                <div id="nodeList" class="space-y-4"></div>
            </div>
        </div>
    `;
}

// 生成集合管理部分
function generateCollectionManager(CONFIG) {
    return `
        <div class="bg-white rounded-lg shadow-lg p-6">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-2xl font-bold text-gray-800">集合管理</h2>
            </div>
            <div class="space-y-4">
                <div class="flex flex-col md:flex-row gap-4">
                    <input type="text" id="collectionName" placeholder="集合名称"
                        class="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    <button onclick="addCollection()"
                        class="whitespace-nowrap px-6 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition duration-200">
                        创建集合
                    </button>
                </div>
                <div class="space-y-2">
                    <h3 class="text-lg font-semibold text-gray-700">选择节点</h3>
                    <div id="nodeSelection" class="grid grid-cols-2 md:grid-cols-3 gap-4 p-4 bg-gray-50 rounded-lg"></div>
                </div>
                <div id="collectionList" class="space-y-4"></div>
            </div>
        </div>
    `;
}

// 生成脚本部分
function generateTemplateManager() {
    return `
        <div class="editorial-pane-stack">
            <section class="editorial-panel p-6">
                <div class="flex flex-col xl:flex-row xl:items-end xl:justify-between gap-5">
                    <div class="space-y-2">
                        <div class="editorial-label">[MODULE_03] TEMPLATE WORKBENCH</div>
                        <h2 class="editorial-title">Template Workbench</h2>
                        <p class="editorial-subtle">Manage Clash and Sing-box templates, choose the active template, and compose rule references or proxy groups in one place.</p>
                    </div>
                    <div class="editorial-card-actions">
                        <button onclick="newTemplate()" class="editorial-button">New Template</button>
                        <select id="templatePresetSelector" class="editorial-select mono">
                            <option value="">Select Built-in Preset</option>
                            ${TEMPLATE_PRESETS.map(preset => `<option value="${preset.id}">${preset.name}</option>`).join('')}
                        </select>
                        <button onclick="loadBuiltInTemplatePreset()" class="editorial-button">Load Preset</button>
                        <button onclick="saveTemplate()" class="editorial-button primary">Save Template</button>
                    </div>
                </div>
            </section>
            <section class="editorial-side-layout">
                <aside class="editorial-panel p-4">
                    <div class="flex items-center justify-between gap-3 mb-3">
                        <div>
                            <div class="editorial-label">[STORED_TEMPLATES]</div>
                            <div class="text-lg font-semibold mt-1">Saved Templates</div>
                        </div>
                        <span id="activeTemplateBadge" class="editorial-badge">Not Active</span>
                    </div>
                    <div id="templateList" class="editorial-side-list"></div>
                </aside>
                <div class="editorial-pane-stack">
                    <section class="editorial-panel p-6 space-y-4">
                        <input type="hidden" id="templateId">
                        <div>
                            <label class="editorial-label block mb-2">Template Name</label>
                            <input type="text" id="templateName" placeholder="Default Routing Template" class="editorial-input">
                        </div>
                        <div class="editorial-card-actions">
                            <button onclick="useCurrentTemplate()" class="editorial-button">Set Active</button>
                            <button onclick="viewCurrentTemplateConfig()" class="editorial-button">View Active Config</button>
                            <button onclick="deleteTemplate()" class="editorial-button danger">Delete</button>
                        </div>
                        <div>
                            <label class="editorial-label block mb-2">Template Content</label>
                            <textarea id="templateContent" rows="18" class="editorial-textarea" placeholder="ruleset=Default,[]MATCH&#10;custom_proxy_group=Proxy&#96;select&#96;[]DIRECT"></textarea>
                        </div>
                    </section>
                    <section class="editorial-panel inset p-6 space-y-4">
                        <div class="editorial-label">[RULE_INSERTION]</div>
                        <div class="editorial-card-actions">
                            <select id="templateRuleSelector" class="editorial-select">
                                <option value="">Choose a rule to insert</option>
                            </select>
                            <button onclick="insertSelectedRuleIntoTemplate()" class="editorial-button">Insert Rule</button>
                        </div>
                        <p class="editorial-subtle">Insert a stored rule reference into the current template with one click.</p>
                    </section>
                    <section class="editorial-panel inset p-6 space-y-4">
                        <div class="editorial-label">[PROXY_GROUPS]</div>
                        <div class="editorial-form-grid columns-4">
                            <input type="text" id="groupNameInput" placeholder="Group Name" class="editorial-input">
                            <select id="groupTypeInput" class="editorial-select mono">
                                <option value="select">select</option>
                                <option value="url-test">url-test</option>
                            </select>
                            <input type="text" id="groupFilterInput" placeholder="Filter e.g. HK|SG" class="editorial-input mono">
                            <input type="text" id="groupRefsInput" placeholder="Refs separated by comma" class="editorial-input mono">
                        </div>
                        <div class="editorial-card-actions">
                            <button onclick="insertGroupLine()" class="editorial-button">Insert Group</button>
                            <button onclick="insertDefaultSelectGroup()" class="editorial-button">Insert Default Group</button>
                        </div>
                        <div class="editorial-hint">
                            Syntax examples:<br>
                            <code>ruleset=Applications,@applications</code><br>
                            <code>custom_proxy_group=Proxy&#96;select&#96;[]DIRECT</code>
                        </div>
                    </section>
                    <section class="editorial-structure-grid">
                        <div class="editorial-structure-box">
                            <div class="flex items-center justify-between mb-3">
                                <div class="text-sm font-semibold">Parsed Rules</div>
                                <span id="templateRuleCount" class="editorial-badge">0</span>
                            </div>
                            <div id="templateParsedRules" class="editorial-structure-list"></div>
                        </div>
                        <div class="editorial-structure-box">
                            <div class="flex items-center justify-between mb-3">
                                <div class="text-sm font-semibold">Parsed Groups</div>
                                <span id="templateGroupCount" class="editorial-badge">0</span>
                            </div>
                            <div id="templateParsedGroups" class="editorial-structure-list"></div>
                        </div>
                    </section>
                </div>
            </section>
        </div>
    `;
}

function generateRuleManager() {
    return `
        <div class="editorial-pane-stack">
            <section class="editorial-panel p-6">
                <div class="flex flex-col xl:flex-row xl:items-end xl:justify-between gap-5">
                    <div class="space-y-2">
                        <div class="editorial-label">[MODULE_04] RULE DIRECTORY</div>
                        <h2 class="editorial-title">Rule Directory</h2>
                        <p class="editorial-subtle">Store stable rule ids for Clash, Mihomo, and Sing-box, then reference them from templates without editing raw links repeatedly.</p>
                    </div>
                    <div class="editorial-card-actions">
                        <button onclick="newRule()" class="editorial-button">New Rule</button>
                        <button onclick="importRulePresets()" class="editorial-button">Import DustinWin Set</button>
                        <button onclick="saveRule()" class="editorial-button primary">Save Rule</button>
                    </div>
                </div>
            </section>
            <section class="editorial-side-layout">
                <aside class="editorial-panel p-4">
                    <div class="editorial-label mb-2">[STORED_RULES]</div>
                    <div class="text-lg font-semibold mb-4">Saved Rules</div>
                    <div id="ruleList" class="editorial-side-list"></div>
                </aside>
                <div class="editorial-pane-stack">
                    <section class="editorial-panel p-6 space-y-4">
                        <input type="hidden" id="ruleIdOriginal">
                        <div class="editorial-form-grid columns-2">
                            <div>
                                <label class="editorial-label block mb-2">Rule Id</label>
                                <input type="text" id="ruleId" placeholder="applications" class="editorial-input mono">
                            </div>
                            <div>
                                <label class="editorial-label block mb-2">Display Name</label>
                                <input type="text" id="ruleName" placeholder="Applications" class="editorial-input">
                            </div>
                        </div>
                        <div class="editorial-form-grid columns-2">
                            <div class="editorial-panel inset p-4 space-y-3">
                                <div class="text-sm font-semibold">Clash / Mihomo</div>
                                <input type="text" id="ruleClashUrl" placeholder="https://..." class="editorial-input mono">
                                <input type="text" id="ruleClashFormat" placeholder="Optional format: text / yaml" class="editorial-input mono">
                            </div>
                            <div class="editorial-panel inset p-4 space-y-3">
                                <div class="text-sm font-semibold">Sing-box</div>
                                <input type="text" id="ruleSingboxUrl" placeholder="https://..." class="editorial-input mono">
                                <input type="text" id="ruleSingboxFormat" placeholder="Optional format: source / binary / srs" class="editorial-input mono">
                            </div>
                        </div>
                        <div class="editorial-card-actions">
                            <button onclick="insertRuleReference()" class="editorial-button">Insert Into Template</button>
                            <button onclick="copyRuleReference()" class="editorial-button">Copy @rule_id</button>
                            <button onclick="deleteRule()" class="editorial-button danger">Delete Rule</button>
                        </div>
                        <div class="editorial-hint">
                            Template reference example:<br>
                            <code>ruleset=DIRECT,@applications</code><br>
                            Clash uses <code>clash.url</code>; Sing-box uses <code>singbox.url</code> when a subscription is generated.
                        </div>
                    </section>
                </div>
            </section>
        </div>
    `;
}

function generateSettingsManager() {
    return `
        <div class="bg-white rounded-lg shadow-lg p-6">
            <div class="mb-6">
                <h2 class="text-2xl font-bold text-gray-800">配置面板</h2>
                <p class="text-sm text-gray-500 mt-1">管理后台管理员账号、密码，以及头部“其他链接”按钮使用的地址。</p>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">管理员账号</label>
                        <input type="text" id="settingsAdminUsername" placeholder="例如：admin"
                            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">管理员密码</label>
                        <input type="password" id="settingsAdminPassword" placeholder="留空则保持当前密码"
                            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    </div>
                    <p id="settingsPasswordHint" class="text-sm text-gray-500">当前密码状态：未设置</p>
                </div>
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">其他链接</label>
                        <input type="text" id="settingsOtherLinkUrl" placeholder="https://..."
                            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    </div>
                    <p class="text-sm text-gray-500">头部“其他链接”按钮会打开这里配置的地址。</p>
                </div>
            </div>
            <div class="mt-6">
                <button onclick="saveSettings()"
                    class="px-4 py-2 rounded-xl bg-blue-600 text-white font-medium shadow-sm hover:bg-blue-700 transition duration-200">
                    保存配置
                </button>
            </div>
        </div>
    `;
}

function generateNodeManagerV2() {
    return `
        <div class="editorial-pane-stack">
            <section class="editorial-panel p-6">
                <div class="flex flex-col xl:flex-row xl:items-end xl:justify-between gap-5">
                    <div class="space-y-2">
                        <div class="editorial-label">[MODULE_02] NODE MANAGEMENT</div>
                        <h2 class="editorial-title">Node Workspace</h2>
                        <p class="editorial-subtle">Create, tag, filter, and review node resources with a denser workstation layout. Tags can be used for grouping and collection selection.</p>
                    </div>
                    <button onclick="addNode()" class="editorial-button primary">Add Node</button>
                </div>
            </section>
            <section class="editorial-panel inset p-6 space-y-4">
                <div class="editorial-label">[QUICK_CREATE]</div>
                <div class="editorial-form-grid columns-3">
                    <input type="text" id="nodeName" placeholder="Node Name" class="editorial-input">
                    <input type="text" id="nodeUrl" placeholder="Node Url" class="editorial-input mono">
                    <input type="text" id="nodeTags" placeholder="tag-a, tag-b" class="editorial-input mono">
                    <button onclick="addNode()" class="editorial-button primary">Create</button>
                </div>
            </section>
            <section class="editorial-panel p-6 space-y-4">
                <div class="flex flex-col xl:flex-row xl:items-end xl:justify-between gap-4">
                    <div class="space-y-2">
                        <div class="editorial-label">[FILTER_AND_VIEW]</div>
                        <div class="editorial-card-actions">
                            <input type="text" id="nodeTagFilter" placeholder="Search by name or tag" oninput="handleNodeFilterChange(this.value)" class="editorial-input" style="min-width: 320px;">
                            <button type="button" onclick="clearNodeFilter()" class="editorial-button">Clear</button>
                            <button type="button" id="nodeViewMode-all" onclick="setNodeViewMode('all')" class="editorial-button primary">Flat</button>
                            <button type="button" id="nodeViewMode-grouped" onclick="setNodeViewMode('grouped')" class="editorial-button">Grouped</button>
                        </div>
                    </div>
                    <div id="nodeTagSummary" class="editorial-card-actions"></div>
                </div>
                <div class="editorial-divider"></div>
                <div id="nodeList" class="editorial-pane-stack"></div>
            </section>
        </div>
    `;
}
function generateCollectionManagerV2(CONFIG) {
    return `
        <div class="editorial-pane-stack">
            <section class="editorial-panel p-6">
                <div class="editorial-hero">
                    <div class="space-y-2">
                        <div class="editorial-label">[MODULE_01] COLLECTION MANAGEMENT</div>
                        <h2 class="editorial-title">Collection Console</h2>
                        <p class="editorial-subtle">Create collection bundles, control expiry and access, and keep universal, Clash, and Sing-box subscriptions available from the primary workspace.</p>
                    </div>
                    <div id="collectionStats" class="editorial-stat-grid">
                        <div class="editorial-stat">
                            <div class="editorial-label mb-2">Collections</div>
                            <div id="statCollectionCount" class="editorial-stat-value">0</div>
                        </div>
                        <div class="editorial-stat">
                            <div class="editorial-label mb-2">Nodes</div>
                            <div id="statNodeCount" class="editorial-stat-value">0</div>
                        </div>
                        <div class="editorial-stat">
                            <div class="editorial-label editorial-kpi-warn mb-2">Expiring Soon</div>
                            <div id="statExpiringCount" class="editorial-stat-value editorial-kpi-warn">0</div>
                        </div>
                        <div class="editorial-stat">
                            <div class="editorial-label editorial-kpi-danger mb-2">Expired</div>
                            <div id="statExpiredCount" class="editorial-stat-value editorial-kpi-danger">0</div>
                        </div>
                    </div>
                </div>
            </section>
            <section class="editorial-panel inset p-6 space-y-4">
                <div class="editorial-label">[QUICK_CREATE]</div>
                <div class="editorial-card-actions">
                    <input type="text" id="collectionName" placeholder="Collection Name" class="editorial-input" style="min-width: 320px;">
                    <button onclick="addCollection()" class="editorial-button primary">Create Collection</button>
                </div>
                <div class="editorial-divider"></div>
                <div class="space-y-3">
                    <div class="flex items-center justify-between gap-3">
                        <div class="editorial-label">[NODE_SELECTION]</div>
                        <div class="editorial-subtle">Select nodes below before creating a new collection. Existing collections can be edited later.</div>
                    </div>
                    <div id="nodeSelection" class="editorial-card-grid"></div>
                </div>
            </section>
            <section class="space-y-3">
                <div class="space-y-1">
                    <div class="editorial-label">[ACTIVE_COLLECTIONS]</div>
                    <div class="text-2xl font-semibold tracking-tight">Current Collections</div>
                    <p class="editorial-subtle">Each card shows username, expiry state, node preview, and direct subscription actions.</p>
                </div>
                <div class="editorial-divider"></div>
                <div id="collectionList" class="editorial-card-grid"></div>
            </section>
        </div>
    `;
}
function renderSettingsManager() {
    return `
        <div class="editorial-pane-stack">
            <section class="editorial-panel p-6">
                <div class="space-y-2 mb-6">
                    <div class="editorial-label">[MODULE_05] SYSTEM SETTINGS</div>
                    <h2 class="editorial-title">System Settings</h2>
                    <p class="editorial-subtle">Update admin credentials and control the header link used by the "Other Link" action.</p>
                </div>
                <div class="editorial-form-grid columns-2">
                    <div class="editorial-panel inset p-5 space-y-4">
                        <div class="text-sm font-semibold">Admin Credentials</div>
                        <div>
                            <label class="editorial-label block mb-2">Admin Username</label>
                            <input type="text" id="settingsAdminUsername" placeholder="admin" class="editorial-input">
                        </div>
                        <div>
                            <label class="editorial-label block mb-2">Admin Password</label>
                            <input type="password" id="settingsAdminPassword" placeholder="Leave blank to keep the current password" class="editorial-input">
                        </div>
                        <p id="settingsPasswordHint" class="editorial-subtle">Password status: not set</p>
                    </div>
                    <div class="editorial-panel inset p-5 space-y-4">
                        <div class="text-sm font-semibold">External Link</div>
                        <div>
                            <label class="editorial-label block mb-2">Header Link Url</label>
                            <input type="text" id="settingsOtherLinkUrl" placeholder="https://..." class="editorial-input mono">
                        </div>
                        <p class="editorial-subtle">The top-right "Other Link" button opens this url.</p>
                    </div>
                </div>
                <div class="mt-6">
                    <button onclick="saveSettings()" class="editorial-button primary">Save Settings</button>
                </div>
            </section>
        </div>
    `;
}

function generateScripts(env, CONFIG) {
    return `
        <script>
            const CONFIG = {
                SUB_WORKER_URL: '${getConfig('SUB_WORKER_URL', env)}',
                API: ${JSON.stringify(CONFIG.API)}
            };
            const BUILT_IN_TEMPLATE_PRESETS = ${JSON.stringify(TEMPLATE_PRESETS).replace(/`/g, '\\`')};

            let templates = [];
            let rules = [];
            let currentSettings = {
                adminUsername: '',
                hasAdminPassword: false,
                otherLinkUrl: '',
                activeTemplateUrl: ''
            };
            let activeTemplateUrl = new URLSearchParams(window.location.search).get('template')
                || localStorage.getItem('sub_house_active_template_url')
                || '';
            let currentManagementPage = 'collections';

            function setAdminAuthenticated(authenticated) {
                const shell = document.getElementById('managementShell');
                const hint = document.getElementById('adminGateHint');
                if (shell) shell.classList.toggle('hidden', !authenticated);
                if (hint) hint.classList.toggle('hidden', authenticated);
            }

            async function ensureAdminSession(showDialogOnFail = true) {
                const response = await fetch(CONFIG.API.ADMIN.SESSION, {
                    credentials: 'same-origin'
                });
                const data = await response.json();
                adminNeedsSetup = !!data.needsSetup;
                setAdminAuthenticated(!!data.authenticated);
                if (!data.authenticated && showDialogOnFail) {
                    showLoginDialog();
                }
                return data.authenticated;
            }

            async function login() {
                const username = document.getElementById('adminUsername')?.value || '';
                const password = document.getElementById('adminPassword')?.value || '';
                const response = await fetch(CONFIG.API.ADMIN.LOGIN, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (!response.ok || !data.success) {
                    if (data.needsSetup) {
                        adminNeedsSetup = true;
                    }
                    showLoginDialog(data.error || 'Login failed');
                    return;
                }
                adminNeedsSetup = false;
                closeLoginDialog();
                setAdminAuthenticated(true);
                await Promise.all([loadNodes(), loadCollections(), loadTemplates(), loadRules(), loadSettings()]);
                showManagementPage(currentManagementPage);
            }

            async function setupAdmin() {
                const username = document.getElementById('adminUsername')?.value || '';
                const password = document.getElementById('adminPassword')?.value || '';
                const response = await fetch(CONFIG.API.ADMIN.BASE + '/setup', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await response.json();
                if (!response.ok || !data.success) {
                    showLoginDialog(data.error || 'Setup failed');
                    return;
                }
                adminNeedsSetup = false;
                closeLoginDialog();
                setAdminAuthenticated(true);
                await Promise.all([loadNodes(), loadCollections(), loadTemplates(), loadRules(), loadSettings()]);
                showManagementPage(currentManagementPage);
            }

            async function logoutAdmin() {
                await fetch(CONFIG.API.ADMIN.LOGOUT, {
                    method: 'POST',
                    credentials: 'same-origin'
                });
                setAdminAuthenticated(false);
                showLoginDialog();
            }

            async function fetchWithAuth(url, options = {}) {
                const response = await fetch(url, {
                    ...options,
                    credentials: 'same-origin'
                });
                if (response.status === 401) {
                    showLoginDialog('Session expired. Please log in again.');
                    throw new Error('Unauthorized');
                }
                return response;
            }

            async function init() {
                try {
                    const authenticated = await ensureAdminSession(false);
                    if (!authenticated) {
                        showLoginDialog();
                        return;
                    }
                    await Promise.all([loadNodes(), loadCollections(), loadTemplates(), loadRules(), loadSettings()]);
                    showManagementPage(currentManagementPage);
                } catch (e) {
                    console.error('Failed to load data:', e);
                }
            }

            init();

            ${generateNodeScriptsV2()}
            ${generateCollectionScripts()}
            ${generateTemplateScripts()}
            ${generateRuleScripts()}
            ${generateUtilityScriptsV2(env, CONFIG)}
        </script>
    `;
}

// 节点脚本
function generateNodeScripts() {
    return `
        async function loadNodes() {
            try {
                const response = await fetchWithAuth('/api/nodes');
                if (response.ok) {
                    const nodes = await response.json();
                    renderNodes(nodes);
                    updateNodeSelection(nodes);
                }
            } catch (e) {
                console.error('Error loading nodes:', e);
                alert('加载节点失败');
            }
        }

        function renderNodes(nodes) {
            const nodeList = document.getElementById('nodeList');
            nodeList.innerHTML = nodes.map(node => \`
                <div class="bg-white rounded-lg border border-gray-200 p-4 hover:shadow-md transition-all duration-200">
                    <div class="flex justify-between items-center">
                        <div class="flex-1 min-w-0">
                            <h3 class="font-medium text-gray-800 flex items-center mb-1">
                                <i class="fas fa-network-wired text-blue-500 mr-2"></i>
                                \${node.name}
                            </h3>
                            <div class="text-sm text-gray-500 font-mono truncate">
                                \${node.url}
                            </div>
                        </div>
                        <div class="flex items-center space-x-2 ml-4">
                            <button onclick="editNode('\${node.id}')"
                                class="p-1.5 text-gray-400 hover:text-blue-500 transition-colors"
                                title="编辑节点">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button onclick="copyNode('\${node.id}')"
                                class="p-1.5 text-gray-400 hover:text-blue-500 transition-colors"
                                title="复制链接">
                                <i class="fas fa-copy"></i>
                            </button>
                            <button onclick="deleteNode('\${node.id}')"
                                class="p-1.5 text-gray-400 hover:text-red-500 transition-colors"
                                title="删除节点">
                                <i class="fas fa-trash-alt"></i>
                            </button>
                        </div>
                    </div>
                </div>
            \`).join('');

            // 添加 Font Awesome 图标库
            if (!document.querySelector('link[href*="font-awesome"]')) {
                const link = document.createElement('link');
                link.rel = 'stylesheet';
                link.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css';
                document.head.appendChild(link);
            }
        }

        async function addNode() {
            const name = document.getElementById('nodeName').value;
            const url = document.getElementById('nodeUrl').value;
            
            if (!name || !url) {
                alert('请填写完整信息');
                return;
            }
            
            try {
                const response = await fetchWithAuth('/api/nodes', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, url })
                });
                
                if (response.ok) {
                    document.getElementById('nodeName').value = '';
                    document.getElementById('nodeUrl').value = '';
                    await loadNodes();
                }
            } catch (e) {
                alert('添加节点失败');
            }
        }

        async function editNode(id) {
            try {
                const response = await fetchWithAuth('/api/nodes');
                const nodes = await response.json();
                const node = nodes.find(n => n.id === id);
                
                if (node) {
                    showEditDialog(node);
                }
            } catch (e) {
                alert('编辑节点失败');
            }
        }

        function showEditDialog(node) {
            const dialog = document.createElement('div');
            dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
            dialog.innerHTML = \`
                <div class="bg-white rounded-lg shadow-xl p-6 max-w-lg w-full mx-4">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-800">编辑节点</h3>
                        <button onclick="this.closest('.fixed').remove()" 
                            class="text-gray-400 hover:text-gray-600">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                            </svg>
                        </button>
                    </div>
                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">节点名称</label>
                            <input type="text" id="editNodeName" value="\${node.name}"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">节点URL</label>
                            <input type="text" id="editNodeUrl" value="\${node.url}"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                    </div>
                    <div class="flex justify-end space-x-3 mt-6">
                        <button onclick="this.closest('.fixed').remove()"
                            class="px-4 py-2 text-gray-600 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors duration-200">
                            取消
                        </button>
                        <button onclick="updateNode('\${node.id}')"
                            class="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors duration-200">
                            保存
                        </button>
                    </div>
                </div>
            \`;
            document.body.appendChild(dialog);
        }

        async function updateNode(id) {
            const name = document.getElementById('editNodeName').value;
            const url = document.getElementById('editNodeUrl').value;
            
            if (!name || !url) {
                alert('请填写完整信息');
                return;
            }
            
            try {
                const response = await fetchWithAuth('/api/nodes', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id, name, url })
                });
                
                if (response.ok) {
                    document.querySelector('.fixed').remove();
                    await loadNodes();
                }
            } catch (e) {
                alert('更新节点失败');
            }
        }

        async function copyNode(id) {
            try {
                const response = await fetchWithAuth('/api/nodes');
                const nodes = await response.json();
                const node = nodes.find(n => n.id === id);
                
                if (node) {
                    await navigator.clipboard.writeText(node.url);
                    showToast('已复制到剪贴板');
                }
            } catch (e) {
                alert('复制失败');
            }
        }

        async function deleteNode(id) {
            if (!confirm('确定要删除这个节点吗？')) return;
            
            try {
                const response = await fetchWithAuth('/api/nodes', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id })
                });
                
                if (response.ok) {
                    await loadNodes();
                }
            } catch (e) {
                alert('删除节点失败');
            }
        }

        // 更新节点选择区域
        function updateNodeSelection(nodes) {
            const nodeSelection = document.getElementById('nodeSelection');
            nodeSelection.innerHTML = nodes.map(node => \`
                <div class="flex items-center space-x-3 p-2 bg-white rounded-lg shadow hover:shadow-md transition-shadow duration-200">
                    <input type="checkbox" id="select_\${node.id}" value="\${node.id}"
                        class="w-4 h-4 text-blue-600 rounded border-gray-300 focus:ring-blue-500">
                    <label for="select_\${node.id}" class="flex-1 text-sm text-gray-700 cursor-pointer">
                        \${node.name}
                    </label>
                </div>
            \`).join('');

            // 添加全选/取消全选按钮
            const selectionControls = document.createElement('div');
            selectionControls.className = 'col-span-2 md:col-span-3 flex justify-end gap-2';
            selectionControls.innerHTML = \`
                <button onclick="selectAllNodes()"
                    class="px-3 py-1 text-sm bg-gray-100 text-gray-600 rounded hover:bg-gray-200 transition-colors duration-200">
                    全选
                </button>
                <button onclick="deselectAllNodes()"
                    class="px-3 py-1 text-sm bg-gray-100 text-gray-600 rounded hover:bg-gray-200 transition-colors duration-200">
                    取消全选
                </button>
            \`;
            nodeSelection.insertBefore(selectionControls, nodeSelection.firstChild);
        }

        // 全选节点
        function selectAllNodes() {
            document.querySelectorAll('#nodeSelection input[type="checkbox"]')
                .forEach(checkbox => checkbox.checked = true);
        }

        // 取消全选节点
        function deselectAllNodes() {
            document.querySelectorAll('#nodeSelection input[type="checkbox"]')
                .forEach(checkbox => checkbox.checked = false);
        }

        // 获取选中的节点ID列表
        function getSelectedNodeIds() {
            return Array.from(document.querySelectorAll('#nodeSelection input:checked'))
                .map(checkbox => checkbox.value);
        }

        // 设置节点选中状态
        function setNodeSelection(nodeIds) {
            document.querySelectorAll('#nodeSelection input[type="checkbox"]')
                .forEach(checkbox => {
                    checkbox.checked = nodeIds.includes(checkbox.value);
                });
        }
    `;
}

// 生成集合相关脚本
function generateCollectionScripts() {
    return `
        function updateCollectionStats(collections, nodes) {
            const now = Date.now();
            const expiringSoonThreshold = 7 * 24 * 60 * 60 * 1000;
            let expiringSoon = 0;
            let expired = 0;

            collections.forEach((collection) => {
                const expiry = collection.tokenExpiry ? new Date(collection.tokenExpiry).getTime() : NaN;
                if (Number.isNaN(expiry)) return;
                if (expiry < now) {
                    expired += 1;
                } else if (expiry - now <= expiringSoonThreshold) {
                    expiringSoon += 1;
                }
            });

            const setText = (id, value) => {
                const el = document.getElementById(id);
                if (el) el.textContent = String(value);
            };

            setText('statCollectionCount', collections.length);
            setText('statNodeCount', nodes.length);
            setText('statExpiringCount', expiringSoon);
            setText('statExpiredCount', expired);
        }

        function renderCollectionCard(collection) {
            return \
                '<article class="editorial-card editorial-list-card">' +
                    '<div class="space-y-4 h-full">' +
                        '<div class="editorial-card-head">' +
                            '<div class="min-w-0 flex-1">' +
                                '<div class="flex items-center gap-2 flex-wrap">' +
                                    '<h3 class="editorial-card-title truncate">' + collection.name + '</h3>' +
                                    '<span id="expiry_' + collection.id + '" class="editorial-badge">Loading</span>' +
                                '</div>' +
                                '<p class="editorial-subtle mt-2">Collection id: <span class="font-mono">' + collection.id + '</span></p>' +
                            '</div>' +
                            '<div class="editorial-card-actions">' +
                                '<button onclick="editCollection(\'' + collection.id + '\')" class="editorial-button">Edit</button>' +
                                '<button onclick="deleteCollection(\'' + collection.id + '\')" class="editorial-button danger">Delete</button>' +
                            '</div>' +
                        '</div>' +
                        '<div class="editorial-card-meta">' +
                            '<div class="editorial-card-meta-item">' +
                                '<div class="editorial-label mb-2">Username</div>' +
                                '<div id="username_' + collection.id + '" class="text-sm font-semibold truncate">--</div>' +
                            '</div>' +
                            '<div class="editorial-card-meta-item">' +
                                '<div class="editorial-label mb-2">Nodes</div>' +
                                '<div id="nodeCount_' + collection.id + '" class="text-sm font-semibold">0</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="space-y-2">' +
                            '<div class="flex items-center justify-between gap-3">' +
                                '<div class="editorial-label">[NODE_PREVIEW]</div>' +
                                '<div class="editorial-subtle">Up to 5 items</div>' +
                            '</div>' +
                            '<div id="nodeList_' + collection.id + '" class="editorial-card-actions">' +
                                '<span class="editorial-badge">Loading</span>' +
                            '</div>' +
                        '</div>' +
                        '<div class="editorial-subscription-row pt-2">' +
                            '<button onclick="universalSubscription(\'' + collection.id + '\')" onmouseenter="showSubscriptionQRCode(event, \'base\', \'" + collection.id + "\', \'Universal\')" onmousemove="moveSubscriptionQRCode(event)" onmouseleave="hideSubscriptionQRCode()" class="editorial-button subscription-primary">Universal</button>' +
                            '<button onclick="singboxSubscription(\'' + collection.id + '\')" onmouseenter="showSubscriptionQRCode(event, \'singbox\', \'" + collection.id + "\', \'Sing-box\')" onmousemove="moveSubscriptionQRCode(event)" onmouseleave="hideSubscriptionQRCode()" class="editorial-button subscription-singbox">Sing-box</button>' +
                            '<button onclick="clashSubscription(\'' + collection.id + '\')" onmouseenter="showSubscriptionQRCode(event, \'clash\', \'" + collection.id + "\', \'Clash\')" onmousemove="moveSubscriptionQRCode(event)" onmouseleave="hideSubscriptionQRCode()" class="editorial-button subscription-clash">Clash</button>' +
                            '<button onclick="shareCollection(\'' + collection.id + '\')" class="editorial-button">Share</button>' +
                        '</div>' +
                    '</div>' +
                '</article>';
        }

        async function loadCollections() {
            try {
                const [collectionsResponse, nodesResponse] = await Promise.all([
                    fetchWithAuth('/api/collections'),
                    fetchWithAuth('/api/nodes')
                ]);
                const collections = await collectionsResponse.json();
                const allNodes = await nodesResponse.json();
                updateCollectionStats(collections, allNodes);

                const collectionList = document.getElementById('collectionList');
                if (!collectionList) return;

                collectionList.innerHTML = collections.length
                    ? collections.map(renderCollectionCard).join('')
                    : '<div class="editorial-empty" style="grid-column: 1 / -1;">No collections yet. Create your first collection from the quick-create panel above.</div>';

                collections.forEach(collection => {
                    updateCollectionNodes(collection, allNodes);
                });
            } catch (e) {
                console.error('Error loading collections:', e);
            }
        }

        async function updateCollectionNodes(collection, cachedNodes) {
            try {
                const tokenResponse = await fetchWithAuth('/api/collections/token/' + collection.id);
                const token = await tokenResponse.json();
                const nodes = Array.isArray(cachedNodes) ? cachedNodes : await (await fetchWithAuth('/api/nodes')).json();
                const collectionNodes = nodes.filter(node => collection.nodeIds.includes(node.id));
                const usernameElement = document.getElementById('username_' + collection.id);
                const nodeCountElement = document.getElementById('nodeCount_' + collection.id);
                const expiryElement = document.getElementById('expiry_' + collection.id);
                const nodeList = document.getElementById('nodeList_' + collection.id);

                if (usernameElement) usernameElement.textContent = token.username || '--';
                if (nodeCountElement) nodeCountElement.textContent = String(collectionNodes.length);

                if (expiryElement) {
                    if (token.expiry) {
                        const expDate = new Date(token.expiry);
                        const delta = expDate.getTime() - Date.now();
                        const expired = delta < 0;
                        const near = !expired && delta <= 7 * 24 * 60 * 60 * 1000;
                        expiryElement.textContent = expired ? 'Expired' : near ? 'Expiring Soon' : 'Active';
                        expiryElement.className = expired
                            ? 'editorial-badge editorial-status-danger'
                            : near
                                ? 'editorial-badge editorial-status-warn'
                                : 'editorial-badge editorial-status-good';
                    } else {
                        expiryElement.textContent = 'No Expiry';
                        expiryElement.className = 'editorial-badge';
                    }
                }

                if (nodeList) {
                    const previewNodes = collectionNodes.slice(0, 5);
                    const overflow = collectionNodes.length - previewNodes.length;
                    nodeList.innerHTML = previewNodes.length
                        ? previewNodes.map(node => '<span class="editorial-chip">' + node.name + '</span>').join('') + (overflow > 0 ? '<span class="editorial-chip-count">+' + overflow + '</span>' : '')
                        : '<span class="editorial-badge">No nodes selected</span>';
                }
            } catch (e) {
                console.error('Error updating collection nodes:', e);
            }
        }

        async function addCollection() {
            const name = document.getElementById('collectionName').value.trim();
            const nodeIds = Array.from(document.querySelectorAll('#nodeSelection input:checked')).map(checkbox => checkbox.value);

            if (!name) {
                alert('Please enter a collection name.');
                return;
            }
            if (nodeIds.length === 0) {
                alert('Please select at least one node.');
                return;
            }

            try {
                const response = await fetchWithAuth('/api/collections', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, nodeIds })
                });
                if (response.ok) {
                    document.getElementById('collectionName').value = '';
                    document.querySelectorAll('#nodeSelection input').forEach(checkbox => checkbox.checked = false);
                    await loadCollections();
                    showToast('Collection created.');
                }
            } catch (e) {
                alert('Failed to create collection.');
            }
        }

        async function editCollection(id) {
            try {
                const [collectionsResponse, nodesResponse] = await Promise.all([
                    fetchWithAuth('/api/collections'),
                    fetchWithAuth('/api/nodes')
                ]);
                const collections = await collectionsResponse.json();
                const allNodes = await nodesResponse.json();
                const collection = collections.find(c => c.id === id);
                if (collection) showCollectionEditDialog(collection, allNodes);
            } catch (e) {
                console.error('Edit collection failed:', e);
                alert('Failed to open the collection editor.');
            }
        }

        function closeCollectionEditDialog() {
            const dialog = document.getElementById('collectionEditDialog');
            if (dialog) dialog.remove();
        }

        function enableCollectionEditDialogDrag(dialog) {
            const panel = dialog.querySelector('[data-dialog-panel]');
            const handle = dialog.querySelector('[data-dialog-drag-handle]');
            if (!panel || !handle) return;

            requestAnimationFrame(() => {
                const rect = panel.getBoundingClientRect();
                panel.style.position = 'fixed';
                panel.style.left = Math.max(16, (window.innerWidth - rect.width) / 2) + 'px';
                panel.style.top = Math.max(16, (window.innerHeight - rect.height) / 2) + 'px';
                panel.style.width = rect.width + 'px';
                panel.style.maxWidth = 'calc(100vw - 2rem)';
                panel.style.margin = '0';
            });

            handle.style.cursor = 'move';
            handle.addEventListener('pointerdown', (event) => {
                if (event.target.closest('button')) return;
                event.preventDefault();
                const startRect = panel.getBoundingClientRect();
                const startX = event.clientX;
                const startY = event.clientY;
                const onMove = (moveEvent) => {
                    const maxLeft = Math.max(16, window.innerWidth - panel.offsetWidth - 16);
                    const maxTop = Math.max(16, window.innerHeight - panel.offsetHeight - 16);
                    const nextLeft = Math.min(maxLeft, Math.max(16, startRect.left + moveEvent.clientX - startX));
                    const nextTop = Math.min(maxTop, Math.max(16, startRect.top + moveEvent.clientY - startY));
                    panel.style.left = nextLeft + 'px';
                    panel.style.top = nextTop + 'px';
                };
                const onUp = () => window.removeEventListener('pointermove', onMove);
                window.addEventListener('pointermove', onMove);
                window.addEventListener('pointerup', onUp, { once: true });
            });
        }

        async function showCollectionEditDialog(collection, nodes) {
            const response = await fetchWithAuth('/api/collections/token/' + collection.id);
            let userToken = {};
            if (response.ok) {
                userToken = await response.json();
            }

            const formatDateForInput = (dateString) => {
                if (!dateString) return '';
                const date = new Date(dateString);
                return date.toISOString().split('T')[0];
            };

            closeCollectionEditDialog();
            const dialog = document.createElement('div');
            dialog.id = 'collectionEditDialog';
            dialog.className = 'editorial-modal-backdrop';
            dialog.innerHTML = \
                '<div data-dialog-panel class="editorial-modal" style="height: min(900px, calc(100vh - 2rem));">' +
                    '<div data-dialog-drag-handle class="editorial-modal-head flex items-center justify-between gap-4 select-none">' +
                        '<div>' +
                            '<div class="editorial-label">[EDIT_COLLECTION]</div>' +
                            '<h2 class="text-xl font-bold text-gray-900 mt-1">Edit Collection</h2>' +
                            '<p class="editorial-subtle mt-1">Drag this window if needed. The footer stays visible while the form scrolls.</p>' +
                        '</div>' +
                        '<button type="button" onclick="closeCollectionEditDialog()" class="editorial-button">Close</button>' +
                    '</div>' +
                    '<div class="editorial-modal-body">' +
                        '<div>' +
                            '<label class="editorial-label block mb-2">Collection Name</label>' +
                            '<input type="text" id="collectionName" value="' + collection.name + '" class="editorial-input">' +
                        '</div>' +
                        '<div class="editorial-form-grid columns-2">' +
                            '<div>' +
                                '<label class="editorial-label block mb-2">Username</label>' +
                                '<input type="text" id="collectionUsername" value="' + (userToken.username || '') + '" class="editorial-input">' +
                                '<p class="editorial-subtle mt-2">Leave blank to auto-generate a username.</p>' +
                            '</div>' +
                            '<div>' +
                                '<label class="editorial-label block mb-2">Password</label>' +
                                '<input type="password" id="collectionPassword" value="" class="editorial-input">' +
                                '<p class="editorial-subtle mt-2">Leave blank to keep the current password.</p>' +
                            '</div>' +
                        '</div>' +
                        '<div>' +
                            '<label class="editorial-label block mb-2">Expiry Date</label>' +
                            '<input type="date" id="collectionExpiry" value="' + formatDateForInput(userToken.expiry) + '" class="editorial-input">' +
                            '<p class="editorial-subtle mt-2">Leave empty if the subscription should not expire.</p>' +
                        '</div>' +
                        '<div>' +
                            '<label class="editorial-label block mb-2">Node Selection</label>' +
                            '<div class="editorial-card-grid">' +
                                nodes.map(node => '<label class="editorial-card p-4 flex items-start gap-3"><input type="checkbox" data-node-checkbox value="' + node.id + '" ' + (collection.nodeIds?.includes(node.id) ? 'checked' : '') + '><span><strong>' + node.name + '</strong><br><span class="editorial-subtle">' + ((node.tags || []).join(', ') || 'No tags') + '</span></span></label>').join('') +
                            '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="editorial-modal-foot">' +
                        '<button type="button" onclick="closeCollectionEditDialog()" class="editorial-button">Cancel</button>' +
                        '<button type="button" onclick="updateCollection(\'' + collection.id + '\')" class="editorial-button primary">Save Changes</button>' +
                    '</div>' +
                '</div>';

            dialog.addEventListener('click', (event) => {
                if (event.target === dialog) closeCollectionEditDialog();
            });

            document.body.appendChild(dialog);
            enableCollectionEditDialogDrag(dialog);
        }

        async function updateCollection(id) {
            const dialog = document.getElementById('collectionEditDialog');
            if (!dialog) return;
            const name = dialog.querySelector('#collectionName').value;
            const username = dialog.querySelector('#collectionUsername').value;
            const password = dialog.querySelector('#collectionPassword').value;
            const expiry = dialog.querySelector('#collectionExpiry').value;
            const nodeIds = Array.from(dialog.querySelectorAll('[data-node-checkbox]:checked')).map((checkbox) => checkbox.value);

            try {
                const response = await fetchWithAuth('/api/collections', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id, nodeIds, username, password, expiry: expiry || null, name })
                });
                if (response.ok) {
                    closeCollectionEditDialog();
                    await loadCollections();
                    showToast('Collection updated.');
                } else {
                    const error = await response.json();
                    throw new Error(error.error || 'Update failed');
                }
            } catch (e) {
                console.error('Update failed:', e);
                alert('Failed to update collection: ' + e.message);
            }
        }

        async function deleteCollection(id) {
            if (!confirm('Delete this collection?')) return;
            try {
                const response = await fetchWithAuth('/api/collections', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id })
                });
                if (response.ok) {
                    await loadCollections();
                    showToast('Collection deleted.');
                }
            } catch (e) {
                alert('Failed to delete collection.');
            }
        }

        async function shareCollection(id) {
            const shareUrl = window.location.origin + '/api/share/' + id;
            try {
                await navigator.clipboard.writeText(shareUrl);
                showToast('Share link copied.');
            } catch (e) {
                alert('Failed to copy the share link.');
            }
        }

        function universalSubscription(id) {
            const shareUrl = window.location.origin + '/api/share/' + id;
            const subUrl = CONFIG.SUB_WORKER_URL ? CONFIG.SUB_WORKER_URL + '/base?url=' + encodeURIComponent(shareUrl) : shareUrl + '/base?internal=1';
            copyToClipboard(subUrl, 'Universal subscription copied.');
        }

        function singboxSubscription(id) {
            const shareUrl = window.location.origin + '/api/share/' + id;
            const templateParam = getTemplateParam();
            const subUrl = CONFIG.SUB_WORKER_URL ? CONFIG.SUB_WORKER_URL + '/singbox?url=' + encodeURIComponent(shareUrl) + templateParam : shareUrl + '/singbox?internal=1' + templateParam;
            copyToClipboard(subUrl, 'Sing-box subscription copied.');
        }

        function clashSubscription(id) {
            const shareUrl = window.location.origin + '/api/share/' + id;
            const templateParam = getTemplateParam();
            const subUrl = CONFIG.SUB_WORKER_URL ? CONFIG.SUB_WORKER_URL + '/clash?url=' + encodeURIComponent(shareUrl) + templateParam : shareUrl + '/clash?internal=1' + templateParam;
            copyToClipboard(subUrl, 'Clash subscription copied.');
        }
    `;
}

function generateTemplateScripts() {
    return `
        function getTemplateParam() {
            return activeTemplateUrl
                ? \`&template=\${encodeURIComponent(activeTemplateUrl)}\`
                : '';
        }

        function updateActiveTemplateBadge() {
            const badge = document.getElementById('activeTemplateBadge');
            if (!badge) return;

            const active = templates.find(template => template.internalUrl === activeTemplateUrl);
            if (active) {
                badge.textContent = 'Active: ' + active.name;
                badge.className = 'editorial-badge editorial-status-good';
                return;
            }

            if (activeTemplateUrl) {
                badge.textContent = 'External Template';
                badge.className = 'editorial-badge editorial-status-warn';
                return;
            }

            badge.textContent = 'Not Active';
            badge.className = 'editorial-badge';
        }

        function setActiveTemplateUrl(url) {
            activeTemplateUrl = url || '';
            if (activeTemplateUrl) {
                localStorage.setItem('sub_house_active_template_url', activeTemplateUrl);
            } else {
                localStorage.removeItem('sub_house_active_template_url');
            }
            updateActiveTemplateBadge();
        }

        async function saveActiveTemplateUrl(url) {
            const response = await fetchWithAuth(CONFIG.API.SETTINGS, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ activeTemplateUrl: url || '' })
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to save active template');
            }
            currentSettings.activeTemplateUrl = data.activeTemplateUrl || '';
            setActiveTemplateUrl(currentSettings.activeTemplateUrl);
            return currentSettings.activeTemplateUrl;
        }

        let editingTemplateRuleIndex = -1;
        let editingTemplateGroupIndex = -1;

        function fillTemplateForm(template = {}) {
            showManagementPage('templates');
            document.getElementById('templateId').value = template.id || '';
            document.getElementById('templateName').value = template.name || '';
            document.getElementById('templateContent').value = template.content || '';
            renderTemplateStructure();
        }

        function escapeHtml(value = '') {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function parseTemplateContent(content) {
            const lines = String(content || '').split(/\r?\n/);
            const rules = [];
            const groups = [];

            lines.forEach((line) => {
                const trimmed = line.trim();
                if (!trimmed) return;

                if (trimmed.startsWith('ruleset=')) {
                    const payload = trimmed.slice('ruleset='.length);
                    const commaIndex = payload.indexOf(',');
                    rules.push({
                        name: commaIndex >= 0 ? payload.slice(0, commaIndex).trim() : payload.trim(),
                        source: commaIndex >= 0 ? payload.slice(commaIndex + 1).trim() : ''
                    });
                    return;
                }

                if (trimmed.startsWith('custom_proxy_group=')) {
                    const payload = trimmed.slice('custom_proxy_group='.length);
                    const parts = payload.split('\`');
                    groups.push({
                        name: (parts[0] || '').trim(),
                        type: (parts[1] || '').trim(),
                        summary: parts.slice(2).filter(Boolean).join(' | ')
                    });
                }
            });

            return { rules, groups };
        }

        function renderTemplateStructure() {
            const textarea = document.getElementById('templateContent');
            const ruleCount = document.getElementById('templateRuleCount');
            const groupCount = document.getElementById('templateGroupCount');
            const ruleContainer = document.getElementById('templateParsedRules');
            const groupContainer = document.getElementById('templateParsedGroups');
            if (!textarea) return;

            const parsed = parseTemplateContent(textarea.value);
            if (ruleCount) ruleCount.textContent = String(parsed.rules.length);
            if (groupCount) groupCount.textContent = String(parsed.groups.length);

            if (ruleContainer) {
                ruleContainer.innerHTML = parsed.rules.length
                    ? parsed.rules.map((item) => '<div class="editorial-structure-item"><div class="font-medium break-all">' + escapeHtml(item.name || 'Unnamed Rule') + '</div><div class="text-xs text-gray-500 mt-1 break-all">' + escapeHtml(item.source || '') + '</div></div>').join('')
                    : '<div class="editorial-empty">No parsed rules yet.</div>';
            }

            if (groupContainer) {
                groupContainer.innerHTML = parsed.groups.length
                    ? parsed.groups.map((item) => '<div class="editorial-structure-item"><div class="font-medium break-all">' + escapeHtml(item.name || 'Unnamed Group') + '</div><div class="text-xs text-gray-500 mt-1 break-all">' + escapeHtml((item.type || '') + (item.summary ? ' | ' + item.summary : '')) + '</div></div>').join('')
                    : '<div class="editorial-empty">No parsed groups yet.</div>';
            }
        }

        function setupTemplateEditorObservers() {
            const textarea = document.getElementById('templateContent');
            if (!textarea || textarea.dataset.bound === '1') return;
            textarea.dataset.bound = '1';
            textarea.addEventListener('input', renderTemplateStructure);
        }

        function newTemplate() {
            fillTemplateForm({
                name: '',
                content: 'ruleset=Default,[]MATCH\n\ncustom_proxy_group=Proxy\select\[]DIRECT'
            });
        }

        function renderTemplates() {
            const container = document.getElementById('templateList');
            if (!container) return;

            if (!templates.length) {
                container.innerHTML = '<div class="editorial-empty">No templates have been saved yet.</div>';
                updateActiveTemplateBadge();
                return;
            }

            container.innerHTML = templates.map(template => \
                '<div class="editorial-structure-item">' +
                    '<div class="flex items-start justify-between gap-3">' +
                        '<div class="min-w-0">' +
                            '<div class="font-medium truncate">' + escapeHtml(template.name) + '</div>' +
                            '<div class="text-xs text-gray-500 mt-1">Updated: ' + escapeHtml(template.updatedAt ? new Date(template.updatedAt).toLocaleString() : 'Unknown') + '</div>' +
                        '</div>' +
                        '<button onclick="editTemplate(\'' + escapeHtml(template.id) + '\')" class="editorial-button">Edit</button>' +
                    '</div>' +
                    '<div class="editorial-card-actions mt-3">' +
                        '<button onclick="activateTemplateById(\'' + escapeHtml(template.id) + '\')" class="editorial-button">Activate</button>' +
                        '<button onclick="copyTemplateUrl(\'' + escapeHtml(template.id) + '\')" class="editorial-button">Copy Url</button>' +
                    '</div>' +
                '</div>'
            ).join('');

            updateActiveTemplateBadge();
        }

        async function loadTemplates() {
            try {
                const response = await fetchWithAuth(CONFIG.API.TEMPLATES);
                if (!response.ok) throw new Error('Failed to load templates');
                templates = await response.json();
                renderTemplates();
            } catch (error) {
                console.error('Load templates error:', error);
                const container = document.getElementById('templateList');
                if (container) {
                    container.innerHTML = '<div class="editorial-empty">Failed to load templates.</div>';
                }
            }
        }

        async function editTemplate(id) {
            try {
                const response = await fetchWithAuth(\`${CONFIG.API.TEMPLATES}/\${encodeURIComponent(id)}\`);
                if (!response.ok) throw new Error('Failed to load template');
                const template = await response.json();
                fillTemplateForm(template);
            } catch (error) {
                console.error('Edit template error:', error);
                alert('Failed to load the template.');
            }
        }

        async function saveTemplate() {
            const id = document.getElementById('templateId').value.trim();
            const name = document.getElementById('templateName').value.trim();
            const content = document.getElementById('templateContent').value;

            if (!name) {
                alert('Please enter a template name.');
                return;
            }
            if (!content.trim()) {
                alert('Please enter template content.');
                return;
            }

            try {
                const response = await fetchWithAuth(id ? \`${CONFIG.API.TEMPLATES}/\${encodeURIComponent(id)}\` : CONFIG.API.TEMPLATES, {
                    method: id ? 'PUT' : 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, content })
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.error || 'Save failed');
                fillTemplateForm(data);
                await loadTemplates();
                showToast('Template saved.');
            } catch (error) {
                console.error('Save template error:', error);
                alert('Failed to save template: ' + error.message);
            }
        }

        async function deleteTemplate() {
            const id = document.getElementById('templateId').value.trim();
            if (!id) {
                alert('Select a saved template first.');
                return;
            }
            if (!confirm('Delete the current template?')) return;

            try {
                const response = await fetchWithAuth(\`${CONFIG.API.TEMPLATES}/\${encodeURIComponent(id)}\`, { method: 'DELETE' });
                if (!response.ok) {
                    const data = await response.json();
                    throw new Error(data.error || 'Delete failed');
                }
                const removed = templates.find(template => template.id === id);
                if (removed?.internalUrl === activeTemplateUrl) {
                    await saveActiveTemplateUrl('');
                }
                fillTemplateForm({});
                await loadTemplates();
                showToast('Template deleted.');
            } catch (error) {
                console.error('Delete template error:', error);
                alert('Failed to delete template: ' + error.message);
            }
        }

        async function activateTemplateById(id) {
            const template = templates.find(item => item.id === id);
            if (!template) return;
            try {
                await saveActiveTemplateUrl(template.internalUrl);
                showToast('Active template updated.');
            } catch (error) {
                alert('Failed to activate template: ' + error.message);
            }
        }

        async function useCurrentTemplate() {
            const id = document.getElementById('templateId').value.trim();
            if (!id) {
                alert('Save the current template first.');
                return;
            }
            await activateTemplateById(id);
        }

        function copyTemplateUrl(id) {
            const template = templates.find(item => item.id === id);
            if (!template) return;
            copyToClipboard(template.internalUrl, 'Template url copied.');
        }

        function copyCurrentTemplateUrl() {
            const id = document.getElementById('templateId').value.trim();
            if (!id) {
                alert('Select a template first.');
                return;
            }
            copyTemplateUrl(id);
        }

        function viewCurrentTemplateConfig() {
            const id = document.getElementById('templateId').value.trim();
            const selectedTemplate = id ? templates.find(item => item.id === id) : null;
            const targetUrl = activeTemplateUrl || selectedTemplate?.internalUrl || '';
            if (!targetUrl) {
                alert('Select or activate a template first.');
                return;
            }
            window.open(targetUrl, '_blank', 'noopener');
        }

        function loadBuiltInTemplatePreset() {
            const selector = document.getElementById('templatePresetSelector');
            const presetId = selector ? selector.value : '';
            if (!presetId) {
                alert('Choose a built-in preset first.');
                return;
            }

            const preset = BUILT_IN_TEMPLATE_PRESETS.find(item => item.id === presetId);
            if (!preset) {
                alert('Unable to find the selected preset.');
                return;
            }

            const currentTemplateId = document.getElementById('templateId').value.trim();
            const currentTemplateName = document.getElementById('templateName').value.trim();
            const nextName = currentTemplateId || currentTemplateName ? preset.name + ' - Copy' : preset.name;
            fillTemplateForm({ id: '', name: nextName, content: preset.content });
            showToast('Preset loaded. Save it as a new template when ready.');
        }

        function appendLineToTemplate(line, successMessage) {
            const templateContent = document.getElementById('templateContent');
            if (!templateContent) {
                alert('Template editor not found.');
                return false;
            }
            const prefix = templateContent.value && !templateContent.value.endsWith('\n') ? '\n' : '';
            templateContent.value += prefix + line + '\n';
            templateContent.focus();
            renderTemplateStructure();
            if (successMessage) showToast(successMessage);
            return true;
        }

        function insertSelectedRuleIntoTemplate() {
            const selector = document.getElementById('templateRuleSelector');
            if (!selector || !selector.value) {
                alert('Select a rule first.');
                return;
            }
            const rule = rules.find(item => item.id === selector.value);
            if (!rule) {
                alert('Selected rule was not found.');
                return;
            }
            appendLineToTemplate('ruleset=' + rule.name + ',@' + rule.id, 'Rule reference inserted.');
        }

        function insertGroupLine() {
            const name = document.getElementById('groupNameInput').value.trim();
            const type = document.getElementById('groupTypeInput').value;
            const filter = document.getElementById('groupFilterInput').value.trim();
            const refs = document.getElementById('groupRefsInput').value
                .split(',')
                .map(item => item.trim())
                .filter(Boolean)
                .map(item => item.startsWith('[]') ? item : '[]' + item);

            if (!name) {
                alert('Please enter a group name.');
                return;
            }

            let line = 'custom_proxy_group=' + name + '\`' + type + '\`';
            if (type === 'url-test') {
                line += (filter || '.*') + '\`http://www.gstatic.com/generate_204\`300,,50';
            } else {
                line += (filter || '.*');
            }
            if (refs.length) {
                line += '\`' + refs.join('\`');
            }
            appendLineToTemplate(line, 'Group line inserted.');
        }

        function insertDefaultSelectGroup() {
            document.getElementById('groupNameInput').value = 'Proxy';
            document.getElementById('groupTypeInput').value = 'select';
            document.getElementById('groupFilterInput').value = '';
            document.getElementById('groupRefsInput').value = 'DIRECT';
            insertGroupLine();
        }

        setupTemplateEditorObservers();
        renderTemplateStructure();
    `;
}

function generateRuleScripts() {
    return `
        function fillRuleForm(rule = {}) {
            showManagementPage('rules');
            document.getElementById('ruleIdOriginal').value = rule.id || '';
            const ruleIdInput = document.getElementById('ruleId');
            ruleIdInput.value = rule.id || '';
            ruleIdInput.readOnly = !!rule.id;
            ruleIdInput.classList.toggle('bg-gray-100', !!rule.id);
            document.getElementById('ruleName').value = rule.name || '';
            document.getElementById('ruleClashUrl').value = (rule.clash && rule.clash.url) || '';
            document.getElementById('ruleClashFormat').value = (rule.clash && rule.clash.format) || '';
            document.getElementById('ruleSingboxUrl').value = (rule.singbox && rule.singbox.url) || '';
            document.getElementById('ruleSingboxFormat').value = (rule.singbox && rule.singbox.format) || '';
        }

        function newRule() {
            fillRuleForm({ id: '', name: '', clash: { url: '', format: '' }, singbox: { url: '', format: '' } });
        }

        function renderRules() {
            const container = document.getElementById('ruleList');
            const selector = document.getElementById('templateRuleSelector');
            if (!container) return;

            if (!rules.length) {
                container.innerHTML = '<div class="editorial-empty">No rules yet. Create one to build your template references.</div>';
                if (selector) selector.innerHTML = '<option value="">No rules available</option>';
                return;
            }

            if (selector) {
                selector.innerHTML = '<option value="">Choose a rule</option>' + rules.map(rule => '<option value="' + escapeHtml(rule.id || '') + '">' + escapeHtml(rule.name || '') + ' (@' + escapeHtml(rule.id || '') + ')</option>').join('');
            }

            container.innerHTML = rules.map(rule => {
                const clashUrl = (rule.clash && rule.clash.url) || 'Not configured';
                const singboxUrl = (rule.singbox && rule.singbox.url) || 'Not configured';
                return '<div class="editorial-structure-item">'
                    + '<div class="flex items-start justify-between gap-3">'
                    + '<div class="min-w-0">'
                    + '<div class="font-medium truncate">' + escapeHtml(rule.name || '') + '</div>'
                    + '<div class="text-xs text-gray-500 mt-1 font-mono">@' + escapeHtml(rule.id || '') + '</div>'
                    + '</div>'
                    + '<button onclick="editRule(' + "'" + escapeHtml(rule.id || '') + "'" + ')" class="editorial-button">Edit</button>'
                    + '</div>'
                    + '<div class="text-xs text-gray-500 mt-3 space-y-1">'
                    + '<div class="truncate">Clash: ' + escapeHtml(clashUrl) + '</div>'
                    + '<div class="truncate">Sing-box: ' + escapeHtml(singboxUrl) + '</div>'
                    + '</div>'
                    + '</div>';
            }).join('');
        }

        async function loadRules() {
            try {
                const response = await fetchWithAuth('${CONFIG.API.RULES}');
                if (!response.ok) throw new Error('Failed to load rules');
                rules = await response.json();
                renderRules();
            } catch (error) {
                console.error('Load rules error:', error);
                const container = document.getElementById('ruleList');
                if (container) container.innerHTML = '<div class="editorial-empty">Failed to load rules.</div>';
            }
        }

        async function importRulePresets() {
            try {
                const response = await fetchWithAuth('${CONFIG.API.RULES_PRESETS}', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({})
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.error || 'Failed to import presets');
                await loadRules();
                showToast('Imported ' + data.imported + ' preset rules. Skipped ' + data.skipped + ' existing items.');
            } catch (error) {
                console.error('Import presets error:', error);
                alert('Failed to import presets: ' + error.message);
            }
        }

        async function editRule(id) {
            try {
                const response = await fetchWithAuth('${CONFIG.API.RULES}/' + encodeURIComponent(id));
                if (!response.ok) throw new Error('Failed to load rule');
                const rule = await response.json();
                fillRuleForm(rule);
            } catch (error) {
                console.error('Edit rule error:', error);
                alert('Failed to load the selected rule.');
            }
        }

        async function saveRule() {
            const originalId = document.getElementById('ruleIdOriginal').value.trim();
            const id = document.getElementById('ruleId').value.trim();
            const name = document.getElementById('ruleName').value.trim();
            const clashUrl = document.getElementById('ruleClashUrl').value.trim();
            const clashFormat = document.getElementById('ruleClashFormat').value.trim();
            const singboxUrl = document.getElementById('ruleSingboxUrl').value.trim();
            const singboxFormat = document.getElementById('ruleSingboxFormat').value.trim();

            if (!id) {
                alert('Please enter a rule id.');
                return;
            }
            if (!name) {
                alert('Please enter a display name.');
                return;
            }
            if (!clashUrl && !singboxUrl) {
                alert('Provide at least one Clash or Sing-box rule source.');
                return;
            }

            const payload = {
                id,
                name,
                clash: { url: clashUrl, format: clashFormat },
                singbox: { url: singboxUrl, format: singboxFormat }
            };

            try {
                const target = originalId || id;
                const response = await fetchWithAuth(originalId ? '${CONFIG.API.RULES}/' + encodeURIComponent(target) : '${CONFIG.API.RULES}', {
                    method: originalId ? 'PUT' : 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await response.json();
                if (!response.ok) throw new Error(data.error || 'Save failed');
                fillRuleForm(data);
                await loadRules();
                showToast('Rule saved.');
            } catch (error) {
                console.error('Save rule error:', error);
                alert('Failed to save rule: ' + error.message);
            }
        }

        async function deleteRule() {
            const id = document.getElementById('ruleIdOriginal').value.trim();
            if (!id) {
                alert('Select a saved rule first.');
                return;
            }
            if (!confirm('Delete this rule?')) return;

            try {
                const response = await fetchWithAuth('${CONFIG.API.RULES}/' + encodeURIComponent(id), { method: 'DELETE' });
                if (!response.ok) {
                    const data = await response.json();
                    throw new Error(data.error || 'Delete failed');
                }
                fillRuleForm({});
                await loadRules();
                showToast('Rule deleted.');
            } catch (error) {
                console.error('Delete rule error:', error);
                alert('Failed to delete rule: ' + error.message);
            }
        }

        function getCurrentRuleReference() {
            const id = document.getElementById('ruleId').value.trim() || document.getElementById('ruleIdOriginal').value.trim();
            return id ? '@' + id : '';
        }

        function copyRuleReference() {
            const ref = getCurrentRuleReference();
            if (!ref) {
                alert('Please enter or select a rule id first.');
                return;
            }
            copyToClipboard(ref, 'Rule reference copied.');
        }

        function insertRuleReference() {
            const ref = getCurrentRuleReference();
            if (!ref) {
                alert('Please enter or select a rule id first.');
                return;
            }
            const templateContent = document.getElementById('templateContent');
            if (!templateContent) {
                alert('Template editor not found.');
                return;
            }
            const displayName = document.getElementById('ruleName').value.trim() || ref.slice(1);
            const line = 'ruleset=' + displayName + ',' + ref;
            const prefix = templateContent.value && !templateContent.value.endsWith('\n') ? '\n' : '';
            templateContent.value += prefix + line + '\n';
            templateContent.focus();
            renderTemplateStructure();
            showToast('Rule reference inserted.');
        }
    `;
}

function generateUtilityScriptsV2(env, CONFIG) {
    return `
        function showManagementPage(page) {
            currentManagementPage = !page || page === 'overview' ? 'collections' : page;
            document.querySelectorAll('[data-page-panel]').forEach((panel) => {
                panel.classList.toggle('hidden', panel.getAttribute('data-page-panel') !== currentManagementPage);
            });
            document.querySelectorAll('[data-page-tab]').forEach((button) => {
                const tab = button.getAttribute('data-page-tab');
                if (tab === 'overview') {
                    button.className = 'hidden';
                    return;
                }
                button.className = tab === currentManagementPage ? 'editorial-tab active' : 'editorial-tab';
            });
        }

        function openUserLogin() {
            window.open('${CONFIG.API.USER.PAGE}', '_blank');
        }

        function applySettingsToForm() {
            const usernameInput = document.getElementById('settingsAdminUsername');
            const passwordInput = document.getElementById('settingsAdminPassword');
            const otherLinkInput = document.getElementById('settingsOtherLinkUrl');
            const passwordHint = document.getElementById('settingsPasswordHint');
            if (usernameInput) usernameInput.value = currentSettings.adminUsername || '';
            if (passwordInput) passwordInput.value = '';
            if (otherLinkInput) otherLinkInput.value = currentSettings.otherLinkUrl || '';
            if (passwordHint) {
                passwordHint.textContent = currentSettings.hasAdminPassword ? 'Password status: configured' : 'Password status: not set';
            }
        }

        async function loadSettings() {
            try {
                const response = await fetchWithAuth(CONFIG.API.SETTINGS);
                if (!response.ok) throw new Error('Failed to load settings');
                const data = await response.json();
                currentSettings = {
                    adminUsername: data.adminUsername || '',
                    hasAdminPassword: Boolean(data.hasAdminPassword),
                    otherLinkUrl: data.otherLinkUrl || '',
                    activeTemplateUrl: data.activeTemplateUrl || ''
                };
                setActiveTemplateUrl(currentSettings.activeTemplateUrl || '');
                applySettingsToForm();
                return currentSettings;
            } catch (error) {
                console.error('Failed to load settings:', error);
                applySettingsToForm();
                return currentSettings;
            }
        }

        async function saveSettings() {
            const adminUsername = document.getElementById('settingsAdminUsername')?.value.trim() || '';
            const adminPassword = document.getElementById('settingsAdminPassword')?.value || '';
            const otherLinkUrl = document.getElementById('settingsOtherLinkUrl')?.value.trim() || '';
            try {
                const response = await fetchWithAuth(CONFIG.API.SETTINGS, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ adminUsername, adminPassword, otherLinkUrl })
                });
                const data = await response.json();
                if (!response.ok || !data.success) throw new Error(data.error || 'Failed to save settings');
                currentSettings = {
                    adminUsername: data.adminUsername || '',
                    hasAdminPassword: Boolean(data.hasAdminPassword),
                    otherLinkUrl: data.otherLinkUrl || '',
                    activeTemplateUrl: data.activeTemplateUrl || currentSettings.activeTemplateUrl || ''
                };
                applySettingsToForm();
                showToast('Settings saved.');
            } catch (error) {
                alert('Failed to save settings: ' + error.message);
            }
        }

        function openOtherLink() {
            const formValue = document.getElementById('settingsOtherLinkUrl')?.value.trim() || '';
            const targetUrl = currentSettings.otherLinkUrl || formValue;
            if (!targetUrl) {
                showToast('Configure the external link in Settings first.');
                return;
            }
            window.open(targetUrl, '_blank', 'noopener');
        }

        let subscriptionQrHideTimer = null;
        let subscriptionQrCurrentKey = '';

        function buildManagementSubscriptionUrl(id, type) {
            const shareUrl = window.location.origin + '/api/share/' + id;
            const templateParam = type === 'base' ? '' : (typeof getTemplateParam === 'function' ? getTemplateParam() : '');
            const typePath = type === 'base' ? '/base' : type === 'singbox' ? '/singbox' : '/clash';
            return CONFIG.SUB_WORKER_URL
                ? CONFIG.SUB_WORKER_URL + typePath + '?url=' + encodeURIComponent(shareUrl) + templateParam
                : shareUrl + typePath + '?internal=1' + templateParam;
        }

        function showSubscriptionQRCode(event, type, id, title) {
            const popup = document.getElementById('subscriptionQrPopup');
            const qrCanvas = document.getElementById('subscriptionQrCanvas');
            const qrTitle = document.getElementById('subscriptionQrTitle');
            if (!popup || !qrCanvas || typeof QRCode === 'undefined') return;
            clearTimeout(subscriptionQrHideTimer);
            const url = buildManagementSubscriptionUrl(id, type);
            const key = type + ':' + id + ':' + url;
            if (subscriptionQrCurrentKey !== key) {
                qrCanvas.innerHTML = '';
                new QRCode(qrCanvas, {
                    text: url,
                    width: 160,
                    height: 160,
                    colorDark: '#111827',
                    colorLight: '#ffffff',
                    correctLevel: QRCode.CorrectLevel.M
                });
                subscriptionQrCurrentKey = key;
            }
            if (qrTitle) qrTitle.textContent = title;
            popup.classList.remove('hidden');
            moveSubscriptionQRCode(event);
        }

        function moveSubscriptionQRCode(event) {
            const popup = document.getElementById('subscriptionQrPopup');
            if (!popup || popup.classList.contains('hidden')) return;
            const margin = 16;
            const rect = popup.getBoundingClientRect();
            let left = event.clientX + 18;
            let top = event.clientY + 18;
            if (left + rect.width > window.innerWidth - margin) left = event.clientX - rect.width - 18;
            if (top + rect.height > window.innerHeight - margin) top = event.clientY - rect.height - 18;
            popup.style.left = Math.max(margin, left) + 'px';
            popup.style.top = Math.max(margin, top) + 'px';
        }

        function hideSubscriptionQRCode() {
            const popup = document.getElementById('subscriptionQrPopup');
            if (!popup) return;
            clearTimeout(subscriptionQrHideTimer);
            subscriptionQrHideTimer = setTimeout(() => popup.classList.add('hidden'), 60);
        }

        async function copyToClipboard(text, message) {
            try {
                await navigator.clipboard.writeText(text);
                showToast(message);
            } catch (e) {
                alert('Copy failed.');
            }
        }

        function showToast(message) {
            const toast = document.createElement('div');
            toast.className = 'editorial-toast';
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2200);
        }
    `;
}

function generateNodeScriptsV2() {
    return `
        let nodeTagFilter = '';
        let nodeViewMode = 'all';
        let collectionNodeFilter = '';
        let cachedNodes = [];

        function normalizeNodeRecord(node) {
            return { ...node, tags: Array.isArray(node.tags) ? node.tags : [] };
        }

        function parseNodeTags(rawValue) {
            return String(rawValue || '')
                .split(',')
                .map(tag => tag.trim())
                .filter(Boolean);
        }

        function getFilteredNodesForDisplay(nodes, keyword) {
            const value = String(keyword || '').trim().toLowerCase();
            if (!value) return nodes;
            return nodes.filter((node) => {
                const nameMatch = String(node.name || '').toLowerCase().includes(value);
                const tagMatch = (node.tags || []).some((tag) => String(tag).toLowerCase().includes(value));
                const ungroupedMatch = value === 'untagged' && (!node.tags || node.tags.length === 0);
                return nameMatch || tagMatch || ungroupedMatch;
            });
        }

        function renderTagSummary(targetId, nodes, clickHandler) {
            const container = document.getElementById(targetId);
            if (!container) return;
            const counts = new Map();
            nodes.forEach((node) => {
                const tags = node.tags && node.tags.length ? node.tags : ['untagged'];
                tags.forEach((tag) => counts.set(tag, (counts.get(tag) || 0) + 1));
            });
            const entries = Array.from(counts.entries()).sort((a, b) => a[0].localeCompare(b[0]));
            container.innerHTML = entries.length
                ? entries.map(([tag, count]) => '<button type="button" onclick="' + clickHandler + '(\'' + tag.replace(/'/g, "\\'") + '\')" class="editorial-chip"><span>' + tag + '</span><span class="editorial-chip-count">' + count + '</span></button>').join('')
                : '<span class="editorial-badge">No tags</span>';
        }

        async function loadNodes() {
            try {
                const response = await fetchWithAuth('/api/nodes');
                if (response.ok) {
                    cachedNodes = (await response.json()).map(normalizeNodeRecord);
                    renderNodes(cachedNodes);
                    updateNodeSelection(cachedNodes);
                }
            } catch (e) {
                console.error('Error loading nodes:', e);
                alert('Failed to load nodes.');
            }
        }

        function setNodeViewMode(mode) {
            nodeViewMode = mode === 'grouped' ? 'grouped' : 'all';
            const allBtn = document.getElementById('nodeViewMode-all');
            const groupedBtn = document.getElementById('nodeViewMode-grouped');
            if (allBtn) allBtn.className = nodeViewMode === 'all' ? 'editorial-button primary' : 'editorial-button';
            if (groupedBtn) groupedBtn.className = nodeViewMode === 'grouped' ? 'editorial-button primary' : 'editorial-button';
            renderNodes(cachedNodes);
        }

        function handleNodeFilterChange(value) {
            nodeTagFilter = value || '';
            renderNodes(cachedNodes);
        }

        function clearNodeFilter() {
            nodeTagFilter = '';
            const input = document.getElementById('nodeTagFilter');
            if (input) input.value = '';
            renderNodes(cachedNodes);
        }

        function applyNodeTagFilter(tag) {
            nodeTagFilter = tag;
            const input = document.getElementById('nodeTagFilter');
            if (input) input.value = tag;
            renderNodes(cachedNodes);
        }

        function renderNodes(nodes) {
            const nodeList = document.getElementById('nodeList');
            if (!nodeList) return;
            const filteredNodes = getFilteredNodesForDisplay(nodes, nodeTagFilter);
            renderTagSummary('nodeTagSummary', nodes, 'applyNodeTagFilter');

            const grouped = new Map();
            if (nodeViewMode === 'grouped') {
                filteredNodes.forEach((node) => {
                    const tags = node.tags && node.tags.length ? node.tags : ['untagged'];
                    tags.forEach((tag) => {
                        if (!grouped.has(tag)) grouped.set(tag, []);
                        grouped.get(tag).push(node);
                    });
                });
            } else {
                grouped.set('all nodes', filteredNodes);
            }

            nodeList.innerHTML = filteredNodes.length
                ? Array.from(grouped.entries()).map(([groupName, items]) => {
                    const uniqueItems = Array.from(new Map(items.map(item => [item.id, item])).values());
                    return '<div class="space-y-3">'
                        + (nodeViewMode === 'grouped' ? '<div class="flex items-center justify-between"><h3 class="text-sm font-semibold text-gray-700">' + groupName + '</h3><span class="editorial-badge">' + uniqueItems.length + '</span></div>' : '')
                        + '<div class="editorial-card-grid">'
                        + uniqueItems.map((node) => {
                            const tags = node.tags && node.tags.length
                                ? node.tags.map((tag) => '<span class="editorial-chip">' + tag + '</span>').join('')
                                : '<span class="editorial-badge">untagged</span>';
                            return '<article class="editorial-card editorial-list-card">'
                                + '<div class="editorial-card-head">'
                                + '<div class="flex-1 min-w-0">'
                                + '<h3 class="editorial-card-title">' + node.name + '</h3>'
                                + '<div class="editorial-subtle mt-2 break-all"><span class="font-mono">' + node.url + '</span></div>'
                                + '<div class="editorial-card-actions mt-3">' + tags + '</div>'
                                + '</div>'
                                + '<div class="editorial-card-actions">'
                                + '<button onclick="editNode(\'' + node.id + '\')" class="editorial-button">Edit</button>'
                                + '<button onclick="copyNode(\'' + node.id + '\')" class="editorial-button">Copy</button>'
                                + '<button onclick="deleteNode(\'' + node.id + '\')" class="editorial-button danger">Delete</button>'
                                + '</div>'
                                + '</div>'
                                + '</article>';
                        }).join('')
                        + '</div>'
                        + '</div>';
                }).join('')
                : '<div class="editorial-empty">No matching nodes.</div>';
        }

        async function addNode() {
            const name = document.getElementById('nodeName').value;
            const url = document.getElementById('nodeUrl').value;
            const tags = parseNodeTags(document.getElementById('nodeTags')?.value || '');
            if (!name || !url) {
                alert('Please fill in both node name and node url.');
                return;
            }
            try {
                const response = await fetchWithAuth('/api/nodes', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, url, tags })
                });
                if (response.ok) {
                    document.getElementById('nodeName').value = '';
                    document.getElementById('nodeUrl').value = '';
                    const tagInput = document.getElementById('nodeTags');
                    if (tagInput) tagInput.value = '';
                    await loadNodes();
                    showToast('Node created.');
                }
            } catch (e) {
                alert('Failed to create node.');
            }
        }

        async function editNode(id) {
            const node = cachedNodes.find((item) => item.id === id);
            if (node) showEditDialog(node);
        }

        function showEditDialog(node) {
            const dialog = document.createElement('div');
            dialog.className = 'editorial-modal-backdrop';
            dialog.innerHTML = \`
                <div class="editorial-modal" style="max-width: 720px;">
                    <div class="editorial-modal-head flex items-center justify-between gap-4">
                        <div>
                            <div class="editorial-label">[EDIT_NODE]</div>
                            <h3 class="text-xl font-semibold text-gray-800 mt-1">Edit Node</h3>
                        </div>
                        <button onclick="this.closest('.editorial-modal-backdrop').remove()" class="editorial-button">Close</button>
                    </div>
                    <div class="editorial-modal-body">
                        <div>
                            <label class="editorial-label block mb-2">Node Name</label>
                            <input type="text" id="editNodeName" value="\${node.name}" class="editorial-input">
                        </div>
                        <div>
                            <label class="editorial-label block mb-2">Node Url</label>
                            <input type="text" id="editNodeUrl" value="\${node.url}" class="editorial-input mono">
                        </div>
                        <div>
                            <label class="editorial-label block mb-2">Tags</label>
                            <input type="text" id="editNodeTags" value="\${(node.tags || []).join(', ')}" class="editorial-input mono" placeholder="HK, Premium, Test">
                            <p class="editorial-subtle mt-2">Separate multiple tags with commas.</p>
                        </div>
                    </div>
                    <div class="editorial-modal-foot">
                        <button onclick="this.closest('.editorial-modal-backdrop').remove()" class="editorial-button">Cancel</button>
                        <button onclick="updateNode('\${node.id}')" class="editorial-button primary">Save</button>
                    </div>
                </div>
            \`;
            document.body.appendChild(dialog);
        }

        async function updateNode(id) {
            const name = document.getElementById('editNodeName').value;
            const url = document.getElementById('editNodeUrl').value;
            const tags = parseNodeTags(document.getElementById('editNodeTags')?.value || '');
            if (!name || !url) {
                alert('Please fill in both node name and node url.');
                return;
            }
            try {
                const response = await fetchWithAuth('/api/nodes', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id, name, url, tags })
                });
                if (response.ok) {
                    document.querySelector('.editorial-modal-backdrop').remove();
                    await loadNodes();
                    showToast('Node updated.');
                }
            } catch (e) {
                alert('Failed to update node.');
            }
        }

        async function copyNode(id) {
            const node = cachedNodes.find((item) => item.id === id);
            if (node) {
                await navigator.clipboard.writeText(node.url);
                showToast('Node url copied.');
            }
        }

        async function deleteNode(id) {
            if (!confirm('Delete this node?')) return;
            try {
                const response = await fetchWithAuth('/api/nodes', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id })
                });
                if (response.ok) {
                    await loadNodes();
                    showToast('Node deleted.');
                }
            } catch (e) {
                alert('Failed to delete node.');
            }
        }

        function updateNodeSelection(nodes) {
            const nodeSelection = document.getElementById('nodeSelection');
            if (!nodeSelection) return;
            const filteredNodes = getFilteredNodesForDisplay(nodes.map(normalizeNodeRecord), collectionNodeFilter);
            nodeSelection.innerHTML = filteredNodes.map(node => \`
                <label class="editorial-card p-4 flex items-start gap-3">
                    <input type="checkbox" id="select_\${node.id}" value="\${node.id}">
                    <span class="flex-1 min-w-0 text-sm text-gray-700">
                        <div class="font-medium truncate">\${node.name}</div>
                        <div class="editorial-card-actions mt-2">\${(node.tags && node.tags.length ? node.tags : ['untagged']).map(tag => '<span class="editorial-chip">' + tag + '</span>').join('')}</div>
                    </span>
                </label>
            \`).join('');
            const selectionControls = document.createElement('div');
            selectionControls.className = 'editorial-card-actions';
            selectionControls.style.gridColumn = '1 / -1';
            selectionControls.innerHTML = \`
                <button onclick="selectAllNodes()" class="editorial-button">Select All</button>
                <button onclick="deselectAllNodes()" class="editorial-button">Clear Selection</button>
            \`;
            nodeSelection.insertBefore(selectionControls, nodeSelection.firstChild);
        }

        function selectAllNodes() {
            document.querySelectorAll('#nodeSelection input[type="checkbox"]').forEach(checkbox => checkbox.checked = true);
        }

        function deselectAllNodes() {
            document.querySelectorAll('#nodeSelection input[type="checkbox"]').forEach(checkbox => checkbox.checked = false);
        }

        function getSelectedNodeIds() {
            return Array.from(document.querySelectorAll('#nodeSelection input:checked')).map(checkbox => checkbox.value);
        }

        function setNodeSelection(nodeIds) {
            document.querySelectorAll('#nodeSelection input[type="checkbox"]').forEach(checkbox => {
                checkbox.checked = nodeIds.includes(checkbox.value);
            });
        }
    `;
}

function generateUtilityScripts(env, CONFIG) {
    return `
        function showManagementPage(page) {
            currentManagementPage = !page || page === 'overview' ? 'collections' : page;
            document.querySelectorAll('[data-page-panel]').forEach((panel) => {
                panel.classList.toggle('hidden', panel.getAttribute('data-page-panel') !== currentManagementPage);
            });
            document.querySelectorAll('[data-page-tab]').forEach((button) => {
                const tab = button.getAttribute('data-page-tab');
                if (tab === 'overview') {
                    button.className = 'hidden';
                    return;
                }
                const active = tab === currentManagementPage;
                button.className = active ? 'editorial-tab active' : 'editorial-tab';
            });
        }

        function openUserLogin() {
            window.open('${CONFIG.API.USER.PAGE}', '_blank');
        }

        function openSubscriber() {
            if (CONFIG.SUBSCRIBER_URL) {
                window.open(CONFIG.SUBSCRIBER_URL, '_blank');
            } else {
                showToast('订阅器地址未配置');
            }
        }

        function openQuickSubscriber() {
            if (CONFIG.QUICK_SUB_URL) {
                window.open(CONFIG.QUICK_SUB_URL, '_blank');
            } else {
                showToast('快速订阅器地址未配置');
            }
        }

        async function copyToClipboard(text, message) {
            try {
                await navigator.clipboard.writeText(text);
                showToast(message);
            } catch (e) {
                alert('复制失败');
            }
        }

        function showToast(message) {
            const toast = document.createElement('div');
            toast.className = 'fixed bottom-4 left-1/2 transform -translate-x-1/2 bg-gray-800 text-white px-4 py-2 rounded-lg';
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2000);
        }
    `;
} 
