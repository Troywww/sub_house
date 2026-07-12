import { CONFIG, TEMPLATE_PRESETS, getConfig } from './config.js';

// 管理页面生成
export function generateManagementPage(env, CONFIG) {
    const html = `
        <!DOCTYPE html>
        <html>
        <head>
            ${generateHead()}
        </head>
        <body class="bg-gray-100 min-h-screen">
            ${generateHeader(CONFIG, env)}
            ${generateMainContent(CONFIG)}
            ${generateScripts(env, CONFIG)}
        </body>
        </html>
    `;

    return new Response(html, {
        headers: { 'Content-Type': 'text/html;charset=utf-8' }
    });
}

// 生成头部
function generateHead() {
    return `
        <title>节点管理系统</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <!-- Non-blocking external CSS — renders immediately, swaps when loaded -->
        <link rel="preconnect" href="https://unpkg.com">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link rel="preconnect" href="https://cdnjs.cloudflare.com">
        <link rel="preconnect" href="https://cdn.jsdelivr.net">
        <link href="https://unpkg.com/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet" media="print" onload="this.media='all'">
        <noscript><link href="https://unpkg.com/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet"></noscript>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" media="print" onload="this.media='all'">
        <noscript><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet"></noscript>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" media="print" onload="this.media='all'">
        <noscript><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css"></noscript>
        <script defer src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
        <style>
            :root {
                /* Base surfaces */
                --surface: #f7f8fa;
                --surface-elevated: #ffffff;
                --surface-hover: #f1f2f4;
                --border: rgba(0, 0, 0, 0.08);
                --border-hover: rgba(0, 0, 0, 0.14);
                --ink: #1a1a2e;
                --muted: #6b7280;

                /* Accent */
                --accent: #2563eb;
                --accent-soft: #eff6ff;
                --accent-border: rgba(37, 99, 235, 0.2);

                /* Semantic statuses */
                --positive: #059669;
                --positive-bg: #ecfdf5;
                --warning: #d97706;
                --warning-bg: #fffbeb;
                --danger: #dc2626;
                --danger-bg: #fef2f2;

                /* Radius */
                --radius: 8px;
                --radius-sm: 6px;
                --radius-lg: 12px;

                /* Shadows */
                --shadow-sm: 0 1px 2px rgba(0,0,0,0.04);
                --shadow-md: 0 4px 12px rgba(0,0,0,0.06);
                --shadow-lg: 0 8px 30px rgba(0,0,0,0.08);
                --shadow-xl: 0 12px 40px rgba(0,0,0,0.1);

                /* Transitions */
                --ease: 180ms cubic-bezier(0.4, 0, 0.2, 1);
            }
            body {
                background: var(--surface);
                color: var(--ink);
                font-family: 'Inter', system-ui, sans-serif;
            }

            /* Utility */
            .console-shell { max-width: 1760px; margin: 0 auto; }
            .console-label {
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                font-weight: 600;
                letter-spacing: 0.08em;
                text-transform: uppercase;
                color: #6b7280;
            }
            .console-label-accent { color: var(--accent); }
            .console-mono { font-family: 'JetBrains Mono', monospace; }
            .console-ghost-divider { height: 1px; background: rgba(0, 0, 0, 0.08); }

            /* Cards */
            .console-card {
                background: var(--surface-elevated);
                border: 1px solid var(--border);
                border-radius: var(--radius);
                box-shadow: var(--shadow-md);
                transition: box-shadow var(--ease), border-color var(--ease);
            }
            .console-card:hover {
                border-color: var(--border-hover);
                box-shadow: var(--shadow-lg);
            }
            .console-inset {
                background: var(--surface-hover);
                border: 1px solid var(--border);
                border-radius: var(--radius);
            }

            /* Buttons */
            .console-button {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                min-height: 44px;
                padding: 0 20px;
                border-radius: var(--radius-sm);
                border: 1px solid var(--border);
                background: var(--surface-elevated);
                color: var(--ink);
                font-weight: 700;
                white-space: nowrap;
                box-shadow: var(--shadow-sm);
                transition: all var(--ease);
            }
            .console-button:hover { background: var(--surface-hover); border-color: var(--border-hover); }
            .console-button-dark {
                background: linear-gradient(180deg, #2563eb 0%, #1d4ed8 100%);
                color: #fff;
                border-color: transparent;
                box-shadow: 0 1px 3px rgba(37, 99, 235, 0.3);
            }
            .console-button-dark:hover {
                background: linear-gradient(180deg, #3b82f6 0%, #2563eb 100%);
                border-color: transparent;
            }
            .console-button-subtle { background: var(--surface-hover); border-color: transparent; }
            .console-button-subtle:hover { background: #e5e7eb; }
            .console-button-compact {
                min-height: 34px;
                padding: 0 12px;
                gap: 6px;
                font-size: 12px;
            }
            .console-button-toolbar {
                border-color: var(--border);
                background: var(--surface-elevated);
                color: #374151;
                font-weight: 600;
                box-shadow: none;
            }
            .console-button-toolbar:hover { background: var(--surface-hover); }
            .console-toolbar-label {
                display: inline-flex;
                align-items: center;
                min-height: 34px;
                padding: 0 6px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 12px;
                font-weight: 600;
                letter-spacing: 0.08em;
                text-transform: uppercase;
                color: #9ca3af;
                white-space: nowrap;
            }
            .console-icon-button {
                width: 36px;
                min-width: 36px;
                min-height: 36px;
                padding: 0;
                gap: 0;
                border-color: var(--border);
                background: var(--surface-elevated);
                color: #4b5563;
                box-shadow: none;
            }
            .console-icon-button:hover {
                background: var(--surface-hover);
                color: var(--ink);
            }
            .console-pill {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 8px 14px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.04em;
            }
            .console-pill-ready { color: var(--positive); background: var(--positive-bg); }

            /* Sidebar */
            .console-sidebar-item {
                display: flex;
                align-items: center;
                gap: 12px;
                width: 100%;
                min-height: 58px;
                padding: 0 18px;
                border-radius: var(--radius-sm);
                color: #4b5563;
                font-weight: 700;
                transition: all var(--ease);
                text-align: left;
            }
            .console-sidebar-item:hover { background: rgba(255, 255, 255, 0.72); color: var(--ink); }
            .console-sidebar-item.active {
                background: linear-gradient(180deg, #323232 0%, #1a1a1a 100%);
                color: #fff;
            }

            /* Tabs */
            .console-topnav {
                display: flex;
                flex-wrap: wrap;
                gap: 4px;
                align-items: center;
                padding: 8px 10px 0;
                background: var(--surface-elevated);
                border: 1px solid var(--border);
                border-bottom: none;
                border-radius: var(--radius) var(--radius) 0 0;
            }
            .console-tab {
                display: inline-flex;
                align-items: center;
                gap: 7px;
                min-height: 34px;
                padding: 0 12px;
                border-radius: var(--radius-sm) var(--radius-sm) 0 0;
                border: 1px solid transparent;
                border-bottom: none;
                background: transparent;
                color: #4b5563;
                font-size: 15px;
                font-weight: 700;
                transition: all var(--ease);
            }
            .console-tab:hover { background: var(--surface-hover); color: var(--ink); }
            .console-tab.active {
                background: var(--surface-elevated);
                border-color: var(--border);
                color: var(--ink);
                position: relative;
                box-shadow: var(--shadow-sm);
            }
            .console-tab.active::before {
                content: '';
                position: absolute;
                left: 0;
                right: 0;
                top: -1px;
                height: 3px;
                background: var(--accent);
                border-radius: 2px 2px 0 0;
            }

            /* Inputs */
            .console-input,
            .console-select,
            .console-textarea {
                width: 100%;
                min-height: 48px;
                border-radius: var(--radius);
                border: 1px solid var(--border-hover);
                background: var(--surface-elevated);
                padding: 0 14px;
                color: var(--ink);
                outline: none;
                transition: border-color var(--ease), box-shadow var(--ease);
            }
            .console-textarea { min-height: 144px; padding: 12px 14px; }
            .console-input:focus,
            .console-select:focus,
            .console-textarea:focus {
                border-color: var(--accent);
                box-shadow: 0 0 0 3px var(--accent-border);
            }
            .console-input::placeholder { color: #9ca3af; }

            /* Status badges */
            .console-status-expired { color: var(--danger); background: var(--danger-bg); }
            .console-status-soon { color: var(--warning); background: var(--warning-bg); }
            .console-status-active { color: var(--positive); background: var(--positive-bg); }

            /* Status dot indicator */
            .console-status-dot {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 3px 10px 3px 8px;
                border-radius: 999px;
                font-size: 11px;
                font-weight: 600;
            }
            .console-status-dot::before {
                content: '';
                width: 6px;
                height: 6px;
                border-radius: 50%;
                flex-shrink: 0;
            }
            .console-status-dot.active { color: var(--positive); background: var(--positive-bg); }
            .console-status-dot.active::before { background: var(--positive); }
            .console-status-dot.soon { color: var(--warning); background: var(--warning-bg); }
            .console-status-dot.soon::before { background: var(--warning); }
            .console-status-dot.expired { color: var(--danger); background: var(--danger-bg); }
            .console-status-dot.expired::before { background: var(--danger); }

/* Subscription buttons */
            .console-subscription-btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                min-height: 38px;
                padding: 0 14px;
                border-radius: var(--radius-sm);
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 0.02em;
                white-space: nowrap;
                transition: all var(--ease);
                border: 1px solid transparent;
            }
            .console-subscription-btn.primary { min-width: 116px; }
            .console-subscription-btn.base { color: #1e40af; background: #dbeafe; border-color: rgba(37, 99, 235, 0.15); }
            .console-subscription-btn.singbox { color: #065f46; background: #d1fae5; border-color: rgba(5, 150, 105, 0.15); }
            .console-subscription-btn.clash { color: #7c2d12; background: #fed7aa; border-color: rgba(234, 88, 12, 0.15); }
            .console-subscription-btn.share { color: #6b7280; background: #f3f4f6; border-color: rgba(0, 0, 0, 0.06); }
            .console-subscription-btn:hover { filter: brightness(0.97); transform: translateY(-1px); box-shadow: var(--shadow-md); }

            /* Node pick */
            .console-node-pick {
                display: flex;
                align-items: center;
                gap: 10px;
                min-height: 56px;
                padding: 10px 12px;
                background: var(--surface-elevated);
                border: 1px solid var(--border);
                border-radius: var(--radius-sm);
                box-shadow: var(--shadow-sm);
                transition: border-color var(--ease), background var(--ease), box-shadow var(--ease);
            }
            .console-node-pick:hover {
                border-color: var(--accent-border);
                background: var(--accent-soft);
                box-shadow: 0 0 0 1px var(--accent-border);
            }
            .console-node-pick input[type="checkbox"] {
                width: 16px;
                height: 16px;
                margin: 0;
                accent-color: var(--accent);
            }
            .console-node-pick-label {
                min-width: 0;
                flex: 1;
                cursor: pointer;
            }
            .console-node-pick-title {
                font-size: 14px;
                font-weight: 600;
                color: #1f2937;
                line-height: 1.2;
            }
            .console-node-pick-meta {
                display: flex;
                flex-wrap: wrap;
                gap: 4px;
                margin-top: 4px;
            }
            .console-node-pick-tag {
                padding: 2px 8px;
                border-radius: 999px;
                background: var(--surface-hover);
                color: #6b7280;
                font-size: 11px;
                line-height: 1.2;
            }
            .console-node-pick-tools {
                display: flex;
                justify-content: flex-end;
                gap: 8px;
                margin-bottom: 2px;
            }
            .console-node-pick-tools button {
                padding: 0;
                border: none;
                background: transparent;
                color: #6b7280;
                font-size: 12px;
                font-weight: 600;
            }
            .console-node-pick-tools button:hover { color: var(--ink); }

            /* Modal */
            .modal-overlay {
                position: fixed;
                inset: 0; z-index: 100;
                background: rgba(0,0,0,0.45);
                display: flex; align-items: center; justify-content: center;
                padding: 16px;
                animation: fadeIn 0.15s ease;
                backdrop-filter: blur(4px);
            }
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            .modal-box {
                background: var(--surface-elevated);
                border-radius: var(--radius-lg);
                box-shadow: var(--shadow-xl);
                padding: 24px;
                max-width: 400px;
                width: 100%;
            }

            /* Toast */
            .console-toast {
                background: rgba(17, 17, 17, 0.92);
                color: #fff;
                border-radius: var(--radius-sm);
                padding: 10px 14px;
                font-size: 13px;
                box-shadow: var(--shadow-lg);
                animation: toastIn 0.2s ease;
            }
            @keyframes toastIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

            /* Loading spinner (inline, no FA dependency) */
            .console-spinner {
                display: inline-block;
                width: 16px;
                height: 16px;
                border: 2px solid rgba(0,0,0,0.12);
                border-top-color: var(--accent);
                border-radius: 50%;
                animation: spin 0.6s linear infinite;
            }
            @keyframes spin { to { transform: rotate(360deg); } }

            /* Header glass */
            .console-header {
                background: rgba(255,255,255,0.85);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border-bottom: 1px solid var(--border);
            }

            /* Page title — top of each tab */
            .console-page-title {
                font-size: 22px;
                font-weight: 800;
                letter-spacing: -0.02em;
                color: var(--ink);
                line-height: 1.2;
            }
            .console-page-desc {
                font-size: 13px;
                color: #6b7280;
                line-height: 1.5;
                margin-top: 4px;
            }

            /* Stat chips */
            .console-stat-chip {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 5px 12px;
                border-radius: 999px;
                background: var(--surface-hover);
                border: 1px solid var(--border);
                font-size: 12px;
                font-weight: 600;
                color: #4b5563;
                white-space: nowrap;
            }
            .console-stat-chip .console-stat-num {
                font-family: 'JetBrains Mono', monospace;
                font-weight: 700;
                color: var(--ink);
            }
            .console-stat-chip.is-active {
                background: var(--positive-bg);
                border-color: rgba(5, 150, 105, 0.2);
                color: var(--positive);
            }
            .console-stat-chip.is-active .console-stat-num { color: var(--positive); }

            /* Empty state */
            .console-empty {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 48px 24px;
                text-align: center;
            }
            .console-empty-icon {
                width: 56px;
                height: 56px;
                border-radius: 50%;
                background: var(--surface-hover);
                display: flex;
                align-items: center;
                justify-content: center;
                color: #9ca3af;
                font-size: 22px;
                margin-bottom: 16px;
            }
            .console-empty-title {
                font-size: 15px;
                font-weight: 700;
                color: #374151;
                margin-bottom: 4px;
            }
            .console-empty-desc {
                font-size: 13px;
                color: #9ca3af;
                line-height: 1.5;
                max-width: 360px;
            }

            /* Collapsible section */
            .console-collapse-toggle {
                display: flex;
                align-items: center;
                justify-content: space-between;
                width: 100%;
                padding: 12px 16px;
                background: var(--surface-elevated);
                border: 1px solid var(--border);
                border-radius: var(--radius);
                font-weight: 700;
                color: var(--ink);
                transition: background var(--ease);
                cursor: pointer;
            }
            .console-collapse-toggle:hover { background: var(--surface-hover); }
            .console-collapse-toggle .console-collapse-arrow {
                transition: transform var(--ease);
                color: #9ca3af;
            }
            .console-collapse-toggle.is-open .console-collapse-arrow { transform: rotate(180deg); }
            .console-collapse-body {
                margin-top: 12px;
                display: none;
            }
            .console-collapse-body.is-open { display: block; }

            /* Collection card badge */
            .console-node-count-badge {
                display: inline-flex;
                align-items: center;
                gap: 5px;
                padding: 2px 10px;
                border-radius: 999px;
                background: var(--surface-hover);
                border: 1px solid var(--border);
                font-size: 11px;
                font-weight: 700;
                color: #6b7280;
                font-family: 'JetBrains Mono', monospace;
            }

            /* Tag pill (collection card node list) */
            .console-node-tag-chip {
                display: inline-flex;
                align-items: center;
                gap: 6px;
                padding: 3px 10px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: 500;
                background: var(--surface-hover);
                color: #4b5563;
            }
            .console-node-tag-chip .console-node-tag-dot {
                width: 6px;
                height: 6px;
                border-radius: 50%;
                flex-shrink: 0;
            }
        </style>
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
                        <div class="console-card w-full max-w-md p-6 shadow-2xl">
                            <div class="console-label mb-3">Admin Setup</div>
                            <h2 class="text-2xl font-extrabold tracking-tight text-gray-900 mb-2">初始化管理员账号</h2>
                            <p class="text-sm leading-6 text-gray-500 mb-4">检测到系统尚未配置管理员账号，请先创建一个管理员账号后再进入后台。</p>
                            <div class="space-y-4">
                                <div id="adminLoginError" class="text-sm text-red-600 min-h-[1.25rem]">\${message}</div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">管理员用户名</label>
                                    <input type="text" id="adminUsername" class="console-input mt-1">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">管理员密码</label>
                                    <input type="password" id="adminPassword" class="console-input mt-1">
                                </div>
                                <button onclick="setupAdmin()" class="console-button console-button-dark w-full">创建并登录</button>
                            </div>
                        </div>
                    \`;
                }

                return \`
                    <div class="console-card w-full max-w-md p-6 shadow-2xl">
                        <div class="console-label mb-3">Admin Gate</div>
                        <h2 class="text-2xl font-extrabold tracking-tight text-gray-900 mb-4">管理员登录</h2>
                        <div class="space-y-4">
                            <div id="adminLoginError" class="text-sm text-red-600 min-h-[1.25rem]">\${message}</div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">用户名</label>
                                <input type="text" id="adminUsername" class="console-input mt-1">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">密码</label>
                                <input type="password" id="adminPassword" class="console-input mt-1">
                            </div>
                            <button onclick="login()" class="console-button console-button-dark w-full">登录</button>
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
                dialog.className = 'fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4';
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

// 生成页面头部
function generateHeader(CONFIG, env) {
    return `
        <header class="console-header sticky top-0 z-40">
            <div class="console-shell px-6 py-2.5 md:px-8 xl:px-10">
                <div class="flex items-center justify-between gap-4">
                    <div class="flex items-center gap-3">
                        <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-gray-900 text-white">
                            <i class="fas fa-cube text-base"></i>
                        </div>
                        <h1 class="text-lg font-extrabold tracking-tight text-gray-900">Sub House</h1>
                    </div>
                    <div class="flex items-center gap-2">
                        <button type="button" onclick="openUserLogin()" class="console-button console-button-compact console-button-toolbar">
                            <i class="fas fa-user"></i><span class="hidden sm:inline">&#29992;&#25143;&#20837;&#21475;</span>
                        </button>
                        <button type="button" onclick="logoutAdmin()" class="console-button console-button-compact console-button-toolbar">
                            <i class="fas fa-sign-out-alt"></i><span class="hidden sm:inline">&#36864;&#20986;</span>
                        </button>
                        <button type="button" onclick="openOtherLink()" class="console-button console-button-compact console-button-dark">
                            <i class="fas fa-link"></i><span class="hidden sm:inline">&#20854;&#20182;&#38142;&#25509;</span>
                        </button>
                    </div>
                </div>
            </div>
        </header>
    `;
}


// 生成主要内容
function generateMainContent(CONFIG) {
    return `
        <main class="console-shell px-6 py-5 md:px-8 xl:px-10">
            <div id="adminGateHint">
                <div class="console-card p-12 text-center">
                    <div class="flex h-16 w-16 mx-auto items-center justify-center rounded-2xl bg-gray-900 text-white mb-5">
                        <i class="fas fa-cube text-3xl"></i>
                    </div>
                    <h2 class="text-3xl font-extrabold tracking-tight text-gray-900">Sub House</h2>
                    <p class="mx-auto mt-3 max-w-xl text-sm text-gray-500">&#30331;&#24405;&#21518;&#21363;&#21487;&#31649;&#29702;&#33410;&#28857;&#12289;&#38598;&#21512;&#12289;&#27169;&#26495;&#12289;&#35268;&#21017;&#30446;&#24405;&#19982;&#21518;&#21488;&#35774;&#32622;&#12290;</p>
                    <button onclick="showLoginDialog()" class="console-button console-button-dark mt-6">&#31435;&#21363;&#30331;&#24405;</button>
                </div>
            </div>
            <div id="managementShell" class="hidden">
                <nav class="console-topnav">
                    <button type="button" data-page-tab="collections" onclick="showManagementPage('collections')" class="console-tab">
                        <i class="fas fa-database"></i><span>&#38598;&#21512;&#31649;&#29702;</span>
                    </button>
                    <button type="button" data-page-tab="nodes" onclick="showManagementPage('nodes')" class="console-tab">
                        <i class="fas fa-network-wired"></i><span>&#33410;&#28857;&#31649;&#29702;</span>
                    </button>
                    <button type="button" data-page-tab="templates" onclick="showManagementPage('templates')" class="console-tab">
                        <i class="fas fa-file-alt"></i><span>&#27169;&#26495;&#31649;&#29702;</span>
                    </button>
                    <button type="button" data-page-tab="rules" onclick="showManagementPage('rules')" class="console-tab">
                        <i class="fas fa-code-branch"></i><span>&#35268;&#21017;&#30446;&#24405;</span>
                    </button>
                    <button type="button" data-page-tab="settings" onclick="showManagementPage('settings')" class="console-tab">
                        <i class="fas fa-sliders-h"></i><span>&#37197;&#32622;</span>
                    </button>
                </nav>
                <div class="-mt-px">
                    <section id="managementPage-collections" data-page-panel="collections" class="hidden">
                        ${generateCollectionManager(CONFIG)}
                    </section>
                    <section id="managementPage-nodes" data-page-panel="nodes" class="hidden">
                        ${generateNodeManager()}
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
            </div>
            <div id="subscriptionQrPopup" class="hidden fixed z-50" style="pointer-events:none;">
                <div class="console-card p-3 shadow-2xl">
                    <p id="subscriptionQrTitle" class="console-label mb-2">&#35746;&#38405;&#20108;&#32500;&#30721;</p>
                    <div id="subscriptionQrCanvas" class="w-40 h-40 flex items-center justify-center"></div>
                </div>
            </div>
        </main>
    `;
}


// 生成脚本部分
function generateTemplateManager() {
    return `
        <div class="console-card rounded-t-none p-6 space-y-5">
            <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                    <div class="console-page-title">&#27169;&#26495;&#31649;&#29702;</div>
                    <div class="console-page-desc">&#32500;&#25252; Clash / Sing-box &#27169;&#26495;&#65292;&#25554;&#20837;&#35268;&#21017;&#24341;&#29992;&#65292;&#35774;&#32622;&#24403;&#21069;&#21551;&#29992;&#27169;&#26495;&#12290;</div>
                </div>
                <div class="flex flex-wrap gap-2">
                    <span id="templateStatTotal" class="console-stat-chip"><i class="fas fa-file-alt text-gray-400"></i>&#27169;&#26495;<span class="console-stat-num">0</span></span>
                    <span id="templateStatActive" class="console-stat-chip"><i class="fas fa-circle-check text-gray-400"></i><span class="console-stat-num">&#26410;&#21551;&#29992;</span></span>
                </div>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <button onclick="newTemplate()" class="console-button console-button-compact console-button-toolbar">
                    <i class="fas fa-plus"></i>&#26032;&#24314;&#27169;&#26495;
                </button>
                <select id="templatePresetSelector"
                    class="console-select console-mono flex-1 min-w-[14rem]"
                    style="height:34px; min-height:34px; line-height:34px; padding-top:0; padding-bottom:0;">
                    <option value="">&#36873;&#25321;&#20869;&#32622;&#27169;&#26495;&#39044;&#32622;</option>
                    ${TEMPLATE_PRESETS.map(preset => `<option value="${preset.id}">${preset.name}</option>`).join('')}
                </select>
                <button onclick="loadBuiltInTemplatePreset()" class="console-button console-button-compact console-button-toolbar">
                    <i class="fas fa-download"></i>&#36733;&#20837;
                </button>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
                <div class="lg:col-span-1">
                    <div class="flex items-center justify-between mb-3">
                        <h3 class="text-sm font-bold text-gray-700">&#24050;&#20445;&#23384;&#27169;&#26495;</h3>
                        <span id="activeTemplateBadge" class="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-600">&#26410;&#21551;&#29992;</span>
                    </div>
                    <div id="templateList" class="space-y-3 max-h-[32rem] overflow-y-auto pr-1"></div>
                </div>
                <div class="lg:col-span-2 space-y-4">
                    <input type="hidden" id="templateId">
                    <div class="flex flex-col gap-3 xl:flex-row xl:items-end">
                        <div class="flex-1">
                            <input type="text" id="templateName" placeholder="&#20363;&#22914;&#65306;&#40664;&#35748;&#20998;&#27969;&#27169;&#26495;" class="console-input">
                        </div>
                        <button onclick="saveTemplate(this)" class="console-button console-button-dark whitespace-nowrap" style="min-height:48px;">
                            <i class="fas fa-save"></i>&#20445;&#23384;&#27169;&#26495;
                        </button>
                    </div>
                    <div class="flex flex-wrap gap-2">
                        <button onclick="useCurrentTemplate()" class="console-button console-button-compact console-button-toolbar">
                            <i class="fas fa-circle-check"></i>&#35774;&#20026;&#24403;&#21069;&#27169;&#26495;
                        </button>
                        <button onclick="viewCurrentTemplateConfig()" class="console-button console-button-compact console-button-toolbar">
                            <i class="fas fa-eye"></i>&#26597;&#30475;&#35746;&#38405;&#37197;&#32622;
                        </button>
                        <button onclick="deleteTemplate()" class="console-button console-button-compact console-button-toolbar" style="color:var(--danger);">
                            <i class="fas fa-trash"></i>&#21024;&#38500;
                        </button>
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#27169;&#26495;&#20869;&#23481;</label>
                        <textarea id="templateContent" rows="16" class="console-textarea console-mono text-sm"
                            placeholder="ruleset=&#40664;&#35748;&#35268;&#21017;,[]MATCH&#10;custom_proxy_group=&#33410;&#28857;&#36873;&#25321;\`select\`[]DIRECT"></textarea>
                    </div>
                    <button type="button" onclick="toggleCollapse('templateInsertBody', this)" class="console-collapse-toggle">
                        <span class="flex items-center gap-2"><i class="fas fa-plus-circle text-gray-400"></i>&#25554;&#20837;&#35268;&#21017; / &#20998;&#32452;</span>
                        <i class="fas fa-chevron-down console-collapse-arrow"></i>
                    </button>
                    <div id="templateInsertBody" class="console-collapse-body">
                        <div class="console-inset p-4 space-y-4">
                            <div class="space-y-3">
                                <div class="text-xs font-semibold text-gray-500 uppercase tracking-wider">&#25554;&#20837;&#35268;&#21017;</div>
                                <div class="flex flex-col md:flex-row gap-3">
                                    <select id="templateRuleSelector" class="console-input flex-1">
                                        <option value="">&#20174;&#35268;&#21017;&#30446;&#24405;&#36873;&#25321;&#19968;&#20010;&#35268;&#21017;</option>
                                    </select>
                                    <button onclick="insertSelectedRuleIntoTemplate()" class="console-button console-button-compact console-button-dark whitespace-nowrap">
                                        <i class="fas fa-arrow-down"></i>&#25554;&#20837;
                                    </button>
                                </div>
                            </div>
                            <div class="space-y-3 pt-2 border-t border-gray-100">
                                <div class="text-xs font-semibold text-gray-500 uppercase tracking-wider">&#25554;&#20837;&#20998;&#32452;</div>
                                <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
                                    <input type="text" id="groupNameInput" placeholder="&#20998;&#32452;&#21517;&#31216;" class="console-input">
                                    <select id="groupTypeInput" class="console-select">
                                        <option value="select">select</option>
                                        <option value="url-test">url-test</option>
                                    </select>
                                    <input type="text" id="groupFilterInput" placeholder="&#36807;&#28388;&#22120;&#65292;&#20363;&#22914; &#28207;|HK" class="console-input">
                                    <input type="text" id="groupRefsInput" placeholder="&#24341;&#29992;&#30446;&#26631;&#65292;&#36887;&#21495;&#20998;&#38548;" class="console-input">
                                </div>
                                <div class="flex flex-wrap gap-2">
                                    <button onclick="insertGroupLine()" class="console-button console-button-compact console-button-dark">
                                        <i class="fas fa-plus"></i>&#25554;&#20837;&#20998;&#32452;
                                    </button>
                                    <button onclick="insertDefaultSelectGroup()" class="console-button console-button-compact console-button-toolbar">
                                        &#25554;&#20837;&#40664;&#35748;&#20998;&#32452;
                                    </button>
                                </div>
                            </div>
                            <div class="text-xs text-gray-400 space-y-1 pt-2 border-t border-gray-100">
                                <p>&#27169;&#26495;&#35821;&#27861;&#65306;<code class="bg-white px-1.5 py-0.5 rounded">ruleset=&#35268;&#21017;&#21517;,@rule_id</code></p>
                                <p><code class="bg-white px-1.5 py-0.5 rounded">custom_proxy_group=&#20998;&#32452;&#21517;\`select/url-test\`&#36807;&#28388;&#22120;\`[]DIRECT</code></p>
                            </div>
                        </div>
                    </div>
                    <button type="button" onclick="toggleCollapse('templateParsedBody', this)" class="console-collapse-toggle">
                        <span class="flex items-center gap-2"><i class="fas fa-list text-gray-400"></i>&#24050;&#35299;&#26512;&#32467;&#26500;</span>
                        <i class="fas fa-chevron-down console-collapse-arrow"></i>
                    </button>
                    <div id="templateParsedBody" class="console-collapse-body">
                        <div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
                            <div class="console-inset p-4">
                                <div class="flex items-center justify-between mb-3">
                                    <h3 class="text-sm font-bold text-gray-700">&#24050;&#35299;&#26512;&#35268;&#21017;</h3>
                                    <span id="templateRuleCount" class="console-stat-chip" style="padding:2px 8px;"><span class="console-stat-num">0</span></span>
                                </div>
                                <div id="templateParsedRules" class="space-y-2 max-h-64 overflow-y-auto"></div>
                            </div>
                            <div class="console-inset p-4">
                                <div class="flex items-center justify-between mb-3">
                                    <h3 class="text-sm font-bold text-gray-700">&#24050;&#35299;&#26512;&#20998;&#32452;</h3>
                                    <span id="templateGroupCount" class="console-stat-chip" style="padding:2px 8px;"><span class="console-stat-num">0</span></span>
                                </div>
                                <div id="templateParsedGroups" class="space-y-2 max-h-64 overflow-y-auto"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function generateRuleManager() {
    return `
        <div class="console-card rounded-t-none p-6 space-y-5">
            <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                    <div class="console-page-title">&#35268;&#21017;&#30446;&#24405;</div>
                    <div class="console-page-desc">&#23450;&#20041;&#35268;&#21017; ID&#12289;&#21517;&#31216;&#65292;&#20197; Clash / Sing-box &#30340;&#36828;&#31243;&#35268;&#21017;&#22320;&#22336;&#12290;</div>
                </div>
                <div class="flex flex-wrap gap-2">
                    <span id="ruleStatTotal" class="console-stat-chip"><i class="fas fa-code-branch text-gray-400"></i>&#35268;&#21017;<span class="console-stat-num">0</span></span>
                </div>
            </div>
            <div class="flex flex-wrap gap-2">
                <button onclick="newRule()" class="console-button console-button-compact console-button-toolbar">
                    <i class="fas fa-plus"></i>&#26032;&#24314;&#35268;&#21017;
                </button>
                <button onclick="importRulePresets()" class="console-button console-button-compact console-button-toolbar">
                    <i class="fas fa-download"></i>&#23548;&#20837; DustinWin
                </button>
                <button onclick="saveRule(this)" class="console-button console-button-compact console-button-dark">
                    <i class="fas fa-save"></i>&#20445;&#23384;&#35268;&#21017;
                </button>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-5">
                <div class="lg:col-span-1">
                    <h3 class="text-sm font-bold text-gray-700 mb-3">&#24050;&#20445;&#23384;&#35268;&#21017;</h3>
                    <div id="ruleList" class="space-y-3 max-h-[28rem] overflow-y-auto pr-1"></div>
                </div>
                <div class="lg:col-span-2 space-y-4">
                    <input type="hidden" id="ruleIdOriginal">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#35268;&#21017; ID</label>
                            <input type="text" id="ruleId" placeholder="&#20363;&#22914;&#65306;applications" class="console-input">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#26174;&#31034;&#21517;&#31216;</label>
                            <input type="text" id="ruleName" placeholder="&#20363;&#22914;&#65306;&#24120;&#35265;&#24212;&#29992;" class="console-input">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="console-inset p-4 space-y-3">
                            <div class="text-xs font-semibold text-gray-500 uppercase tracking-wider">Clash / Mihomo</div>
                            <input type="text" id="ruleClashUrl" placeholder="https://..." class="console-input">
                            <input type="text" id="ruleClashFormat" placeholder="&#21487;&#36873;&#65292;&#20363;&#22914; text / yaml" class="console-input">
                        </div>
                        <div class="console-inset p-4 space-y-3">
                            <div class="text-xs font-semibold text-gray-500 uppercase tracking-wider">Sing-box</div>
                            <input type="text" id="ruleSingboxUrl" placeholder="https://..." class="console-input">
                            <input type="text" id="ruleSingboxFormat" placeholder="&#21487;&#36873;&#65292;&#20363;&#22914; source / binary / srs" class="console-input">
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-2">
                        <button onclick="insertRuleReference()" class="console-button console-button-compact console-button-toolbar">
                            <i class="fas fa-arrow-right"></i>&#25554;&#20837;&#21040;&#24403;&#21069;&#27169;&#26495;
                        </button>
                        <button onclick="copyRuleReference()" class="console-button console-button-compact console-button-toolbar">
                            <i class="fas fa-copy"></i>&#22797;&#21046; @rule_id
                        </button>
                        <button onclick="deleteRule()" class="console-button console-button-compact console-button-toolbar" style="color:var(--danger);">
                            <i class="fas fa-trash"></i>&#21024;&#38500;
                        </button>
                    </div>
                    <div class="console-inset p-4 text-sm text-gray-500 space-y-1">
                        <p>&#27169;&#26495;&#20013;&#21487;&#20197;&#36825;&#26679;&#24341;&#29992;&#65306;<code class="bg-white px-1.5 py-0.5 rounded">ruleset=DIRECT,@applications</code></p>
                        <p>&#29983;&#25104; Clash &#26102;&#35835;&#21462; <code>clash.url</code>&#65292;&#29983;&#25104; Sing-box &#26102;&#35835;&#21462; <code>singbox.url</code>&#12290;</p>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function generateNodeManager() {
    return `
        <div class="console-card rounded-t-none p-6 space-y-5">
            <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                    <div class="console-page-title">&#33410;&#28857;&#31649;&#29702;</div>
                    <div class="console-page-desc">&#32500;&#25252;&#33410;&#28857;&#22320;&#22336;&#12289;&#26631;&#31614;&#19982;&#23637;&#31034;&#26041;&#24335;&#12290;</div>
                </div>
                <div class="flex flex-wrap gap-2">
                    <span id="nodeStatTotal" class="console-stat-chip"><i class="fas fa-network-wired text-gray-400"></i>&#33410;&#28857;<span class="console-stat-num">0</span></span>
                    <span id="nodeStatTags" class="console-stat-chip"><i class="fas fa-tags text-gray-400"></i>&#26631;&#31614;<span class="console-stat-num">0</span></span>
                </div>
            </div>
            <div class="flex flex-col lg:flex-row lg:items-end gap-4">
                <div class="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-4">
                    <input type="text" id="nodeName" placeholder="&#33410;&#28857;&#21517;&#31216;" class="console-input lg:col-span-3">
                    <input type="text" id="nodeUrl" placeholder="&#33410;&#28857; URL" class="console-input console-mono lg:col-span-6">
                    <input type="text" id="nodeTags" placeholder="&#26631;&#31614;&#65292;&#29992;&#36887;&#21495;&#20998;&#38548;" class="console-input lg:col-span-3">
                </div>
                <button onclick="addNode(this)" class="console-button console-button-dark whitespace-nowrap">&#28155;&#21152;&#33410;&#28857;</button>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <div class="relative flex-1 min-w-[200px] max-w-xs">
                    <i class="fas fa-search absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-300 text-sm"></i>
                    <input type="text" id="nodeTagFilter" placeholder="&#25628;&#32034;&#33410;&#28857;&#25110;&#26631;&#31614;"
                        oninput="debouncedNodeFilter(this.value)"
                        class="console-input" style="padding-left:38px; min-height:40px;">
                </div>
                <div class="inline-flex overflow-hidden rounded-md flex-shrink-0" style="border:1px solid var(--border);">
                    <button type="button" id="nodeViewMode-all" onclick="setNodeViewMode('all')" class="console-button console-button-compact rounded-none border-0" style="min-height:40px;">&#24179;&#38138;</button>
                    <button type="button" id="nodeViewMode-grouped" onclick="setNodeViewMode('grouped')" class="console-button console-button-compact rounded-none border-0" style="min-height:40px; border-left:1px solid var(--border);">&#26631;&#31614;&#20998;&#32452;</button>
                </div>
                <button type="button" onclick="clearNodeFilter()" class="console-button console-button-compact console-button-toolbar" style="min-height:40px;">&#28165;&#31354;&#31579;&#36873;</button>
            </div>
            <div class="flex flex-wrap items-center gap-2">
                <span class="text-xs font-semibold text-gray-400 uppercase tracking-wider whitespace-nowrap">&#26631;&#31614;&#31579;&#36873;</span>
                <div id="nodeTagSummary" class="flex flex-wrap gap-2"></div>
            </div>
            <div id="nodeList" class="space-y-4"></div>
        </div>
    `;
}


function generateCollectionManager(CONFIG) {
    return `
        <div class="console-card rounded-t-none p-6 space-y-5">
            <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                    <div class="console-page-title">&#38598;&#21512;&#31649;&#29702;</div>
                    <div class="console-page-desc">&#21019;&#24314;&#38598;&#21512;&#12289;&#32465;&#23450;&#33410;&#28857;&#65292;&#31649;&#29702;&#35746;&#38405;&#19982;&#32534;&#36753;&#12290;</div>
                </div>
                <div class="flex flex-wrap gap-2">
                    <span id="collectionStatTotal" class="console-stat-chip"><i class="fas fa-layer-group text-gray-400"></i>&#38598;&#21512;<span class="console-stat-num">0</span></span>
                    <span id="collectionStatNodes" class="console-stat-chip"><i class="fas fa-network-wired text-gray-400"></i>&#33410;&#28857;<span class="console-stat-num">0</span></span>
                </div>
            </div>
            <div class="space-y-4">
                <div>
                    <button type="button" onclick="toggleCollapse('collectionCreateBody', this)" class="console-collapse-toggle is-open">
                        <span class="flex items-center gap-2"><i class="fas fa-plus-circle text-gray-400"></i>&#21019;&#24314;&#26032;&#38598;&#21512;</span>
                        <i class="fas fa-chevron-down console-collapse-arrow"></i>
                    </button>
                    <div id="collectionCreateBody" class="console-collapse-body is-open">
                        <div class="console-inset p-4 space-y-3">
                            <div class="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
                                <div class="flex flex-col gap-2 md:flex-row md:items-center md:gap-3">
                                    <div class="w-full md:w-72 xl:w-80">
                                        <input type="text" id="collectionName" placeholder="&#38598;&#21512;&#21517;&#31216;&#65292;&#20363;&#22914;&#65306;HK / &#26085;&#24120; / &#35270;&#39057;" class="console-input">
                                    </div>
                                    <button onclick="addCollection(this)" class="console-button console-button-dark whitespace-nowrap">&#21019;&#24314;&#38598;&#21512;</button>
                                </div>
                            </div>
                            <div id="nodeSelection" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3"></div>
                        </div>
                    </div>
                </div>
                <div class="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
                    <div class="flex items-center gap-2">
                        <span id="collectionListLabel" class="text-sm font-bold text-gray-800">&#24050;&#21019;&#24314;&#38598;&#21512;</span>
                    </div>
                    <div class="w-full md:w-72 xl:w-80">
                        <div class="relative">
                            <i class="fas fa-search absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-300 text-sm"></i>
                            <input type="text" id="collectionSearch" placeholder="&#25628;&#32034;&#38598;&#21512;&#21517;&#31216;"
                                oninput="debouncedCollectionSearch(this.value)"
                                class="console-input" style="padding-left:38px; min-height:40px;">
                        </div>
                    </div>
                </div>
                <div id="collectionList" class="grid grid-cols-1 gap-4 xl:grid-cols-2"></div>
            </div>
        </div>
    `;
}


function renderSettingsManager() {
    return `
        <div class="console-card rounded-t-none p-6 space-y-5">
            <div>
                <div class="console-page-title">&#37197;&#32622;</div>
                <div class="console-page-desc">&#31649;&#29702;&#21518;&#21488;&#36134;&#21495;&#12289;&#23494;&#30721;&#65292;&#20197;&#21450;&#39030;&#37096;&#8220;&#20854;&#20182;&#38142;&#25509;&#8221;&#25353;&#38062;&#20351;&#29992;&#30340;&#22320;&#22336;&#12290;</div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div class="space-y-4">
                    <div>
                        <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#31649;&#29702;&#21592;&#36134;&#21495;</label>
                        <input type="text" id="settingsAdminUsername" placeholder="&#20363;&#22914;&#65306;admin" class="console-input">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#31649;&#29702;&#21592;&#23494;&#30721;</label>
                        <input type="password" id="settingsAdminPassword" placeholder="&#30041;&#31354;&#21017;&#20445;&#25345;&#24403;&#21069;&#23494;&#30721;" class="console-input">
                    </div>
                    <p id="settingsPasswordHint" class="text-sm text-gray-500">&#24403;&#21069;&#23494;&#30721;&#29366;&#24577;&#65306;&#26410;&#35774;&#32622;</p>
                </div>
                <div class="space-y-4">
                    <div>
                        <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#20854;&#20182;&#38142;&#25509;</label>
                        <input type="text" id="settingsOtherLinkUrl" placeholder="https://..." class="console-input console-mono">
                    </div>
                    <p class="text-sm text-gray-500">&#39030;&#37096;&#8220;&#20854;&#20182;&#38142;&#25509;&#8221;&#25353;&#38062;&#20250;&#25171;&#24320;&#36825;&#37324;&#37197;&#32622;&#30340;&#22320;&#22336;&#12290;</p>
                </div>
            </div>
            <div>
                <button onclick="saveSettings(this)" class="console-button console-button-dark"><i class="fas fa-save"></i>&#20445;&#23384;&#37197;&#32622;</button>
            </div>
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

            function shouldSuppressBootstrapError(error) {
                if (adminNeedsSetup) return true;
                const message = String(error?.message || error || '');
                return message.includes('Unauthorized');
            }

            async function init() {
                try {
                    const authenticated = await ensureAdminSession(false);
                    if (!authenticated) {
                        showLoginDialog();
                        return;
                    }
                    // Show UI shell immediately, then load data progressively
                    showManagementPage(currentManagementPage);
                    Promise.all([loadNodes(), loadCollections(), loadTemplates(), loadRules(), loadSettings()])
                        .catch(function(e) { console.error('Failed to load data:', e); });
                } catch (e) {
                    console.error('Failed to load data:', e);
                }
            }

            // Debounce utility — limits how often a function can fire
            function debounce(fn, ms) {
                let timer;
                return function(...args) {
                    clearTimeout(timer);
                    timer = setTimeout(() => fn.apply(this, args), ms);
                };
            }

            init();

            ${generateNodeScripts()}
            ${generateCollectionScripts()}
            ${generateTemplateScripts()}
            ${generateRuleScripts()}
            ${generateUtilityScripts(env, CONFIG)}
        </script>
    `;
}

// 生成集合相关脚本
function generateCollectionScripts() {
    return `
        let collectionSearchKeyword = '';
        let cachedCollections = [];

        async function loadCollections() {
            try {
                const response = await fetchWithAuth('/api/collections');
                cachedCollections = await response.json();
                // Update stat chips
                const statTotal = document.getElementById('collectionStatTotal');
                if (statTotal) {
                    const numEl = statTotal.querySelector('.console-stat-num');
                    if (numEl) numEl.textContent = String(cachedCollections.length);
                }
                const statNodes = document.getElementById('collectionStatNodes');
                if (statNodes) {
                    const numEl = statNodes.querySelector('.console-stat-num');
                    if (numEl) numEl.textContent = String(cachedNodes ? cachedNodes.length : 0);
                }
                // Wait for nodes to be loaded too before rendering collection node lists
                if (cachedNodes && cachedNodes.length > 0) {
                    renderCollectionsList();
                }
            } catch (e) {
                console.error('Error loading collections:', e);
            }
        }

        function handleCollectionSearchChange(value) {
            collectionSearchKeyword = String(value || '').trim().toLowerCase();
            renderCollectionsList();
        }
        const debouncedCollectionSearch = debounce((value) => {
            handleCollectionSearchChange(value);
        }, 200);

        function renderCollectionsList() {
            const collectionList = document.getElementById('collectionList');
            if (!collectionList) return;

            const filteredCollections = collectionSearchKeyword
                ? cachedCollections.filter(collection => String(collection.name || '').toLowerCase().includes(collectionSearchKeyword))
                : cachedCollections;

            // Update list label count
            const labelEl = document.getElementById('collectionListLabel');
            if (labelEl) {
                labelEl.textContent = filteredCollections.length === cachedCollections.length
                    ? '\u5df2\u521b\u5efa\u96c6\u5408\uff08' + cachedCollections.length + '\uff09'
                    : '\u641c\u7d22\u7ed3\u679c\uff08' + filteredCollections.length + '\uff09';
            }

            if (filteredCollections.length === 0) {
                collectionList.innerHTML = \`
                    <div class="xl:col-span-2 console-card console-empty">
                        <div class="console-empty-icon"><i class="fas fa-$\{collectionSearchKeyword ? 'search' : 'layer-group'}"></i></div>
                        <div class="console-empty-title">$\{collectionSearchKeyword ? '\u672a\u627e\u5230\u5339\u914d\u7684\u96c6\u5408' : '\u8fd8\u6ca1\u6709\u96c6\u5408'}</div>
                        <div class="console-empty-desc">$\{collectionSearchKeyword ? '\u8bf7\u5c1d\u8bd5\u5176\u4ed6\u5173\u952e\u8bcd\u3002' : '\u5c55\u5f00\u201c\u521b\u5efa\u65b0\u96c6\u5408\u201d\uff0c\u9009\u62e9\u8282\u70b9\u540e\u5373\u53ef\u751f\u6210\u8ba2\u9605\u3002'}</div>
                    </div>
                \`;
                return;
            }

            const borderColorVar = 'var(--accent)';
            collectionList.innerHTML = filteredCollections.map((collection) => \`
                    <div class="console-card p-5" style="border-left:3px solid \${borderColorVar}">
                        <div class="flex flex-col gap-4">
                            <div class="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                                <div class="min-w-0 flex-1">
                                    <div class="flex flex-wrap items-center gap-3">
                                        <h3 class="text-lg font-extrabold tracking-tight text-gray-900 flex items-center">
                                            <i class="fas fa-layer-group mr-2 text-gray-400"></i>
                                            \${collection.name}
                                        </h3>
                                        <span class="console-node-count-badge"><i class="fas fa-network-wired"></i><span id="nodeCount_\${collection.id}">\${collection.nodeIds ? collection.nodeIds.length : 0}</span></span>
                                        <span id="expiry_\${collection.id}"></span>
                                    </div>
                                </div>
                                <div class="flex items-center gap-2">
                                    <button onclick="editCollection('\${collection.id}')" class="console-button console-icon-button" title="&#32534;&#36753;&#38598;&#21512;">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button onclick="deleteCollection('\${collection.id}')" class="console-button console-icon-button" title="&#21024;&#38500;&#38598;&#21512;">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </div>
                            <div id="nodeList_\${collection.id}" class="flex flex-wrap gap-2"></div>
                            <div class="console-ghost-divider"></div>
                            <div class="flex flex-wrap gap-2">
                                <button onclick="shareCollection('\${collection.id}')" class="console-subscription-btn share">
                                    <i class="fas fa-share-alt"></i>&#20998;&#20139;
                                </button>
                                <button onclick="universalSubscription('\${collection.id}')"
                                    onmouseenter="showSubscriptionQRCode(event, 'base', '\${collection.id}', '&#36890;&#29992;&#35746;&#38405;')"
                                    onmousemove="moveSubscriptionQRCode(event)"
                                    onmouseleave="hideSubscriptionQRCode()"
                                    class="console-subscription-btn primary base">
                                    <i class="fas fa-link"></i>&#36890;&#29992;&#35746;&#38405;
                                </button>
                                <button onclick="singboxSubscription('\${collection.id}')"
                                    onmouseenter="showSubscriptionQRCode(event, 'singbox', '\${collection.id}', 'SingBox &#35746;&#38405;')"
                                    onmousemove="moveSubscriptionQRCode(event)"
                                    onmouseleave="hideSubscriptionQRCode()"
                                    class="console-subscription-btn primary singbox">
                                    <i class="fas fa-box"></i>SingBox&#35746;&#38405;
                                </button>
                                <button onclick="clashSubscription('\${collection.id}')"
                                    onmouseenter="showSubscriptionQRCode(event, 'clash', '\${collection.id}', 'Clash &#35746;&#38405;')"
                                    onmousemove="moveSubscriptionQRCode(event)"
                                    onmouseleave="hideSubscriptionQRCode()"
                                    class="console-subscription-btn primary clash">
                                    <i class="fas fa-bolt"></i>Clash&#35746;&#38405;
                                </button>
                            </div>
                        </div>
                    </div>
                \`).join('');

            // Batch update with cached nodes (avoid N+1 API calls)
            filteredCollections.forEach(collection => {
                updateCollectionNodes(collection, cachedNodes);
            });
        }

        async function updateCollectionNodes(collection, nodes) {
            try {
                // Use passed nodes array instead of re-fetching (performance fix)
                const allNodes = nodes || await (await fetchWithAuth('/api/nodes')).json();
                const tokenResponse = await fetchWithAuth(\`/api/collections/token/\${collection.id}\`);
                const token = await tokenResponse.json();
                const collectionNodes = allNodes.filter(node => collection.nodeIds.includes(node.id));
                
                // 更新有效期显示
                const expiryElement = document.getElementById(\`expiry_\${collection.id}\`);
                if (expiryElement && token.expiry) {
                    const expDate = new Date(token.expiry);
                    const isExpired = expDate < new Date();
                    const isNearExpiry = !isExpired && (expDate - new Date() < 7 * 24 * 60 * 60 * 1000);
                    
                    if (isExpired) {
                        expiryElement.innerHTML = \`
                            <span class="console-status-dot expired">
                                &#24050;&#36807;&#26399; &#183; \${expDate.toLocaleDateString('zh-CN', { year: 'numeric', month: 'numeric', day: 'numeric' })}
                            </span>
                        \`;
                    } else if (isNearExpiry) {
                        expiryElement.innerHTML = \`
                            <span class="console-status-dot soon">
                                &#21363;&#23558;&#21040;&#26399; &#183; \${expDate.toLocaleDateString('zh-CN', { year: 'numeric', month: 'numeric', day: 'numeric' })}
                            </span>
                        \`;
                    } else {
                        expiryElement.innerHTML = \`
                            <span class="console-status-dot active">
                                &#26377;&#25928; &#183; \${expDate.toLocaleDateString('zh-CN', { year: 'numeric', month: 'numeric', day: 'numeric' })}
                            </span>
                        \`;
                    }
                } else if (expiryElement) {
                    expiryElement.innerHTML = \`
                        <span class="console-status-dot active">&#38271;&#26399;</span>
                    \`;
                }
                
                // 更新节点列表
                const nodeList = document.getElementById(\`nodeList_\${collection.id}\`);
                if (nodeList) {
                    if (collectionNodes.length === 0) {
                        nodeList.innerHTML = '<span class="text-xs text-gray-400">&#35813;&#38598;&#21512;&#26242;&#26080;&#33410;&#28857;</span>';
                    } else {
                        nodeList.innerHTML = collectionNodes.map(node => \`
                            <span class="console-node-tag-chip">
                                <span class="console-node-tag-dot bg-gray-400"></span>
                                \${node.name}
                            </span>
                        \`).join('');
                    }
                }
            } catch (e) {
                console.error('Error updating collection nodes:', e);
            }
        }

        async function addCollection(btn) {
            if (btn) setButtonLoading(btn, true);
            const name = document.getElementById('collectionName').value;
            const nodeIds = Array.from(document.querySelectorAll('#nodeSelection input:checked'))
                .map(checkbox => checkbox.value);

            if (!name) {
                if (btn) setButtonLoading(btn, false);
                alertModal('请输入集合名称');
                return;
            }

            if (nodeIds.length === 0) {
                if (btn) setButtonLoading(btn, false);
                alertModal('请选择至少一个节点');
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
                    document.querySelectorAll('#nodeSelection input').forEach(
                        checkbox => checkbox.checked = false
                    );
                    await loadCollections();
                }
            } catch (e) {
                alertModal('创建集合失败');
            } finally {
                if (btn) setButtonLoading(btn, false);
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
                
                if (collection) {
                    showCollectionEditDialog(collection, allNodes);
                }
            } catch (e) {
                console.error('编辑集合失败:', e);
                alertModal('编辑集合失败');
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
                panel.style.left = \`\${Math.max(16, (window.innerWidth - rect.width) / 2)}px\`;
                panel.style.top = \`\${Math.max(16, (window.innerHeight - rect.height) / 2)}px\`;
                panel.style.width = \`\${rect.width}px\`;
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
                    panel.style.left = \`\${nextLeft}px\`;
                    panel.style.top = \`\${nextTop}px\`;
                };

                const onUp = () => {
                    window.removeEventListener('pointermove', onMove);
                };

                window.addEventListener('pointermove', onMove);
                window.addEventListener('pointerup', onUp, { once: true });
            });
        }

        async function showCollectionEditDialog(collection, nodes) {
            const response = await fetchWithAuth(\`/api/collections/token/\${collection.id}\`);
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
            dialog.className = 'fixed inset-0 z-50 bg-black bg-opacity-50 overflow-y-auto p-4';
            dialog.innerHTML = \`
                <div data-dialog-panel class="console-card shadow-2xl w-full max-w-3xl overflow-hidden flex flex-col" style="height: min(900px, calc(100vh - 2rem)); max-height: calc(100vh - 2rem);">
                    <div data-dialog-drag-handle class="flex items-center justify-between gap-4 px-6 py-4 border-b border-gray-100 bg-white select-none">
                        <div>
                            <div class="console-label mb-2">Collection Editor</div>
                            <h2 class="text-xl font-extrabold tracking-tight text-gray-900">编辑集合</h2>
                            <p class="text-sm text-gray-500 mt-1">窗口支持拖动，内容过长时可滚动查看。</p>
                        </div>
                        <button type="button" onclick="closeCollectionEditDialog()" class="console-button console-icon-button">
                            <i class="fas fa-times text-xl"></i>
                        </button>
                    </div>
                    <div class="p-6 space-y-4 overflow-y-auto flex-1 min-h-0">
                        <div>
                            <label class="block text-sm font-medium text-gray-700">集合名称</label>
                            <input type="text" id="collectionName" value="\${collection.name}"
                                class="console-input mt-1">
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700">访问用户名</label>
                                <input type="text" id="collectionUsername" value="\${userToken.username || ''}"
                                    class="console-input mt-1">
                                <p class="mt-1 text-sm text-gray-500">留空将自动生成用户名。</p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">访问密码</label>
                                <input type="password" id="collectionPassword" value=""
                                    class="console-input mt-1">
                                <p class="mt-1 text-sm text-gray-500">留空则保持当前密码不变。</p>
                            </div>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">有效期</label>
                            <input type="date" id="collectionExpiry" value="\${formatDateForInput(userToken.expiry)}"
                                class="console-input mt-1">
                            <p class="mt-1 text-sm text-gray-500">可选，不填写表示不过期。</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">选择节点</label>
                            <div class="max-h-72 overflow-y-auto console-inset p-4 space-y-2">
                                \${nodes.map(node => \`
                                    <label class="console-node-pick">
                                        <input type="checkbox" data-node-checkbox value="\${node.id}" \${collection.nodeIds?.includes(node.id) ? 'checked' : ''}>
                                        <span class="console-node-pick-title">\${node.name}</span>
                                    </label>
                                \`).join('')}
                            </div>
                        </div>
                    </div>
                    <div class="flex justify-end gap-2 px-6 py-4 border-t border-gray-100 bg-white shrink-0">
                        <button type="button" onclick="closeCollectionEditDialog()"
                            class="console-button console-button-compact console-button-toolbar">
                            取消
                        </button>
                        <button type="button" onclick="updateCollection('\${collection.id}')"
                            class="console-button console-button-compact console-button-dark">
                            保存
                        </button>
                    </div>
                </div>
            \`;

            dialog.addEventListener('click', (event) => {
                if (event.target === dialog) {
                    closeCollectionEditDialog();
                }
            });

            document.body.appendChild(dialog);
            enableCollectionEditDialogDrag(dialog);
        }

        async function updateCollection(id) {
            const dialog = document.getElementById('collectionEditDialog');
            if (!dialog) {
                console.error('Dialog not found');
                return;
            }

            const nameInput = dialog.querySelector('#collectionName');
            if (!nameInput) {
                console.error('Name input not found');
                return;
            }

            const name = nameInput.value;
            const username = dialog.querySelector('#collectionUsername').value;
            const password = dialog.querySelector('#collectionPassword').value;
            const expiry = dialog.querySelector('#collectionExpiry').value;
            const nodeIds = Array.from(dialog.querySelectorAll('[data-node-checkbox]:checked'))
                .map((checkbox) => checkbox.value);

            try {
                const response = await fetchWithAuth('/api/collections', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        id,
                        nodeIds,
                        username,
                        password,
                        expiry: expiry || null,
                        name
                    })
                });

                if (response.ok) {
                    closeCollectionEditDialog();
                    await loadCollections();
                } else {
                    const error = await response.json();
                    throw new Error(error.error || '更新失败');
                }
            } catch (e) {
                console.error('Update failed:', e);
                alertModal('更新集合失败: ' + e.message);
            }
        }

        async function deleteCollection(id) {
            if (!await confirmModal('确定要删除这个集合吗？')) return;
            
            try {
                const response = await fetchWithAuth('/api/collections', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id })
                });
                
                if (response.ok) {
                    await loadCollections();
                }
            } catch (e) {
                alertModal('删除集合失败');
            }
        }

        // 订阅相关函数
        async function shareCollection(id) {
            const shareUrl = \`\${window.location.origin}/api/share/\${id}\`;
            try {
                await navigator.clipboard.writeText(shareUrl);
                showToast('分享链接已复制到剪贴板');
            } catch (e) {
                alertModal('复制分享链接失败');
            }
        }

        function universalSubscription(id) {
            const shareUrl = \`\${window.location.origin}/api/share/\${id}\`;
            const subUrl = CONFIG.SUB_WORKER_URL ? 
                \`\${CONFIG.SUB_WORKER_URL}/base?url=\${encodeURIComponent(shareUrl)}\` :
                \`\${shareUrl}/base?internal=1\`;
            copyToClipboard(subUrl, '通用订阅链接已复制到剪贴板');
        }

        function singboxSubscription(id) {
            const shareUrl = \`\${window.location.origin}/api/share/\${id}\`;
            const templateParam = getTemplateParam();
            const subUrl = CONFIG.SUB_WORKER_URL ? 
                \`\${CONFIG.SUB_WORKER_URL}/singbox?url=\${encodeURIComponent(shareUrl)}\${templateParam}\` :
                \`\${shareUrl}/singbox?internal=1\${templateParam}\`;
            copyToClipboard(subUrl, 'Sing-box 订阅链接已复制到剪贴板');
        }

        function clashSubscription(id) {
            const shareUrl = \`\${window.location.origin}/api/share/\${id}\`;
            const templateParam = getTemplateParam();
            const subUrl = CONFIG.SUB_WORKER_URL ? 
                \`\${CONFIG.SUB_WORKER_URL}/clash?url=\${encodeURIComponent(shareUrl)}\${templateParam}\` :
                \`\${shareUrl}/clash?internal=1\${templateParam}\`;
            copyToClipboard(subUrl, 'Clash 订阅链接已复制到剪贴板');
        }
    `;
}

// 生成工具函数脚本
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
                badge.textContent = \`当前模板：\${active.name}\`;
                badge.className = 'text-xs px-2 py-1 rounded-full bg-green-100 text-green-700';
                return;
            }

            if (activeTemplateUrl) {
                badge.textContent = '使用外部模板';
                badge.className = 'text-xs px-2 py-1 rounded-full bg-yellow-100 text-yellow-700';
                return;
            }

            badge.textContent = '未启用';
            badge.className = 'text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-600';
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
                body: JSON.stringify({
                    activeTemplateUrl: url || ''
                })
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
            const lines = String(content || '').split(/\\r?\\n/);
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
                    ? parsed.rules.map((item) => {
                        return '<div class="border border-gray-200 rounded-lg bg-white p-3">'
                            + '<div class="font-medium text-gray-800 break-all">' + escapeHtml(item.name || '未命名规则') + '</div>'
                            + '<div class="text-xs text-gray-500 mt-1 break-all">' + escapeHtml(item.source || '') + '</div>'
                            + '</div>';
                    }).join('')
                    : '<div class="text-sm text-gray-500">暂无已解析规则</div>';
            }

            if (groupContainer) {
                groupContainer.innerHTML = parsed.groups.length
                    ? parsed.groups.map((item) => {
                        return '<div class="border border-gray-200 rounded-lg bg-white p-3">'
                            + '<div class="font-medium text-gray-800 break-all">' + escapeHtml(item.name || '未命名分组') + '</div>'
                            + '<div class="text-xs text-gray-500 mt-1 break-all">' + escapeHtml((item.type || '') + (item.summary ? ' | ' + item.summary : '')) + '</div>'
                            + '</div>';
                    }).join('')
                    : '<div class="text-sm text-gray-500">暂无已解析分组</div>';
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
                content: 'ruleset=默认规则,[]MATCH\\n\\ncustom_proxy_group=节点选择\`select\`[]DIRECT'
            });
        }

        function renderTemplates() {
            const container = document.getElementById('templateList');
            if (!container) return;

            if (!templates.length) {
                container.innerHTML = '<div class="text-sm text-gray-500 bg-gray-50 rounded-lg p-4">暂无模板</div>';
                updateActiveTemplateBadge();
                return;
            }

            container.innerHTML = templates.map(template => \`
                <div class="console-inset p-3 transition-colors duration-200 \${template.internalUrl === activeTemplateUrl ? 'border-green-300 bg-green-50' : 'hover:border-gray-400'}">
                    <div class="flex items-start justify-between gap-3">
                        <div class="min-w-0">
                            <div class="font-semibold text-gray-800 truncate">\${template.name}</div>
                            <div class="text-xs text-gray-500 mt-1">\${template.updatedAt ? new Date(template.updatedAt).toLocaleString() : '\u672a\u77e5'}</div>
                        </div>
                        <button onclick="editTemplate('\${template.id}')" class="console-button console-icon-button" title="\u7f16\u8f91\u6a21\u677f"><i class="fas fa-pen"></i></button>
                    </div>
                    <div class="flex flex-wrap gap-2 mt-3 text-xs">
                        <button onclick="activateTemplateById('\${template.id}')" class="console-button console-button-compact console-button-toolbar">\u542f\u7528</button>
                        <button onclick="copyTemplateUrl('\${template.id}')" class="console-button console-button-compact console-button-toolbar">\u590d\u5236\u5730\u5740</button>
                    </div>
                </div>
            \`).join('');

            // Update template stat chips
            const tplStatTotal = document.getElementById('templateStatTotal');
            if (tplStatTotal) {
                const numEl = tplStatTotal.querySelector('.console-stat-num');
                if (numEl) numEl.textContent = String(templates.length);
            }
            const tplStatActive = document.getElementById('templateStatActive');
            if (tplStatActive) {
                const active = templates.find(t => t.internalUrl === activeTemplateUrl);
                const numEl = tplStatActive.querySelector('.console-stat-num');
                if (numEl) numEl.textContent = active ? active.name : '\u672a\u542f\u7528';
                if (tplStatActive) {
                    tplStatActive.classList.toggle('is-active', !!active);
                }
            }

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
                if (container && !shouldSuppressBootstrapError(error)) {
                    container.innerHTML = '<div class="text-sm text-red-500 bg-red-50 rounded-lg p-4">加载失败</div>';
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
                alertModal('加载模板失败');
            }
        }

        async function saveTemplate(btn) {
            if (btn) setButtonLoading(btn, true);
            const id = document.getElementById('templateId').value.trim();
            const name = document.getElementById('templateName').value.trim();
            const content = document.getElementById('templateContent').value;

            if (!name) {
                if (btn) setButtonLoading(btn, false);
                alertModal('请输入模板名称');
                return;
            }

            if (!content.trim()) {
                if (btn) setButtonLoading(btn, false);
                alertModal('请输入模板内容');
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
                showToast('保存成功');
            } catch (error) {
                console.error('Save template error:', error);
                alertModal('保存失败：' + error.message);
            } finally {
                if (btn) setButtonLoading(btn, false);
            }
        }

        async function deleteTemplate() {
            const id = document.getElementById('templateId').value.trim();
            if (!id) {
                alertModal('请先选择一个已保存的模板');
                return;
            }

            if (!await confirmModal('确定要删除当前模板吗？')) return;

            try {
                const response = await fetchWithAuth(\`${CONFIG.API.TEMPLATES}/\${encodeURIComponent(id)}\`, {
                    method: 'DELETE'
                });
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
                showToast('删除成功');
            } catch (error) {
                console.error('Delete template error:', error);
                alertModal('删除失败：' + error.message);
            }
        }

        async function activateTemplateById(id) {
            const template = templates.find(item => item.id === id);
            if (!template) return;
            try {
                await saveActiveTemplateUrl(template.internalUrl);
                showToast('已切换当前模板');
            } catch (error) {
                alertModal('切换当前模板失败：' + error.message);
            }
        }

        async function useCurrentTemplate() {
            const id = document.getElementById('templateId').value.trim();
            if (!id) {
                alertModal('请先保存当前模板');
                return;
            }
            await activateTemplateById(id);
        }

        function copyTemplateUrl(id) {
            const template = templates.find(item => item.id === id);
            if (!template) return;
            copyToClipboard(template.internalUrl, '模板地址已复制到剪贴板');
        }

        function copyCurrentTemplateUrl() {
            const id = document.getElementById('templateId').value.trim();
            if (!id) {
                alertModal('请先选择一个模板');
                return;
            }
            copyTemplateUrl(id);
        }

        function viewCurrentTemplateConfig() {
            const id = document.getElementById('templateId').value.trim();
            const selectedTemplate = id ? templates.find(item => item.id === id) : null;
            const targetUrl = activeTemplateUrl || selectedTemplate?.internalUrl || '';
            if (!targetUrl) {
                alertModal('请先选择或启用一个模板');
                return;
            }
            window.open(targetUrl, '_blank', 'noopener');
        }

        function loadBuiltInTemplatePreset() {
            const selector = document.getElementById('templatePresetSelector');
            const presetId = selector ? selector.value : '';
            if (!presetId) {
                alertModal('请先选择一个内置模板');
                return;
            }

            const preset = BUILT_IN_TEMPLATE_PRESETS.find(item => item.id === presetId);
            if (!preset) {
                alertModal('未找到所选模板预置');
                return;
            }

            const currentTemplateId = document.getElementById('templateId').value.trim();
            const currentTemplateName = document.getElementById('templateName').value.trim();
            const nextName = currentTemplateId || currentTemplateName
                ? preset.name + ' - 副本'
                : preset.name;

            fillTemplateForm({
                id: '',
                name: nextName,
                content: preset.content
            });
            showToast('已载入内置模板，请保存为新模板');
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
            fillRuleForm({
                id: '',
                name: '',
                clash: { url: '', format: '' },
                singbox: { url: '', format: '' }
            });
        }

        function renderRules() {
            const container = document.getElementById('ruleList');
            const selector = document.getElementById('templateRuleSelector');
            if (!container) return;

            if (!rules.length) {
                container.innerHTML = '<div class="text-sm text-gray-500 bg-gray-50 rounded-lg p-4">暂无规则，请先创建一条规则。</div>';
                if (selector) {
                    selector.innerHTML = '<option value="">暂无可插入规则</option>';
                }
                return;
            }

            if (selector) {
                selector.innerHTML = '<option value="">选择规则后插入模板</option>' +
                    rules.map(rule => '<option value="' + escapeHtml(rule.id || '') + '">' + escapeHtml(rule.name || '') + ' (@' + escapeHtml(rule.id || '') + ')</option>').join('');
            }

            // Update rule stat chip
            const ruleStatTotal = document.getElementById('ruleStatTotal');
            if (ruleStatTotal) {
                const numEl = ruleStatTotal.querySelector('.console-stat-num');
                if (numEl) numEl.textContent = String(rules.length);
            }

            container.innerHTML = rules.map(rule => {
                const clashUrl = (rule.clash && rule.clash.url) || '未配置';
                const singboxUrl = (rule.singbox && rule.singbox.url) || '未配置';
                return '<div class="console-inset p-3 transition-colors duration-200 hover:border-gray-400">'
                    + '<div class="flex items-start justify-between gap-3">'
                    + '<div class="min-w-0">'
                    + '<div class="font-semibold text-gray-800 truncate">' + escapeHtml(rule.name || '') + '</div>'
                    + '<div class="text-xs text-gray-500 mt-1 font-mono">@' + escapeHtml(rule.id || '') + '</div>'
                    + '</div>'
                    + '<button onclick="editRule(' + "'" + escapeHtml(rule.id || '') + "'" + ')" class="console-button console-icon-button" title="编辑规则"><i class="fas fa-pen"></i></button>'
                    + '</div>'
                    + '<div class="mt-3 text-xs text-gray-500 space-y-1">'
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
                if (container && !shouldSuppressBootstrapError(error)) {
                    container.innerHTML = '<div class="text-sm text-red-500 bg-red-50 rounded-lg p-4">规则加载失败，请稍后重试。</div>';
                }
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
                if (!response.ok) {
                    throw new Error(data.error || 'Failed to import presets');
                }
                await loadRules();
                showToast('已导入 ' + data.imported + ' 条 DustinWin 规则集，跳过 ' + data.skipped + ' 条已存在规则');
            } catch (error) {
                console.error('Import presets error:', error);
                alertModal('导入 DustinWin 规则集失败：' + error.message);
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
                alertModal('加载规则失败');
            }
        }

        async function saveRule(btn) {
            if (btn) setButtonLoading(btn, true);
            const originalId = document.getElementById('ruleIdOriginal').value.trim();
            const id = document.getElementById('ruleId').value.trim();
            const name = document.getElementById('ruleName').value.trim();
            const clashUrl = document.getElementById('ruleClashUrl').value.trim();
            const clashFormat = document.getElementById('ruleClashFormat').value.trim();
            const singboxUrl = document.getElementById('ruleSingboxUrl').value.trim();
            const singboxFormat = document.getElementById('ruleSingboxFormat').value.trim();

            if (!id) {
                if (btn) setButtonLoading(btn, false);
                alertModal('请填写规则 ID');
                return;
            }

            if (!name) {
                if (btn) setButtonLoading(btn, false);
                alertModal('请填写显示名称');
                return;
            }

            if (!clashUrl && !singboxUrl) {
                if (btn) setButtonLoading(btn, false);
                alertModal('Clash 和 Sing-box 至少填写一个规则地址');
                return;
            }

            const payload = {
                id: id,
                name: name,
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
                showToast('规则已保存');
            } catch (error) {
                console.error('Save rule error:', error);
                alertModal('保存失败：' + error.message);
            } finally {
                if (btn) setButtonLoading(btn, false);
            }
        }

        async function deleteRule() {
            const id = document.getElementById('ruleIdOriginal').value.trim();
            if (!id) {
                alertModal('请先选择要删除的规则');
                return;
            }

            if (!await confirmModal('确认删除这条规则吗？')) return;

            try {
                const response = await fetchWithAuth('${CONFIG.API.RULES}/' + encodeURIComponent(id), {
                    method: 'DELETE'
                });
                if (!response.ok) {
                    const data = await response.json();
                    throw new Error(data.error || 'Delete failed');
                }
                fillRuleForm({});
                await loadRules();
                showToast('规则已删除');
            } catch (error) {
                console.error('Delete rule error:', error);
                alertModal('删除失败：' + error.message);
            }
        }

        function getCurrentRuleReference() {
            const id = document.getElementById('ruleId').value.trim() || document.getElementById('ruleIdOriginal').value.trim();
            return id ? '@' + id : '';
        }

        function copyRuleReference() {
            const ref = getCurrentRuleReference();
            if (!ref) {
                alertModal('请先填写规则 ID');
                return;
            }
            copyToClipboard(ref, '规则引用已复制');
        }

        function insertRuleReference() {
            const ref = getCurrentRuleReference();
            if (!ref) {
                alertModal('请先填写规则 ID');
                return;
            }
            const templateContent = document.getElementById('templateContent');
            if (!templateContent) {
                alertModal('未找到模板编辑器');
                return;
            }
            const displayName = document.getElementById('ruleName').value.trim() || ref.slice(1);
            const line = 'ruleset=' + displayName + ',' + ref;
            const prefix = templateContent.value && !templateContent.value.endsWith('\\n') ? '\\n' : '';
            templateContent.value += prefix + line + '\\n';
            templateContent.focus();
            renderTemplateStructure();
            showToast('规则引用已插入模板');
        }

        function appendLineToTemplate(line, successMessage) {
            const templateContent = document.getElementById('templateContent');
            if (!templateContent) {
                alertModal('未找到模板编辑器');
                return false;
            }
            const prefix = templateContent.value && !templateContent.value.endsWith('\\n') ? '\\n' : '';
            templateContent.value += prefix + line + '\\n';
            templateContent.focus();
            renderTemplateStructure();
            if (successMessage) showToast(successMessage);
            return true;
        }

        function insertSelectedRuleIntoTemplate() {
            const selector = document.getElementById('templateRuleSelector');
            if (!selector || !selector.value) {
                alertModal('请先选择一条规则');
                return;
            }
            const rule = rules.find(item => item.id === selector.value);
            if (!rule) {
                alertModal('未找到选中的规则');
                return;
            }
            appendLineToTemplate('ruleset=' + rule.name + ',@' + rule.id, '规则引用已插入');
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
                alertModal('请填写分组名称');
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

            appendLineToTemplate(line, '分组规则已插入');
        }

        function insertDefaultSelectGroup() {
            document.getElementById('groupNameInput').value = '节点选择';
            document.getElementById('groupTypeInput').value = 'select';
            document.getElementById('groupFilterInput').value = '';
            document.getElementById('groupRefsInput').value = 'DIRECT';
            insertGroupLine();
        }
    `;
}

function generateUtilityScripts(env, CONFIG) {
    return `
        function confirmModal(message) {
            return new Promise((resolve) => {
                const overlay = document.createElement('div');
                overlay.className = 'fixed inset-0 z-[100] bg-black bg-opacity-50 flex items-center justify-center p-4';
                overlay.innerHTML = '<div class="console-card shadow-2xl p-6 max-w-sm w-full">'
                    + '<div class="console-label mb-3">Confirm</div>'
                    + '<p class="text-sm text-gray-700 leading-6">' + String(message).replace(/</g,'&lt;') + '</p>'
                    + '<div class="flex justify-end gap-2 mt-6">'
                    + '<button class="cancel-btn console-button console-button-compact console-button-toolbar">取消</button>'
                    + '<button class="confirm-btn console-button console-button-compact console-button-dark">确定</button>'
                    + '</div></div>';
                overlay.querySelector('.confirm-btn').onclick = () => { overlay.remove(); resolve(true); };
                overlay.querySelector('.cancel-btn').onclick = () => { overlay.remove(); resolve(false); };
                overlay.onclick = (e) => { if (e.target === overlay) { overlay.remove(); resolve(false); } };
                document.body.appendChild(overlay);
            });
        }

        function alertModal(message) {
            const overlay = document.createElement('div');
            overlay.className = 'fixed inset-0 z-[100] bg-black bg-opacity-50 flex items-center justify-center p-4';
            overlay.innerHTML = '<div class="console-card shadow-2xl p-6 max-w-sm w-full">'
                + '<div class="console-label mb-3">Notice</div>'
                + '<p class="text-sm text-gray-700 leading-6">' + String(message).replace(/</g,'&lt;') + '</p>'
                + '<div class="flex justify-end mt-6">'
                + '<button class="ok-btn console-button console-button-compact console-button-dark">确定</button>'
                + '</div></div>';
            overlay.querySelector('.ok-btn').onclick = () => overlay.remove();
            overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
            document.body.appendChild(overlay);
        }

        function setButtonLoading(btn, loading) {
            if (!btn) return;
            if (loading) {
                btn._origHtml = btn.innerHTML;
                btn.disabled = true;
                btn.style.pointerEvents = 'none';
                btn.style.opacity = '0.8';
                btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>' + (btn._origHtml.replace(/<i[^>]*><\\/i>\\s*/g, ''));
            } else {
                btn.disabled = false;
                btn.style.pointerEvents = '';
                btn.style.opacity = '';
                if (btn._origHtml) btn.innerHTML = btn._origHtml;
            }
        }

        function showManagementPage(page) {
            currentManagementPage = !page || page === 'overview' ? 'collections' : page;
            document.querySelectorAll('[data-page-panel]').forEach((panel) => {
                panel.classList.toggle('hidden', panel.getAttribute('data-page-panel') !== currentManagementPage);
            });
            document.querySelectorAll('[data-page-tab]').forEach((button) => {
                const tab = button.getAttribute('data-page-tab');
                const active = tab === currentManagementPage;
                button.className = active
                    ? 'console-tab active'
                    : 'console-tab';
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

            if (usernameInput) {
                usernameInput.value = currentSettings.adminUsername || '';
            }
            if (passwordInput) {
                passwordInput.value = '';
            }
            if (otherLinkInput) {
                otherLinkInput.value = currentSettings.otherLinkUrl || '';
            }
            if (passwordHint) {
                passwordHint.textContent = currentSettings.hasAdminPassword
                    ? '当前密码状态：已设置'
                    : '当前密码状态：未设置';
            }
        }

        async function loadSettings() {
            try {
                const response = await fetchWithAuth(CONFIG.API.SETTINGS);
                if (!response.ok) {
                    throw new Error('Failed to load settings');
                }
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

        async function saveSettings(btn) {
            if (btn) setButtonLoading(btn, true);
            const adminUsername = document.getElementById('settingsAdminUsername')?.value.trim() || '';
            const adminPassword = document.getElementById('settingsAdminPassword')?.value || '';
            const otherLinkUrl = document.getElementById('settingsOtherLinkUrl')?.value.trim() || '';

            try {
                const response = await fetchWithAuth(CONFIG.API.SETTINGS, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        adminUsername,
                        adminPassword,
                        otherLinkUrl
                    })
                });
                const data = await response.json();
                if (!response.ok || !data.success) {
                    throw new Error(data.error || '保存配置失败');
                }
                currentSettings = {
                    adminUsername: data.adminUsername || '',
                    hasAdminPassword: Boolean(data.hasAdminPassword),
                    otherLinkUrl: data.otherLinkUrl || '',
                    activeTemplateUrl: data.activeTemplateUrl || currentSettings.activeTemplateUrl || ''
                };
                applySettingsToForm();
                showToast('配置已保存');
            } catch (error) {
                alertModal('保存配置失败：' + error.message);
            } finally {
                if (btn) setButtonLoading(btn, false);
            }
        }

        function openOtherLink() {
            const formValue = document.getElementById('settingsOtherLinkUrl')?.value.trim() || '';
            const targetUrl = currentSettings.otherLinkUrl || formValue;
            if (!targetUrl) {
                showToast('请先在配置面板填写“其他链接”地址');
                return;
            }
            window.open(targetUrl, '_blank', 'noopener');
        }

        let subscriptionQrHideTimer = null;
        let subscriptionQrCurrentKey = '';

        function buildManagementSubscriptionUrl(id, type) {
            const shareUrl = \`\${window.location.origin}/api/share/\${id}\`;
            const templateParam = type === 'base' ? '' : (typeof getTemplateParam === 'function' ? getTemplateParam() : '');
            const typePath = type === 'base'
                ? '/base'
                : type === 'singbox'
                    ? '/singbox'
                    : '/clash';

            return CONFIG.SUB_WORKER_URL
                ? \`\${CONFIG.SUB_WORKER_URL}\${typePath}?url=\${encodeURIComponent(shareUrl)}\${templateParam}\`
                : \`\${shareUrl}\${typePath}?internal=1\${templateParam}\`;
        }

        function showSubscriptionQRCode(event, type, id, title) {
            const popup = document.getElementById('subscriptionQrPopup');
            const qrCanvas = document.getElementById('subscriptionQrCanvas');
            const qrTitle = document.getElementById('subscriptionQrTitle');
            if (!popup || !qrCanvas || typeof QRCode === 'undefined') return;

            clearTimeout(subscriptionQrHideTimer);
            const url = buildManagementSubscriptionUrl(id, type);
            const key = \`\${type}:\${id}:\${url}\`;
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

            if (qrTitle) {
                qrTitle.textContent = title;
            }

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

            if (left + rect.width > window.innerWidth - margin) {
                left = event.clientX - rect.width - 18;
            }
            if (top + rect.height > window.innerHeight - margin) {
                top = event.clientY - rect.height - 18;
            }

            popup.style.left = \`\${Math.max(margin, left)}px\`;
            popup.style.top = \`\${Math.max(margin, top)}px\`;
        }

        function hideSubscriptionQRCode() {
            const popup = document.getElementById('subscriptionQrPopup');
            if (!popup) return;

            clearTimeout(subscriptionQrHideTimer);
            subscriptionQrHideTimer = setTimeout(() => {
                popup.classList.add('hidden');
            }, 60);
        }

        async function copyToClipboard(text, message) {
            try {
                await navigator.clipboard.writeText(text);
                showToast(message);
            } catch (e) {
                alertModal('复制失败');
            }
        }

        function showToast(message) {
            const toast = document.createElement('div');
            toast.className = 'console-toast fixed bottom-4 left-1/2 transform -translate-x-1/2';
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        function toggleCollapse(bodyId, toggleBtn) {
            const body = document.getElementById(bodyId);
            if (!body) return;
            const isOpen = body.classList.toggle('is-open');
            if (toggleBtn) toggleBtn.classList.toggle('is-open', isOpen);
        }
    `;
}

function generateNodeScripts() {
    return `
        let nodeTagFilter = '';
        let nodeViewMode = 'all';
        let collectionNodeFilter = '';
        let cachedNodes = [];

        function normalizeNodeRecord(node) {
            return {
                ...node,
                tags: Array.isArray(node.tags) ? node.tags : []
            };
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
                const ungroupedMatch = value === '未分组' && (!node.tags || node.tags.length === 0);
                return nameMatch || tagMatch || ungroupedMatch;
            });
        }

        function renderTagSummary(targetId, nodes, clickHandler) {
            const container = document.getElementById(targetId);
            if (!container) return;

            const counts = new Map();
            nodes.forEach((node) => {
                const tags = node.tags && node.tags.length ? node.tags : ['未分组'];
                tags.forEach((tag) => counts.set(tag, (counts.get(tag) || 0) + 1));
            });

            const entries = Array.from(counts.entries()).sort((a, b) => a[0].localeCompare(b[0]));
            container.innerHTML = entries.length
                ? entries.map(([tag, count]) => '<button type="button" onclick="' + clickHandler + '(\\'' + tag.replace(/'/g, "\\\\'") + '\\')" class="inline-flex items-center px-2.5 py-1 rounded-full bg-gray-100 text-gray-700 hover:bg-blue-100 hover:text-blue-700 transition-colors"><span>' + tag + '</span><span class="ml-1 text-xs text-gray-500">' + count + '</span></button>').join('')
                : '<span class="text-sm text-gray-400">暂无标签</span>';
        }

        async function loadNodes() {
            try {
                const response = await fetchWithAuth('/api/nodes');
                if (response.ok) {
                    cachedNodes = (await response.json()).map(normalizeNodeRecord);
                    renderNodes(cachedNodes);
                    updateNodeSelection(cachedNodes);
                    // Re-render collections now that nodes are available
                    if (cachedCollections && cachedCollections.length > 0) {
                        renderCollectionsList();
                    }
                }
            } catch (e) {
                console.error('Error loading nodes:', e);
                if (!shouldSuppressBootstrapError(e)) {
                    alertModal('加载节点失败');
                }
            }
        }

        function setNodeViewMode(mode) {
            nodeViewMode = mode === 'grouped' ? 'grouped' : 'all';
            const allBtn = document.getElementById('nodeViewMode-all');
            const groupedBtn = document.getElementById('nodeViewMode-grouped');
            if (allBtn) {
                allBtn.className = nodeViewMode === 'all'
                    ? 'console-button console-button-compact console-button-dark rounded-none border-0'
                    : 'console-button console-button-compact console-button-toolbar rounded-none border-0';
            }
            if (groupedBtn) {
                groupedBtn.className = nodeViewMode === 'grouped'
                    ? 'console-button console-button-compact console-button-dark rounded-none border-0'
                    : 'console-button console-button-compact console-button-toolbar rounded-none border-0';
                if (groupedBtn.style) groupedBtn.style.borderLeft = '1px solid var(--border)';
            }
            renderNodes(cachedNodes);
        }

        function handleNodeFilterChange(value) {
            nodeTagFilter = value || '';
            renderNodes(cachedNodes);
        }
        const debouncedNodeFilter = debounce((value) => {
            handleNodeFilterChange(value);
        }, 200);

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

        // Tag-to-color mapping
        var _tagColors = {};
        var _tagPalette = [
            { border: '#2563eb', bg: 'bg-blue-100', text: 'text-blue-700' },
            { border: '#7c3aed', bg: 'bg-purple-100', text: 'text-purple-700' },
            { border: '#dc2626', bg: 'bg-red-100', text: 'text-red-700' },
            { border: '#059669', bg: 'bg-emerald-100', text: 'text-emerald-700' },
            { border: '#d97706', bg: 'bg-amber-100', text: 'text-amber-700' },
            { border: '#0891b2', bg: 'bg-cyan-100', text: 'text-cyan-700' },
            { border: '#ec4899', bg: 'bg-pink-100', text: 'text-pink-700' },
            { border: '#f97316', bg: 'bg-orange-100', text: 'text-orange-700' },
            { border: '#6366f1', bg: 'bg-indigo-100', text: 'text-indigo-700' },
            { border: '#14b8a6', bg: 'bg-teal-100', text: 'text-teal-700' },
            { border: '#84cc16', bg: 'bg-lime-100', text: 'text-lime-700' },
            { border: '#a855f7', bg: 'bg-fuchsia-100', text: 'text-fuchsia-700' },
        ];
        var _tagColorIdx = 0;

        function getTagColor(tag) {
            if (!_tagColors[tag]) {
                _tagColors[tag] = _tagPalette[_tagColorIdx % _tagPalette.length];
                _tagColorIdx++;
            }
            return _tagColors[tag];
        }

        function getNodeServerInfo(url) {
            if (!url) return '';
            try {
                var u = new URL(url);
                if (u.hostname) return u.hostname + (u.port ? ':' + u.port : '');
            } catch(e) {}
            return '';
        }

                function renderNodes(nodes) {
            const nodeList = document.getElementById('nodeList');
            if (!nodeList) return;

            const filteredNodes = getFilteredNodesForDisplay(nodes, nodeTagFilter);
            renderTagSummary('nodeTagSummary', nodes, 'applyNodeTagFilter');

            // Update stat chips
            const nodeStatTotal = document.getElementById('nodeStatTotal');
            if (nodeStatTotal) {
                const numEl = nodeStatTotal.querySelector('.console-stat-num');
                if (numEl) numEl.textContent = String(nodes.length);
            }
            const nodeStatTags = document.getElementById('nodeStatTags');
            if (nodeStatTags) {
                const tagSet = new Set();
                nodes.forEach((node) => {
                    (node.tags || []).forEach((tag) => tagSet.add(tag));
                });
                const numEl = nodeStatTags.querySelector('.console-stat-num');
                if (numEl) numEl.textContent = String(tagSet.size);
            }

            const grouped = new Map();
            if (nodeViewMode === 'grouped') {
                filteredNodes.forEach((node) => {
                    const tags = node.tags && node.tags.length ? node.tags : ['未分组'];
                    tags.forEach((tag) => {
                        if (!grouped.has(tag)) grouped.set(tag, []);
                        grouped.get(tag).push(node);
                    });
                });
            } else {
                grouped.set('全部节点', filteredNodes);
            }

            nodeList.innerHTML = filteredNodes.length
                ? Array.from(grouped.entries()).map(([groupName, items]) => {
                    const uniqueItems = Array.from(new Map(items.map(item => [item.id, item])).values());
                    return '<div class="space-y-3">'
                        + (nodeViewMode === 'grouped'
                            ? '<div class="flex items-center justify-between"><h3 class="text-sm font-bold text-gray-700">' + groupName + '</h3><span class="text-xs text-gray-400">' + uniqueItems.length + ' \u4e2a\u8282\u70b9</span></div>'
                            : '')
                        + '<div class="grid grid-cols-1 xl:grid-cols-2 gap-4">' + uniqueItems.map((node) => {
                            const tags = node.tags && node.tags.length
                                ? node.tags.map(function(tag) { var tc = getTagColor(tag); return '<span class="px-2 py-1 rounded-full text-xs font-medium ' + tc.bg + ' ' + tc.text + '">' + tag + '</span>'; }).join('')
                                : '<span class="px-2 py-1 rounded-full bg-gray-100 text-gray-500 text-xs">未分组</span>';

                            // First tag determines left border color
                            var tagColor = (node.tags && node.tags.length) ? getTagColor(node.tags[0]).border : '#d1d5db';
                            var serverInfo = getNodeServerInfo(node.url);

                            return '<div class="bg-white rounded-lg border border-gray-200 p-4 hover:shadow-md transition-all duration-200" style="border-left: 4px solid ' + tagColor + ';">'
                                + '<div class="flex justify-between items-start gap-4">'
                                + '<div class="flex-1 min-w-0">'

                                + '<h3 class="font-semibold text-gray-900 text-[15px] leading-tight">' + node.name + '</h3>'
                                + (serverInfo ? '<div class="text-xs text-gray-400 font-mono mt-0.5 truncate">' + serverInfo + '</div>' : '')
                                + '<div class="flex flex-wrap gap-2 mt-3">' + tags + '</div>'
                                + '</div>'
                                + '<div class="flex items-center space-x-2 ml-4 shrink-0">'
                                + '<button onclick="editNode(\\'' + node.id + '\\')" class="p-1.5 text-gray-400 hover:text-gray-700 transition-colors" title="编辑节点"><i class="fas fa-edit"></i></button>'
                                + '<button onclick="copyNode(\\'' + node.id + '\\')" class="p-1.5 text-gray-400 hover:text-gray-700 transition-colors" title="复制链接"><i class="fas fa-copy"></i></button>'
                                + '<button onclick="deleteNode(\\'' + node.id + '\\')" class="p-1.5 text-gray-400 hover:text-red-500 transition-colors" title="删除节点"><i class="fas fa-trash-alt"></i></button>'
                                + '</div>'
                                + '</div>'
                                + '</div>';
                        }).join('')
                        + '</div>'
                        + '</div>'; 
                }).join('')
                : '<div class="console-empty bg-gray-50 border border-dashed border-gray-200 rounded-lg"><div class="console-empty-icon"><i class="fas fa-' + (nodeTagFilter ? 'search' : 'network-wired') + '"></i></div><div class="console-empty-title">' + (nodeTagFilter ? '\u6ca1\u6709\u5339\u914d\u7684\u8282\u70b9' : '\u8fd8\u6ca1\u6709\u8282\u70b9') + '</div><div class="console-empty-desc">' + (nodeTagFilter ? '\u5c1d\u8bd5\u5176\u4ed6\u5173\u952e\u8bcd\u6216\u6e05\u7a7a\u7b5b\u9009\u3002' : '\u5728\u4e0a\u65b9\u586b\u5199\u8282\u70b9\u540d\u79f0\u3001URL \u548c\u6807\u7b7e\uff0c\u7136\u540e\u70b9\u51fb\u201c\u6dfb\u52a0\u8282\u70b9\u201d\u3002') + '</div></div>';

            if (!document.querySelector('link[href*="font-awesome"]')) {
                const link = document.createElement('link');
                link.rel = 'stylesheet';
                link.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css';
                document.head.appendChild(link);
            }
        }

        async function addNode(btn) {
            if (btn) setButtonLoading(btn, true);
            const name = document.getElementById('nodeName').value;
            const url = document.getElementById('nodeUrl').value;
            const tags = parseNodeTags(document.getElementById('nodeTags')?.value || '');

            if (!name || !url) {
                if (btn) setButtonLoading(btn, false);
                alertModal('请填写完整信息');
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
                }
            } catch (e) {
                alertModal('添加节点失败');
            } finally {
                if (btn) setButtonLoading(btn, false);
            }
        }

        async function editNode(id) {
            const node = cachedNodes.find((item) => item.id === id);
            if (node) {
                showEditDialog(node);
            }
        }

        function showEditDialog(node) {
            const dialog = document.createElement('div');
            dialog.id = 'nodeEditDialog';
            dialog.className = 'fixed inset-0 z-50 bg-black bg-opacity-50 flex items-center justify-center p-4';
            dialog.innerHTML = \`
                <div class="console-card shadow-2xl p-6 max-w-lg w-full">
                    <div class="flex justify-between items-center mb-4">
                        <div>
                            <div class="console-page-title" style="font-size:20px;">&#32534;&#36753;&#33410;&#28857;</div>
                        </div>
                        <button onclick="this.closest('.fixed').remove()" class="console-button console-icon-button">
                            <i class="fas fa-times text-xl"></i>
                        </button>
                    </div>
                    <div class="space-y-4">
                        <div>
                            <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#33410;&#28857;&#21517;&#31216;</label>
                            <input type="text" id="editNodeName" value="\${node.name}" class="console-input">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#33410;&#28857; URL</label>
                            <input type="text" id="editNodeUrl" value="\${node.url}" class="console-input console-mono">
                        </div>
                        <div>
                            <label class="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">&#33410;&#28857;&#26631;&#31614;</label>
                            <input type="text" id="editNodeTags" value="\${(node.tags || []).join(', ')}" class="console-input" placeholder="&#20363;&#22914;&#65306;HK, Premium, Test">
                            <p class="mt-1 text-sm text-gray-500">&#22810;&#20010;&#26631;&#31614;&#35831;&#29992;&#33521;&#25991;&#36887;&#21495;&#20998;&#38548;&#12290;</p>
                        </div>
                    </div>
                    <div class="flex justify-end gap-2 mt-6">
                        <button onclick="this.closest('.fixed').remove()" class="console-button console-button-compact console-button-toolbar">&#21462;&#28040;</button>
                        <button onclick="updateNode('\${node.id}')" class="console-button console-button-compact console-button-dark"><i class="fas fa-save"></i>&#20445;&#23384;</button>
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
                alertModal('&#35831;&#22635;&#20889;&#23436;&#25972;&#20449;&#24687;');
                return;
            }

            try {
                const response = await fetchWithAuth('/api/nodes', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id, name, url, tags })
                });

                if (response.ok) {
                    const dialog = document.getElementById('nodeEditDialog');
                    if (dialog) dialog.remove();
                    await loadNodes();
                }
            } catch (e) {
                alertModal('&#26356;&#26032;&#33410;&#28857;&#22833;&#36133;');
            }
        }

        async function copyNode(id) {
            const node = cachedNodes.find((item) => item.id === id);
            if (node) {
                await navigator.clipboard.writeText(node.url);
                showToast('已复制到剪贴板');
            }
        }

        async function deleteNode(id) {
            if (!await confirmModal('确定要删除这个节点吗？')) return;

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
                alertModal('删除节点失败');
            }
        }

        function updateNodeSelection(nodes) {
            const nodeSelection = document.getElementById('nodeSelection');
            if (!nodeSelection) return;

            const filteredNodes = getFilteredNodesForDisplay(nodes.map(normalizeNodeRecord), collectionNodeFilter);

            nodeSelection.innerHTML = filteredNodes.map(node => \`
                <div class="console-node-pick">
                    <input type="checkbox" id="select_\${node.id}" value="\${node.id}" class="text-gray-700 rounded border-gray-300 focus:ring-gray-400">
                    <label for="select_\${node.id}" class="console-node-pick-label">
                        <div class="console-node-pick-title truncate">\${node.name}</div>
                        <div class="console-node-pick-meta">\${(node.tags && node.tags.length ? node.tags : ['未分组']).map(tag => '<span class="console-node-pick-tag">' + tag + '</span>').join('')}</div>
                    </label>
                </div>
            \`).join('');

            const selectionControls = document.createElement('div');
            selectionControls.className = 'md:col-span-2 xl:col-span-3 flex items-center gap-4 text-left';
            selectionControls.innerHTML = \`
                <span class="text-lg font-bold tracking-tight text-gray-900">&#36873;&#25321;&#33410;&#28857;</span>
                <button onclick="selectAllNodes()" type="button" class="text-sm font-semibold text-gray-500 hover:text-gray-900">全选</button>
                <button onclick="deselectAllNodes()" type="button" class="text-sm font-semibold text-gray-500 hover:text-gray-900">取消全选</button>
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

