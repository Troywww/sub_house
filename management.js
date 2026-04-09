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
                        <div class="bg-white rounded-lg p-6 w-full max-w-md shadow-xl">
                            <h2 class="text-xl font-bold mb-2">初始化管理员账号</h2>
                            <p class="text-sm text-gray-500 mb-4">检测到系统尚未配置管理员账号，请先创建一个管理员账号后再进入后台。</p>
                            <div class="space-y-4">
                                <div id="adminLoginError" class="text-sm text-red-600 min-h-[1.25rem]">\${message}</div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">管理员用户名</label>
                                    <input type="text" id="adminUsername" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700">管理员密码</label>
                                    <input type="password" id="adminPassword" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                                </div>
                                <button onclick="setupAdmin()" class="w-full px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600">创建并登录</button>
                            </div>
                        </div>
                    \`;
                }

                return \`
                    <div class="bg-white rounded-lg p-6 w-full max-w-md shadow-xl">
                        <h2 class="text-xl font-bold mb-4">管理员登录</h2>
                        <div class="space-y-4">
                            <div id="adminLoginError" class="text-sm text-red-600 min-h-[1.25rem]">\${message}</div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">用户名</label>
                                <input type="text" id="adminUsername" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">密码</label>
                                <input type="password" id="adminPassword" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                            </div>
                            <button onclick="login()" class="w-full px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600">登录</button>
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

// 生成页面头部
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
                            ????
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
        <div class="bg-white rounded-lg shadow-lg p-6">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-gray-800">模板管理</h2>
                    <p class="text-sm text-gray-500 mt-1">在这里维护 Clash / Sing-box 的模板、规则引用和当前启用模板。</p>
                </div>
                    <div class="flex flex-wrap items-center gap-3">
                        <button onclick="newTemplate()"
                            class="px-4 py-2 rounded-xl border border-gray-200 bg-white text-gray-700 shadow-sm hover:bg-gray-50 hover:border-gray-300 transition duration-200">
                            新建模板
                        </button>
                        <select id="templatePresetSelector"
                            class="min-w-[14rem] px-4 py-2 rounded-xl border border-gray-300 bg-white text-gray-700 shadow-sm focus:ring-2 focus:ring-green-500 focus:border-transparent">
                            <option value="">选择内置模板预置</option>
                            ${TEMPLATE_PRESETS.map(preset => `<option value="${preset.id}">${preset.name}</option>`).join('')}
                        </select>
                        <button onclick="loadBuiltInTemplatePreset()"
                            class="px-4 py-2 rounded-xl bg-green-600 text-white font-medium shadow-sm hover:bg-green-700 transition duration-200">
                            载入内置模板
                        </button>
                        <button onclick="saveTemplate()"
                            class="px-4 py-2 rounded-xl bg-blue-600 text-white font-medium shadow-sm hover:bg-blue-700 transition duration-200">
                            保存模板
                        </button>
                </div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="lg:col-span-1">
                    <div class="flex items-center justify-between mb-3">
                        <h3 class="text-lg font-semibold text-gray-700">已保存模板</h3>
                        <span id="activeTemplateBadge" class="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-600">未启用</span>
                    </div>
                    <div id="templateList" class="space-y-3 max-h-[32rem] overflow-y-auto pr-1"></div>
                </div>
                <div class="lg:col-span-2 space-y-4">
                    <input type="hidden" id="templateId">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">模板名称</label>
                        <input type="text" id="templateName" placeholder="例如：默认分流模板"
                            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    </div>
                    <div class="flex flex-wrap gap-2 text-sm">
                        <button onclick="useCurrentTemplate()"
                            class="px-3 py-1.5 bg-green-100 text-green-700 rounded-lg hover:bg-green-200 transition duration-200">
                            设为当前模板
                        </button>
                        <button onclick="viewCurrentTemplateConfig()"
                            class="px-3 py-1.5 bg-yellow-100 text-yellow-700 rounded-lg hover:bg-yellow-200 transition duration-200">
                            查看当前默认订阅配置
                        </button>
                        <button onclick="deleteTemplate()"
                            class="px-3 py-1.5 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 transition duration-200">
                            删除模板
                        </button>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">模板内容</label>
                        <textarea id="templateContent" rows="18"
                            class="w-full px-4 py-3 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                            placeholder="ruleset=默认规则,[]MATCH&#10;custom_proxy_group=节点选择\`select\`[]DIRECT"></textarea>
                    </div>
                    <div class="p-4 bg-gray-50 rounded-lg space-y-3">
                        <div class="flex flex-col md:flex-row gap-3">
                            <select id="templateRuleSelector"
                                class="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                                <option value="">从规则目录选择一个规则并插入模板</option>
                            </select>
                            <button onclick="insertSelectedRuleIntoTemplate()"
                                class="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition duration-200">
                                插入选中规则
                            </button>
                        </div>
                        <p class="text-sm text-gray-500">会自动插入形如 <code class="bg-white px-1 py-0.5 rounded">ruleset=显示名,@rule_id</code> 的规则引用。</p>
                    </div>
                    <div class="p-4 bg-gray-50 rounded-lg space-y-3">
                        <div class="grid grid-cols-1 md:grid-cols-4 gap-3">
                            <input type="text" id="groupNameInput" placeholder="分组名称"
                                class="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                            <select id="groupTypeInput"
                                class="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                                <option value="select">select</option>
                                <option value="url-test">url-test</option>
                            </select>
                            <input type="text" id="groupFilterInput" placeholder="过滤器，例如 港|HK"
                                class="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                            <input type="text" id="groupRefsInput" placeholder="引用目标，逗号分隔"
                                class="px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                        <div class="flex flex-wrap gap-2">
                            <button onclick="insertGroupLine()"
                                class="px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition duration-200">
                                插入分组
                            </button>
                            <button onclick="insertDefaultSelectGroup()"
                                class="px-4 py-2 bg-indigo-100 text-indigo-700 rounded-lg hover:bg-indigo-200 transition duration-200">
                                插入默认分组
                            </button>
                        </div>
                        <p class="text-sm text-gray-500">会自动生成 <code class="bg-white px-1 py-0.5 rounded">custom_proxy_group=...</code> 并插入到模板文本中。</p>
                    </div>
                    <div class="p-4 bg-gray-50 rounded-lg text-sm text-gray-600 space-y-1">
                        <p>模板语法示例：</p>
                        <p><code class="bg-white px-1 py-0.5 rounded">ruleset=规则名,@rule_id</code></p>
                        <p><code class="bg-white px-1 py-0.5 rounded">custom_proxy_group=分组名\`select/url-test\`过滤器\`[]DIRECT</code></p>
                    </div>
                    <div class="grid grid-cols-1 xl:grid-cols-2 gap-4">
                        <div class="p-4 bg-gray-50 rounded-lg">
                            <div class="flex items-center justify-between mb-3">
                                <h3 class="font-semibold text-gray-800">已解析规则</h3>
                                <span id="templateRuleCount" class="text-xs px-2 py-1 rounded-full bg-white text-gray-600">0</span>
                            </div>
                            <div id="templateParsedRules" class="space-y-2 max-h-64 overflow-y-auto"></div>
                        </div>
                        <div class="p-4 bg-gray-50 rounded-lg">
                            <div class="flex items-center justify-between mb-3">
                                <h3 class="font-semibold text-gray-800">已解析分组</h3>
                                <span id="templateGroupCount" class="text-xs px-2 py-1 rounded-full bg-white text-gray-600">0</span>
                            </div>
                            <div id="templateParsedGroups" class="space-y-2 max-h-64 overflow-y-auto"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function generateRuleManager() {
    return `
        <div class="bg-white rounded-lg shadow-lg p-6">
            <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-gray-800">规则目录</h2>
                    <p class="text-sm text-gray-500 mt-1">为同一条规则定义稳定 ID，并分别配置 Clash / Mihomo 与 Sing-box 的远程规则地址。</p>
                </div>
                <div class="flex flex-wrap gap-2">
                    <button onclick="newRule()"
                        class="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition duration-200">
                        新建规则
                    </button>
                    <button onclick="importRulePresets()"
                        class="px-4 py-2 rounded-xl bg-purple-600 text-white font-medium shadow-sm hover:bg-purple-700 transition duration-200">
                        导入 DustinWin 规则集
                    </button>
                    <button onclick="saveRule()"
                        class="px-4 py-2 rounded-xl bg-blue-600 text-white font-medium shadow-sm hover:bg-blue-700 transition duration-200">
                        保存规则
                    </button>
                </div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="lg:col-span-1">
                    <h3 class="text-lg font-semibold text-gray-700 mb-3">已保存规则</h3>
                    <div id="ruleList" class="space-y-3 max-h-[28rem] overflow-y-auto pr-1"></div>
                </div>
                <div class="lg:col-span-2 space-y-4">
                    <input type="hidden" id="ruleIdOriginal">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">规则 ID</label>
                            <input type="text" id="ruleId" placeholder="例如：applications"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">显示名称</label>
                            <input type="text" id="ruleName" placeholder="例如：常见应用"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="p-4 bg-gray-50 rounded-lg space-y-3">
                            <h3 class="font-semibold text-gray-800">Clash / Mihomo</h3>
                            <input type="text" id="ruleClashUrl" placeholder="https://..."
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                            <input type="text" id="ruleClashFormat" placeholder="可选，例如 text / yaml"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                        <div class="p-4 bg-gray-50 rounded-lg space-y-3">
                            <h3 class="font-semibold text-gray-800">Sing-box</h3>
                            <input type="text" id="ruleSingboxUrl" placeholder="https://..."
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                            <input type="text" id="ruleSingboxFormat" placeholder="可选，例如 source / binary / srs"
                                class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                    </div>
                    <div class="flex flex-wrap gap-2 text-sm">
                        <button onclick="insertRuleReference()"
                            class="px-3 py-1.5 bg-green-100 text-green-700 rounded-lg hover:bg-green-200 transition duration-200">
                            插入到当前模板
                        </button>
                        <button onclick="copyRuleReference()"
                            class="px-3 py-1.5 bg-yellow-100 text-yellow-700 rounded-lg hover:bg-yellow-200 transition duration-200">
                            复制 @rule_id
                        </button>
                        <button onclick="deleteRule()"
                            class="px-3 py-1.5 bg-red-100 text-red-700 rounded-lg hover:bg-red-200 transition duration-200">
                            删除当前规则
                        </button>
                    </div>
                    <div class="p-4 bg-gray-50 rounded-lg text-sm text-gray-600 space-y-1">
                        <p>模板中可以直接这样引用：</p>
                        <p><code class="bg-white px-1 py-0.5 rounded">ruleset=DIRECT,@applications</code></p>
                        <p>生成 Clash 时会读取该规则的 <code>clash.url</code>，生成 Sing-box 时会读取 <code>singbox.url</code>。</p>
                        <p>“导入 DustinWin 规则集”会补齐 mrs / srs 新式规则集，适合 mihomo / sing-box 原生远程规则模式。</p>
                    </div>
                </div>
            </div>
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
        <div class="bg-white rounded-xl shadow-lg p-8 space-y-6">
            <div class="flex flex-col lg:flex-row lg:items-end gap-4">
                <div class="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-4">
                    <input type="text" id="nodeName" placeholder="节点名称"
                        class="lg:col-span-3 px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    <input type="text" id="nodeUrl" placeholder="节点 URL"
                        class="lg:col-span-6 px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    <input type="text" id="nodeTags" placeholder="标签，逗号分隔"
                        class="lg:col-span-3 px-4 py-2.5 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                </div>
                <button onclick="addNode()"
                    class="whitespace-nowrap px-6 py-2.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition duration-200">
                    添加节点
                </button>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_220px] gap-4 items-start">
                <div class="flex flex-wrap items-center gap-3">
                    <input type="text" id="nodeTagFilter" placeholder="按标签或节点名筛选"
                        oninput="handleNodeFilterChange(this.value)"
                        class="w-full sm:w-72 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    <button type="button" onclick="clearNodeFilter()"
                        class="px-3 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition duration-200">
                        清空筛选
                    </button>
                    <div class="inline-flex rounded-lg border border-gray-200 overflow-hidden">
                        <button type="button" id="nodeViewMode-all" onclick="setNodeViewMode('all')"
                            class="px-3 py-2 bg-blue-500 text-white text-sm">
                            平铺显示
                        </button>
                        <button type="button" id="nodeViewMode-grouped" onclick="setNodeViewMode('grouped')"
                            class="px-3 py-2 bg-white text-gray-700 text-sm hover:bg-gray-50">
                            标签分组
                        </button>
                    </div>
                </div>
                <div id="nodeTagSummary" class="flex flex-wrap lg:justify-end gap-2"></div>
            </div>
            <div id="nodeList" class="space-y-6"></div>
        </div>
    `;
}

function generateCollectionManagerV2(CONFIG) {
    return `
        <div class="space-y-4">
            <section class="bg-white rounded-xl shadow-sm border border-gray-100 p-5">
                <div class="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-3">
                    <div>
                        <h2 class="text-2xl font-bold text-gray-900">集合管理</h2>
                        <p class="text-sm text-gray-500 mt-1">创建订阅集合、维护有效期并快速分发通用 / Sing-box / Clash 订阅。</p>
                    </div>
                    <div class="grid grid-cols-2 lg:grid-cols-4 gap-2.5 w-full lg:w-auto" id="collectionStats">
                        <div class="rounded-2xl border border-gray-100 bg-gray-50 px-4 py-2.5 min-w-[112px]">
                            <div class="text-xs text-gray-500">集合总数</div>
                            <div id="statCollectionCount" class="mt-1 text-2xl font-semibold text-gray-900">0</div>
                        </div>
                        <div class="rounded-2xl border border-gray-100 bg-gray-50 px-4 py-2.5 min-w-[112px]">
                            <div class="text-xs text-gray-500">节点总数</div>
                            <div id="statNodeCount" class="mt-1 text-2xl font-semibold text-gray-900">0</div>
                        </div>
                        <div class="rounded-2xl border border-amber-100 bg-amber-50 px-4 py-2.5 min-w-[112px]">
                            <div class="text-xs text-amber-700">即将到期</div>
                            <div id="statExpiringCount" class="mt-1 text-2xl font-semibold text-amber-700">0</div>
                        </div>
                        <div class="rounded-2xl border border-red-100 bg-red-50 px-4 py-2.5 min-w-[112px]">
                            <div class="text-xs text-red-700">已过期</div>
                            <div id="statExpiredCount" class="mt-1 text-2xl font-semibold text-red-700">0</div>
                        </div>
                    </div>
                </div>
            </section>

            <section class="bg-white rounded-xl shadow-sm border border-gray-100 p-5 space-y-4">
                <div class="flex items-center justify-between gap-3">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-900">快速创建集合</h3>
                        <p class="text-sm text-gray-500">先命名集合，再选择需要包含的节点。</p>
                    </div>
                </div>
                <div class="flex flex-col xl:flex-row gap-4">
                    <input type="text" id="collectionName" placeholder="集合名称"
                        class="flex-1 px-4 py-2.5 border border-gray-300 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                    <button onclick="addCollection()"
                        class="whitespace-nowrap px-5 py-2.5 bg-blue-600 text-white rounded-xl hover:bg-blue-700 transition duration-200 shadow-sm">
                        创建集合
                    </button>
                </div>
                <div class="space-y-2">
                    <div class="flex items-center justify-between gap-3">
                        <h3 class="text-base font-semibold text-gray-800">选择节点</h3>
                        <p class="text-xs text-gray-400">可先到节点管理页维护标签后再回来选取。</p>
                    </div>
                    <div id="nodeSelection" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 p-4 bg-gray-50 rounded-xl border border-gray-100"></div>
                </div>
            </section>

            <section class="space-y-2.5">
                <div class="flex items-end justify-between gap-3">
                    <div>
                        <h3 class="text-xl font-semibold text-gray-900">当前所有集合</h3>
                        <p class="text-sm text-gray-500">优先查看状态、有效期和分发入口，不必先进入编辑弹窗。</p>
                    </div>
                </div>
                <div id="collectionList" class="grid grid-cols-1 xl:grid-cols-2 gap-4"></div>
            </section>
        </div>
    `;
}

function renderSettingsManager() {
    return `
        <div class="bg-white rounded-xl shadow-lg p-8">
            <div class="mb-6">
                <h2 class="text-2xl font-bold text-gray-800">配置面板</h2>
                <p class="text-sm text-gray-500 mt-1">管理后台管理员账号、密码，以及顶部“其他链接”按钮使用的地址。</p>
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
                    <p class="text-sm text-gray-500">顶部“其他链接”按钮会打开这里配置的地址。</p>
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
            const now = new Date();
            const expiringSoonThreshold = 7 * 24 * 60 * 60 * 1000;
            let expiringSoon = 0;
            let expired = 0;

            collections.forEach((collection) => {
                const expiry = collection.tokenExpiry ? new Date(collection.tokenExpiry) : null;
                if (!expiry || Number.isNaN(expiry.getTime())) return;
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

        async function loadCollections() {
            try {
                const [collectionsResponse, nodesResponse] = await Promise.all([
                    fetchWithAuth('/api/collections'),
                    fetchWithAuth('/api/nodes')
                ]);
                const collections = await collectionsResponse.json();
                const allNodes = await nodesResponse.json();
                console.log('Loaded collections:', collections);
                updateCollectionStats(collections, allNodes);
                
                const collectionList = document.getElementById('collectionList');
                collectionList.innerHTML = collections.map(collection => \`
                    <article class="bg-white rounded-2xl border border-gray-100 shadow-sm p-5 hover:shadow-md transition-all duration-200">
                        <div class="flex flex-col gap-4 h-full">
                            <div class="flex justify-between items-start gap-4">
                                <div class="flex-1 min-w-0">
                                    <div class="flex items-center gap-2 flex-wrap">
                                        <h3 class="text-lg font-semibold text-gray-900 flex items-center min-w-0">
                                            <i class="fas fa-layer-group text-blue-500 mr-2"></i>
                                            <span class="truncate">\${collection.name}</span>
                                        </h3>
                                        <span id="expiry_\${collection.id}" class="text-sm text-gray-500"></span>
                                    </div>
                                    <div class="grid grid-cols-2 gap-3 mt-4">
                                        <div class="rounded-xl bg-gray-50 border border-gray-100 px-3 py-2">
                                            <div class="text-xs text-gray-500">访问用户名</div>
                                            <div id="username_\${collection.id}" class="mt-1 text-sm font-medium text-gray-800 truncate">--</div>
                                        </div>
                                        <div class="rounded-xl bg-gray-50 border border-gray-100 px-3 py-2">
                                            <div class="text-xs text-gray-500">节点数量</div>
                                            <div id="nodeCount_\${collection.id}" class="mt-1 text-sm font-medium text-gray-800">0</div>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex items-center space-x-2 shrink-0">
                                    <button onclick="editCollection('\${collection.id}')"
                                        class="p-2 text-gray-400 hover:text-blue-500 transition-colors rounded-lg hover:bg-blue-50"
                                        title="编辑集合">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button onclick="deleteCollection('\${collection.id}')"
                                        class="p-2 text-gray-400 hover:text-red-500 transition-colors rounded-lg hover:bg-red-50"
                                        title="删除集合">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </div>

                            <div>
                                <div class="flex items-center justify-between mb-2">
                                    <h4 class="text-sm font-medium text-gray-700">节点摘要</h4>
                                    <span class="text-xs text-gray-400">最多展示前 5 个</span>
                                </div>
                                <div id="nodeList_\${collection.id}" class="flex flex-wrap gap-2 min-h-[2.25rem]">
                                    <span class="px-2 py-1 rounded-full bg-gray-100 text-gray-400 text-xs">加载中</span>
                                </div>
                            </div>

                            <div class="flex flex-wrap gap-2 pt-4 border-t border-gray-100 mt-auto">
                                <button onclick="universalSubscription('\${collection.id}')"
                                    onmouseenter="showSubscriptionQRCode(event, 'base', '\${collection.id}', '通用订阅')"
                                    onmousemove="moveSubscriptionQRCode(event)"
                                    onmouseleave="hideSubscriptionQRCode()"
                                    class="inline-flex items-center justify-center px-3.5 py-1.5 bg-gray-900 text-white text-sm rounded-lg hover:bg-gray-800 transition-colors min-w-[8rem] shadow-sm">
                                    <i class="fas fa-link mr-1.5"></i>通用订阅
                                </button>
                                <button onclick="singboxSubscription('\${collection.id}')"
                                    onmouseenter="showSubscriptionQRCode(event, 'singbox', '\${collection.id}', 'SingBox 订阅')"
                                    onmousemove="moveSubscriptionQRCode(event)"
                                    onmouseleave="hideSubscriptionQRCode()"
                                    class="inline-flex items-center justify-center px-3 py-1.5 bg-white text-green-700 text-sm rounded-lg border border-green-200 hover:bg-green-50 transition-colors min-w-[7rem]">
                                    <i class="fas fa-box mr-1.5"></i>SingBox订阅
                                </button>
                                <button onclick="clashSubscription('\${collection.id}')"
                                    onmouseenter="showSubscriptionQRCode(event, 'clash', '\${collection.id}', 'Clash 订阅')"
                                    onmousemove="moveSubscriptionQRCode(event)"
                                    onmouseleave="hideSubscriptionQRCode()"
                                    class="inline-flex items-center justify-center px-3 py-1.5 bg-white text-purple-700 text-sm rounded-lg border border-purple-200 hover:bg-purple-50 transition-colors min-w-[6.5rem]">
                                    <i class="fas fa-bolt mr-1.5"></i>Clash订阅
                                </button>
                                <button onclick="shareCollection('\${collection.id}')"
                                    class="inline-flex items-center justify-center px-3 py-1.5 bg-white text-gray-700 text-sm rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors min-w-[5.5rem]">
                                    <i class="fas fa-share-alt mr-1.5"></i>分享
                                </button>
                            </div>
                        </div>
                        </div>
                    </article>
                \`).join('');

                // 更新每个集合的节点列表和有效期
                collections.forEach(collection => {
                    updateCollectionNodes(collection);
                });
            } catch (e) {
                console.error('Error loading collections:', e);
            }
        }

        async function updateCollectionNodes(collection) {
            try {
                const [nodesResponse, tokenResponse] = await Promise.all([
                    fetchWithAuth('/api/nodes'),
                    fetchWithAuth(\`/api/collections/token/\${collection.id}\`)
                ]);
                
                const nodes = await nodesResponse.json();
                const token = await tokenResponse.json();
                const collectionNodes = nodes.filter(node => collection.nodeIds.includes(node.id));
                const usernameElement = document.getElementById(\`username_\${collection.id}\`);
                const nodeCountElement = document.getElementById(\`nodeCount_\${collection.id}\`);
                if (usernameElement) {
                    usernameElement.textContent = token.username || '--';
                }
                if (nodeCountElement) {
                    nodeCountElement.textContent = String(collectionNodes.length);
                }
                
                // 更新有效期显示
                const expiryElement = document.getElementById(\`expiry_\${collection.id}\`);
                if (expiryElement && token.expiry) {
                    const expDate = new Date(token.expiry);
                    const isExpired = expDate < new Date();
                    const isNearExpiry = !isExpired && (expDate - new Date() < 7 * 24 * 60 * 60 * 1000);
                    
                    expiryElement.innerHTML = \`
                        <span class="text-gray-500">
                            (到期：\${expDate.toLocaleDateString('zh-CN', {
                                year: 'numeric',
                                month: 'numeric',
                                day: 'numeric'
                            })})
                        </span>
                        \${isExpired ? \`
                            <span class="ml-1 px-1.5 py-0.5 bg-red-100 text-red-600 text-xs rounded-full">
                                已过期
                            </span>
                        \` : isNearExpiry ? \`
                            <span class="ml-1 px-1.5 py-0.5 bg-yellow-100 text-yellow-600 text-xs rounded-full">
                                即将到期
                            </span>
                        \` : ''}
                    \`;
                }
                
                // 更新节点列表，使用更简洁的样式
                const nodeList = document.getElementById(\`nodeList_\${collection.id}\`);
                if (nodeList) {
                    const previewNodes = collectionNodes.slice(0, 5);
                    const overflow = collectionNodes.length - previewNodes.length;
                    nodeList.innerHTML = previewNodes.map(node => \`
                        <span class="inline-flex items-center px-2.5 py-1 bg-gray-50 text-gray-700 text-xs rounded-full border border-gray-200">
                            <span class="w-1.5 h-1.5 bg-blue-500 rounded-full mr-2"></span>
                            \${node.name}
                        </span>
                    \`).join('') + (overflow > 0 ? \`<span class="inline-flex items-center px-2.5 py-1 bg-gray-100 text-gray-500 text-xs rounded-full">+\${overflow}</span>\` : '') || '<span class="inline-flex items-center px-2.5 py-1 bg-gray-100 text-gray-400 text-xs rounded-full">暂无节点</span>';
                }
            } catch (e) {
                console.error('Error updating collection nodes:', e);
            }
        }

        async function addCollection() {
            const name = document.getElementById('collectionName').value;
            const nodeIds = Array.from(document.querySelectorAll('#nodeSelection input:checked'))
                .map(checkbox => checkbox.value);
            
            if (!name) {
                alert('请输入集合名称');
                return;
            }
            
            if (nodeIds.length === 0) {
                alert('请选择至少一个节点');
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
                alert('创建集合失败');
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
                alert('编辑集合失败');
            }
        }

        async function showCollectionEditDialog(collection, nodes) {
            // 获取前用户令牌信息
            const response = await fetchWithAuth(\`/api/collections/token/\${collection.id}\`);
            let userToken = {};
            if (response.ok) {
                userToken = await response.json();
            }

            // 格式化日期为 YYYY-MM-DD 格式
            const formatDateForInput = (dateString) => {
                if (!dateString) return '';
                const date = new Date(dateString);
                return date.toISOString().split('T')[0];
            };

            const dialog = document.createElement('div');
            dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center';
            dialog.innerHTML = \`
                <div class="bg-white rounded-lg p-6 w-full max-w-2xl space-y-4">
                    <h2 class="text-xl font-bold text-gray-900">编辑集合</h2>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">集合名称</label>
                        <input type="text" id="collectionName" value="\${collection.name}"
                            class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700">访问用户名</label>
                            <input type="text" id="collectionUsername" value="\${userToken.username || ''}"
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                            <p class="mt-1 text-sm text-gray-500">留空将自动生成用户名</p>
                            \${userToken.username ? \`
                                <p class="mt-1 text-sm text-blue-600">当前用户名: \${userToken.username}</p>
                            \` : ''}
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">访问密码</label>
                            <input type="password" id="collectionPassword" value=""
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                            <p class="mt-1 text-sm text-gray-500">Leave blank to keep the current password. Fill this field only when you want to reset it.</p>
                            \${userToken.hasPassword ? \`
                                <p class="mt-1 text-sm text-blue-600">Password is set for this collection.</p>
                            \` : \`
                                <p class="mt-1 text-sm text-gray-500">No password is currently set for this collection.</p>
                            \`}
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700">有效期</label>
                        <input type="date" id="collectionExpiry" 
                            value="\${formatDateForInput(userToken.expiry)}"
                            class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                        <p class="mt-1 text-sm text-gray-500">可选，设置订阅的有效期</p>
                        \${userToken.expiry ? \`
                            <p class="mt-1 text-sm text-blue-600">
                                当前有效期: \${new Date(userToken.expiry).toLocaleDateString()}
                            </p>
                        \` : ''}
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">选择节点</label>
                        <div class="max-h-60 overflow-y-auto bg-gray-50 p-4 rounded-md space-y-2">
                            \${nodes.map(node => \`
                                <label class="flex items-center space-x-2">
                                    <input type="checkbox" value="\${node.id}" 
                                        \${collection.nodeIds?.includes(node.id) ? 'checked' : ''}>
                                    <span>\${node.name}</span>
                                </label>
                            \`).join('')}
                        </div>
                    </div>
                    <div class="flex justify-end space-x-3 mt-6">
                        <button onclick="this.closest('.fixed').remove()"
                            class="px-4 py-2 text-gray-600 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors duration-200">
                            取消
                        </button>
                        <button onclick="updateCollection('\${collection.id}')"
                            class="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors duration-200">
                            保存
                        </button>
                    </div>
                </div>
            \`;
            document.body.appendChild(dialog);
        }

        async function updateCollection(id) {
            // 获取编辑对话框中的所有输入值
            const dialog = document.querySelector('.fixed');
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
            const nodeIds = Array.from(dialog.querySelectorAll('input[type="checkbox"]:checked'))
                .map(checkbox => checkbox.value);
            
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
                    dialog.remove();
                    await loadCollections();
                } else {
                    const error = await response.json();
                    throw new Error(error.error || '更新失败');
                }
            } catch (e) {
                console.error('Update failed:', e);
                alert('更新集合失败: ' + e.message);
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
                <div data-dialog-panel class="bg-white rounded-xl shadow-2xl w-full max-w-3xl overflow-hidden flex flex-col" style="height: min(900px, calc(100vh - 2rem)); max-height: calc(100vh - 2rem);">
                    <div data-dialog-drag-handle class="flex items-center justify-between gap-4 px-6 py-4 border-b border-gray-100 bg-white select-none">
                        <div>
                            <h2 class="text-xl font-bold text-gray-900">编辑集合</h2>
                            <p class="text-sm text-gray-500 mt-1">窗口支持拖动，内容过长时可滚动查看。</p>
                        </div>
                        <button type="button" onclick="closeCollectionEditDialog()" class="text-gray-400 hover:text-gray-600">
                            <i class="fas fa-times text-xl"></i>
                        </button>
                    </div>
                    <div class="p-6 space-y-4 overflow-y-auto flex-1 min-h-0">
                        <div>
                            <label class="block text-sm font-medium text-gray-700">集合名称</label>
                            <input type="text" id="collectionName" value="\${collection.name}"
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                        </div>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700">访问用户名</label>
                                <input type="text" id="collectionUsername" value="\${userToken.username || ''}"
                                    class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                                <p class="mt-1 text-sm text-gray-500">留空将自动生成用户名。</p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">访问密码</label>
                                <input type="password" id="collectionPassword" value=""
                                    class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                                <p class="mt-1 text-sm text-gray-500">留空则保持当前密码不变。</p>
                            </div>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700">有效期</label>
                            <input type="date" id="collectionExpiry" value="\${formatDateForInput(userToken.expiry)}"
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                            <p class="mt-1 text-sm text-gray-500">可选，不填写表示不过期。</p>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-2">选择节点</label>
                            <div class="max-h-72 overflow-y-auto bg-gray-50 p-4 rounded-md space-y-2 border border-gray-100">
                                \${nodes.map(node => \`
                                    <label class="flex items-center space-x-2">
                                        <input type="checkbox" data-node-checkbox value="\${node.id}" \${collection.nodeIds?.includes(node.id) ? 'checked' : ''}>
                                        <span>\${node.name}</span>
                                    </label>
                                \`).join('')}
                            </div>
                        </div>
                    </div>
                    <div class="flex justify-end space-x-3 px-6 py-4 border-t border-gray-100 bg-white shrink-0">
                        <button type="button" onclick="closeCollectionEditDialog()"
                            class="px-4 py-2 text-gray-600 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors duration-200">
                            取消
                        </button>
                        <button type="button" onclick="updateCollection('\${collection.id}')"
                            class="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors duration-200">
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
                alert('更新集合失败: ' + e.message);
            }
        }

        async function deleteCollection(id) {
            if (!confirm('确定要删除这个集合吗？')) return;
            
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
                alert('删除集合失败');
            }
        }

        // 订阅相关函数
        async function shareCollection(id) {
            const shareUrl = \`\${window.location.origin}/api/share/\${id}\`;
            try {
                await navigator.clipboard.writeText(shareUrl);
                showToast('分享链接已复制到剪贴板');
            } catch (e) {
                alert('复制分享链接失败');
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
                <div class="border rounded-lg p-3 transition-colors duration-200 \${template.internalUrl === activeTemplateUrl ? 'border-green-400 bg-green-50' : 'border-gray-200 hover:border-blue-300'}">
                    <div class="flex items-start justify-between gap-3">
                        <div class="min-w-0">
                            <div class="font-medium text-gray-800 truncate">\${template.name}</div>
                            <div class="text-xs text-gray-500 mt-1">更新时间：\${template.updatedAt ? new Date(template.updatedAt).toLocaleString() : '未知'}</div>
                        </div>
                        <button onclick="editTemplate('\${template.id}')" class="text-sm text-blue-600 hover:text-blue-700">编辑</button>
                    </div>
                    <div class="flex flex-wrap gap-2 mt-3 text-xs">
                        <button onclick="activateTemplateById('\${template.id}')" class="px-2 py-1 rounded bg-green-100 text-green-700 hover:bg-green-200">启用</button>
                        <button onclick="copyTemplateUrl('\${template.id}')" class="px-2 py-1 rounded bg-yellow-100 text-yellow-700 hover:bg-yellow-200">复制地址</button>
                    </div>
                </div>
            \`).join('');

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
                alert('加载模板失败');
            }
        }

        async function saveTemplate() {
            const id = document.getElementById('templateId').value.trim();
            const name = document.getElementById('templateName').value.trim();
            const content = document.getElementById('templateContent').value;

            if (!name) {
                alert('请输入模板名称');
                return;
            }

            if (!content.trim()) {
                alert('请输入模板内容');
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
                alert('保存失败：' + error.message);
            }
        }

        async function deleteTemplate() {
            const id = document.getElementById('templateId').value.trim();
            if (!id) {
                alert('请先选择一个已保存的模板');
                return;
            }

            if (!confirm('确定要删除当前模板吗？')) return;

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
                alert('删除失败：' + error.message);
            }
        }

        async function activateTemplateById(id) {
            const template = templates.find(item => item.id === id);
            if (!template) return;
            try {
                await saveActiveTemplateUrl(template.internalUrl);
                showToast('已切换当前模板');
            } catch (error) {
                alert('切换当前模板失败：' + error.message);
            }
        }

        async function useCurrentTemplate() {
            const id = document.getElementById('templateId').value.trim();
            if (!id) {
                alert('请先保存当前模板');
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
                alert('请先选择一个模板');
                return;
            }
            copyTemplateUrl(id);
        }

        function viewCurrentTemplateConfig() {
            const id = document.getElementById('templateId').value.trim();
            const selectedTemplate = id ? templates.find(item => item.id === id) : null;
            const targetUrl = activeTemplateUrl || selectedTemplate?.internalUrl || '';
            if (!targetUrl) {
                alert('请先选择或启用一个模板');
                return;
            }
            window.open(targetUrl, '_blank', 'noopener');
        }

        function loadBuiltInTemplatePreset() {
            const selector = document.getElementById('templatePresetSelector');
            const presetId = selector ? selector.value : '';
            if (!presetId) {
                alert('请先选择一个内置模板');
                return;
            }

            const preset = BUILT_IN_TEMPLATE_PRESETS.find(item => item.id === presetId);
            if (!preset) {
                alert('未找到所选模板预置');
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

            container.innerHTML = rules.map(rule => {
                const clashUrl = (rule.clash && rule.clash.url) || '未配置';
                const singboxUrl = (rule.singbox && rule.singbox.url) || '未配置';
                return '<div class="border rounded-lg p-3 transition-colors duration-200 border-gray-200 hover:border-blue-300">'
                    + '<div class="flex items-start justify-between gap-3">'
                    + '<div class="min-w-0">'
                    + '<div class="font-medium text-gray-800 truncate">' + escapeHtml(rule.name || '') + '</div>'
                    + '<div class="text-xs text-gray-500 mt-1 font-mono">@' + escapeHtml(rule.id || '') + '</div>'
                    + '</div>'
                    + '<button onclick="editRule(' + "'" + escapeHtml(rule.id || '') + "'" + ')" class="text-sm text-blue-600 hover:text-blue-700">编辑</button>'
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
                if (container) {
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
                alert('导入 DustinWin 规则集失败：' + error.message);
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
                alert('加载规则失败');
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
                alert('请填写规则 ID');
                return;
            }

            if (!name) {
                alert('请填写显示名称');
                return;
            }

            if (!clashUrl && !singboxUrl) {
                alert('Clash 和 Sing-box 至少填写一个规则地址');
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
                alert('保存失败：' + error.message);
            }
        }

        async function deleteRule() {
            const id = document.getElementById('ruleIdOriginal').value.trim();
            if (!id) {
                alert('请先选择要删除的规则');
                return;
            }

            if (!confirm('确认删除这条规则吗？')) return;

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
                alert('删除失败：' + error.message);
            }
        }

        function getCurrentRuleReference() {
            const id = document.getElementById('ruleId').value.trim() || document.getElementById('ruleIdOriginal').value.trim();
            return id ? '@' + id : '';
        }

        function copyRuleReference() {
            const ref = getCurrentRuleReference();
            if (!ref) {
                alert('请先填写规则 ID');
                return;
            }
            copyToClipboard(ref, '规则引用已复制');
        }

        function insertRuleReference() {
            const ref = getCurrentRuleReference();
            if (!ref) {
                alert('请先填写规则 ID');
                return;
            }
            const templateContent = document.getElementById('templateContent');
            if (!templateContent) {
                alert('未找到模板编辑器');
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
                alert('未找到模板编辑器');
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
                alert('请先选择一条规则');
                return;
            }
            const rule = rules.find(item => item.id === selector.value);
            if (!rule) {
                alert('未找到选中的规则');
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
                alert('请填写分组名称');
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
                    button.className = 'hidden px-4 py-2 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200';
                    return;
                }
                const active = tab === currentManagementPage;
                button.className = active
                    ? 'px-4 py-2 rounded-lg bg-blue-500 text-white'
                    : 'px-4 py-2 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200';
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

        async function saveSettings() {
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
                alert('保存配置失败：' + error.message);
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

function generateNodeScriptsV2() {
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
                }
            } catch (e) {
                console.error('Error loading nodes:', e);
                alert('加载节点失败');
            }
        }

        function setNodeViewMode(mode) {
            nodeViewMode = mode === 'grouped' ? 'grouped' : 'all';
            const allBtn = document.getElementById('nodeViewMode-all');
            const groupedBtn = document.getElementById('nodeViewMode-grouped');
            if (allBtn) {
                allBtn.className = nodeViewMode === 'all'
                    ? 'px-3 py-2 bg-blue-500 text-white text-sm'
                    : 'px-3 py-2 bg-white text-gray-700 text-sm hover:bg-gray-50';
            }
            if (groupedBtn) {
                groupedBtn.className = nodeViewMode === 'grouped'
                    ? 'px-3 py-2 bg-blue-500 text-white text-sm'
                    : 'px-3 py-2 bg-white text-gray-700 text-sm hover:bg-gray-50';
            }
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
                            ? '<div class="flex items-center justify-between"><h3 class="text-sm font-semibold text-gray-700">' + groupName + '</h3><span class="text-xs text-gray-400">' + uniqueItems.length + ' 个节点</span></div>'
                            : '')
                        + '<div class="grid grid-cols-1 xl:grid-cols-2 gap-4">' + uniqueItems.map((node) => {
                            const tags = node.tags && node.tags.length
                                ? node.tags.map((tag) => '<span class="px-2 py-1 rounded-full bg-blue-50 text-blue-700 text-xs">' + tag + '</span>').join('')
                                : '<span class="px-2 py-1 rounded-full bg-gray-100 text-gray-500 text-xs">未分组</span>';
                            return '<div class="bg-white rounded-lg border border-gray-200 p-4 hover:shadow-md transition-all duration-200">'
                                + '<div class="flex justify-between items-start gap-4">'
                                + '<div class="flex-1 min-w-0">'
                                + '<h3 class="font-medium text-gray-800 flex items-center mb-1"><i class="fas fa-network-wired text-blue-500 mr-2"></i>' + node.name + '</h3>'
                                + '<div class="text-sm text-gray-500 font-mono truncate">' + node.url + '</div>'
                                + '<div class="flex flex-wrap gap-2 mt-3">' + tags + '</div>'
                                + '</div>'
                                + '<div class="flex items-center space-x-2 ml-4">'
                                + '<button onclick="editNode(\\'' + node.id + '\\')" class="p-1.5 text-gray-400 hover:text-blue-500 transition-colors" title="编辑节点"><i class="fas fa-edit"></i></button>'
                                + '<button onclick="copyNode(\\'' + node.id + '\\')" class="p-1.5 text-gray-400 hover:text-blue-500 transition-colors" title="复制链接"><i class="fas fa-copy"></i></button>'
                                + '<button onclick="deleteNode(\\'' + node.id + '\\')" class="p-1.5 text-gray-400 hover:text-red-500 transition-colors" title="删除节点"><i class="fas fa-trash-alt"></i></button>'
                                + '</div>'
                                + '</div>'
                                + '</div>';
                        }).join('')
                        + '</div>'
                        + '</div>'; 
                }).join('')
                : '<div class="bg-gray-50 border border-dashed border-gray-200 rounded-lg p-8 text-center text-gray-400">没有匹配的节点</div>';

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
            const tags = parseNodeTags(document.getElementById('nodeTags')?.value || '');

            if (!name || !url) {
                alert('请填写完整信息');
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
                alert('添加节点失败');
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
            dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
            dialog.innerHTML = \`
                <div class="bg-white rounded-lg shadow-xl p-6 max-w-lg w-full mx-4">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-lg font-semibold text-gray-800">编辑节点</h3>
                        <button onclick="this.closest('.fixed').remove()" class="text-gray-400 hover:text-gray-600">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                            </svg>
                        </button>
                    </div>
                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">节点名称</label>
                            <input type="text" id="editNodeName" value="\${node.name}" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">节点URL</label>
                            <input type="text" id="editNodeUrl" value="\${node.url}" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">节点标签</label>
                            <input type="text" id="editNodeTags" value="\${(node.tags || []).join(', ')}" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent" placeholder="例如：HK, Premium, Test">
                            <p class="mt-1 text-sm text-gray-500">多个标签请用英文逗号分隔。</p>
                        </div>
                    </div>
                    <div class="flex justify-end space-x-3 mt-6">
                        <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 text-gray-600 bg-gray-100 rounded-md hover:bg-gray-200 transition-colors duration-200">取消</button>
                        <button onclick="updateNode('\${node.id}')" class="px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600 transition-colors duration-200">保存</button>
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
                alert('请填写完整信息');
                return;
            }

            try {
                const response = await fetchWithAuth('/api/nodes', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id, name, url, tags })
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
            const node = cachedNodes.find((item) => item.id === id);
            if (node) {
                await navigator.clipboard.writeText(node.url);
                showToast('已复制到剪贴板');
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

        function updateNodeSelection(nodes) {
            const nodeSelection = document.getElementById('nodeSelection');
            if (!nodeSelection) return;

            const filteredNodes = getFilteredNodesForDisplay(nodes.map(normalizeNodeRecord), collectionNodeFilter);

            nodeSelection.innerHTML = filteredNodes.map(node => \`
                <div class="flex items-center space-x-3 p-3 bg-white rounded-lg shadow hover:shadow-md transition-shadow duration-200">
                    <input type="checkbox" id="select_\${node.id}" value="\${node.id}" class="w-4 h-4 text-blue-600 rounded border-gray-300 focus:ring-blue-500">
                    <label for="select_\${node.id}" class="flex-1 min-w-0 text-sm text-gray-700 cursor-pointer">
                        <div class="font-medium truncate">\${node.name}</div>
                        <div class="flex flex-wrap gap-1 mt-1">\${(node.tags && node.tags.length ? node.tags : ['未分组']).map(tag => '<span class="px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 text-xs">' + tag + '</span>').join('')}</div>
                    </label>
                </div>
            \`).join('');

            const selectionControls = document.createElement('div');
            selectionControls.className = 'md:col-span-2 xl:col-span-3 flex justify-end gap-2';
            selectionControls.innerHTML = \`
                <button onclick="selectAllNodes()" class="px-3 py-1 text-sm bg-gray-100 text-gray-600 rounded hover:bg-gray-200 transition-colors duration-200">全选</button>
                <button onclick="deselectAllNodes()" class="px-3 py-1 text-sm bg-gray-100 text-gray-600 rounded hover:bg-gray-200 transition-colors duration-200">取消全选</button>
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
                    button.className = 'hidden px-4 py-2 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200';
                    return;
                }
                const active = tab === currentManagementPage;
                button.className = active
                    ? 'px-4 py-2 rounded-lg bg-blue-500 text-white'
                    : 'px-4 py-2 rounded-lg bg-gray-100 text-gray-700 hover:bg-gray-200';
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
