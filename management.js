import { CONFIG, getConfig } from './config.js';

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
        <script>
            // 保存认证信息到 localStorage 和 sessionStorage
            function saveAuth(username, password) {
                const auth = btoa(username + ':' + password);
                try {
                    localStorage.setItem('auth', auth);
                } catch (e) {
                    console.warn('localStorage not available');
                }
                sessionStorage.setItem('auth', auth);
                return auth;
            }

            // 获取认证信息，优先从 sessionStorage 获取
            function getAuth() {
                return sessionStorage.getItem('auth') || localStorage.getItem('auth');
            }

            // 清除所有认证信息
            function clearAuth() {
                try {
                    localStorage.removeItem('auth');
                } catch (e) {
                    console.warn('localStorage not available');
                }
                sessionStorage.removeItem('auth');
            }

            // 显示登录对话框
            function showLoginDialog() {
                const dialog = document.createElement('div');
                dialog.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
                dialog.innerHTML = \`
                    <div class="bg-white rounded-lg p-6 w-full max-w-md">
                        <h2 class="text-xl font-bold mb-4">管理员登录</h2>
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-700">用户名</label>
                                <input type="text" id="username" 
                                    class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">密码</label>
                                <input type="password" id="password" 
                                    class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                            </div>
                            <button onclick="login()"
                                class="w-full px-4 py-2 bg-blue-500 text-white rounded-md hover:bg-blue-600">
                                登录
                            </button>
                        </div>
                    </div>
                \`;
                document.body.appendChild(dialog);

                // 添加回车键登录支持
                const inputs = dialog.querySelectorAll('input');
                inputs.forEach(input => {
                    input.addEventListener('keypress', (e) => {
                        if (e.key === 'Enter') {
                            login();
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
        <header class="bg-white shadow-lg rounded-xl mb-8 backdrop-blur-lg bg-opacity-90">
            <div class="max-w-7xl mx-auto py-6 px-6 sm:px-8">
                <div class="flex justify-between items-center">
                    <div class="flex items-center">
                        <i class="fas fa-server text-blue-500 text-3xl mr-3"></i>
                        <div>
                            <h1 class="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 text-transparent bg-clip-text">
                                节点管理系统
                            </h1>
                            <p class="text-sm text-gray-500 mt-1">Node Management System</p>
                        </div>
                    </div>
                    <div class="flex items-center space-x-4">
                        <div class="flex space-x-2">
                            <button onclick="openUserLogin()"
                                class="inline-flex items-center px-4 py-2 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-yellow-500 hover:bg-yellow-600 transition-all duration-200">
                                <i class="fas fa-user text-white mr-2"></i>用户登录
                            </button>
                        </div>
                        <div class="flex space-x-2">
                            <button onclick="openSubscriber()"
                                class="inline-flex items-center px-4 py-2 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-indigo-500 hover:bg-indigo-600 transition-all duration-200">
                                <i class="fas fa-list text-white mr-2"></i>自选订阅器
                            </button>
                            <button onclick="openQuickSubscriber()"
                                class="inline-flex items-center px-4 py-2 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-green-500 hover:bg-green-600 transition-all duration-200">
                                <i class="fas fa-bolt text-white mr-2"></i>快速订阅器
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
        <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
            <div class="px-4 sm:px-0">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    ${generateNodeManager()}
                    ${generateCollectionManager(CONFIG)}
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
                <a href="${CONFIG.DEFAULT_TEMPLATE_URL}" 
                    target="_blank"
                    class="text-sm text-gray-500 hover:text-gray-700 flex items-center">
                    <span>查看默认订阅配置</span>
                    <svg class="w-4 h-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                            d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                    </svg>
                </a>
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
function generateScripts(env, CONFIG) {
    return `
        <script>
            // 配置常量，直接使用 getConfig 处理的值
            const CONFIG = {
                SUB_WORKER_URL: '${getConfig('SUB_WORKER_URL', env)}',
                TEMPLATE_URL: '${getConfig('DEFAULT_TEMPLATE_URL', env)}',
                SUBSCRIBER_URL: '${getConfig('SUBSCRIBER_URL', env)}',
                QUICK_SUB_URL: '${getConfig('QUICK_SUB_URL', env)}',
                API: ${JSON.stringify(CONFIG.API)}
            };

            // 简化的 fetchWithAuth 函数
            async function fetchWithAuth(url, options = {}) {
                const response = await fetch(url, options);
                if (response.status === 401) {
                    location.reload();
                    throw new Error('Unauthorized');
                }
                return response;
            }

            // 初始化函数
            async function init() {
                try {
                    await Promise.all([loadNodes(), loadCollections()]);
                } catch (e) {
                    console.error('Failed to load data:', e);
                }
            }

            // 启动初始化
            init();

            ${generateNodeScripts()}
            ${generateCollectionScripts()}
            ${generateUtilityScripts(env, CONFIG)}
        </script>
    `;
}

// 生成节点相关脚本
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
        async function loadCollections() {
            try {
                const response = await fetchWithAuth('/api/collections');
                const collections = await response.json();
                console.log('Loaded collections:', collections);
                
                const collectionList = document.getElementById('collectionList');
                collectionList.innerHTML = collections.map(collection => \`
                    <div class="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-all duration-200">
                        <div class="flex flex-col space-y-4">
                            <!-- 集合标题、有效期和操作按钮 -->
                            <div class="flex justify-between items-start">
                                <div class="flex-1">
                                    <div class="flex items-center gap-2">
                                        <h3 class="text-lg font-semibold text-gray-800 flex items-center">
                                            <i class="fas fa-layer-group text-blue-500 mr-2"></i>
                                            \${collection.name}
                                        </h3>
                                        <span id="expiry_\${collection.id}" class="text-sm text-gray-500"></span>
                                    </div>
                                </div>
                                <div class="flex space-x-2">
                                    <button onclick="editCollection('\${collection.id}')"
                                        class="p-1.5 text-gray-400 hover:text-blue-500 transition-colors"
                                        title="编辑集合">
                                        <i class="fas fa-edit"></i>
                                    </button>
                                    <button onclick="deleteCollection('\${collection.id}')"
                                        class="p-1.5 text-gray-400 hover:text-red-500 transition-colors"
                                        title="删除集合">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            </div>

                            <!-- 节点列表 -->
                            <div id="nodeList_\${collection.id}" class="flex flex-wrap gap-2">
                                <!-- 节点列表将通过 updateCollectionNodes 函数更新 -->
                            </div>

                            <!-- 操作按钮组 -->
                            <div class="flex flex-wrap gap-2 pt-4 border-t border-gray-100">
                                <button onclick="shareCollection('\${collection.id}')"
                                    class="inline-flex items-center px-3 py-1.5 bg-blue-500 text-white text-sm rounded-lg hover:bg-blue-600 transition-colors">
                                    <i class="fas fa-share-alt mr-1.5"></i>分享
                                </button>
                                <button onclick="universalSubscription('\${collection.id}')"
                                    class="inline-flex items-center px-3 py-1.5 bg-indigo-500 text-white text-sm rounded-lg hover:bg-indigo-600 transition-colors">
                                    <i class="fas fa-link mr-1.5"></i>通用订阅
                                </button>
                                <button onclick="singboxSubscription('\${collection.id}')"
                                    class="inline-flex items-center px-3 py-1.5 bg-green-500 text-white text-sm rounded-lg hover:bg-green-600 transition-colors">
                                    <i class="fas fa-box mr-1.5"></i>SingBox订阅
                                </button>
                                <button onclick="clashSubscription('\${collection.id}')"
                                    class="inline-flex items-center px-3 py-1.5 bg-purple-500 text-white text-sm rounded-lg hover:bg-purple-600 transition-colors">
                                    <i class="fas fa-bolt mr-1.5"></i>Clash订阅
                                </button>
                            </div>
                        </div>
                    </div>
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
                    nodeList.innerHTML = collectionNodes.map(node => \`
                        <span class="inline-flex items-center px-3 py-1 bg-gray-50 text-gray-700 text-sm rounded-lg">
                            <span class="w-1.5 h-1.5 bg-red-500 rounded-full mr-2"></span>
                            \${node.name}
                        </span>
                    \`).join('');
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
                            <input type="text" id="collectionPassword" value=""
                                class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md">
                            <p class="mt-1 text-sm text-gray-500">设置后需要密码才能访问此集合</p>
                            \${userToken.password ? \`
                                <p class="mt-1 text-sm text-blue-600">当前密码: \${userToken.password}</p>
                            \` : ''}
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
                \`\${CONFIG.SUB_WORKER_URL}/a?url=\${encodeURIComponent(shareUrl)}\` :
                \`\${shareUrl}/a?internal=1\`;
            copyToClipboard(subUrl, '通用订阅链接已复制到剪贴板');
        }

        function singboxSubscription(id) {
            const shareUrl = \`\${window.location.origin}/api/share/\${id}\`;
            const templateParam = window.location.search ? 
                \`&template=\${encodeURIComponent(new URLSearchParams(window.location.search).get('template'))}\` : '';
            const subUrl = CONFIG.SUB_WORKER_URL ? 
                \`\${CONFIG.SUB_WORKER_URL}/singbox?url=\${encodeURIComponent(shareUrl)}\${templateParam}\` :
                \`\${shareUrl}/singbox?internal=1\`;
            copyToClipboard(subUrl, 'SingBox订阅链接已复制到剪贴板');
        }

        function clashSubscription(id) {
            const shareUrl = \`\${window.location.origin}/api/share/\${id}\`;
            const templateParam = window.location.search ? 
                \`&template=\${encodeURIComponent(new URLSearchParams(window.location.search).get('template'))}\` : '';
            const subUrl = CONFIG.SUB_WORKER_URL ? 
                \`\${CONFIG.SUB_WORKER_URL}/clash?url=\${encodeURIComponent(shareUrl)}\${templateParam}\` :
                \`\${shareUrl}/clash?internal=1\`;
            copyToClipboard(subUrl, 'Clash订阅链接已复制到剪贴板');
        }
    `;
}

// 生成工具函数脚本
function generateUtilityScripts(env, CONFIG) {
    return `
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