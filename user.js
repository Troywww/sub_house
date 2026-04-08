import { CONFIG, getConfig } from './config.js';

async function resolveActiveTemplateUrl(env) {
    if (env?.NODE_STORE) {
        const raw = await env.NODE_STORE.get(CONFIG.APP_SETTINGS_KEY);
        if (raw) {
            try {
                const settings = JSON.parse(raw) || {};
                if (settings.activeTemplateUrl) {
                    return settings.activeTemplateUrl;
                }
            } catch {
                // Ignore invalid settings payload and fall back to environment defaults.
            }
        }
    }

    return getConfig('DEFAULT_TEMPLATE_URL', env);
}

export async function generateUserPage(env, pageType = 'login', userData = null) {
    switch (pageType) {
        case 'login':
            return generateLoginPage();
        case 'secret':
            return generateSecretPage(env, userData, await resolveActiveTemplateUrl(env));
        default:
            return new Response('Not Found', { status: 404 });
    }
}

// 生成登录页面
function generateLoginPage() {
    const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>用户登录</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://unpkg.com/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        </head>
        <body class="bg-gradient-to-br from-blue-500 to-purple-600 min-h-screen flex items-center justify-center" data-page="login">
            <div class="max-w-md w-full mx-4">
                <!-- 登录卡片 -->
                <div class="bg-white rounded-lg shadow-2xl p-8 transform transition-all duration-300 hover:scale-105">
                    <!-- 标题部分 -->
                    <div class="text-center mb-8">
                        <div class="inline-block p-4 rounded-full bg-blue-100 mb-4">
                            <i class="fas fa-rocket text-blue-500 text-3xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-gray-800">订阅中心</h1>
                        <p class="text-gray-600 mt-2">请登录以访问您的订阅</p>
                    </div>

                    <!-- 登录表单 -->
                    <form id="loginForm" class="space-y-6">
                        <!-- 用户名输入框 -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                <i class="fas fa-user text-gray-400 mr-2"></i>用户名
                            </label>
                            <input type="text" id="username" name="username" required
                                class="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                                placeholder="请输入用户名">
                        </div>

                        <!-- 密码输入框 -->
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">
                                <i class="fas fa-lock text-gray-400 mr-2"></i>密码
                            </label>
                            <div class="relative">
                                <input type="password" id="password" name="password" required
                                    class="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                                    placeholder="请输入密码">
                                <button type="button" id="togglePassword" 
                                    class="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                        </div>

                        <!-- 登录按钮 -->
                        <button type="submit"
                            class="w-full flex items-center justify-center px-4 py-2 border border-transparent rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors">
                            <i class="fas fa-sign-in-alt mr-2"></i>
                            <span>登录</span>
                        </button>
                    </form>

                    <!-- 错误提示 -->
                    <div id="errorMessage" class="mt-4 text-center text-red-500 hidden">
                        <i class="fas fa-exclamation-circle mr-1"></i>
                        <span></span>
                    </div>
                </div>
            </div>

            <!-- 加载动画 -->
            <div id="loadingOverlay" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center hidden">
                <div class="bg-white rounded-lg p-4">
                    <div class="animate-spin rounded-full h-8 w-8 border-4 border-blue-500 border-t-transparent"></div>
                </div>
            </div>

            <script>
                // 显示/隐藏密码
                document.getElementById('togglePassword').onclick = function() {
                    const passwordInput = document.getElementById('password');
                    const icon = this.querySelector('i');
                    
                    if (passwordInput.type === 'password') {
                        passwordInput.type = 'text';
                        icon.classList.remove('fa-eye');
                        icon.classList.add('fa-eye-slash');
                    } else {
                        passwordInput.type = 'password';
                        icon.classList.remove('fa-eye-slash');
                        icon.classList.add('fa-eye');
                    }
                };

                // 显示错误信息
                function showError(message) {
                    const errorDiv = document.getElementById('errorMessage');
                    errorDiv.querySelector('span').textContent = message;
                    errorDiv.classList.remove('hidden');
                    setTimeout(() => {
                        errorDiv.classList.add('hidden');
                    }, 3000);
                }

                // 显示/隐藏加载动画
                function toggleLoading(show) {
                    document.getElementById('loadingOverlay').classList.toggle('hidden', !show);
                }

                // 登录表单处理
                document.getElementById('loginForm').addEventListener('submit', async (e) => {
                    e.preventDefault();
                    
                    const username = document.getElementById('username').value.trim();
                    const password = document.getElementById('password').value.trim();

                    if (!username || !password) {
                        showError('请输入用户名和密码');
                        return;
                    }

                    try {
                        toggleLoading(true);
                        const response = await fetch('/api/user/login', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ username, password })
                        });

                        const data = await response.json();
                        
                        if (data.success) {
                            window.location.href = '/user?token=' + encodeURIComponent(data.sessionToken);
                        } else {
                            showError(data.error || '登录失败');
                        }
                    } catch (error) {
                        showError('登录失败，请重试');
                        console.error('Login error:', error);
                    } finally {
                        toggleLoading(false);
                    }
                });
            </script>
        </body>
        </html>
    `;

    return new Response(html, {
        headers: { 'Content-Type': 'text/html;charset=utf-8' }
    });
}

function generateSecretPage(env, userData, activeTemplateUrl = '') {
    try {
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>订阅信息</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="https://unpkg.com/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
            </head>
            <body class="bg-gray-100 min-h-screen" data-page="secret">
                <div class="container mx-auto px-4 py-8">
                    <!-- 顶部导航栏 -->
                    <nav class="bg-white shadow-lg rounded-lg mb-8">
                        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                            <div class="flex justify-between h-16">
                                <div class="flex items-center">
                                    <i class="fas fa-rocket text-blue-500 text-2xl mr-2"></i>
                                    <span class="text-xl font-bold">订阅中心</span>
                                </div>
                                <div class="flex items-center">
                                    <span class="text-gray-600 mr-4">
                                        <i class="fas fa-user mr-2"></i>${userData.username}
                                        ${userData.expiry ? `
                                            <span class="text-sm text-gray-500 ml-2">
                                                (到期：${new Date(userData.expiry).toLocaleDateString('zh-CN', {
                                                    year: 'numeric',
                                                    month: 'numeric',
                                                    day: 'numeric'
                                                })})
                                            </span>
                                        ` : ''}
                                    </span>
                                    <button id="logoutBtn" 
                                        class="inline-flex items-center px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600 transition-colors">
                                        <i class="fas fa-sign-out-alt mr-2"></i>登出
                                    </button>
                                </div>
                            </div>
                        </div>
                    </nav>

                    <!-- 订阅卡片 -->
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <!-- 通用订阅 -->
                        <div class="bg-white rounded-lg shadow-lg p-6 transform hover:scale-105 transition-transform duration-200">
                            <div class="flex items-center justify-between mb-4">
                                <h2 class="text-xl font-semibold text-gray-800">
                                    <i class="fas fa-link text-blue-500 mr-2"></i>通用订阅
                                </h2>
                            </div>
                            <p class="text-gray-600 mb-4">适用于大多数代理客户端的通用订阅格式</p>
                            <div class="flex space-x-2">
                                <button onclick="universalSubscription('${userData.collectionId}')"
                                    class="flex-1 flex items-center justify-center px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-all duration-200">
                                    <i class="fas fa-copy mr-2"></i>复制链接
                                </button>
                                <button onclick="showQRCode('base', '${userData.collectionId}')"
                                    class="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 transition-all duration-200">
                                    <i class="fas fa-qrcode"></i>
                                </button>
                            </div>
                        </div>

                        <!-- SingBox 订阅 -->
                        <div class="bg-white rounded-lg shadow-lg p-6 transform hover:scale-105 transition-transform duration-200">
                            <div class="flex items-center justify-between mb-4">
                                <h2 class="text-xl font-semibold text-gray-800">
                                    <i class="fas fa-box text-green-500 mr-2"></i>SingBox
                                </h2>
                            </div>
                            <p class="text-gray-600 mb-4">专用于 SingBox 客户端的配置订阅</p>
                            <div class="flex space-x-2">
                                <button onclick="singboxSubscription('${userData.collectionId}')"
                                    class="flex-1 flex items-center justify-center px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 transition-all duration-200">
                                    <i class="fas fa-copy mr-2"></i>复制链接
                                </button>
                                <button onclick="showQRCode('singbox', '${userData.collectionId}')"
                                    class="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 transition-all duration-200">
                                    <i class="fas fa-qrcode"></i>
                                </button>
                            </div>
                        </div>

                        <!-- Clash 订阅 -->
                        <div class="bg-white rounded-lg shadow-lg p-6 transform hover:scale-105 transition-transform duration-200">
                            <div class="flex items-center justify-between mb-4">
                                <h2 class="text-xl font-semibold text-gray-800">
                                    <i class="fas fa-bolt text-purple-500 mr-2"></i>Clash
                                </h2>
                            </div>
                            <p class="text-gray-600 mb-4">专用于 Clash 客户端的配置订阅</p>
                            <div class="flex space-x-2">
                                <button onclick="clashSubscription('${userData.collectionId}')"
                                    class="flex-1 flex items-center justify-center px-4 py-2 bg-purple-500 text-white rounded hover:bg-purple-600 transition-all duration-200">
                                    <i class="fas fa-copy mr-2"></i>复制链接
                                </button>
                                <button onclick="showQRCode('clash', '${userData.collectionId}')"
                                    class="px-4 py-2 bg-purple-500 text-white rounded hover:bg-purple-600 transition-all duration-200">
                                    <i class="fas fa-qrcode"></i>
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- 提示框 -->
                    <div id="toast" class="fixed bottom-4 right-4 bg-gray-800 text-white px-6 py-3 rounded-lg shadow-lg hidden transform transition-transform duration-300">
                        <div class="flex items-center">
                            <i class="fas fa-check-circle mr-2"></i>
                            <span id="toastMessage"></span>
                        </div>
                    </div>
                </div>

                <!-- 添加二维码对话框 -->
                <div id="qrcodeDialog" class="fixed inset-0 bg-black bg-opacity-50 hidden flex items-center justify-center z-50">
                    <div class="bg-white rounded-xl shadow-2xl p-6 max-w-sm w-full mx-4">
                        <div class="flex justify-between items-center mb-6">
                            <h3 class="text-xl font-semibold text-gray-800">
                                <i class="fas fa-qrcode text-blue-500 mr-2"></i>
                                订阅二维码
                            </h3>
                            <button onclick="closeQRCode()" class="text-gray-400 hover:text-gray-600">
                                <i class="fas fa-times text-xl"></i>
                            </button>
                        </div>
                        <div class="bg-gray-50 p-6 rounded-lg">
                            <div id="qrcode" class="flex justify-center items-center min-h-[256px]"></div>
                        </div>
                        <div class="mt-6 text-center text-sm text-gray-500">
                            <p>扫描二维码获取订阅</p>
                        </div>
                    </div>
                </div>

                <script>
                    // 配置常量，直接使用 getConfig 处理的值
                    const CONFIG = {
                        SUB_WORKER_URL: '${getConfig('SUB_WORKER_URL', env)}',
                        TEMPLATE_URL: '${activeTemplateUrl}',
                        API: ${JSON.stringify(CONFIG.API)},
                        SUBSCRIPTION: ${JSON.stringify(CONFIG.SUBSCRIPTION)}
                    };

                    // 显示提示框
                    function showToast(message, duration = 2000) {
                        const toast = document.getElementById('toast');
                        const toastMessage = document.getElementById('toastMessage');
                        toastMessage.textContent = message;
                        
                        toast.classList.remove('hidden');
                        toast.classList.add('translate-y-0');
                        
                        setTimeout(() => {
                            toast.classList.add('translate-y-full');
                            setTimeout(() => {
                                toast.classList.add('hidden');
                                toast.classList.remove('translate-y-full');
                            }, 300);
                        }, duration);
                    }

                    // 复制到剪贴板
                    function copyToClipboard(text, message) {
                        navigator.clipboard.writeText(text).then(() => {
                            showToast(message);
                        }).catch(() => {
                            const input = document.createElement('input');
                            input.value = text;
                            document.body.appendChild(input);
                            input.select();
                            document.execCommand('copy');
                            document.body.removeChild(input);
                            showToast(message);
                        });
                    }

                    // 生成订阅链接
                    function generateSubscriptionUrl(id, type) {
                        const shareUrl = window.location.origin + CONFIG.API.SHARE + '/' + id;
                        
                        // 只在非 base 类型时添加 template 参数，且只在有模板 URL 时添加
                        const templateParam = (type !== 'base' && CONFIG.TEMPLATE_URL) ? 
                            '&template=' + encodeURIComponent(CONFIG.TEMPLATE_URL) : '';
                        
                        // 根据型获取订阅路径
                        const typePath = type === 'base' ? CONFIG.SUBSCRIPTION.BASE_PATH :
                                       type === 'singbox' ? CONFIG.SUBSCRIPTION.SINGBOX_PATH :
                                       type === 'clash' ? CONFIG.SUBSCRIPTION.CLASH_PATH : '';
                        
                        if (CONFIG.SUB_WORKER_URL) {
                            return \`\${CONFIG.SUB_WORKER_URL}\${typePath}?url=\${encodeURIComponent(shareUrl)}\${templateParam}\`;
                        } else {
                            return \`\${shareUrl}\${typePath}?internal=1\${templateParam}\`;
                        }
                    }

                    // 订阅链接处理函数
                    function universalSubscription(id) {
                        const subUrl = generateSubscriptionUrl(id, 'base');
                        copyToClipboard(subUrl, '通用订阅链接已复制');
                    }

                    function singboxSubscription(id) {
                        const subUrl = generateSubscriptionUrl(id, 'singbox');
                        copyToClipboard(subUrl, 'SingBox订阅链接已复制');
                    }

                    function clashSubscription(id) {
                        const subUrl = generateSubscriptionUrl(id, 'clash');
                        copyToClipboard(subUrl, 'Clash订阅链接已复制');
                    }

                    // 登出功能
                    document.getElementById('logoutBtn').onclick = async function() {
                        try {
                            const token = new URLSearchParams(window.location.search).get('token');
                            if (token) {
                                await fetch('/api/user/logout?token=' + encodeURIComponent(token));
                            }
                        } catch (error) {
                            console.error('Logout error:', error);
                        } finally {
                            window.location.href = '/user';
                        }
                    };

                    // 显示二维码对话框
                    function showQRCode(type, id) {
                        const url = generateSubscriptionUrl(id, type);
                        const dialog = document.getElementById('qrcodeDialog');
                        const qrcodeDiv = document.getElementById('qrcode');
                        
                        // 清除旧的二维码
                        qrcodeDiv.innerHTML = '';
                        
                        // 显示加载动画
                        qrcodeDiv.innerHTML = '<div class="animate-spin rounded-full h-8 w-8 border-4 border-blue-500 border-t-transparent"></div>';
                        
                        // 生成新的二维码
                        setTimeout(function() {
                            qrcodeDiv.innerHTML = '';
                            new QRCode(qrcodeDiv, {
                                text: url,
                                width: 256,
                                height: 256,
                                colorDark: "#000000",
                                colorLight: "#ffffff",
                                correctLevel: QRCode.CorrectLevel.H
                            });
                        }, 300);
                        
                        // 显示对话框
                        dialog.classList.remove('hidden');
                    }

                    // 修改关闭函数
                    function closeQRCode() {
                        const dialog = document.getElementById('qrcodeDialog');
                        dialog.classList.add('hidden');
                    }

                    // 点击背景关闭
                    document.getElementById('qrcodeDialog').addEventListener('click', function(e) {
                        if (e.target === this) {
                            closeQRCode();
                        }
                    });
                </script>
            </body>
            </html>
        `;

        return new Response(html, {
            headers: { 'Content-Type': 'text/html;charset=utf-8' }
        });
    } catch (error) {
        return new Response('Error: ' + error.message, { 
            status: 500,
            headers: { 'Content-Type': 'text/plain' }
        });
    }
}
