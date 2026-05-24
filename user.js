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
                // Ignore invalid settings payload and leave template unset.
            }
        }
    }

    return '';
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

function generateLoginPage() {
    const html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>&#29992;&#25143;&#30331;&#24405;</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link href="https://unpkg.com/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
            <style>
                :root { --surface:#f9f9f9; --surface-low:#f3f3f3; --surface-card:#fff; --ink:#121212; --ruby-text:#ba1a1a; --ruby-bg:rgba(186,26,26,.12); }
                body { background:#f9f9f9; color:var(--ink); font-family:'Inter',system-ui,sans-serif; }
                .user-shell{max-width:1560px;margin:0 auto}.user-label{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#6b7280}.user-card{background:var(--surface-card);border:1px solid rgba(198,198,198,.4);border-radius:4px}.user-button{display:inline-flex;align-items:center;justify-content:center;gap:10px;min-height:42px;padding:0 16px;border-radius:4px;border:1px solid rgba(198,198,198,.6);background:#fff;color:var(--ink);font-weight:700;transition:all .16s ease}.user-button:hover{background:var(--surface-low)}.user-button-dark{border-color:rgba(104,137,186,.32);background:linear-gradient(180deg,#edf4ff 0%,#dde9fb 100%);color:#29486f}.user-button-dark:hover{background:linear-gradient(180deg,#e5efff 0%,#d4e3fa 100%)}.user-input{width:100%;min-height:46px;border-radius:4px;border:1px solid rgba(198,198,198,.7);background:#fff;padding:0 16px;color:var(--ink);outline:none}.user-input:focus{border-color:#111827;box-shadow:none}.user-error{color:var(--ruby-text);background:var(--ruby-bg);border-radius:4px}
            </style>
        </head>
        <body data-page="login">
            <div class="user-shell min-h-screen px-8 py-8 md:px-10 xl:px-12">
                <header class="mb-6 border-b border-gray-200 pb-4">
                    <div class="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                        <div class="flex items-center gap-4">
                            <div class="flex h-10 w-10 items-center justify-center rounded bg-black text-white"><i class="fas fa-terminal text-xl"></i></div>
                            <div>
                                <div class="user-label mb-1">Subscriber Console</div>
                                <h1 class="text-3xl font-extrabold tracking-tight text-gray-900 md:text-4xl">&#35746;&#38405;&#20013;&#24515;</h1>
                                <p class="mt-1 text-sm text-gray-500">&#30331;&#24405;&#21518;&#21487;&#26597;&#30475;&#24182;&#22797;&#21046;&#24744;&#30340;&#35746;&#38405;&#38142;&#25509;</p>
                            </div>
                        </div>
                        <div class="user-label">Cloudflare Worker / User Access</div>
                    </div>
                </header>
                <div class="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,540px)_minmax(320px,420px)] xl:items-start xl:justify-center">
                    <section class="user-card p-6 md:p-7 xl:sticky xl:top-8">
                        <div class="user-label mb-4">Login Gate</div>
                        <div class="max-w-md">
                            <h2 class="text-3xl font-extrabold tracking-tight text-gray-900">&#29992;&#25143;&#30331;&#24405;</h2>
                            <p class="mt-4 text-sm leading-7 text-gray-500">&#20351;&#29992;&#24744;&#30340;&#38598;&#21512;&#24080;&#21495;&#21487;&#20197;&#33719;&#21462;&#36890;&#29992;&#35746;&#38405;&#12289;Clash &#21644; Sing-box &#38142;&#25509;&#12290;</p>
                        </div>
                        <form id="loginForm" class="mt-8 max-w-md space-y-5">
                            <div><label class="mb-2 block text-sm font-semibold text-gray-700">&#29992;&#25143;&#21517;</label><input type="text" id="username" name="username" required class="user-input" placeholder="Username"></div>
                            <div><label class="mb-2 block text-sm font-semibold text-gray-700">&#23494;&#30721;</label><div class="relative"><input type="password" id="password" name="password" required class="user-input pr-12" placeholder="Password"><button type="button" id="togglePassword" class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-700"><i class="fas fa-eye"></i></button></div></div>
                            <button type="submit" class="user-button user-button-dark w-full md:w-auto md:min-w-[180px]"><i class="fas fa-sign-in-alt"></i><span>&#30331;&#24405;</span></button>
                        </form>
                        <div id="errorMessage" class="user-error mt-4 hidden max-w-md px-4 py-3 text-sm font-medium"><i class="fas fa-exclamation-circle mr-2"></i><span></span></div>
                    </section>
                    <aside class="space-y-4">
                        <section class="user-card p-6">
                            <div class="user-label mb-3">Access Notes</div>
                            <p class="text-sm leading-7 text-gray-500">&#30331;&#24405;&#25104;&#21151;&#21518;&#65292;&#31995;&#32479;&#20250;&#25552;&#20379;&#36890;&#29992;&#35746;&#38405;&#12289;Clash &#19982; Sing-box &#19977;&#31181;&#36755;&#20986;&#65292;&#24182;&#25903;&#25345;&#20108;&#32500;&#30721;&#25195;&#25551;&#19982;&#19968;&#38190;&#22797;&#21046;&#12290;</p>
                        </section>
                        <section class="user-card p-6">
                            <div class="user-label mb-3">Formats</div>
                            <div class="space-y-3 text-sm text-gray-600">
                                <div class="flex items-center justify-between"><span>Base</span><span class="font-mono text-gray-400">/base</span></div>
                                <div class="flex items-center justify-between"><span>Sing-box</span><span class="font-mono text-gray-400">/singbox</span></div>
                                <div class="flex items-center justify-between"><span>Clash</span><span class="font-mono text-gray-400">/clash</span></div>
                            </div>
                        </section>
                        <section class="user-card p-6">
                            <div class="user-label mb-3">Session</div>
                            <p class="text-sm leading-7 text-gray-500">&#25104;&#21151;&#30331;&#24405;&#21518;&#20250;&#29983;&#25104;&#35775;&#38382; Token&#65292;&#21487;&#30452;&#25509;&#29992;&#20110;&#35746;&#38405;&#39029;&#38754;&#36339;&#36716;&#19982;&#38142;&#25509;&#22797;&#21046;&#12290;</p>
                        </section>
                    </aside>
                </div>
            </div>
            <div id="loadingOverlay" class="fixed inset-0 hidden bg-black bg-opacity-40"><div class="flex h-full items-center justify-center"><div class="user-card p-5"><div class="h-8 w-8 animate-spin rounded-full border-4 border-black border-t-transparent"></div></div></div></div>
            <script>
                document.getElementById('togglePassword').onclick = function() { const passwordInput = document.getElementById('password'); const icon = this.querySelector('i'); if (passwordInput.type === 'password') { passwordInput.type = 'text'; icon.classList.remove('fa-eye'); icon.classList.add('fa-eye-slash'); } else { passwordInput.type = 'password'; icon.classList.remove('fa-eye-slash'); icon.classList.add('fa-eye'); } };
                function showError(message) { const errorDiv = document.getElementById('errorMessage'); errorDiv.querySelector('span').textContent = message; errorDiv.classList.remove('hidden'); setTimeout(() => errorDiv.classList.add('hidden'), 3000); }
                function toggleLoading(show) { document.getElementById('loadingOverlay').classList.toggle('hidden', !show); }
                document.getElementById('loginForm').addEventListener('submit', async (e) => { e.preventDefault(); const username = document.getElementById('username').value.trim(); const password = document.getElementById('password').value.trim(); if (!username || !password) { showError('&#35831;&#36755;&#20837;&#29992;&#25143;&#21517;&#21644;&#23494;&#30721;'); return; } try { toggleLoading(true); const response = await fetch('/api/user/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) }); const data = await response.json(); if (data.success) { window.location.href = '/user?token=' + encodeURIComponent(data.sessionToken); } else { showError(data.error || '&#30331;&#24405;&#22833;&#36133;'); } } catch (error) { showError('&#30331;&#24405;&#22833;&#36133;&#65292;&#35831;&#37325;&#35797;'); console.error('Login error:', error); } finally { toggleLoading(false); } });
            </script>
        </body>
        </html>
    `;
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

function generateSecretPage(env, userData, activeTemplateUrl = '') {
    try {
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>&#35746;&#38405;&#20449;&#24687;</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <link href="https://unpkg.com/tailwindcss@2/dist/tailwind.min.css" rel="stylesheet">
                <link rel="preconnect" href="https://fonts.googleapis.com">
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
                <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
                <script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
                <style>
                    :root { --surface:#f9f9f9; --surface-card:#fff; --ink:#121212; }
                    body { background: var(--surface); color: var(--ink); font-family:'Inter',system-ui,sans-serif; }
                    .user-shell{max-width:1680px;margin:0 auto}.user-label{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#6b7280}.user-card{background:var(--surface-card);border:1px solid rgba(198,198,198,.4);border-radius:4px}.user-button{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:38px;padding:0 14px;border-radius:4px;font-size:12px;font-weight:700;transition:all .16s ease}.user-button:hover{filter:brightness(.98);transform:translateY(-1px)}.user-button-base{background:#dbe7fb;color:#29486f}.user-button-singbox{background:#d1fae5;color:#0f5132}.user-button-clash{background:#dbeafe;color:#1d4ed8}.user-button-subtle{background:#f3f4f6;color:#374151}.user-toast{background:rgba(17,17,17,.92);color:#fff;border-radius:4px;padding:10px 14px;font-size:13px;box-shadow:0 4px 32px rgba(0,0,0,.08)}
                </style>
            </head>
            <body data-page="secret">
                <div class="user-shell px-8 py-8 md:px-10 xl:px-12">
                    <header class="mb-6 border-b border-gray-200 pb-4">
                        <div class="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                            <div class="flex items-center gap-4">
                                <div class="flex h-10 w-10 items-center justify-center rounded bg-black text-white"><i class="fas fa-terminal text-xl"></i></div>
                                <div><div class="user-label mb-1">Subscriber Console</div><h1 class="text-3xl font-extrabold tracking-tight text-gray-900 md:text-4xl">&#35746;&#38405;&#20013;&#24515;</h1><p class="mt-1 text-sm text-gray-500">&#31649;&#29702;&#24744;&#30340;&#35746;&#38405;&#38142;&#25509;&#19982;&#23458;&#25143;&#31471;&#36755;&#20986;</p></div>
                            </div>
                            <div class="flex flex-col items-start gap-3 xl:items-end">
                                <div class="flex flex-wrap items-center gap-3">
                                    <div class="user-card px-4 py-2 text-sm text-gray-600"><i class="fas fa-user mr-2"></i>${userData.username}</div>
                                    <div class="user-card px-4 py-2 text-sm text-gray-600"><span class="mr-2 text-gray-400">Collection</span><span class="font-mono text-xs text-gray-500">${userData.collectionId}</span></div>
                                    ${userData.expiry ? `<div class="user-card px-4 py-2 text-sm text-gray-600"><span class="mr-2 text-gray-400">Expiry</span><span class="font-mono text-xs text-gray-500">${new Date(userData.expiry).toLocaleDateString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' })}</span></div>` : ''}
                                </div>
                                <button id="logoutBtn" class="user-button user-button-subtle"><i class="fas fa-sign-out-alt"></i><span>&#30331;&#20986;</span></button>
                            </div>
                        </div>
                    </header>
                    <div class="grid grid-cols-1 gap-8 xl:grid-cols-[minmax(0,1fr)_320px]">
                        <section class="space-y-6">
                            <div class="user-card p-6"><div class="user-label mb-4">Subscription Deck</div><h2 class="text-3xl font-extrabold tracking-tight text-gray-900">&#21487;&#29992;&#35746;&#38405;&#36755;&#20986;</h2><p class="mt-3 max-w-3xl text-sm leading-7 text-gray-500">&#21487;&#30452;&#25509;&#22797;&#21046;&#38142;&#25509;&#25110;&#36890;&#36807;&#20108;&#32500;&#30721;&#25195;&#25551;&#23558;&#35746;&#38405;&#23548;&#20837;&#21040;&#23458;&#25143;&#31471;&#12290;</p></div>
                            <div class="grid grid-cols-1 gap-6 xl:grid-cols-3">
                                <article class="user-card p-5"><div class="user-label mb-3">Base</div><h3 class="text-xl font-extrabold tracking-tight text-gray-900">&#36890;&#29992;&#35746;&#38405;</h3><p class="mt-2 text-sm leading-6 text-gray-500">&#36866;&#29992;&#20110;&#22823;&#22810;&#25968;&#20195;&#29702;&#23458;&#25143;&#31471;&#30340;&#22522;&#30784;&#35746;&#38405;&#36755;&#20986;&#12290;</p><div class="mt-4 flex flex-wrap gap-2"><button onclick="universalSubscription('${userData.collectionId}')" class="user-button user-button-base flex-1"><i class="fas fa-copy"></i><span>&#22797;&#21046;&#38142;&#25509;</span></button><button onclick="showQRCode('base', '${userData.collectionId}')" class="user-button user-button-subtle"><i class="fas fa-qrcode"></i></button></div></article>
                                <article class="user-card p-5"><div class="user-label mb-3">Sing-box</div><h3 class="text-xl font-extrabold tracking-tight text-gray-900">Sing-box</h3><p class="mt-2 text-sm leading-6 text-gray-500">&#20379; Sing-box &#23458;&#25143;&#31471;&#30452;&#25509;&#20351;&#29992;&#30340;&#37197;&#32622;&#35746;&#38405;&#12290;</p><div class="mt-4 flex flex-wrap gap-2"><button onclick="singboxSubscription('${userData.collectionId}')" class="user-button user-button-singbox flex-1"><i class="fas fa-copy"></i><span>&#22797;&#21046;&#38142;&#25509;</span></button><button onclick="showQRCode('singbox', '${userData.collectionId}')" class="user-button user-button-subtle"><i class="fas fa-qrcode"></i></button></div></article>
                                <article class="user-card p-5"><div class="user-label mb-3">Clash</div><h3 class="text-xl font-extrabold tracking-tight text-gray-900">Clash</h3><p class="mt-2 text-sm leading-6 text-gray-500">&#20379; Clash / Mihomo &#23458;&#25143;&#31471;&#20351;&#29992;&#30340;&#35268;&#21017;&#37197;&#32622;&#35746;&#38405;&#12290;</p><div class="mt-4 flex flex-wrap gap-2"><button onclick="clashSubscription('${userData.collectionId}')" class="user-button user-button-clash flex-1"><i class="fas fa-copy"></i><span>&#22797;&#21046;&#38142;&#25509;</span></button><button onclick="showQRCode('clash', '${userData.collectionId}')" class="user-button user-button-subtle"><i class="fas fa-qrcode"></i></button></div></article>
                            </div>
                        </section>
                        <aside class="space-y-6">
                            <section class="user-card p-6"><div class="user-label mb-3">Template</div><p class="text-sm leading-7 text-gray-500">${activeTemplateUrl ? '&#24403;&#21069;&#24050;&#35774;&#20026;&#20869;&#37096;&#27169;&#26495;&#65292;&#38750; Base &#36755;&#20986;&#20250;&#24102;&#19978; template &#21442;&#25968;&#12290;' : '&#24403;&#21069;&#26410;&#35774;&#32622;&#20869;&#37096;&#27169;&#26495;&#65292;Sing-box &#19982; Clash &#36755;&#20986;&#19981;&#20250;&#38468;&#21152; template &#21442;&#25968;&#12290;'}</p>${activeTemplateUrl ? `<div class="mt-4 rounded border border-gray-200 bg-gray-50 px-4 py-3 font-mono text-xs text-gray-500 break-all">${activeTemplateUrl}</div>` : `<div class="mt-4 rounded border border-dashed border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-400">未设置当前模板</div>`}</section>
                        </aside>
                    </div>
                    <div id="toast" class="user-toast fixed bottom-4 right-4 hidden"><div class="flex items-center"><i class="fas fa-check-circle mr-2"></i><span id="toastMessage"></span></div></div>
                </div>
                <div id="qrcodeDialog" class="fixed inset-0 hidden bg-black bg-opacity-40 z-50"><div class="flex h-full items-center justify-center px-4"><div class="user-card w-full max-w-sm p-6"><div class="mb-5 flex items-center justify-between"><h3 class="text-xl font-extrabold tracking-tight text-gray-900"><i class="fas fa-qrcode mr-2"></i>&#35746;&#38405;&#20108;&#32500;&#30721;</h3><button onclick="closeQRCode()" class="text-gray-400 hover:text-gray-700"><i class="fas fa-times text-xl"></i></button></div><div class="rounded border border-gray-200 bg-gray-50 p-6"><div id="qrcode" class="flex min-h-[256px] items-center justify-center"></div></div><p class="mt-4 text-center text-sm text-gray-500">&#25195;&#25551;&#20108;&#32500;&#30721;&#33719;&#21462;&#35746;&#38405;</p></div></div></div>
                <script>
                    const CONFIG = { SUB_WORKER_URL: '${getConfig('SUB_WORKER_URL', env)}', TEMPLATE_URL: '${activeTemplateUrl}', API: ${JSON.stringify(CONFIG.API)}, SUBSCRIPTION: ${JSON.stringify(CONFIG.SUBSCRIPTION)} };
                    function showToast(message, duration = 2000) { const toast = document.getElementById('toast'); document.getElementById('toastMessage').textContent = message; toast.classList.remove('hidden'); setTimeout(() => toast.classList.add('hidden'), duration); }
                    function copyToClipboard(text, message) { navigator.clipboard.writeText(text).then(() => showToast(message)).catch(() => { const input = document.createElement('input'); input.value = text; document.body.appendChild(input); input.select(); document.execCommand('copy'); document.body.removeChild(input); showToast(message); }); }
                    function generateSubscriptionUrl(id, type) { const shareUrl = window.location.origin + CONFIG.API.SHARE + '/' + id; const templateParam = (type !== 'base' && CONFIG.TEMPLATE_URL) ? '&template=' + encodeURIComponent(CONFIG.TEMPLATE_URL) : ''; const typePath = type === 'base' ? CONFIG.SUBSCRIPTION.BASE_PATH : type === 'singbox' ? CONFIG.SUBSCRIPTION.SINGBOX_PATH : type === 'clash' ? CONFIG.SUBSCRIPTION.CLASH_PATH : ''; return CONFIG.SUB_WORKER_URL ? (CONFIG.SUB_WORKER_URL + typePath + '?url=' + encodeURIComponent(shareUrl) + templateParam) : (shareUrl + typePath + '?internal=1' + templateParam); }
                    function universalSubscription(id) { copyToClipboard(generateSubscriptionUrl(id, 'base'), '&#36890;&#29992;&#35746;&#38405;&#38142;&#25509;&#24050;&#22797;&#21046;'); }
                    function singboxSubscription(id) { copyToClipboard(generateSubscriptionUrl(id, 'singbox'), 'Sing-box &#35746;&#38405;&#38142;&#25509;&#24050;&#22797;&#21046;'); }
                    function clashSubscription(id) { copyToClipboard(generateSubscriptionUrl(id, 'clash'), 'Clash &#35746;&#38405;&#38142;&#25509;&#24050;&#22797;&#21046;'); }
                    document.getElementById('logoutBtn').onclick = async function() { try { const token = new URLSearchParams(window.location.search).get('token'); if (token) await fetch('/api/user/logout?token=' + encodeURIComponent(token)); } catch (error) { console.error('Logout error:', error); } finally { window.location.href = '/user'; } };
                    function showQRCode(type, id) { const url = generateSubscriptionUrl(id, type); const dialog = document.getElementById('qrcodeDialog'); const qrcodeDiv = document.getElementById('qrcode'); qrcodeDiv.innerHTML = '<div class="animate-spin rounded-full h-8 w-8 border-4 border-black border-t-transparent"></div>'; setTimeout(() => { qrcodeDiv.innerHTML = ''; new QRCode(qrcodeDiv, { text: url, width: 256, height: 256, colorDark: '#000000', colorLight: '#ffffff', correctLevel: QRCode.CorrectLevel.H }); }, 300); dialog.classList.remove('hidden'); }
                    function closeQRCode() { document.getElementById('qrcodeDialog').classList.add('hidden'); }
                    document.getElementById('qrcodeDialog').addEventListener('click', function(e) { if (e.target === this) closeQRCode(); });
                </script>
            </body>
            </html>
        `;
        return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    } catch (error) {
        return new Response('Error: ' + error.message, { status: 500, headers: { 'Content-Type': 'text/plain' } });
    }
}
