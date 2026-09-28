//! 浏览器指纹伪装 (gpt-pp-team 反检测 + 现代 Chrome 指纹补全)。
//! 目标: 降低 hCaptcha 风控等级 — 明文轮比例上升 (加密轮=图片资源封锁, 视觉死刑)。
//! 注入点: add_init_script — 每个新 document (含 iframe) 加载前执行。

pub const STEALTH: &str = r#"(() => {
    // 1. webdriver 标记 — 最基础的自动化检测
    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    // 删除 headless UA 泄露 (HeadlessChrome → Chrome)
    try {
        const ua = navigator.userAgent.replace('HeadlessChrome/', 'Chrome/');
        Object.defineProperty(navigator, 'userAgent', { get: () => ua });
        Object.defineProperty(navigator, 'appVersion', { get: () => ua.replace('Mozilla/', '') });
    } catch (e) {}

    // 2. 平台与硬件
    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
    Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
    Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0 });
    Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh', 'en-US', 'en'] });

    // 3. window.chrome 对象 (Chrome 特征, 缺失 = 无头特征)
    if (!window.chrome) {
        window.chrome = { runtime: {}, loadTimes: function(){}, csi: function(){}, app: {isInstalled: false} };
    }

    // 4. permissions 查询伪装 (Notification permission 检测是经典指纹)
    const origQuery = window.Notification && Notification.permission;
    if (navigator.permissions && navigator.permissions.query) {
        const origPermissionsQuery = navigator.permissions.query.bind(navigator.permissions);
        navigator.permissions.query = (p) => {
            if (p.name === 'notifications') {
                return Promise.resolve({ state: Notification.permission, onchange: null });
            }
            return origPermissionsQuery(p);
        };
    }

    // 5. plugins 伪装 (真实 Chrome 有 5 个)
    Object.defineProperty(navigator, 'plugins', {
        get: () => {
            const arr = [
                { name: 'PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'Chrome PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'Chromium PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'Microsoft Edge PDF Viewer', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
                { name: 'WebKit built-in PDF', filename: 'internal-pdf-viewer', description: 'Portable Document Format' },
            ];
            arr.item = (i) => arr[i] || null;
            arr.namedItem = (n) => arr.find((p) => p.name === n) || null;
            arr.refresh = () => {};
            return arr;
        },
    });

    // 6. WebGL 渲染器伪装 (数据中心 GPU/ swiftshader 是强特征)
    const getParameterPatch = (proto) => {
        if (!proto) return;
        const orig = proto.getParameter;
        proto.getParameter = function(p) {
            // UNMASKED_VENDOR_WEBGL / UNMASKED_RENDERER_WEBGL
            if (p === 37445) return 'Intel Inc.';
            if (p === 37446) return 'Intel(R) UHD Graphics 620';
            return orig.call(this, p);
        };
    };
    try { getParameterPatch(WebGLRenderingContext.prototype); } catch (e) {}
    try { getParameterPatch(WebGL2RenderingContext.prototype); } catch (e) {}

    // 7. screen 分辨率伪装
    Object.defineProperty(screen, 'width', { get: () => 1920 });
    Object.defineProperty(screen, 'height', { get: () => 1080 });
    Object.defineProperty(screen, 'availWidth', { get: () => 1920 });
    Object.defineProperty(screen, 'availHeight', { get: () => 1040 });
    Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
    Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });

    // 8. headless 的 chrome.runtime 深层检测
    if (window.chrome && window.chrome.runtime && !window.chrome.runtime.connect) {
        window.chrome.runtime.connect = function() {};
        window.chrome.runtime.sendMessage = function() {};
    }
})()"#;
