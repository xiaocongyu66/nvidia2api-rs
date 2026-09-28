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

    // 9. WebRTC 真实 IP 泄漏封锁 — 走代理时本机 IP 仍经 ICE candidate 暴露给 hCaptcha
    //    (mDNS candidate 封锁 + RTCPeerConnection 出口校验)
    try {
        const OrigPC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
        if (OrigPC) {
            const PatchedPC = function(cfg, ...rest) {
                const c = Object.assign({}, cfg || {});
                c.iceServers = []; // 禁 STUN — 只留 host candidate
                const pc = new OrigPC(c, ...rest);
                const origLS = pc.getLocalStreams ? pc.getLocalStreams.bind(pc) : undefined;
                pc.addEventListener('icecandidate', (e) => {
                    if (e.candidate && e.candidate.candidate && e.candidate.candidate.indexOf('typ srflx') >= 0) {
                        // srflx (服务器反射=真实公网IP) 候选直接丢弃
                        e.stopImmediatePropagation ? e.stopImmediatePropagation() : null;
                    }
                });
                return pc;
            };
            PatchedPC.prototype = OrigPC.prototype;
            window.RTCPeerConnection = PatchedPC;
            if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = PatchedPC;
        }
    } catch (e) {}

    // 10. playwright/自动化注入物清除 (每个 document 最先执行)
    try {
        delete Object.getPrototypeOf(navigator).webdriver;
        for (const k of ['__playwright__', '__playwright__binding__', '__pwInitScripts',
                         '__pw_manualGcpProxy', 'playwright', '__nightmare', '_phantom',
                         'callPhantom', 'domAutomation', 'domAutomationController',
                         '__webdriver_evaluate', '__selenium_evaluate', '__driver_evaluate',
                         '__webdriver_unwrapped', '__driver_unwrapped', '_Selenium_IDE_Recorder',
                         '_selenium', 'calledSelenium', '_WEBDRIVER_ELEM_CACHE',
                         'ChromeDriverw', 'driver-hierarchy', 'webdriver-has-inline-script']) {
            try { delete window[k]; } catch (e) {}
            try { delete document[k]; } catch (e) {}
        }
    } catch (e) {}

    // 11. Runtime.enable 检测污染 — hCaptcha 用 console.debug 对象副作用计数检测 CDP
    try {
        const origDebug = console.debug;
        console.debug = function(...args) {
            // 屏蔽检测探针 (hCaptcha 传特殊对象并数响应), 其余放行
            return undefined;
        };
        console.debug.toString = () => 'function debug() { [native code] }';
    } catch (e) {}

    // 12. AudioContext 指纹加噪 (静态降噪环境会被 fingerprintjs 命中)
    try {
        const OrigAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (OrigAC) {
            const origGetChannelData = OrigAC.prototype.getChannelData;
            OrigAC.prototype.getChannelData = function(...args) {
                const data = origGetChannelData.apply(this, args);
                if (data && data.length > 0 && !this.__noised) {
                    this.__noised = true;
                    for (let i = 0; i < data.length; i += 450) {
                        data[i] += (Math.random() - 0.5) * 1e-7;
                    }
                }
                return data;
            };
        }
    } catch (e) {}

    // 13. iframe contentWindow 一致性 (webdriver 在 frame 里泄漏)
    try {
        const origContentWindowGetter = Object.getOwnPropertyDescriptor(window, 'contentWindow');
        // HTMLIFrameElement.contentWindow 返回的 window 的 navigator.webdriver 已由第 1 层覆盖
        // (init script 对每个 document 生效, 包括同源/异源 frame 的主世界) — 无需额外处理
        void origContentWindowGetter;
    } catch (e) {}
})()"#;
