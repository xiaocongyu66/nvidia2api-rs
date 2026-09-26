//! nvidia2api-rs 管理台 — NVIDIA 绿信号风格: 深底面板 + 竞速 Winner 视角。
use dioxus::prelude::*;
use lumen_blocks::components::button::{Button, ButtonVariant};
use lumen_blocks::components::input::Input;
use lumen_blocks::components::switch::Switch;
use lucide_dioxus::{
    Gauge, KeyRound, ArrowLeftRight, Layers, Boxes, KeySquare, ScrollText,
    Settings as CogIcon, UserPlus, Activity, Trash2, Globe, Upload, RefreshCw,
    Rocket, Save, LogIn, LogOut, Zap,
};
use serde_json::Value;
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = localStorage)]
    fn getItem(key: &str) -> Option<String>;
    #[wasm_bindgen(js_namespace = localStorage)]
    fn setItem(key: &str, val: &str);
    #[wasm_bindgen(js_namespace = localStorage)]
    fn removeItem(key: &str);
}

fn token() -> String {
    getItem("nv_admin_token").unwrap_or_default()
}

fn set_token(t: &str) {
    if t.is_empty() {
        removeItem("nv_admin_token");
    } else {
        setItem("nv_admin_token", t);
    }
}

async fn api_get(path: &str) -> Result<Value, String> {
    let resp = gloo_net::http::Request::get(path)
        .header("authorization", &format!("Bearer {}", token()))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let text = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("{} | {text}", e))
}

async fn api_send(method: &'static str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let m = gloo_net::http::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    let req = gloo_net::http::RequestBuilder::new(path)
        .method(m)
        .header("authorization", &format!("Bearer {}", token()))
        .header("content-type", "application/json");
    let req = match &body {
        Some(b) => req.body(b.to_string()).map_err(|e| e.to_string())?,
        None => req.build().map_err(|e| e.to_string())?,
    };
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let text = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("{e} | {text}"))
}

fn trim_text(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or("").to_string()
}

// ---------------------------------------------------------------------------
// 路由
// ---------------------------------------------------------------------------

#[derive(Clone, Routable, Debug, PartialEq)]
enum Route {
    #[layout(ConsoleLayout)]
    #[route("/")]
    Overview {},
    #[route("/keys")]
    Keys {},
    #[route("/proxies")]
    Proxies {},
    #[route("/groups")]
    Groups {},
    #[route("/models")]
    Models {},
    #[route("/ukeys")]
    UKeys {},
    #[route("/logs")]
    Logs {},
    #[route("/settings")]
    Settings {},
    #[route("/register")]
    Register {},
}

#[component]
fn App() -> Element {
    rsx! { Router::<Route> {} }
}

// ---------------------------------------------------------------------------
// 壳层: 登录闸门 + 顶部导航
// ---------------------------------------------------------------------------

async fn login_request(username: String, password: String) -> Result<String, String> {
    match api_send("POST", "/api/admin/login",
        Some(serde_json::json!({"username": username, "password": password}))).await {
        Ok(v) => {
            let t = trim_text(&v, "token");
            if t.is_empty() { Err("登录失败".into()) } else { Ok(t) }
        }
        Err(e) => Err(e),
    }
}

#[component]
fn ConsoleLayout() -> Element {
    let mut authed = use_signal(|| !token().is_empty());
    let mut username = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut login_err = use_signal(String::new);

    if !authed() {
        rsx! {
            div { class: "flex min-h-screen items-center justify-center bg-paper text-ink",
                div { class: "login-card",
                    div { class: "mb-5 flex items-baseline gap-2",
                        span { class: "text-lg font-semibold tracking-tight", "nvidia2api" }
                        span { class: "text-xs text-ink/55", "多账号调度网关" }
                    }
                    Input { placeholder: "用户名", class: "mb-2.5 h-9 rounded-sm border border-line bg-paper px-3 text-sm text-ink focus:border-ink focus:outline-none".to_string(), value: "{username()}", on_input: move |e: dioxus::prelude::FormEvent| username.set(e.value()) }
                    Input { input_type: "password", placeholder: "密码", class: "mb-4 h-9 rounded-sm border border-line bg-paper px-3 text-sm text-ink focus:border-ink focus:outline-none".to_string(), value: "{password()}", on_input: move |e: dioxus::prelude::FormEvent| password.set(e.value()) }
                    if !login_err().is_empty() {
                        div { class: "mb-3 rounded-sm border border-down/40 bg-down/10 px-3 py-2 text-xs text-down", {login_err()} }
                    }
                    Button { variant: ButtonVariant::Primary, full_width: true, class: "h-9 rounded-sm text-sm",
                        on_click: move |_| {
                            let u = username();
                            let pw = password();
                            spawn(async move {
                                match login_request(u, pw).await {
                                    Ok(t) => { set_token(&t); login_err.set(String::new()); authed.set(true); }
                                    Err(e) => login_err.set(e),
                                }
                            });
                        },
                        "登 录"
                    }
                }
            }
        }
    } else {
        rsx! {
            div { class: "min-h-screen bg-paper text-ink",
                header { class: "sticky top-0 z-30 border-b-2 border-ink bg-paper",
                    div { class: "mx-auto flex w-full max-w-[1120px] flex-wrap items-center gap-x-6 gap-y-2 px-6 py-3 sm:px-10",
                        div { class: "flex items-baseline gap-2",
                            span { class: "text-lg font-semibold tracking-tight", "nvidia2api" }
                            span { class: "text-xs text-ink/55", "race · schedule · win" }
                        }
                        nav { class: "flex flex-wrap items-center gap-1",
                            NavTab { to: Route::Overview {}, label: "概览" }
                            NavTab { to: Route::Keys {}, label: "NVIDIA Keys" }
                            NavTab { to: Route::Proxies {}, label: "代理池" }
                            NavTab { to: Route::Groups {}, label: "分组" }
                            NavTab { to: Route::Models {}, label: "模型" }
                            NavTab { to: Route::UKeys {}, label: "API Key" }
                            NavTab { to: Route::Register {}, label: "注册机" }
                            NavTab { to: Route::Logs {}, label: "日志" }
                            NavTab { to: Route::Settings {}, label: "设置" }
                        }
                        div { class: "ml-auto flex items-center gap-2",
                            span { class: "h-2 w-2 rounded-full bg-alive" }
                            button {
                                class: "text-xs text-ink/55 transition-colors hover:text-ink",
                                onclick: move |_| { set_token(""); authed.set(false); },
                                "退出"
                            }
                        }
                    }
                }
                main { class: "mx-auto w-full max-w-[1120px] px-6 py-8 sm:px-10",
                    Outlet::<Route> {}
                }
            }
        }
    }
}

/// 顶部导航按钮: 大点击区, 激活态墨底反白。
#[component]
fn NavTab(to: Route, label: &'static str) -> Element {
    let active = use_route::<Route>() == to;
    let cls = if active {
        "flex h-9 items-center rounded-sm bg-ink px-4 text-sm font-medium text-paper"
    } else {
        "flex h-9 items-center rounded-sm px-4 text-sm text-ink/60 transition-colors hover:bg-ink/[0.07] hover:text-ink"
    };
    rsx! {
        Link { to, class: cls, {label} }
    }
}

#[component]
fn PageHead(title: String, desc: String) -> Element {
    rsx! {
        header { class: "mb-5 border-t-2 border-ink pt-3",
            h2 { class: "text-sm font-semibold tracking-tight", {title} }
            p { class: "mt-0.5 text-xs text-ink/45", {desc} }
        }
    }
}

#[component]
fn Tag(status: String) -> Element {
    let cls = match status.as_str() {
        "available" | "healthy" | "success" | "enabled" => "badge badge-ok",
        "invalid" | "unhealthy" | "error" | "disabled" => "badge badge-bad",
        "rate_limited" | "cooling" => "badge badge-warn",
        _ => "badge badge-idle",
    };
    rsx! {
        span { class: cls, {status} }
    }
}

#[component]
fn ErrBox(msg: String) -> Element {
    if msg.is_empty() {
        rsx! {}
    } else {
        rsx! { div { class: "mb-3 rounded-sm border border-down/40 bg-down/10 px-3 py-2 text-sm text-down", {msg} } }
    }
}

fn num_i64(v: &Value, key: &str) -> i64 {
    v[key].as_i64().unwrap_or(0)
}
fn num_f64(v: &Value, key: &str) -> f64 {
    v[key].as_f64().unwrap_or(0.0)
}

// ---------------------------------------------------------------------------
// 概览
// ---------------------------------------------------------------------------

#[component]
fn Overview() -> Element {
    let mut data: Signal<Option<Value>> = use_signal(|| None);
    let mut usage: Signal<Option<Value>> = use_signal(|| None);
    let mut err = use_signal(String::new);
    let mut tick = use_signal(|| 0u64);

    use_future(move || async move {
        let _ = tick();
        if let Ok(v) = api_get("/api/admin/dashboard").await {
            data.set(Some(v));
        } else {
            err.set("dashboard 无响应".into());
        }
        if let Ok(v) = api_get("/api/admin/dashboard/usage").await {
            usage.set(Some(v));
        }
    });

    rsx! {
        PageHead { title: "概览".to_string(), desc: "Key 池 / 代理 / 模型 / 请求量实时状态".to_string() }
        ErrBox { msg: err() }
        match data() {
            Some(v) => rsx! {
                div { class: "mb-4 grid grid-cols-2 gap-3 md:grid-cols-4",
                    StatCard { label: "Keys 可用", value: format!("{}/{}", num_i64(&v["keys"], "available"), num_i64(&v["keys"], "total")) }
                    StatCard { label: "代理启用", value: format!("{}/{} (健康 {})", num_i64(&v["proxies"], "enabled"), num_i64(&v["proxies"], "total"), num_i64(&v["proxies"], "healthy")) }
                    StatCard { label: "启用模型", value: format!("{}/{}", num_i64(&v["models"], "enabled"), num_i64(&v["models"], "total")) }
                    StatCard { label: "24h 成功率", value: format!("{:.1}%", num_f64(&v["requests_24h"], "success_rate")) }
                }
                div { class: "card card-hover",
                    div { class: "mb-2 text-sm font-semibold", "24h 请求" }
                    div { class: "flex flex-wrap gap-x-6 gap-y-1 text-sm text-ink/55",
                        span { "总量 " b { class: "text-ink", {format!("{}", num_i64(&v["requests_24h"], "total"))} } }
                        span { "成功 " b { class: "text-alive", {format!("{}", num_i64(&v["requests_24h"], "success"))} } }
                        span { "平均延迟 " b { class: "text-alive", {format!("{:.0}ms", num_f64(&v["requests_24h"], "avg_latency_ms"))} } }
                        span { "API Keys " b { class: "text-ink", {format!("{}", num_i64(&v["api_keys"], "total"))} } }
                    }
                }
                if let Some(u) = usage() {
                    div { class: "mt-4 card",
                        div { class: "mb-2 text-sm font-semibold", "14 天用量" }
                        table { class: "w-full text-sm",
                            thead { tr { class: "text-left text-xs text-ink/55",
                                th {"日期" } th {"总量" }
                                th {"成功" } th {"平均延迟" }
                            } }
                            tbody { for day in u["days"].as_array().cloned().unwrap_or_default() {
                                tr {
                                    td {{trim_text(&day, "date")} }
                                    td {{format!("{}", num_i64(&day, "total"))} }
                                    td { class: "py-1.5 pr-4 text-alive", {format!("{}", num_i64(&day, "success"))} }
                                    td { class: "py-1.5", {format!("{:.0}ms", num_f64(&day, "avg_latency_ms"))} }
                                }
                            } }
                        }
                    }
                }
                div { class: "mt-4 text-xs text-ink/55",
                    button {
                        class: "rounded border border-line px-3 py-1.5 hover:text-ink",
                        onclick: move |_| tick.set(tick() + 1),
                        "刷新"
                    }
                }
            },
            None => rsx! { div { class: "text-ink/55", "加载中…" } },
        }
    }
}

#[component]
fn StatCard(label: String, value: String) -> Element {
    rsx! {
        div { class: "card text-center",
            b { class: "block text-2xl text-alive", {value} }
            span { class: "text-xs text-ink/55", {label} }
        }
    }
}

// ---------------------------------------------------------------------------
// NVIDIA Keys
// ---------------------------------------------------------------------------

#[component]
fn Keys() -> Element {
    let mut items: Signal<Vec<Value>> = use_signal(Vec::new);
    let mut err = use_signal(String::new);
    let mut msg = use_signal(String::new);
    let mut import_text = use_signal(String::new);
    let mut tick = use_signal(|| 0u64);

    use_future(move || async move {
        let _ = tick();
        match api_get("/api/admin/nvidia-keys").await {
            Ok(v) => {
                items.set(v["items"].as_array().cloned().unwrap_or_default());
                err.set(String::new());
            }
            Err(e) => err.set(e),
        }
    });

    let items_snapshot: Vec<Value> = items();

    rsx! {
        PageHead { title: "NVIDIA Keys".to_string(), desc: "Key 池: 导入 nvapi- Key, 每账号独立 RPM / 冷却 / 竞速调度".to_string() }
        ErrBox { msg: err() }
        if !msg().is_empty() { div { class: "mb-3 rounded-sm border border-alive/40 bg-alive/10 px-3 py-2 text-sm text-alive", {msg()} } }

        div { class: "mb-4 card",
            div { class: "mb-2 text-sm font-semibold", "批量导入" }
            p { class: "mb-2 text-xs text-ink/55", "每行一个: <code>主账号01---nvapi-xxx</code> 或裸 <code>nvapi-xxx</code>, 自动去重命名" }
            textarea {
                class: "mb-2 w-full rounded border border-line bg-paper p-2 text-xs focus:border-nvgreen focus:outline-none",
                placeholder: "nvapi-xxx\n主号02---nvapi-yyy",
                value: import_text(),
                oninput: move |e| import_text.set(e.value()),
            }
            Button { variant: ButtonVariant::Primary, class: "h-8 rounded-sm text-xs",
                on_click: move |_| {
                    let text = import_text();
                    spawn(async move {
                        match api_send("POST", "/api/admin/nvidia-keys/import", Some(serde_json::json!({"text": text}))).await {
                            Ok(v) => {
                                msg.set(format!("导入成功 {} · 重复 {} · 无效 {}", num_i64(&v, "success"), num_i64(&v, "duplicate"), num_i64(&v, "invalid")));
                                import_text.set(String::new());
                                tick.set(tick() + 1);
                            }
                            Err(e) => err.set(e),
                        }
                    });
                },
                "导入"
            }
        }

        div { class: "table-card card card-hover",
            table { class: "w-full text-sm",
                thead { tr { class: "text-left text-xs text-ink/55",
                    th {"名称" } th {"Key" }
                    th {"状态" } th {"RPM" }
                    th {"成功/失败" } th {"冷却至" }
                    th {"最后错误" } th {"操作" }
                } }
                tbody { for k in items_snapshot.into_iter() {
                    KeyRow { k: k, err: err, msg: msg, tick: tick }
                } }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 代理
// ---------------------------------------------------------------------------

#[component]
fn Proxies() -> Element {
    let mut items: Signal<Vec<Value>> = use_signal(Vec::new);
    let mut err = use_signal(String::new);
    let mut msg = use_signal(String::new);
    let mut import_text = use_signal(String::new);
    let mut checking = use_signal(|| false);
    let mut tick = use_signal(|| 0u64);

    use_future(move || async move {
        let _ = tick();
        match api_get("/api/admin/proxies").await {
            Ok(v) => {
                items.set(v["items"].as_array().cloned().unwrap_or_default());
                err.set(String::new());
            }
            Err(e) => err.set(e),
        }
    });

    let items_snapshot: Vec<Value> = items();

    rsx! {
        PageHead { title: "代理池".to_string(), desc: "SOCKS5/HTTP/HTTPS · 启用上限 = Key数-1 · 每代理与直连竞速".to_string() }
        ErrBox { msg: err() }
        if !msg().is_empty() { div { class: "mb-3 rounded-sm border border-alive/40 bg-alive/10 px-3 py-2 text-sm text-alive", {msg()} } }

        div { class: "mb-4 grid gap-3 md:grid-cols-2",
            div { class: "card card-hover",
                div { class: "mb-2 text-sm font-semibold", "批量导入" }
                textarea {
                    class: "mb-2 w-full rounded border border-line bg-paper p-2 text-xs focus:border-nvgreen focus:outline-none",
                    placeholder: "socks5://user:pass@host:port\nhost:port (默认 socks5)",
                    value: import_text(),
                    oninput: move |e| import_text.set(e.value()),
                }
                Button { variant: ButtonVariant::Primary, class: "h-8 rounded-sm text-xs",
                    on_click: move |_| {
                        let text = import_text();
                        spawn(async move {
                            match api_send("POST", "/api/admin/proxies/import", Some(serde_json::json!({"text": text, "protocol": "socks5"}))).await {
                                Ok(v) => {
                                    msg.set(format!("导入 {} · 重复 {}", num_i64(&v, "success"), num_i64(&v, "duplicate")));
                                    import_text.set(String::new());
                                    tick.set(tick() + 1);
                                }
                                Err(e) => err.set(e),
                            }
                        });
                    },
                    "导入"
                }
            }
            div { class: "card card-hover",
                div { class: "mb-2 text-sm font-semibold", "全量测速" }
                p { class: "mb-3 text-xs text-ink/55", "并发检测延迟 + 公网 IP + 地理位置" }
                button {
                    class: "rounded border border-line px-4 py-1.5 text-sm hover:text-alive disabled:opacity-40",
                    disabled: checking(),
                    onclick: move |_| {
                        checking.set(true);
                        spawn(async move {
                            match api_send("POST", "/api/admin/proxies/check-all", None).await {
                                Ok(v) => { msg.set(format!("测速完成 {} 条", num_i64(&v, "checked"))); checking.set(false); tick.set(tick() + 1); }
                                Err(e) => { err.set(e); checking.set(false); }
                            }
                        });
                    },
                    {if checking() { "测速中…" } else { "开始测速" }}
                }
            }
        }

        div { class: "table-card card card-hover",
            table { class: "w-full text-sm",
                thead { tr { class: "text-left text-xs text-ink/55",
                    th {"名称" } th {"协议" }
                    th {"状态" } th {"延迟" }
                    th {"公网 IP" } th {"位置" }
                    th {"成功/失败" } th {"操作" }
                } }
                tbody { for p in items_snapshot.into_iter() {
                    ProxyRow { p: p, err: err, msg: msg, tick: tick }
                } }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 分组
// ---------------------------------------------------------------------------

#[component]
fn Groups() -> Element {
    let mut items: Signal<Vec<Value>> = use_signal(Vec::new);
    let mut err = use_signal(String::new);
    let mut name = use_signal(String::new);
    let mut country = use_signal(String::new);
    let mut tick = use_signal(|| 0u64);

    use_future(move || async move {
        let _ = tick();
        match api_get("/api/admin/proxy-groups").await {
            Ok(v) => items.set(v["items"].as_array().cloned().unwrap_or_default()),
            Err(e) => err.set(e),
        }
    });

    let items_snapshot: Vec<Value> = items();

    rsx! {
        PageHead { title: "代理分组".to_string(), desc: "按分组管理代理国家/用途".to_string() }
        ErrBox { msg: err() }
        div { class: "mb-4 flex flex-wrap items-center gap-2 card",
            input {
                class: "h-9 w-52 rounded-sm border border-line bg-paper px-3 text-sm text-ink focus:border-ink focus:outline-none",
                placeholder: "分组名 (如: US-住宅)",
                value: name(),
                oninput: move |e| name.set(e.value()),
            }
            input {
                class: "h-9 w-40 rounded-sm border border-line bg-paper px-3 text-sm text-ink focus:border-ink focus:outline-none",
                placeholder: "国家代码 (可选)",
                value: country(),
                oninput: move |e| country.set(e.value()),
            }
            Button { variant: ButtonVariant::Primary, class: "h-8 rounded-sm text-xs",
                on_click: move |_| {
                    let n = name(); let c = country();
                    spawn(async move {
                        match api_send("POST", "/api/admin/proxy-groups", Some(serde_json::json!({"name": n, "country": c}))).await {
                            Ok(_) => { name.set(String::new()); country.set(String::new()); tick.set(tick() + 1); }
                            Err(e) => err.set(e),
                        }
                    });
                },
                "创建"
            }
        }
        div { class: "card card-hover",
            table { class: "w-full text-sm",
                thead { tr { class: "text-left text-xs text-ink/55",
                    th {"名称" } th {"国家" }
                    th {"状态" } th {"操作" }
                } }
                tbody { for g in items_snapshot.into_iter() {
                    GroupRow { g: g, err: err, tick: tick }
                } }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 模型
// ---------------------------------------------------------------------------

#[component]
fn Models() -> Element {
    let mut items: Signal<Vec<Value>> = use_signal(Vec::new);
    let mut err = use_signal(String::new);
    let mut msg = use_signal(String::new);
    let mut syncing = use_signal(|| false);
    let mut tick = use_signal(|| 0u64);

    use_future(move || async move {
        let _ = tick();
        match api_get("/api/admin/models").await {
            Ok(v) => {
                items.set(v["items"].as_array().cloned().unwrap_or_default());
                err.set(String::new());
            }
            Err(e) => err.set(e),
        }
    });

    let items_snapshot: Vec<Value> = items();

    rsx! {
        PageHead { title: "模型".to_string(), desc: "从 NVIDIA 同步模型列表, 仅启用模型对外暴露".to_string() }
        ErrBox { msg: err() }
        if !msg().is_empty() { div { class: "mb-3 rounded-sm border border-alive/40 bg-alive/10 px-3 py-2 text-sm text-alive", {msg()} } }
        div { class: "mb-3",
            button {
                class: "btn-primary disabled:opacity-40",
                disabled: syncing(),
                onclick: move |_| {
                    syncing.set(true);
                    spawn(async move {
                        match api_send("POST", "/api/admin/models/sync", None).await {
                            Ok(v) => {
                                msg.set(format!("同步: 新增 {} · 已有 {}", num_i64(&v, "created"), num_i64(&v, "existing")));
                                syncing.set(false);
                                tick.set(tick() + 1);
                            }
                            Err(e) => { err.set(e); syncing.set(false); }
                        }
                    });
                },
                {if syncing() { "同步中…" } else { "同步 NVIDIA 模型" }}
            }
        }
        div { class: "table-card card card-hover",
            table { class: "w-full text-sm",
                thead { tr { class: "text-left text-xs text-ink/55",
                    th {"模型" } th {"Provider" }
                    th {"状态" } th {"操作" }
                } }
                tbody { for m in items_snapshot.into_iter() {
                    ModelRow { m: m, err: err, tick: tick }
                } }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// API Keys (用户侧)
// ---------------------------------------------------------------------------

#[component]
fn UKeys() -> Element {
    let mut items: Signal<Vec<Value>> = use_signal(Vec::new);
    let mut err = use_signal(String::new);
    let mut name = use_signal(String::new);
    let mut raw_new = use_signal(String::new);
    let mut tick = use_signal(|| 0u64);

    use_future(move || async move {
        let _ = tick();
        match api_get("/api/admin/api-keys").await {
            Ok(v) => {
                items.set(v["items"].as_array().cloned().unwrap_or_default());
                err.set(String::new());
            }
            Err(e) => err.set(e),
        }
    });

    let items_snapshot: Vec<Value> = items();

    rsx! {
        PageHead { title: "API Keys".to_string(), desc: "sk-nvidia2api-* · SHA-256 存储 · 每 Key 独立限流".to_string() }
        ErrBox { msg: err() }
        if !raw_new().is_empty() {
            div { class: "mb-3 rounded-lg border border-nvgreen bg-alive/10 p-4",
                div { class: "mb-1 text-xs text-alive", "新 Key (仅此一次展示, 立即复制):" }
                code { class: "break-all font-data text-xs text-ink", {raw_new()} }
            }
        }
        div { class: "mb-4 flex flex-wrap items-center gap-2 card",
            input {
                class: "h-9 w-52 rounded-sm border border-line bg-paper px-3 text-sm text-ink focus:border-ink focus:outline-none",
                placeholder: "Key 名称",
                value: name(),
                oninput: move |e| name.set(e.value()),
            }
            Button { variant: ButtonVariant::Primary, class: "h-8 rounded-sm text-xs",
                on_click: move |_| {
                    let n = name();
                    spawn(async move {
                        match api_send("POST", "/api/admin/api-keys", Some(serde_json::json!({"name": n}))).await {
                            Ok(v) => { raw_new.set(trim_text(&v, "raw_key")); name.set(String::new()); tick.set(tick() + 1); }
                            Err(e) => err.set(e),
                        }
                    });
                },
                "创建"
            }
        }
        div { class: "card card-hover",
            table { class: "w-full text-sm",
                thead { tr { class: "text-left text-xs text-ink/55",
                    th {"名称" } th {"前缀" }
                    th {"状态" } th {"总/成/败" }
                    th {"操作" }
                } }
                tbody { for k in items_snapshot.into_iter() {
                    UKeysRow { k: k, err: err, tick: tick }
                } }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------

#[component]
fn Logs() -> Element {
    let mut items: Signal<Vec<Value>> = use_signal(Vec::new);
    let mut err = use_signal(String::new);
    let mut tick = use_signal(|| 0u64);

    use_future(move || async move {
        let _ = tick();
        match api_get("/api/admin/logs?limit=100").await {
            Ok(v) => {
                items.set(v["items"].as_array().cloned().unwrap_or_default());
                err.set(String::new());
            }
            Err(e) => err.set(e),
        }
    });

    let items_snapshot: Vec<Value> = items();

    rsx! {
        PageHead { title: "请求日志".to_string(), desc: "Winner 线路 / TTFT / Token 统计".to_string() }
        ErrBox { msg: err() }
        div { class: "mb-3",
            button {
                class: "rounded border border-line px-3 py-1.5 text-xs hover:text-alive",
                onclick: move |_| tick.set(tick() + 1),
                "刷新"
            }
        }
        div { class: "table-card card card-hover",
            table { class: "w-full text-sm",
                thead { tr { class: "text-left text-xs text-ink/55",
                    th {"时间" } th {"模型" }
                    th {"状态" } th {"耗时" }
                    th {"TTFT" } th {"Winner 线路" }
                    th {"Key" } th {"Tokens" }
                    th {"错误" }
                } }
                tbody { for l in items_snapshot.into_iter() {
                    LogRow { l: l }
                } }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 设置
// ---------------------------------------------------------------------------

#[component]
fn Settings() -> Element {
    let mut data: Signal<Option<Value>> = use_signal(|| None);
    let mut err = use_signal(String::new);
    let mut msg = use_signal(String::new);
    let mut draft = use_signal(String::new);
    let mut tick = use_signal(|| 0u64);

    use_future(move || async move {
        let _ = tick();
        match api_get("/api/admin/settings").await {
            Ok(v) => {
                data.set(Some(v));
                err.set(String::new());
            }
            Err(e) => err.set(e),
        }
    });

    rsx! {
        PageHead { title: "运行时设置".to_string(), desc: "system_setting 表 · 运行时读取热生效".to_string() }
        ErrBox { msg: err() }
        if !msg().is_empty() { div { class: "mb-3 rounded-sm border border-alive/40 bg-alive/10 px-3 py-2 text-sm text-alive", {msg()} } }
        div { class: "card card-hover",
            p { class: "mb-2 text-xs text-ink/55", "JSON 格式, 例: default_nvidia_rpm = 40, max_routes_per_request = 50 (值均为字符串)" }
            textarea {
                class: "mb-2 w-full rounded-sm border border-line bg-paper p-2 font-data text-xs text-ink focus:border-ink focus:outline-none",
                value: draft(),
                oninput: move |e| draft.set(e.value()),
                placeholder: "default_nvidia_rpm = 40",
            }
            Button { variant: ButtonVariant::Primary, class: "h-8 rounded-sm text-xs",
                on_click: move |_| {
                    let text = draft();
                    spawn(async move {
                        match serde_json::from_str::<Value>(&text) {
                            Ok(v) => match api_send("POST", "/api/admin/settings", Some(v)).await {
                                Ok(_) => { msg.set("已保存".into()); tick.set(tick() + 1); }
                                Err(e) => err.set(e),
                            },
                            Err(e) => err.set(format!("JSON 解析失败: {e}")),
                        }
                    });
                },
                "保存"
            }
        }
        match data() {
            Some(v) => rsx! {
                div { class: "mt-4 card",
                    div { class: "mb-2 text-sm font-semibold", "当前值" }
                    pre { class: "font-data text-xs text-ink/55", {serde_json::to_string_pretty(&v["settings"]).unwrap_or_default()} }
                }
            },
            None => rsx! {},
        }
    }
}

// ---------------------------------------------------------------------------
// 注册机
// ---------------------------------------------------------------------------

fn sleep_ms(ms: i32) -> wasm_bindgen_futures::JsFuture {
    let p = js_sys::Promise::new(&mut |resolve, _| {
        let _ = web_sys::window()
            .expect("no window")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
    });
    wasm_bindgen_futures::JsFuture::from(p)
}

#[component]
fn Register() -> Element {
    let mut cfg: Signal<Option<Value>> = use_signal(|| None);
    let mut status: Signal<Option<Value>> = use_signal(|| None);
    let mut err = use_signal(String::new);
    let mut msg = use_signal(String::new);
    let mut count = use_signal(|| "1".to_string());

    // 初始: 配置 + 状态
    use_future(move || async move {
        if let Ok(v) = api_get("/api/admin/register/config").await {
            cfg.set(Some(v));
        }
        if let Ok(v) = api_get("/api/admin/register/status").await {
            status.set(Some(v));
        }
    });

    // 状态轮询 (3s)
    use_future(move || async move {
        loop {
            if let Ok(v) = api_get("/api/admin/register/status").await {
                status.set(Some(v));
            }
            let _ = sleep_ms(3000).await;
        }
    });

    rsx! {
        PageHead { title: "注册机".to_string(), desc: "NVIDIA BUILD 账号自动注册 (playwright) · 成功即入 Key 池".to_string() }
        ErrBox { msg: err() }
        if !msg().is_empty() { div { class: "mb-3 rounded-sm border border-alive/40 bg-alive/10 px-3 py-2 text-sm text-alive", {msg()} } }

        // 运行状态
        match status() {
            Some(st) => rsx! {
                div { class: "mb-4 card",
                    div { class: "flex flex-wrap items-center gap-x-5 gap-y-1 text-sm",
                        span { class: if st["running"].as_bool().unwrap_or(false) { "font-bold text-alive" } else { "font-bold text-ink/55" },
                            {if st["running"].as_bool().unwrap_or(false) { "● 运行中" } else { "○ 空闲" }} }
                        span { class: "text-ink/55", "进度 " b { class: "text-ink", {format!("{}/{}", num_i64(&st, "done"), num_i64(&st, "count"))} } }
                        span { class: "text-alive", {format!("成功 {}", num_i64(&st, "ok"))} }
                        span { class: "text-down", {format!("失败 {}", num_i64(&st, "fail"))} }
                        span { class: "text-alive", {format!("入库 {}", num_i64(&st, "imported"))} }
                        if st["running"].as_bool().unwrap_or(false) {
                            button {
                                class: "ml-auto rounded border border-down/40 px-3 py-1 text-xs text-down hover:bg-down/10",
                                onclick: move |_| {
                                    spawn(async move {
                                        match api_send("POST", "/api/admin/register/stop", None).await {
                                            Ok(_) => msg.set("已发送停止信号 (当前账号完成后退出)".into()),
                                            Err(e) => err.set(e),
                                        }
                                    });
                                },
                                "停止"
                            }
                        }
                    }
                    pre { class: "log-box",
                        {st["logs"].as_array().cloned().unwrap_or_default().iter().map(|l| l.as_str().unwrap_or("").to_string()).collect::<Vec<_>>().join("\n")}
                    }
                }
            },
            None => rsx! {},
        }

        // 启动
        div { class: "mb-4 flex flex-wrap items-center gap-2 card",
            input {
                class: "h-9 w-24 rounded-sm border border-line bg-paper px-3 text-sm text-ink focus:border-ink focus:outline-none",
                value: count(),
                oninput: move |e| count.set(e.value()),
                placeholder: "数量",
            }
            Button { variant: ButtonVariant::Primary, class: "h-8 rounded-sm text-xs",
                on_click: move |_| {
                    let n: u64 = count().parse().unwrap_or(1);
                    spawn(async move {
                        match api_send("POST", "/api/admin/register/start", Some(serde_json::json!({"count": n}))).await {
                            Ok(_) => msg.set(format!("已启动 {n} 个注册任务")),
                            Err(e) => err.set(e),
                        }
                    });
                },
                Rocket { class: "w-4 h-4" } "开始注册"
            }
        }

        // 配置表单
        match cfg() {
            Some(c) => rsx! {
                RegConfigForm { c: c }
            },
            None => rsx! { div { class: "text-ink/55", "配置加载中…" } },
        }
    }
}

#[component]
fn RegConfigForm(c: Value) -> Element {
    let email_provider_v = trim_text(&c, "email_provider");
    let cf_api_url_v = trim_text(&c, "cf_api_url");
    let cf_admin_auth_v = trim_text(&c, "cf_admin_auth");
    let cf_domain_v = trim_text(&c, "cf_domain");
    let duck_api_url_v = trim_text(&c, "duck_api_url");
    let duck_domain_v = trim_text(&c, "duck_domain");
    let duck_api_key_v = trim_text(&c, "duck_api_key");
    let captcha_mode_v = trim_text(&c, "captcha_mode");
    let yescaptcha_key_v = trim_text(&c, "yescaptcha_key");
    let captcharun_token_v = trim_text(&c, "captcharun_token");
    let headless_v = c["headless"].as_bool().unwrap_or(true);
    let org_name_v = trim_text(&c, "org_name");
    let key_expiry_v = trim_text(&c, "key_expiry");

    let mut email_provider = use_signal(move || email_provider_v.clone());
    let mut cf_api_url = use_signal(move || cf_api_url_v.clone());
    let mut cf_admin_auth = use_signal(move || cf_admin_auth_v.clone());
    let mut cf_domain = use_signal(move || cf_domain_v.clone());
    let mut duck_api_url = use_signal(move || duck_api_url_v.clone());
    let mut duck_domain = use_signal(move || duck_domain_v.clone());
    let mut duck_api_key = use_signal(move || duck_api_key_v.clone());
    let mut captcha_mode = use_signal(move || captcha_mode_v.clone());
    let mut yescaptcha_key = use_signal(move || yescaptcha_key_v.clone());
    let mut captcharun_token = use_signal(move || captcharun_token_v.clone());
    let mut headless = use_signal(move || headless_v);
    let mut org_name = use_signal(move || org_name_v.clone());
    let mut key_expiry = use_signal(move || key_expiry_v.clone());
    let mut msg = use_signal(|| String::new());
    let mut err = use_signal(|| String::new());

    rsx! {
        div { class: "card card-hover",
            div { class: "grid gap-x-6 md:grid-cols-2",
                div { class: "mb-2",
                    label { class: "mb-1 block text-xs text-ink/55", "邮箱服务" }
                    select {
                        class: "input",
                        value: email_provider(),
                        onchange: move |e| email_provider.set(e.value()),
                        option { value: "cloudflare_temp_email", "cloudflare_temp_email (自部署)" }
                        option { value: "duckmail", "duckmail" }
                    }
                }
                div { class: "mb-2",
                    label { class: "mb-1 block text-xs text-ink/55", "验证码模式" }
                    select {
                        class: "input",
                        value: captcha_mode(),
                        onchange: move |e| captcha_mode.set(e.value()),
                        option { value: "yescaptcha", "YesCaptcha" }
                        option { value: "captcharun", "CaptchaRun" }
                    }
                }
                RegField { label: "CF API URL".to_string(), value: cf_api_url(), placeholder: "https://your-cf-temp-email.example".to_string(), oninput: move |v| cf_api_url.set(v) }
                RegField { label: "CF Admin Auth".to_string(), value: cf_admin_auth(), placeholder: "x-admin-auth 值".to_string(), oninput: move |v| cf_admin_auth.set(v) }
                RegField { label: "CF 邮箱域名".to_string(), value: cf_domain(), placeholder: "mail.example.com".to_string(), oninput: move |v| cf_domain.set(v) }
                RegField { label: "DuckMail API".to_string(), value: duck_api_url(), placeholder: "https://api.duckmail.sbs".to_string(), oninput: move |v| duck_api_url.set(v) }
                RegField { label: "DuckMail 域名".to_string(), value: duck_domain(), placeholder: "duckmail.sbs".to_string(), oninput: move |v| duck_domain.set(v) }
                RegField { label: "DuckMail Key".to_string(), value: duck_api_key(), placeholder: "".to_string(), oninput: move |v| duck_api_key.set(v) }
                RegField { label: "YesCaptcha Key".to_string(), value: yescaptcha_key(), placeholder: "clientKey".to_string(), oninput: move |v| yescaptcha_key.set(v) }
                RegField { label: "CaptchaRun Token".to_string(), value: captcharun_token(), placeholder: "Bearer token".to_string(), oninput: move |v| captcharun_token.set(v) }
                RegField { label: "组织名 (跳过手机验证)".to_string(), value: org_name(), placeholder: "nvidia2api-org".to_string(), oninput: move |v| org_name.set(v) }
                RegField { label: "Key 过期日".to_string(), value: key_expiry(), placeholder: "2028-01-01".to_string(), oninput: move |v| key_expiry.set(v) }
                div { class: "mb-2",
                    label { class: "mb-1 block text-xs text-ink/55", "无头浏览器" }
                    button {
                        class: if headless() { "btn-ghost !text-alive !border-alive/60" } else { "btn-ghost" },
                        onclick: move |_| headless.set(!headless()),
                        {if headless() { "headless ✓" } else { "headless ✗" }}
                    }
                }
            }
            button {
                class: "mt-2 btn-primary",
                onclick: move |_| {
                    let body = serde_json::json!({
                        "email_provider": email_provider(), "cf_api_url": cf_api_url(), "cf_admin_auth": cf_admin_auth(),
                        "cf_domain": cf_domain(), "duck_api_url": duck_api_url(), "duck_domain": duck_domain(),
                        "duck_api_key": duck_api_key(), "captcha_mode": captcha_mode(), "yescaptcha_key": yescaptcha_key(),
                        "captcharun_token": captcharun_token(), "headless": headless(), "org_name": org_name(),
                        "key_expiry": key_expiry(),
                    });
                    spawn(async move {
                        match api_send("POST", "/api/admin/register/config", Some(body)).await {
                            Ok(_) => msg.set("配置已保存".into()),
                            Err(e) => err.set(e),
                        }
                    });
                },
                Save { class: "w-4 h-4" } "保存配置"
            }
            if !msg().is_empty() { span { class: "ml-3 text-xs text-alive", {msg()} } }
            if !err().is_empty() { span { class: "ml-3 text-xs text-down", {err()} } }
        }
    }
}

#[component]
fn RegField(label: String, value: String, placeholder: String, oninput: EventHandler<String>) -> Element {
    rsx! {
        div { class: "mb-2",
            label { class: "mb-1 block text-xs text-ink/55", {label} }
            input {
                class: "input",
                value: value,
                oninput: move |e| oninput.call(e.value()),
                placeholder: placeholder,
            }
        }
    }
}

#[component]
fn KeyRow(k: Value, mut err: Signal<String>, mut msg: Signal<String>, mut tick: Signal<u64>) -> Element {
    let id = num_i64(&k, "id");
    let is_disabled = trim_text(&k, "status") == "disabled";
    let mut confirm = use_signal(|| false);
    rsx! {
        tr {
            td {{trim_text(&k, "name")} }
            td { class: "font-data text-xs text-ink/55", {trim_text(&k, "masked_key")} }
            td {Tag { status: trim_text(&k, "status") } }
            td {{format!("{}", num_i64(&k, "rpm_limit"))} }
            td {{format!("{}/{}", num_i64(&k, "success_count"), num_i64(&k, "failure_count"))} }
            td { class: "text-xs text-ink/55", {trim_text(&k, "cooldown_until")} }
            td { class: "text-xs text-down", {trim_text(&k, "last_error")} }
            td {
                div { class: "flex gap-1.5",
                    Button { variant: ButtonVariant::Ghost, class: "h-7 rounded-sm text-xs",
                        on_click: move |_| {
                            spawn(async move {
                                match api_send("POST", &format!("/api/admin/nvidia-keys/{id}/test"), None).await {
                                    Ok(v) => {
                                        msg.set(if v["ok"].as_bool().unwrap_or(false) { format!("Key {id} 探活通过") } else { format!("Key {id} 探活失败: {}", v["http_status"]) });
                                        tick.set(tick() + 1);
                                    }
                                    Err(e) => err.set(e),
                                }
                            });
                        },
                        Activity { class: "w-3.5 h-3.5" }
                        "测活"
                    }
                    SwitchRow { checked: !is_disabled, on_toggle: move |_| {
                        let st = if is_disabled { "available" } else { "disabled" };
                        spawn(async move {
                            match api_send("PUT", &format!("/api/admin/nvidia-keys/{id}"), Some(serde_json::json!({"status": st}))).await {
                                Ok(_) => tick.set(tick() + 1),
                                Err(e) => err.set(e),
                            }
                        });
                    } }
                    button {
                        class: "btn-danger",
                        onclick: move |_| confirm.set(true),
                        Trash2 { class: "w-3.5 h-3.5" }
                        "删除"
                    }
                    if confirm() {
                        ConfirmDialog { title: "删除该 NVIDIA Key".to_string(), desc: "删除后立即从调度池移除, 不可恢复。".to_string(),
                            on_confirm: move |_| {
                                confirm.set(false);
                                spawn(async move {
                                    match api_send("DELETE", &format!("/api/admin/nvidia-keys/{id}"), None).await {
                                        Ok(_) => tick.set(tick() + 1),
                                        Err(e) => err.set(e),
                                    }
                                });
                            },
                            on_cancel: move |_| confirm.set(false) }
                    }
                }
            }
        }
    }
}

#[component]
fn ProxyRow(p: Value, mut err: Signal<String>, mut msg: Signal<String>, mut tick: Signal<u64>) -> Element {
    let id = num_i64(&p, "id");
    let enabled = p["enabled"].as_bool().unwrap_or(false);
    let mut confirm = use_signal(|| false);
    rsx! {
        tr {
            td {{trim_text(&p, "name")} }
            td { class: "text-xs text-ink/55", {trim_text(&p, "protocol")} }
            td {
                div { class: "flex items-center gap-2",
                    Tag { status: trim_text(&p, "status") }
                    if enabled { Tag { status: "enabled".to_string() } }
                }
            }
            td {{match p["latency_ms"].as_f64() { Some(l) => format!("{l:.0}ms"), None => "-".into() }} }
            td { class: "text-xs", {trim_text(&p, "public_ip")} }
            td { class: "text-xs text-ink/55", {format!("{} {}", trim_text(&p, "country"), trim_text(&p, "city"))} }
            td {{format!("{}/{}", num_i64(&p, "success_count"), num_i64(&p, "failure_count"))} }
            td {
                div { class: "flex gap-1.5",
                    SwitchRow { checked: enabled, on_toggle: move |_| {
                        let enable = !enabled;
                        spawn(async move {
                            match api_send("PUT", &format!("/api/admin/proxies/{id}"), Some(serde_json::json!({"enabled": enable}))).await {
                                Ok(_) => { msg.set(String::new()); tick.set(tick() + 1); }
                                Err(e) => err.set(e),
                            }
                        });
                    } }
                    Button { variant: ButtonVariant::Ghost, class: "h-7 rounded-sm text-xs",
                        on_click: move |_| {
                            spawn(async move {
                                match api_send("POST", &format!("/api/admin/proxies/{id}/fetch-ip"), None).await {
                                    Ok(v) => {
                                        if v["ok"].as_bool().unwrap_or(false) { msg.set(format!("IP: {} ({:.0}ms)", trim_text(&v, "public_ip"), num_f64(&v, "latency_ms"))); }
                                        else { msg.set(format!("失败: {}", trim_text(&v, "error"))); }
                                        tick.set(tick() + 1);
                                    }
                                    Err(e) => err.set(e),
                                }
                            });
                        },
                        Globe { class: "w-3.5 h-3.5" }
                        "查IP"
                    }
                    button {
                        class: "btn-danger",
                        onclick: move |_| confirm.set(true),
                        Trash2 { class: "w-3.5 h-3.5" }
                        "删除"
                    }
                    if confirm() {
                        ConfirmDialog { title: "删除该代理".to_string(), desc: "删除后从调度线路中移除, 不可恢复。".to_string(),
                            on_confirm: move |_| {
                                confirm.set(false);
                                spawn(async move {
                                    match api_send("DELETE", &format!("/api/admin/proxies/{id}"), None).await {
                                        Ok(_) => tick.set(tick() + 1),
                                        Err(e) => err.set(e),
                                    }
                                });
                            },
                            on_cancel: move |_| confirm.set(false) }
                    }
                }
            }
        }
    }
}

#[component]
fn GroupRow(g: Value, mut err: Signal<String>, mut tick: Signal<u64>) -> Element {
    let id = num_i64(&g, "id");
    let mut confirm = use_signal(|| false);
    rsx! {
        tr {
            td {{trim_text(&g, "name")} }
            td {{trim_text(&g, "country")} }
            td {Tag { status: if g["enabled"].as_bool().unwrap_or(false) { "enabled".to_string() } else { "disabled".to_string() } } }
            td {
                Button { variant: ButtonVariant::Destructive, class: "h-7 rounded-sm text-xs",
                    on_click: move |_| {
                        spawn(async move {
                            match api_send("DELETE", &format!("/api/admin/proxy-groups/{id}"), None).await {
                                Ok(_) => tick.set(tick() + 1),
                                Err(e) => err.set(e),
                            }
                        });
                    },
                    "删除"
                }
            }
        }
    }
}

#[component]
fn ModelRow(m: Value, mut err: Signal<String>, mut tick: Signal<u64>) -> Element {
    let id = num_i64(&m, "id");
    let enabled = m["enabled"].as_bool().unwrap_or(false);
    rsx! {
        tr {
            td { class: "font-data text-xs", {trim_text(&m, "model_name")} }
            td { class: "text-ink/55", {trim_text(&m, "provider")} }
            td {Tag { status: if enabled { "enabled".to_string() } else { "disabled".to_string() } } }
            td {
                SwitchRow { checked: enabled, on_toggle: move |_| {
                    let enable = !enabled;
                    spawn(async move {
                        match api_send("PUT", &format!("/api/admin/models/{id}"), Some(serde_json::json!({"enabled": enable}))).await {
                            Ok(_) => tick.set(tick() + 1),
                            Err(e) => err.set(e),
                        }
                    });
                } }
            }
        }
    }
}

#[component]
fn UKeysRow(k: Value, mut err: Signal<String>, mut tick: Signal<u64>) -> Element {
    let id = num_i64(&k, "id");
    let enabled = k["enabled"].as_bool().unwrap_or(false);
    let mut confirm = use_signal(|| false);
    rsx! {
        tr {
            td {{trim_text(&k, "name")} }
            td { class: "font-data text-xs text-ink/55", {trim_text(&k, "key_prefix")} }
            td {Tag { status: if enabled { "enabled".to_string() } else { "disabled".to_string() } } }
            td {{format!("{}/{}/{}", num_i64(&k, "total_requests"), num_i64(&k, "success_requests"), num_i64(&k, "failed_requests"))} }
            td {
                div { class: "flex items-center gap-2",
                    SwitchRow { checked: enabled, on_toggle: move |_| {
                        let enable = !enabled;
                        spawn(async move {
                            match api_send("PUT", &format!("/api/admin/api-keys/{id}"), Some(serde_json::json!({"enabled": enable}))).await {
                                Ok(_) => tick.set(tick() + 1),
                                Err(e) => err.set(e),
                            }
                        });
                    } }
                    button {
                        class: "btn-danger",
                        onclick: move |_| confirm.set(true),
                        Trash2 { class: "w-3.5 h-3.5" }
                        "删除"
                    }
                    if confirm() {
                        ConfirmDialog { title: "删除该 API Key".to_string(), desc: "调用此 Key 的客户端将立即 401, 不可恢复。".to_string(),
                            on_confirm: move |_| {
                                confirm.set(false);
                                spawn(async move {
                                    match api_send("DELETE", &format!("/api/admin/api-keys/{id}"), None).await {
                                        Ok(_) => tick.set(tick() + 1),
                                        Err(e) => err.set(e),
                                    }
                                });
                            },
                            on_cancel: move |_| confirm.set(false) }
                    }
                }
            }
        }
    }
}

#[component]
fn LogRow(l: Value) -> Element {
    rsx! {
        tr {
            td { class: "text-xs text-ink/55", {trim_text(&l, "created_at")} }
            td { class: "font-data text-xs", {trim_text(&l, "model")} }
            td {Tag { status: trim_text(&l, "status") } }
            td {{format!("{:.0}ms", num_f64(&l, "duration_ms"))} }
            td {{match l["first_token_ms"].as_f64() { Some(t) => format!("{t:.0}ms"), None => "-".into() }} }
            td { class: "p-2.5 text-xs",
                span { class: "text-ink/55", {trim_text(&l, "winner_route_type")} " · " }
                span { {trim_text(&l, "winner_proxy_name")} }
            }
            td { class: "text-xs", {trim_text(&l, "winner_key_name")} }
            td { class: "text-xs text-ink/55", {format!("{}", num_i64(&l, "total_tokens"))} }
            td { class: "text-xs text-down", {format!("{} {}", trim_text(&l, "error_type"), num_i64(&l, "http_status"))} }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Icon { Gauge, KeyRound, ArrowLeftRight, Layers, Boxes, KeySquare, ScrollText, Settings, UserPlus }

/// shadcn Switch — 表格行启停。
#[component]
fn SwitchRow(checked: bool, on_toggle: EventHandler<()>) -> Element {
    let mut st = use_signal(move || checked);
    rsx! {
        Switch { checked: st, on_checked_change: move |v| {
            st.set(v);
            on_toggle.call(());
        } }
    }
}

/// shadcn 风格确认对话框。
#[component]
fn ConfirmDialog(title: String, desc: String, on_confirm: EventHandler<()>, on_cancel: EventHandler<()>) -> Element {
    rsx! {
        div { class: "dialog-overlay",
            div { class: "dialog-box fade-up",
                div { class: "mb-1 text-sm font-bold", {title} }
                div { class: "mb-5 text-xs text-ink/55 leading-relaxed", {desc} }
                div { class: "flex justify-end gap-2",
                    Button { variant: ButtonVariant::Ghost, class: "h-8 rounded-sm text-xs", on_click: move |_| on_cancel.call(()), "取消" }
                    Button { variant: ButtonVariant::Destructive, class: "h-8 rounded-sm text-xs", on_click: move |_| on_confirm.call(()), "确认删除" }
                }
            }
        }
    }
}

fn main() {
    dioxus::launch(App);
}
