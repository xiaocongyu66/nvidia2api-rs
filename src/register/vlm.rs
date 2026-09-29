//! VLM 主路径求解 — 完整移植 gpt-pp-team 三层决策的第 1 层:
//! 1. chat_completion 核心 (system+user+多图, Claude/JSON 兼容, 提取容错)
//! 2. 候选框模式: overlay 编号图 + 候选 metadata → VLM 选 ID
//! 3. 直出坐标模式: VLM 直出归一化坐标 (候选提取失败时回退)
//! 4. 拖拽决策: missing-piece 的 source/target 配对
//! CLIP/OpenCV 启发式作为回退层 (captcha.rs 控制)。

use image::RgbImage;
use serde_json::Value;

pub struct VlmConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub timeout_secs: u64,
}

pub fn config() -> Option<VlmConfig> {
    let api_key = std::env::var("VLM_API_KEY").unwrap_or_default();
    if api_key.is_empty() {
        return None;
    }
    Some(VlmConfig {
        base_url: std::env::var("VLM_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com/v1".into())
            .trim_end_matches('/')
            .to_string(),
        api_key,
        model: std::env::var("VLM_MODEL").unwrap_or_else(|_| "gpt-4o".into()),
        timeout_secs: std::env::var("VLM_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(45),
    })
}

/// 候选框 (页面/画布像素坐标)
#[derive(Clone, Debug)]
pub struct CandidateBox {
    pub id: String,
    pub kind: &'static str, // "grid" | "object" | "source" | "target"
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl CandidateBox {
    pub fn center(&self) -> (f64, f64) {
        (self.x + self.w / 2.0, self.y + self.h / 2.0)
    }
}

pub struct VlmDecision {
    pub parsed: Value,
    pub raw_text: String,
}

// ---------------------------------------------------------------------------
// chat/completions 核心
// ---------------------------------------------------------------------------

fn png_data_url(bytes: &[u8]) -> String {
    format!("data:image/png;base64,{}", b64_encode(bytes))
}

fn b64_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TBL[(n >> 18) as usize & 63] as char);
        out.push(TBL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TBL[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TBL[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// 从任意文本提取首个平衡 JSON 对象 (容忍 markdown 围栏/前后缀)
pub fn extract_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if esc {
            esc = false;
            continue;
        }
        match b {
            b'\\' if in_str => esc = true,
            b'"' => in_str = !in_str,
            b'{' if !in_str => depth += 1,
            b'}' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Claude 系模型不支持 response_format, 用 prompt 强约束 + 失败重试
fn is_claude(model: &str) -> bool {
    model.to_lowercase().contains("claude")
}

pub async fn chat_completion(
    cfg: &VlmConfig,
    system_prompt: &str,
    user_text: &str,
    images: &[Vec<u8>],
) -> Result<VlmDecision, String> {
    let claude = is_claude(&cfg.model);
    let mut system = system_prompt.to_string();
    if claude {
        system.push_str(
            "\n\nIMPORTANT: You MUST respond with ONLY a valid JSON object. \
             No explanation, no markdown, no text before or after the JSON. \
             Start your response with '{' and end with '}'.",
        );
    }

    let mut content = vec![serde_json::json!({"type": "text", "text": user_text})];
    for img in images {
        content.push(serde_json::json!({
            "type": "image_url",
            "image_url": {"url": png_data_url(img), "detail": "high"}
        }));
    }
    let mut payload = serde_json::json!({
        "model": cfg.model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": content},
        ],
        "max_tokens": 3072,
    });
    if !claude {
        payload["response_format"] = serde_json::json!({"type": "json_object"});
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .build()
        .map_err(|e| format!("vlm client: {e}"))?;
    let url = format!("{}/chat/completions", cfg.base_url);

    let attempts = if claude { 2 } else { 1 };
    let mut last_err = String::new();
    for attempt in 0..attempts {
        let resp = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", cfg.api_key))
            .json(&payload)
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                last_err = format!("vlm 请求: {e}");
                continue;
            }
        };
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status != 200 {
            last_err = format!(
                "vlm HTTP {status}: {}",
                text.chars().take(160).collect::<String>()
            );
            continue;
        }
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                last_err = format!("vlm 响应解析: {e}");
                continue;
            }
        };
        let raw = &v["choices"][0]["message"]["content"];
        let mut content_text = if raw.is_array() {
            raw.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("")
                })
                .unwrap_or_default()
        } else {
            raw.as_str().unwrap_or("").to_string()
        };
        // reasoning 模型: content 耗尽为空时从 reasoning_content 提取结论 JSON
        if extract_json_object(&content_text).is_none() {
            if let Some(r) = v["choices"][0]["message"]["reasoning_content"].as_str() {
                if let Some(js) = extract_json_object(r) {
                    println!("[vlm] content 空, 从 reasoning 提取 JSON");
                    content_text = js.to_string();
                }
            }
        }
        if let Some(js) = extract_json_object(&content_text) {
            if let Ok(parsed) = serde_json::from_str::<Value>(js) {
                return Ok(VlmDecision { parsed, raw_text: content_text });
            }
        }
        last_err = format!(
            "vlm content 无 JSON: {}",
            content_text.chars().take(100).collect::<String>()
        );
        if attempt == 0 && claude {
            // 重试: 追加强制 JSON 提示
            let msgs = payload["messages"].as_array().cloned().unwrap_or_default();
            let mut m = msgs;
            m.push(serde_json::json!({"role": "assistant", "content": content_text.chars().take(200).collect::<String>()}));
            m.push(serde_json::json!({"role": "user", "content": "You did not return valid JSON. Reply with ONLY a JSON object, nothing else. Start with {"}));
            payload["messages"] = Value::Array(m);
        }
    }
    Err(last_err)
}

// ---------------------------------------------------------------------------
// overlay 绘制 (零依赖点阵字: 5x7)
// ---------------------------------------------------------------------------

/// 5x7 点阵, 每字符 7 个 u8 (高位在左, bit4..bit0 = 列 0..4)
const GLYPHS: &[(&str, [u8; 7])] = &[
    ("0", [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E]),
    ("1", [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E]),
    ("2", [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F]),
    ("3", [0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E]),
    ("4", [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02]),
    ("5", [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E]),
    ("6", [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E]),
    ("7", [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08]),
    ("8", [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E]),
    ("9", [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C]),
    ("G", [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F]),
    ("S", [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E]),
    ("T", [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04]),
    ("H", [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11]),
];

const PALETTE: [[u8; 3]; 6] = [
    [255, 99, 71],
    [0, 191, 255],
    [255, 215, 0],
    [50, 205, 50],
    [186, 85, 211],
    [255, 140, 0],
];

fn draw_glyph(img: &mut RgbImage, ch: char, x0: i64, y0: i64, color: [u8; 3]) {
    let g = GLYPHS
        .iter()
        .find(|(c, _)| c.chars().next() == Some(ch))
        .map(|(_, g)| g);
    if let Some(rows) = g {
        for (ry, &row) in rows.iter().enumerate() {
            for col in 0..5 {
                if row & (0x10 >> col) != 0 {
                    let px = x0 + col as i64;
                    let py = y0 + ry as i64;
                    if px >= 0 && py >= 0 {
                        let (px, py) = (px as u32, py as u32);
                        if px < img.width() && py < img.height() {
                            img.put_pixel(px, py, image::Rgb(color));
                        }
                    }
                }
            }
        }
    }
}

fn draw_label(img: &mut RgbImage, label: &str, x0: i64, y0: i64, color: [u8; 3]) {
    for (i, ch) in label.chars().enumerate() {
        draw_glyph(img, ch, x0 + (i as i64) * 6, y0, color);
    }
}

fn rect_outline(img: &mut RgbImage, x: i64, y: i64, w: i64, h: i64, color: [u8; 3], thick: u32) {
    let (iw, ih) = (img.width() as i64, img.height() as i64);
    for t in 0..thick as i64 {
        let tt = t as i64;
        for px in x..=(x + w) {
            for py in [y + tt, y + h - tt] {
                if px >= 0 && py >= 0 && px < iw && py < ih {
                    img.put_pixel(px as u32, py as u32, image::Rgb(color));
                }
            }
        }
        for py in y..=(y + h) {
            for px in [x + tt, x + w - tt] {
                if px >= 0 && py >= 0 && px < iw && py < ih {
                    img.put_pixel(px as u32, py as u32, image::Rgb(color));
                }
            }
        }
    }
}

/// 候选框编号 overlay — 与原 gpt-pp-team 相同布局: 彩框 + 左上角标号牌
pub fn draw_overlay(base: &RgbImage, candidates: &[CandidateBox]) -> RgbImage {
    let mut img = base.clone();
    for (idx, c) in candidates.iter().enumerate() {
        let color = PALETTE[idx % PALETTE.len()];
        rect_outline(
            &mut img,
            c.x as i64,
            c.y as i64,
            c.w as i64,
            c.h as i64,
            color,
            3,
        );
        let lx = c.x as i64 + 3;
        let ly = (c.y as i64 - 14).max(1);
        draw_label(&mut img, &c.id, lx, ly, color);
    }
    img
}

/// 候选 metadata JSON (对齐 _candidate_metadata)
pub fn candidate_metadata(candidates: &[CandidateBox], full_w: usize, full_h: usize) -> Value {
    Value::Array(
        candidates
            .iter()
            .map(|c| {
                let (cx, cy) = c.center();
                serde_json::json!({
                    "id": c.id,
                    "kind": c.kind,
                    "box": [c.x as i64, c.y as i64, c.w as i64, c.h as i64],
                    "center": [round2(cx), round2(cy)],
                    "normalized_center": [round2(cx / full_w.max(1) as f64), round2(cy / full_h.max(1) as f64)],
                })
            })
            .collect(),
    )
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

// ---------------------------------------------------------------------------
// 决策模式
// ---------------------------------------------------------------------------

/// 候选框点击决策 → selected ids (保持候选顺序)
pub async fn click_decision(
    cfg: &VlmConfig,
    arr: &RgbImage,
    candidates: &[CandidateBox],
    prompt: &str,
    submit_text: &str,
) -> Result<Vec<String>, String> {
    let overlay = draw_overlay(arr, candidates);
    let meta = candidate_metadata(
        candidates,
        arr.width() as usize,
        arr.height() as usize,
    );
    let mut obuf = Vec::new();
    image::DynamicImage::ImageRgb8(overlay)
        .write_to(&mut std::io::Cursor::new(&mut obuf), image::ImageFormat::Png)
        .map_err(|e| format!("overlay 编码: {e}"))?;
    let mut abuf = Vec::new();
    image::DynamicImage::ImageRgb8(arr.clone())
        .write_to(&mut std::io::Cursor::new(&mut abuf), image::ImageFormat::Png)
        .map_err(|e| format!("原图编码: {e}"))?;

    let system = "你是一个验证码视觉决策器。用户会给你 challenge prompt、原始图片、带候选框编号的图片, 以及候选框元数据。你的任务是只根据图片内容和 prompt, 判断应该点击哪些候选框。只返回 JSON, 不要输出任何额外解释。JSON 结构必须是: {\"action\":\"click\",\"selected_ids\":[\"ID1\",\"ID2\"],\"confidence\":0.0,\"reasoning\":\"...\"}。如果是单选题, 也仍然返回 selected_ids, 只包含一个元素。不要返回候选框之外的坐标。";
    let user = format!(
        "Prompt: {prompt}\nSubmit button text: {}\nCandidates JSON:\n{meta}\n请输出应该点击的 candidate ids。",
        submit_text_or(submit_text)
    );
    let decision = chat_completion(cfg, system, &user, &[abuf, obuf]).await?;
    let ids: Vec<String> = decision.parsed["selected_ids"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if ids.is_empty() {
        return Err(format!(
            "vlm click 无 selected_ids: {}",
            decision.raw_text.chars().take(80).collect::<String>()
        ));
    }
    println!("[vlm] 候选框选择: {ids:?}");
    Ok(ids)
}

fn submit_text_or(s: &str) -> &str {
    if s.is_empty() {
        "(none)"
    } else {
        s
    }
}

/// 直出坐标点击 → 像素坐标列表 (归一化/像素自动判别)
pub async fn direct_click(
    cfg: &VlmConfig,
    arr: &RgbImage,
    prompt: &str,
    submit_text: &str,
    expected_count: Option<usize>,
) -> Result<Vec<(f64, f64)>, String> {
    let (width, height) = (arr.width() as f64, arr.height() as f64);
    let system = "你是一个视觉点击坐标标注助手。用户会给你 challenge prompt 和题图。你的任务是根据当前截图状态, 返回'下一步需要点击哪些位置'。注意: 某些题图里已经被选中的对象会显示明显的圆圈/叉号/关闭图标覆盖层; 如果一个对象被错误选中, 你应该返回它的中心点, 让用户再次点击以取消选择。如果一个正确目标尚未被选中, 你应该返回它的中心点。因此你返回的是'纠正到正确最终状态所需的点击点'。只输出 JSON, 格式为 {\"action\":\"click\",\"click_points\":[[x,y],...],\"confidence\":0.0,\"reasoning\":\"...\"}。其中 x,y 默认使用 0 到 1 之间的归一化坐标; 如果你输出像素坐标, 也必须确保落在图片范围内。";
    let count_hint = match expected_count {
        Some(n) if n > 0 => format!(
            "\nExpected final selected target count: {n}. 这是最终正确选中目标的数量, 不一定等于本轮需要点击的次数。"
        ),
        _ => String::new(),
    };
    let user = format!(
        "Prompt: {prompt}\nSubmit text: {}\nImage size: width={}, height={}\n{count_hint}\n请只选择真正匹配 prompt 的目标, 避免背景或干扰物。",
        submit_text_or(submit_text),
        width as i64,
        height as i64
    );
    let mut abuf = Vec::new();
    image::DynamicImage::ImageRgb8(arr.clone())
        .write_to(&mut std::io::Cursor::new(&mut abuf), image::ImageFormat::Png)
        .map_err(|e| format!("原图编码: {e}"))?;
    let decision = chat_completion(cfg, system, &user, &[abuf]).await?;
    parse_points(&decision.parsed["click_points"], width, height)
}

/// 直出坐标拖拽 → (from, to) 像素坐标
pub async fn direct_drag(
    cfg: &VlmConfig,
    arr: &RgbImage,
    prompt: &str,
    submit_text: &str,
) -> Result<((f64, f64), (f64, f64)), String> {
    let (width, height) = (arr.width() as f64, arr.height() as f64);
    let system = "你是一个验证码视觉拖拽定位助手。用户会给你 challenge prompt 和当前题图。请直接返回拖拽起点和终点坐标。只输出 JSON, 格式为 {\"action\":\"drag\",\"drag_from\":[x,y],\"drag_to\":[x,y],\"confidence\":0.0,\"reasoning\":\"...\"}。其中 x,y 优先使用 0 到 1 之间的归一化坐标; 如果你输出像素坐标, 也必须确保落在图片范围内。";
    let user = format!(
        "Prompt: {prompt}\nSubmit text: {}\nImage size: width={}, height={}\n请根据图中左右配对关系, 给出一个最合理的拖拽起点和终点。",
        submit_text_or(submit_text),
        width as i64,
        height as i64
    );
    let mut abuf = Vec::new();
    image::DynamicImage::ImageRgb8(arr.clone())
        .write_to(&mut std::io::Cursor::new(&mut abuf), image::ImageFormat::Png)
        .map_err(|e| format!("原图编码: {e}"))?;
    let decision = chat_completion(cfg, system, &user, &[abuf]).await?;
    let from_v = decision
        .parsed
        .get("drag_from")
        .cloned()
        .or_else(|| decision.parsed.get("source_point").cloned())
        .unwrap_or(Value::Null);
    let to_v = decision
        .parsed
        .get("drag_to")
        .cloned()
        .or_else(|| decision.parsed.get("target_point").cloned())
        .unwrap_or(Value::Null);
    let from = parse_point(&from_v, width, height)?;
    let to = parse_point(&to_v, width, height)?;
    Ok((from, to))
}

/// 题型自适应 VLM 求解 (网格/拖拽统一协议):
/// 返回 Ok(Left(indices)) = 网格选中项; Ok(Right((from,to))) = 拖拽归一化坐标。
pub async fn solve_adaptive(
    cfg: &VlmConfig,
    image_png: &[u8],
    prompt: &str,
) -> Result<Result<Vec<usize>, ((f64, f64), (f64, f64))>, String> {
    let p = if prompt.is_empty() {
        "(prompt text was not captured — read the challenge image yourself)".to_string()
    } else {
        format!("\"{prompt}\"")
    };
    let instruction = format!(
        "You are an hCaptcha solver. The image shows one challenge. It is either \
         (a) a 3x3 grid of tiles (number them 1-9 row-major, top-left = 1) or \
         (b) a drag challenge (drag a piece/letter from its source to the target slot). \
         Challenge prompt: {p}. If the prompt is unavailable, read it from the image. \
         IMPORTANT for grid challenges: if the prompt mentions a 'sample'/'example'/'reference' \
         item (e.g. 'weighs less than the animal in the sample'), that sample tile is a \
         REFERENCE for comparison — do NOT select it; compare every other tile against it. \
         'less than the animal' means find tiles whose item is lighter than the sample animal. \
         For a grid challenge respond ONLY: {{\"type\":\"grid\",\"selected\":[tile numbers]}} \
         (empty list if nothing matches). \
         For a drag challenge respond ONLY: {{\"type\":\"drag\",\"from\":[x,y],\"to\":[x,y]}} \
         with normalized 0-1 coordinates. No markdown, no explanation."
    );
    let decision = chat_completion(
        cfg,
        "You are an hCaptcha visual solver. Always answer with a single JSON object.",
        &instruction,
        &[image_png.to_vec()],
    )
    .await?;
    println!(
        "[vlm] 原始回答: {}",
        decision.raw_text.chars().take(150).collect::<String>()
    );
    let t = decision.parsed["type"].as_str().unwrap_or("grid");
    if t == "drag" {
        let (w, h) = (480.0f64, 480.0f64);
        let from = parse_point(
            decision.parsed.get("from").unwrap_or(&Value::Null),
            w,
            h,
        )?;
        let to = parse_point(
            decision.parsed.get("to").unwrap_or(&Value::Null),
            w,
            h,
        )?;
        println!("[vlm] 题型自适应: drag ({from:.2?}) → ({to:.2?})");
        Ok(Err((from, to)))
    } else {
        let selected: Vec<usize> = decision.parsed["selected"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_u64())
                    .filter(|&n| (1..=9).contains(&n))
                    .map(|n| (n - 1) as usize)
                    .collect()
            })
            .unwrap_or_default();
        println!(
            "[vlm] 题型自适应: grid {:?}",
            selected.iter().map(|i| i + 1).collect::<Vec<_>>()
        );
        Ok(Ok(selected))
    }
}

// ---------------------------------------------------------------------------
// 解析辅助
// ---------------------------------------------------------------------------

fn parse_points(raw: &Value, width: f64, height: f64) -> Result<Vec<(f64, f64)>, String> {
    let arr = raw
        .as_array()
        .ok_or_else(|| format!("vlm 直出坐标失败: {raw}"))?;
    let mut pts = Vec::new();
    for item in arr {
        if let Ok(p) = parse_point(item, width, height) {
            pts.push(p);
        }
    }
    if pts.is_empty() {
        return Err("vlm 直出坐标未返回有效点位".into());
    }
    println!(
        "[vlm] 直出坐标: {} 个点",
        pts.len()
    );
    Ok(pts)
}

fn parse_point(raw: &Value, width: f64, height: f64) -> Result<(f64, f64), String> {
    let arr = raw
        .as_array()
        .ok_or_else(|| format!("vlm 点位非法: {raw}"))?;
    if arr.len() < 2 {
        return Err(format!("vlm 点位长度不足: {raw}"));
    }
    let x = arr[0].as_f64().ok_or("vlm x 非数")?;
    let y = arr[1].as_f64().ok_or("vlm y 非数")?;
    let (px, py) = if (0.0..=1.0).contains(&x) && (0.0..=1.0).contains(&y) {
        (x * width, y * height)
    } else {
        (x, y)
    };
    Ok((px.clamp(1.0, (width - 2.0).max(1.0)), py.clamp(1.0, (height - 2.0).max(1.0))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_extraction_balanced() {
        let t = "前缀 {\"a\":{\"b\":1},\"c\":\"}\"} 尾注";
        assert_eq!(extract_json_object(t), Some("{\"a\":{\"b\":1},\"c\":\"}\"}"));
    }

    #[test]
    fn json_extraction_none() {
        assert_eq!(extract_json_object("no json here"), None);
    }

    #[test]
    fn overlay_smoke() {
        let img = RgbImage::new(100, 100);
        let cands = vec![CandidateBox {
            id: "G1".into(),
            kind: "grid",
            x: 10.0,
            y: 10.0,
            w: 30.0,
            h: 30.0,
        }];
        let o = draw_overlay(&img, &cands);
        assert_eq!(o.width(), 100);
        // 框左上角应有调色板颜色
        assert_eq!(o.get_pixel(10, 10).0, PALETTE[0]);
    }
}
