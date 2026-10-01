//! ddddocr 移植 (sml2h3/ddddocr): CRNN OCR 本地推理 — 加密轮 prompt 解密。
//! 模型 common_old.onnx 13.6MB (CRNN, 输入 [1,1,64,W] 动态宽) + charset 8210 字符。
//! 预处理: 灰度 → 高 64 等比缩宽 → /255; 解码: argmax → 去连续重复 → 跳 index 0 (blank)。

use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

const OCR_MODEL_BYTES: &[u8] = include_bytes!("../../model/ocr_common_old.onnx");
const OCR_CHARSET_JSON: &str = include_str!("../../model/ocr_charset.json");

struct OcrEngine {
    session: Mutex<ort::session::Session>,
    charset: Vec<String>,
}

static OCR: OnceLock<OcrEngine> = OnceLock::new();

/// OCR 引擎就绪 (落盘模型 + 建 session)。幂等。
pub fn ensure_ocr() -> Result<(), String> {
    if OCR.get().is_some() {
        return Ok(());
    }
    super::vision::ensure_engine()?; // 复用 dylib 落盘+ORT_DYLIB_PATH 设置
    let dir = super::vision::models_dir();
    let model_path = dir.join("ocr-common-old.onnx");
    if !model_path.exists() {
        std::fs::write(&model_path, OCR_MODEL_BYTES)
            .map_err(|e| format!("write ocr model: {e}"))?;
    }
    let charset: Vec<String> = serde_json::from_str::<Vec<String>>(OCR_CHARSET_JSON)
        .map_err(|e| format!("parse ocr charset: {e}"))?;

    let b = ort::session::Session::builder().map_err(|e| format!("ort builder: {e}"))?;
    let b = b
        .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
        .map_err(|e| format!("ort opt: {e}"))?;
    let mut b = b.with_intra_threads(4).map_err(|e| format!("ort threads: {e}"))?;
    let session = b
        .commit_from_file(&model_path)
        .map_err(|e| format!("ocr session: {e}"))?;
    let _ = OCR.set(OcrEngine {
        session: Mutex::new(session),
        charset,
    });
    Ok(())
}

/// OCR 一张图 (png/jpeg bytes) → 文本。空图/推理失败返回空串。
pub fn recognize(png: &[u8]) -> String {
    let Some(eng) = OCR.get() else { return String::new() };
    let img = match image::load_from_memory(png) {
        Ok(i) => i,
        Err(_) => return String::new(),
    };
    // 高 64 等比缩宽 (宽至少 8, 避免退化输入)
    let (w0, h0) = (img.width().max(1) as f64, img.height().max(1) as f64);
    let tw = ((w0 * (64.0 / h0)).round() as u32).clamp(8, 2048);
    let gray = img.to_luma8();
    let thumb = image::imageops::resize(&gray, tw, 64, image::imageops::FilterType::Lanczos3);
    let mut input = vec![0f32; (tw as usize) * 64];
    for (i, p) in thumb.pixels().enumerate() {
        input[i] = p.0[0] as f32 / 255.0;
    }

    let mut sess = match eng.session.lock() {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let shape = vec![1i64, 1i64, 64i64, tw as i64];
    let Ok(input_v) = ort::value::Tensor::from_array((shape, input)) else {
        return String::new();
    };
    let outputs = match sess.run(ort::inputs![input_v]) {
        Ok(o) => o,
        Err(_) => return String::new(),
    };
    // 输出 (seq, 1, classes) 或 (1, seq, classes) — argmax 得索引序列
    let Some(logits) = (|| {
        let (shape, data) = outputs[0].try_extract_tensor::<f32>().ok()?;
        let dims: Vec<usize> = shape.to_vec().iter().map(|d| *d as usize).collect();
        Some((dims, data.to_vec()))
    })() else {
        return String::new();
    };
    let (dims, data) = logits;
    if dims.len() != 3 {
        return String::new();
    }
    // 规范成 (seq, classes)
    let (seq, classes) = if dims[1] == 1 {
        (dims[0], dims[2])
    } else {
        (dims[1], dims[2])
    };
    if classes == 0 || data.len() < seq * classes {
        return String::new();
    }
    // argmax per timestep
    let mut prev: usize = usize::MAX;
    let mut out = String::new();
    for t in 0..seq {
        let row = &data[t * classes..(t + 1) * classes];
        let (mut bi, mut bv) = (0usize, f32::MIN);
        for (i, v) in row.iter().enumerate() {
            if *v > bv {
                bv = *v;
                bi = i;
            }
        }
        // CTC: 去连续重复 + 跳 blank(0)
        if bi != prev && bi != 0 {
            if let Some(c) = eng.charset.get(bi) {
                out.push_str(c);
            }
        }
        prev = bi;
    }
    out
}

/// prompt 后处理: hCaptcha prompt 常以 "Please select/select/tap..." 开头, 修正常见 OCR 误读。
pub fn normalize_prompt(raw: &str) -> String {
    let t = raw.trim().replace('\n', " ");
    let t = t.trim_start_matches(|c: char| !c.is_ascii_alphabetic());
    let lower = t.to_lowercase();
    // 只接受像 prompt 的文本 (含动作动词)
    let ok = ["please", "select", "pick", "click", "tap", "choose"];
    if ok.iter().any(|k| lower.starts_with(k)) {
        t.to_string()
    } else {
        String::new()
    }
}

/// OCR 结果 → 已知 prompt 模板匹配 (data/train/*/_prompt.json + 内置题池)。
/// CRNN 丢空格/错一两个字是常态, 无空格对齐 + 公共前缀长度取最佳, 命中即还原原文 (空格+大小写)。
pub fn match_known_prompt(ocr_raw: &str) -> Option<String> {
    let key: String = ocr_raw
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if key.len() < 10 {
        return None;
    }
    let mut best: Option<(usize, String)> = None;
    // 内置题池 (已知 hCaptcha 固定 prompt 集)
    const POOL: &[&str] = &[
        "Select all images with something that uses legs for movement",
        "Select tools you can use to scoop the material",
        "Pick the toys made for the bathtub",
        "Click on everything that weighs less than the animal in the picture",
        "Tap on the vehicle this one could move",
        "Pick the vehicle this one could move",
        "In the mirror, click the reflection facing the wrong way",
        "Select items safe for a hot oven",
        "Please select all images containing an animal",
        "Please click on each image containing a vehicle",
    ];
    for t in POOL {
        let tk: String = t
            .to_lowercase()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect();
        if let Some(s) = prefix_score(&key, &tk) {
            if best.as_ref().map(|(bs, _)| s > *bs).unwrap_or(true) {
                best = Some((s, t.to_string()));
            }
        }
    }
    // 采集库动态模板
    if let Ok(rd) = std::fs::read_dir(std::path::Path::new("data/train")) {
        for e in rd.flatten() {
            let p = e.path().join("_prompt.json");
            let Ok(raw) = std::fs::read_to_string(&p) else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&raw) else { continue };
            let Some(t) = v["prompt"].as_str() else { continue };
            let tk: String = t
                .to_lowercase()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric())
                .collect();
            if let Some(s) = prefix_score(&key, &tk) {
                if best.as_ref().map(|(bs, _)| s > *bs).unwrap_or(true) {
                    best = Some((s, t.to_string()));
                }
            }
        }
    }
    // 至少 70% 长度匹配才信任 (防 OCR 半截误命中)
    let (s, t) = best?;
    if s * 10 >= key.len() * 7 {
        Some(t)
    } else {
        None
    }
}

/// 公共前缀长度 (无空格 key vs 模板)。
fn prefix_score(key: &str, template: &str) -> Option<usize> {
    let n = key.chars().count().min(template.chars().count());
    let kc: Vec<char> = key.chars().collect();
    let tc: Vec<char> = template.chars().collect();
    let mut same = 0usize;
    for i in 0..n {
        if kc[i] == tc[i] {
            same += 1;
        } else {
            break;
        }
    }
    // 模板被 key 包含 (OCR 结果比模板长且模板在前面完整出现)
    if template.len() >= 12 && key.contains(template) {
        return Some(template.chars().count());
    }
    if same >= 12 {
        Some(same)
    } else {
        None
    }
}

pub fn charset_len() -> usize {
    OCR.get().map(|e| e.charset.len()).unwrap_or(0)
}

pub fn debug_meta() -> Value {
    serde_json::json!({"ready": OCR.get().is_some(), "charset": charset_len()})
}
