//! 本地 ONNX 视觉求解 — CLIP ViT-B/32 图像塔（自包含, 无外部服务）。
//!
//! 模型与 ORT 引擎动态库均编译期内嵌；首次使用时落盘到数据目录并加载。
//! 分类语义完全对齐 zero199901/gpt-pp-team 原版: 余弦×logit_scale(100)→softmax→margin 排序。

use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// ORT 引擎动态库 (load-dynamic, 按架构内嵌)
#[cfg(target_arch = "aarch64")]
static ORT_DYLIB_BYTES: &[u8] = include_bytes!("../../model/lib/libonnxruntime-arm64.so");
#[cfg(target_arch = "x86_64")]
static ORT_DYLIB_BYTES: &[u8] = include_bytes!("../../model/lib/libonnxruntime-amd64.so");

/// CLIP ViT-B/32 图像塔 (int8 量化)
static VISION_MODEL_BYTES: &[u8] = include_bytes!("../../model/vision_model.onnx");

/// 预计算文本嵌入 + 题型标签配置 (runtime/embedding_builder.py 产出)
static TEXT_EMBEDDINGS_JSON: &str = include_str!("../embeddings.json");

const LOGIT_SCALE: f32 = 100.0;
const INPUT_SIZE: usize = 224;
const EMBED_DIM: usize = 512;
// CLIP 官方预处理参数 (preprocessor_config.json)
const MEAN: [f32; 3] = [0.481_454_66, 0.457_827_5, 0.408_210_73];
const STD: [f32; 3] = [0.268_629_54, 0.261_302_58, 0.275_777_11];

pub struct TypeSpec {
    pub positive: Vec<String>,
    pub negative: Vec<String>,
    pub threshold: f32,
    pub singular: bool,
}

struct Engine {
    session: Mutex<ort::session::Session>,
    specs: HashMap<String, TypeSpec>,
    /// 归一化文本嵌入 (512 维)
    texts: HashMap<String, Vec<f32>>,
}

static ENGINE: OnceLock<Engine> = OnceLock::new();

fn models_dir() -> PathBuf {
    crate::storage::data_dir().join("models")
}

/// 确保引擎就绪 (落盘内嵌资源 + 初始化 session)。线程安全, 幂等。
pub fn ensure_engine() -> Result<(), String> {
    if ENGINE.get().is_some() {
        return Ok(());
    }
    let dir = models_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir models: {e}"))?;

    let dylib_path = dir.join("libonnxruntime.so");
    if !dylib_path.exists() {
        std::fs::write(&dylib_path, ORT_DYLIB_BYTES).map_err(|e| format!("write dylib: {e}"))?;
    }
    let model_path = dir.join("clip-vision-vit-b32-int8.onnx");
    if !model_path.exists() {
        std::fs::write(&model_path, VISION_MODEL_BYTES)
            .map_err(|e| format!("write vision model: {e}"))?;
    }

    // ORT_DYLIB_PATH 在首次 ort API 调用时读取 (lib.rs setup_api), 必须先设
    if std::env::var("ORT_DYLIB_PATH").map(|v| v.is_empty()).unwrap_or(true) {
        std::env::set_var("ORT_DYLIB_PATH", &dylib_path);
    }

    // ort builder 的错误类型是 Error<SessionBuilder> (可恢复), 逐步 map_err 避开 and_then 类型不匹配
    let b = ort::session::Session::builder().map_err(|e| format!("ort builder: {e}"))?;
    let b = b
        .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
        .map_err(|e| format!("ort opt level: {e}"))?;
    let mut b = b.with_intra_threads(4).map_err(|e| format!("ort threads: {e}"))?;
    let session = b.commit_from_file(&model_path).map_err(|e| format!("ort session init: {e}"))?;

    // 解析预计算嵌入
    let raw: Value = serde_json::from_str(TEXT_EMBEDDINGS_JSON).map_err(|e| format!("parse embeddings: {e}"))?;
    let mut texts = HashMap::new();
    for (t, arr) in raw["texts"].as_object().ok_or("texts not object")? {
        let v: Vec<f32> = arr
            .as_array()
            .ok_or("embedding not array")?
            .iter()
            .map(|x| x.as_f64().unwrap_or(0.0) as f32)
            .collect();
        if v.len() != EMBED_DIM {
            return Err(format!("embedding dim {} != {EMBED_DIM}", v.len()));
        }
        texts.insert(t.clone(), v);
    }
    let mut specs = HashMap::new();
    for (k, v) in raw["types"].as_object().ok_or("types not object")? {
        let get_arr = |name: &str| -> Vec<String> {
            v[name]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };
        specs.insert(
            k.clone(),
            TypeSpec {
                positive: get_arr("positive"),
                negative: get_arr("negative"),
                threshold: v["threshold"].as_f64().unwrap_or(0.5) as f32,
                singular: v["singular"].as_bool().unwrap_or(false),
            },
        );
    }

    let _ = ENGINE.set(Engine { session: Mutex::new(session), specs, texts });
    Ok(())
}

fn engine() -> &'static Engine {
    ENGINE.get().expect("vision engine not initialized")
}

/// 图像 bytes (JPEG/PNG) → 归一化 NCHW f32 向量 (224×224)。
fn preprocess(bytes: &[u8]) -> Result<Vec<f32>, String> {
    let img = image::load_from_memory(bytes).map_err(|e| format!("decode image: {e}"))?;
    let img = image::imageops::resize(
        &img.to_rgb8(),
        INPUT_SIZE as u32,
        INPUT_SIZE as u32,
        image::imageops::FilterType::CatmullRom,
    );
    let (w, h) = (img.width() as usize, img.height() as usize);
    let mut out = vec![0f32; 3 * INPUT_SIZE * INPUT_SIZE];
    for c in 0..3 {
        for y in 0..INPUT_SIZE.min(h) {
            for x in 0..INPUT_SIZE.min(w) {
                let px = img.get_pixel(x as u32, y as u32)[c] as f32;
                out[c * INPUT_SIZE * INPUT_SIZE + y * INPUT_SIZE + x] = (px / 255.0 - MEAN[c]) / STD[c];
            }
        }
    }
    Ok(out)
}

/// 批量图像 → [N, 512] 归一化嵌入。
pub fn embed_images(images: &[(String, Vec<u8>)]) -> Result<Vec<[f32; EMBED_DIM]>, String> {
    ensure_engine()?;
    let eng = engine();
    if images.is_empty() {
        return Ok(vec![]);
    }
    let n = images.len();
    let mut data = Vec::with_capacity(n * 3 * INPUT_SIZE * INPUT_SIZE);
    for (name, bytes) in images {
        let one = preprocess(bytes).map_err(|e| format!("{name}: {e}"))?;
        data.extend(one);
    }
    let shape = vec![n as i64, 3, INPUT_SIZE as i64, INPUT_SIZE as i64];
    let tensor = ort::value::Tensor::from_array((shape, data)).map_err(|e| format!("tensor: {e}"))?;

    let mut session = eng.session.lock().unwrap_or_else(|p| p.into_inner());
    let outputs = session
        .run(ort::inputs!["pixel_values" => tensor])
        .map_err(|e| format!("run: {e}"))?;
    // try_extract_tensor 无需 ndarray feature, 返回 (shape, &[f32]) 平铺数据
    let (shape, flat) = outputs["image_embeds"]
        .try_extract_tensor::<f32>()
        .map_err(|e| format!("extract: {e}"))?;
    if flat.len() < n * EMBED_DIM {
        return Err(format!("output size {} < {n}×{EMBED_DIM} (shape {shape:?})", flat.len()));
    }

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut e = [0f32; EMBED_DIM];
        e.copy_from_slice(&flat[i * EMBED_DIM..(i + 1) * EMBED_DIM]);
        let norm = e.iter().map(|x| x * x).sum::<f32>().sqrt().max(1e-8);
        for x in &mut e {
            *x /= norm;
        }
        out.push(e);
    }
    Ok(out)
}

/// 一组 tile 的分类结果 (对齐原版 classify_tiles_binary_prompt_groups)。
pub struct TileScore {
    pub positive_score: f32,
    pub negative_score: f32,
    pub margin: f32,
}

/// 对题型 `type_key` 分类: 输入归一化 tile 嵌入, 输出每 tile 的 pos/neg/margin。
/// 数学: logits = 100 × cos(tile, text), softmax 过文本轴 (对齐原版 logits_per_image.softmax)。
pub fn classify(type_key: &str, tile_embeds: &[[f32; EMBED_DIM]]) -> Result<Vec<TileScore>, String> {
    let eng = engine();
    let spec = eng.specs.get(type_key).ok_or(format!("unknown type {type_key}"))?;
    let labels: Vec<&String> = spec.positive.iter().chain(spec.negative.iter()).collect();
    let pos_end = spec.positive.len();

    // 文本嵌入矩阵
    let mut tmat = Vec::with_capacity(labels.len() * EMBED_DIM);
    for l in &labels {
        let e = eng.texts.get(*l).ok_or(format!("missing embedding for {l}"))?;
        tmat.extend_from_slice(e);
    }
    let n_texts = labels.len();

    let mut out = Vec::with_capacity(tile_embeds.len());
    for te in tile_embeds {
        // logits = 100 × cos
        let mut logits = Vec::with_capacity(n_texts);
        for j in 0..n_texts {
            let dot: f32 = (0..EMBED_DIM).map(|d| te[d] * tmat[j * EMBED_DIM + d]).sum();
            logits.push(dot * LOGIT_SCALE);
        }
        // softmax over texts
        let maxl = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let exps: Vec<f32> = logits.iter().map(|l| (l - maxl).exp()).collect();
        let sum: f32 = exps.iter().sum();
        let probs: Vec<f32> = exps.iter().map(|e| e / sum).collect();
        let pos = probs[..pos_end].iter().cloned().fold(0f32, f32::max);
        let neg = probs[pos_end..].iter().cloned().fold(0f32, f32::max);
        out.push(TileScore { positive_score: pos, negative_score: neg, margin: pos - neg });
    }
    Ok(out)
}

pub fn spec_of(type_key: &str) -> Option<&'static TypeSpec> {
    engine().specs.get(type_key)
}

/// 生成点击集 (对齐原版 build_candidate_click_sets)。
/// 返回按优先级排列的多套候选 (tile 索引组), attempt 轮换使用。
pub fn build_click_sets(scores: &[TileScore], singular: bool, threshold: f32) -> Vec<Vec<usize>> {
    let mut ranked: Vec<usize> = (0..scores.len()).collect();
    ranked.sort_by(|&a, &b| {
        scores[b]
            .margin
            .partial_cmp(&scores[a].margin)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(
                scores[b]
                    .positive_score
                    .partial_cmp(&scores[a].positive_score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    let strong: Vec<usize> = ranked
        .iter()
        .cloned()
        .filter(|&i| scores[i].positive_score >= threshold && scores[i].positive_score > scores[i].negative_score)
        .collect();
    let medium_thr = (0.35f32).max(threshold - 0.15);
    let medium: Vec<usize> = ranked.iter().cloned().filter(|&i| scores[i].positive_score >= medium_thr).collect();

    let mut sets: Vec<Vec<usize>> = Vec::new();
    let mut push = |s: Vec<usize>| {
        if !s.is_empty() && !sets.contains(&s) {
            sets.push(s);
        }
    };
    if singular {
        for &i in ranked.iter().take(4.min(ranked.len())) {
            push(vec![i]);
        }
        if let Some(&first) = strong.first() {
            push(vec![first]);
        }
        return sets;
    }
    if !strong.is_empty() {
        push(strong.clone());
    }
    if !medium.is_empty() {
        push(medium.iter().take(3.min(medium.len())).cloned().collect());
    }
    if let Some(&first) = ranked.first() {
        push(vec![first]);
    }
    if ranked.len() >= 2 {
        push(ranked.iter().take(2).cloned().collect());
    }
    if ranked.len() >= 3 {
        push(ranked.iter().take(3).cloned().collect());
    }
    sets
}

/// 按提示词路由题型 (对齐原版 is_*_prompt 表, 顺序敏感)。
pub fn route_type(prompt: &str) -> Option<&'static str> {
    let p = prompt.to_lowercase();
    // 1. water travel (须在 drag 之前)
    if p.contains("water travel")
        || p.contains("operate on water")
        || (p.contains("vehicle") && p.contains("water"))
    {
        return Some("water_travel");
    }
    // 2. drag 类 (Phase 2; Phase 1 返回 None 触发 refresh)
    if p.contains("drag")
        || (p.contains("drop") && (p.contains("pair") || p.contains("image") || p.contains("match")))
        || p.contains("complete the pair")
        || p.contains("complete the image")
        || p.contains("missing piece")
    {
        return None;
    }
    // 3. float on water
    if p.contains("float") && p.contains("water") {
        return Some("float_on_water");
    }
    // 4. heat/work
    if p.contains("heat") && (p.contains("work") || p.contains("produce")) {
        return Some("heat_work");
    }
    // 5. served hot
    if p.contains("served hot") || (p.contains("hot") && p.contains("food")) {
        return Some("hot_food");
    }
    // 6. hop/jump animals
    if (p.contains("hop") || p.contains("jump")) && (p.contains("animal") || p.contains("click")) {
        return Some("hop_animals");
    }
    // 7. shiny
    if p.contains("shiny") {
        return Some("shiny_thing");
    }
    // 8. kept outside
    if p.contains("outside") || p.contains("outdoors") {
        return Some("kept_outside");
    }
    // 9. dissolve/melt
    if (p.contains("dissolve") || p.contains("melt")) && p.contains("water") {
        return Some("dissolve_melt");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_type_matches_original_table() {
        assert_eq!(route_type("Please click on each vehicle that is made for water travel"), Some("water_travel"));
        assert_eq!(route_type("please select the object that can operate on water"), Some("water_travel"));
        // drag 类 Phase 1 不支持 → None (触发 refresh)
        assert_eq!(route_type("Please drag the object to complete the pair"), None);
        assert_eq!(route_type("drag the missing piece into place"), None);
        assert_eq!(route_type("Please click on the object that can float on water"), Some("float_on_water"));
        assert_eq!(route_type("click the item that is served hot"), Some("hot_food"));
        assert_eq!(route_type("select the shiny thing"), Some("shiny_thing"));
        assert_eq!(route_type("pick the item typically kept outside"), Some("kept_outside"));
        assert_eq!(route_type("click each object that can dissolve or melt in water"), Some("dissolve_melt"));
        assert_eq!(route_type("click the animals that hop or jump"), Some("hop_animals"));
        // road completion 关键词排在 drag 后但不能被 "complete" 误吞
        assert_eq!(route_type("complete the road to the finish line"), None);
    }

    #[test]
    fn build_click_sets_singular_vs_multi() {
        let mk = |p: f32, n: f32| TileScore { positive_score: p, negative_score: n, margin: p - n };
        // 9 tile: 0,1,2 强阳性; 3 中等; 其余阴性
        let scores: Vec<TileScore> = (0..9)
            .map(|i| match i {
                0 => mk(0.80, 0.05),
                1 => mk(0.70, 0.10),
                2 => mk(0.60, 0.15),
                3 => mk(0.40, 0.20),
                _ => mk(0.10, 0.50),
            })
            .collect();
        let multi = build_click_sets(&scores, false, 0.55);
        assert!(!multi.is_empty());
        assert_eq!(multi[0], vec![0, 1, 2]); // strong 集优先
        let single = build_click_sets(&scores, true, 0.55);
        assert_eq!(single[0], vec![0]); // 单选最高分优先
        assert!(single.len() >= 4); // 单选给多套候选
    }

    #[test]
    fn engine_full_pipeline_selfcheck() {
        // 全链路自检: 内嵌模型落盘 + dylib 加载 + 嵌入解析 + 空分类
        ensure_engine().expect("engine init");
        let eng = engine();
        assert!(!eng.specs.is_empty(), "types spec parsed");
        assert!(eng.specs.contains_key("water_travel"));
        assert!(!eng.texts.is_empty(), "text embeddings parsed");
        // 验证标签嵌入齐全
        for (k, spec) in &eng.specs {
            for t in spec.positive.iter().chain(spec.negative.iter()) {
                assert!(eng.texts.contains_key(t), "missing embedding {t} in {k}");
            }
        }
    }
}
