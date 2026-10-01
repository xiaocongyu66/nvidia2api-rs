//! 题库精确匹配: 下载的 tile 图与 data/train/<slug>/ 标注图做 aHash 比对,
//! 全部命中已标注图 → 直接用标注答案, 跳过 VLM (确定性与零延迟)。
//! 标注文件: data/train/<slug>/_labels.json — {"<tile文件名>": 1/0} (1=选, 0=不选)。

use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

/// aHash 64 位: 缩 8x8 灰度, 按均值阈值出位 (无新依赖, image crate 已有)。
fn ahash(png: &[u8]) -> Option<u64> {
    let img = image::load_from_memory(png).ok()?.to_luma8();
    let thumb = image::imageops::thumbnail(&img, 8, 8);
    let px: Vec<u8> = thumb.pixels().map(|p| p.0[0]).collect();
    let mean = px.iter().map(|v| *v as u32).sum::<u32>() / 64;
    let mut h = 0u64;
    for (i, v) in px.iter().enumerate() {
        if *v as u32 > mean {
            h |= 1 << i;
        }
    }
    Some(h)
}

fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

fn slug_of(prompt: &str) -> String {
    prompt
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
        .chars()
        .take(48)
        .collect()
}

/// 尝试题库匹配。返回 Some(应选 tile 序号列表) = 全部命中且已标注。
pub fn lookup(tiles: &[Vec<u8>], prompt: &str) -> Option<Vec<usize>> {
    if tiles.is_empty() || prompt.is_empty() {
        return None;
    }
    let dir = std::path::Path::new("data/train").join(slug_of(prompt));
    let labels_raw = std::fs::read_to_string(dir.join("_labels.json")).ok()?;
    let labels: HashMap<String, i32> = serde_json::from_str(&labels_raw).ok()?;
    if labels.is_empty() {
        return None;
    }
    // 库图 aHash 缓存在内存 (每进程一次)
    let mut cache = LIB_CACHE.lock().unwrap();
    if cache.dir.as_deref() != Some(dir.to_string_lossy().as_ref()) {
        let mut entries = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
                if ext != "png" && ext != "jpeg" && ext != "jpg" {
                    continue;
                }
                let name = p.file_name()?.to_string_lossy().to_string();
                let Some(idx) = name.split('_').next().and_then(|s| s.parse::<usize>().ok()) else {
                    continue;
                };
                let Some(h) = std::fs::read(&p).ok().and_then(|b| ahash(&b)) else {
                    continue;
                };
                entries.push((idx, h, name));
            }
        }
        *cache = LibCache {
            dir: Some(dir.to_string_lossy().to_string()),
            entries,
        };
    }
    // 每 tile 找库中最相似图 (距离 ≤ 10 视为同图)
    let mut answers = Vec::new();
    for t in tiles {
        let Some(th) = ahash(t) else { return None };
        let mut best: Option<(u32, i32)> = None;
        for (idx, h, name) in cache.entries.iter() {
            let d = hamming(th, *h);
            if d <= 10 {
                let Some(v) = labels.get(name) else { return None };
                match best {
                    Some((bd, _)) if bd <= d => {}
                    _ => best = Some((d, *v)),
                }
            }
        }
        let Some((_, v)) = best else { return None };
        answers.push((answers.len(), v));
    }
    let selected: Vec<usize> = answers
        .iter()
        .filter(|(_, v)| *v == 1)
        .map(|(i, _)| *i)
        .collect();
    println!(
        "[lib] 题库命中: {} tile 全匹配, 应选 {:?}",
        tiles.len(),
        selected
    );
    Some(selected)
}

struct LibCache {
    dir: Option<String>,
    entries: Vec<(usize, u64, String)>,
}

static LIB_CACHE: std::sync::Mutex<LibCache> = std::sync::Mutex::new(LibCache {
    dir: None,
    entries: Vec::new(),
});

/// prompt 是否为可静态标注的 "Select all images with X" 类 (无样例比较)。
pub fn static_labelable(prompt: &str) -> bool {
    let p = prompt.to_lowercase();
    (p.contains("select all") || p.contains("select the") || p.contains("pick the"))
        && !p.contains("this one")
        && !p.contains("sample")
        && !p.contains("mirror")
        && !p.contains("weighs")
}

pub fn debug_dump(data: &Value) {
    let _ = data;
}
