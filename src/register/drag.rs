//! Phase 2 — 拖拽题型求解 (pair_drag / missing_pieces)。
//!
//! 算法移植自原版 solver: 挑战 canvas 截图 → 饱和度列评分找左右分界 →
//! 右侧颜色/背景差掩码找源图块 → 左侧连通组件 + 同色像素计数定位缺块 →
//! 完整组件 skeleton 与缺块 skeleton 的 IoU 匹配 → 相对位置推算落点。
//! 全部 CV 原语手写 (无 OpenCV 依赖): 形态学/连通组件/PCA 主轴/掩码 IoU。

use image::RgbImage;

pub struct DragSolution {
    /// 起点 (canvas 内像素坐标)
    pub from: (f64, f64),
    /// 落点 (canvas 内像素坐标)
    pub to: (f64, f64),
}

struct Comp {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    area: usize,
    cx: f32,
    cy: f32,
    /// box 内掩码 (w*h)
    mask: Vec<bool>,
}

// ---------------------------------------------------------------------------
// CV 原语
// ---------------------------------------------------------------------------

fn median_f32(v: &mut Vec<f32>) -> f32 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

/// 矩形核腐蚀 (k 为核边长, 奇数)
fn erode(mask: &[bool], w: usize, h: usize, k: usize) -> Vec<bool> {
    let r = k / 2;
    let mut out = vec![false; w * h];
    for y in r..h.saturating_sub(r) {
        for x in r..w.saturating_sub(r) {
            let mut all = true;
            'outer: for dy in 0..k {
                for dx in 0..k {
                    if !mask[(y + dy - r) * w + (x + dx - r)] {
                        all = false;
                        break 'outer;
                    }
                }
            }
            out[y * w + x] = all;
        }
    }
    out
}

/// 矩形核膨胀
fn dilate(mask: &[bool], w: usize, h: usize, k: usize) -> Vec<bool> {
    let r = k / 2;
    let mut out = vec![false; w * h];
    for y in 0..h {
        for x in 0..w {
            let mut any = false;
            'outer: for dy in 0..k {
                let sy = y as isize + dy as isize - r as isize;
                if sy < 0 || sy >= h as isize {
                    continue;
                }
                for dx in 0..k {
                    let sx = x as isize + dx as isize - r as isize;
                    if sx < 0 || sx >= w as isize {
                        continue;
                    }
                    if mask[sy as usize * w + sx as usize] {
                        any = true;
                        break 'outer;
                    }
                }
            }
            out[y * w + x] = any;
        }
    }
    out
}

/// 开运算 = 腐蚀 + 膨胀 (去小噪点)
fn morph_open(mask: &[bool], w: usize, h: usize, k: usize) -> Vec<bool> {
    dilate(&erode(mask, w, h, k), w, h, k)
}

/// 4/8 邻接连通组件 (BFS), 过滤 min_area
fn connected_components(mask: &[bool], w: usize, h: usize, min_area: usize) -> Vec<Comp> {
    let mut seen = vec![false; w * h];
    let mut out = Vec::new();
    for start in 0..w * h {
        if !mask[start] || seen[start] {
            continue;
        }
        let mut stack = vec![start];
        seen[start] = true;
        let mut pixels: Vec<usize> = Vec::new();
        while let Some(p) = stack.pop() {
            pixels.push(p);
            let px = p % w;
            let py = p / w;
            for (dx, dy) in [(1isize, 0isize), (-1, 0), (0, 1), (0, -1), (1, 1), (-1, -1), (1, -1), (-1, 1)] {
                let nx = px as isize + dx;
                let ny = py as isize + dy;
                if nx < 0 || ny < 0 || nx >= w as isize || ny >= h as isize {
                    continue;
                }
                let np = ny as usize * w + nx as usize;
                if mask[np] && !seen[np] {
                    seen[np] = true;
                    stack.push(np);
                }
            }
        }
        if pixels.len() < min_area {
            continue;
        }
        let mut minx = w;
        let mut miny = h;
        let mut maxx = 0;
        let mut maxy = 0;
        let mut sx = 0f64;
        let mut sy = 0f64;
        for &p in &pixels {
            let x = p % w;
            let y = p / w;
            minx = minx.min(x);
            miny = miny.min(y);
            maxx = maxx.max(x);
            maxy = maxy.max(y);
            sx += x as f64;
            sy += y as f64;
        }
        let bw = maxx - minx + 1;
        let bh = maxy - miny + 1;
        let mut m = vec![false; bw * bh];
        for &p in &pixels {
            m[(p / w - miny) * bw + (p % w - minx)] = true;
        }
        out.push(Comp {
            x: minx as i32,
            y: miny as i32,
            w: bw as i32,
            h: bh as i32,
            area: pixels.len(),
            cx: (sx / pixels.len() as f64) as f32,
            cy: (sy / pixels.len() as f64) as f32,
            mask: m,
        });
    }
    out
}

/// 像素级最近邻缩放 (布尔掩码)
fn resize_mask(m: &[bool], w: usize, h: usize, nw: usize, nh: usize) -> Vec<bool> {
    let mut out = vec![false; nw * nh];
    for y in 0..nh {
        let sy = y * h / nh;
        for x in 0..nw {
            let sx = x * w / nw;
            out[y * nw + x] = m[sy * w + sx];
        }
    }
    out
}

fn mask_iou(a: &[bool], b: &[bool]) -> f32 {
    let mut inter = 0usize;
    let mut union = 0usize;
    for i in 0..a.len().min(b.len()) {
        if a[i] && b[i] {
            inter += 1;
        }
        if a[i] || b[i] {
            union += 1;
        }
    }
    inter as f32 / union.max(1) as f32
}

/// PCA 主轴角度 (用于形状匹配的惩罚项)
fn pca_angle(c: &Comp) -> f32 {
    let mut sxx = 0f64;
    let mut syy = 0f64;
    let mut sxy = 0f64;
    let n = c.mask.len() as f64;
    for y in 0..c.h as usize {
        for x in 0..c.w as usize {
            if c.mask[y * c.w as usize + x] {
                let dx = x as f64 - c.cx as f64;
                let dy = y as f64 - c.cy as f64;
                sxx += dx * dx;
                syy += dy * dy;
                sxy += dx * dy;
            }
        }
    }
    let _ = n;
    0.5 * (2.0 * sxy).atan2(sxx - syy) as f32
}

fn angle_delta(a: f32, b: f32) -> f32 {
    let d = (a - b).abs() % std::f32::consts::PI;
    d.min(std::f32::consts::PI - d)
}

// ---------------------------------------------------------------------------
// 画布预处理 (对齐原版 extract_visible_canvas)
// ---------------------------------------------------------------------------

/// 裁掉顶部暗行 (行均值 <= 30), 返回 (rgb, w, h, y_offset)
fn extract_visible(px: &[u8], w: usize, h: usize) -> (Vec<u8>, usize, usize, usize) {
    let mut y0 = 0usize;
    for y in 0..h {
        let mut sum = 0f64;
        for x in 0..w {
            let i = (y * w + x) * 3;
            sum += (px[i] as u32 + px[i + 1] as u32 + px[i + 2] as u32) as f64 / 3.0;
        }
        if sum / w as f64 > 30.0 {
            y0 = y;
            break;
        }
    }
    let nh = h - y0;
    (px[y0 * w * 3..].to_vec(), w, nh, y0)
}

// ---------------------------------------------------------------------------
// pair_drag (字母/配对拖拽) — 对齐原版 solve_pair_drag
// ---------------------------------------------------------------------------

pub fn solve_pair_drag(px: &[u8], w: usize, h: usize) -> Result<DragSolution, String> {
    let (vis, w, h, y_off) = extract_visible(px, w, h);

    // 1. 饱和度列评分 → 分界线
    let sat: Vec<f32> = (0..w * h)
        .map(|i| {
            let r = vis[i * 3] as f32;
            let g = vis[i * 3 + 1] as f32;
            let b = vis[i * 3 + 2] as f32;
            r.max(g).max(b) - r.min(g).min(b)
        })
        .collect();

    let x_lo = (w as f32 * 0.45) as usize;
    let x_hi = (w as f32 * 0.8) as usize;
    let col_score = |x: usize| -> f32 {
        let mut s = 0f32;
        for y in 0..h {
            s += sat[y * w + x];
        }
        s / h as f32
    };
    let mut split = x_lo;
    let mut best = f32::MAX;
    for x in x_lo..x_hi.min(w) {
        let s = col_score(x);
        if s < best {
            best = s;
            split = x;
        }
    }

    // 2. 右侧找源图块 (最大连通组件)
    let rw = w - split;
    let mut right_bg = [0f32; 3];
    {
        let mut chans = [Vec::new(), Vec::new(), Vec::new()];
        for y in 0..50.min(h) {
            for x in 0..50.min(rw) {
                let i = (y * w + split + x) * 3;
                for c in 0..3 {
                    chans[c].push(vis[i + c] as f32);
                }
            }
        }
        for c in 0..3 {
            right_bg[c] = median_f32(&mut chans[c]);
        }
    }
    let mut src_mask = vec![false; rw * h];
    for y in 0..h {
        for x in 0..rw {
            let gi = y * w + split + x;
            let i = gi * 3;
            let s = sat[gi];
            let d = (vis[i] as f32 - right_bg[0]).abs()
                + (vis[i + 1] as f32 - right_bg[1]).abs()
                + (vis[i + 2] as f32 - right_bg[2]).abs();
            src_mask[y * rw + x] = s > 20.0 && d > 25.0;
        }
    }
    let src_mask = morph_open(&src_mask, rw, h, 5);
    let src_comps = connected_components(&src_mask, rw, h, 1);
    let src = src_comps
        .iter()
        .max_by_key(|c| c.area)
        .ok_or("右侧 source object 未识别到")?;

    // 源图块平均色
    let mut src_mean = [0f64; 3];
    {
        let mut cnt = 0usize;
        for yy in 0..src.h as usize {
            for xx in 0..src.w as usize {
                if src.mask[yy * src.w as usize + xx] {
                    let gi = ((src.y as usize + yy) * w + split + src.x as usize + xx) * 3;
                    for c in 0..3 {
                        src_mean[c] += vis[gi + c] as f64;
                    }
                    cnt += 1;
                }
            }
        }
        if cnt > 0 {
            for c in 0..3 {
                src_mean[c] /= cnt as f64;
            }
        }
    }

    // 3. 左侧: 同色像素 + 目标组件
    let lw = split;
    let mut src_like = vec![false; lw * h];
    for y in 0..h {
        for x in 0..lw {
            let i = (y * w + x) * 3;
            let d = ((vis[i] as f64 - src_mean[0]).powi(2)
                + (vis[i + 1] as f64 - src_mean[1]).powi(2)
                + (vis[i + 2] as f64 - src_mean[2]).powi(2))
                .sqrt();
            src_like[y * lw + x] = d < 55.0;
        }
    }
    let src_like = morph_open(&src_like, lw, h, 3);

    let mut left_bg = [0f32; 3];
    {
        let mut chans = [Vec::new(), Vec::new(), Vec::new()];
        for y in 0..50.min(h) {
            for x in 0..50.min(lw) {
                let i = (y * w + x) * 3;
                for c in 0..3 {
                    chans[c].push(vis[i + c] as f32);
                }
            }
        }
        for c in 0..3 {
            left_bg[c] = median_f32(&mut chans[c]);
        }
    }
    let mut obj_mask = vec![false; lw * h];
    for y in 0..h {
        for x in 0..lw {
            let gi = y * w + x;
            let i = gi * 3;
            let s = sat[gi];
            let d = (vis[i] as f32 - left_bg[0]).abs()
                + (vis[i + 1] as f32 - left_bg[1]).abs()
                + (vis[i + 2] as f32 - left_bg[2]).abs();
            obj_mask[y * lw + x] = s > 20.0 && d > 25.0;
        }
    }
    let obj_mask = dilate(&obj_mask, lw, h, 9);
    let obj_mask = dilate(&obj_mask, lw, h, 9);
    let obj_mask = morph_open(&obj_mask, lw, h, 5);

    let mut comps = connected_components(&obj_mask, lw, h, 1500);
    if comps.len() < 2 {
        return Err(format!("左侧 object cluster 数量不足 ({})", comps.len()));
    }
    for c in &mut comps {
        c.mask = c.mask.clone();
    }
    // 每组件的 src_like 像素计数
    let src_pixels_of = |c: &Comp| -> usize {
        let mut n = 0;
        for yy in 0..c.h as usize {
            for xx in 0..c.w as usize {
                if c.mask[yy * c.w as usize + xx]
                    && src_like[(c.y as usize + yy) * lw + c.x as usize + xx]
                {
                    n += 1;
                }
            }
        }
        n
    };
    let (inc_i, _) = comps
        .iter()
        .enumerate()
        .map(|(i, c)| (i, src_pixels_of(c)))
        .min_by_key(|(_, n)| *n)
        .ok_or("组件扫描失败")?;
    let inc = &comps[inc_i];

    // 4. skeleton IoU 匹配最像的完整组件
    let extract_skeleton = |c: &Comp| -> (Vec<bool>, usize, usize, Vec<(usize, usize)>) {
        let cw = c.w as usize;
        let ch = c.h as usize;
        let mut skel = vec![false; cw * ch];
        let mut src_pts = Vec::new();
        for yy in 0..ch {
            for xx in 0..cw {
                let gi = (c.y as usize + yy) * lw + c.x as usize + xx;
                if c.mask[yy * cw + xx] && !src_like[gi] {
                    skel[yy * cw + xx] = true;
                }
                if c.mask[yy * cw + xx] && src_like[gi] {
                    src_pts.push((xx, yy));
                }
            }
        }
        (skel, cw, ch, src_pts)
    };

    let (inc_skel, iw, ih, _) = extract_skeleton(inc);
    let mut best_score = -1e9f32;
    let mut best_rel: Option<(f64, f64)> = None;
    for (ci, comp) in comps.iter().enumerate() {
        if ci == inc_i {
            continue;
        }
        let (skel, cw, ch, src_pts) = extract_skeleton(comp);
        if src_pts.is_empty() {
            continue;
        }
        let resized = resize_mask(&skel, cw, ch, iw, ih);
        let score = mask_iou(&resized, &inc_skel);
        let rel = (
            src_pts.iter().map(|p| p.0).sum::<usize>() as f64 / src_pts.len() as f64 / cw as f64,
            src_pts.iter().map(|p| p.1).sum::<usize>() as f64 / src_pts.len() as f64 / ch as f64,
        );
        let size_penalty = ((comp.w.max(1) as f64 / inc.w.max(1) as f64).ln().abs()
            + (comp.h.max(1) as f64 / inc.h.max(1) as f64).ln().abs()) as f32;
        let aspect_penalty = (((comp.w.max(1) as f64 / comp.h.max(1) as f64)
            / (inc.w.max(1) as f64 / inc.h.max(1) as f64))
            .ln()
            .abs()) as f32;
        let row_penalty =
            ((comp.cy - inc.cy).abs() / inc.h.max(comp.h).max(1) as f32) as f32;
        let adjusted = score - 0.20 * size_penalty - 0.20 * aspect_penalty - 0.15 * row_penalty;
        if adjusted > best_score {
            best_score = adjusted;
            best_rel = Some(rel);
        }
    }
    let rel = best_rel.ok_or("未找到可用于推算落点的完整 pair")?;

    // 5. 落点推算 (canvas 坐标, 加回 y_off)
    let target_x = inc.x as f64 + rel.0 * inc.w as f64;
    let target_y = inc.y as f64 + rel.1 * inc.h as f64;
    Ok(DragSolution {
        from: (split as f64 + src.cx as f64, src.cy as f64 + y_off as f64),
        to: (target_x, target_y + y_off as f64),
    })
}

// ---------------------------------------------------------------------------
// missing_pieces (拼图缺块) — 对齐原版 solve_missing_pieces_drag
// ---------------------------------------------------------------------------

pub fn solve_missing_pieces(px: &[u8], w: usize, h: usize) -> Result<DragSolution, String> {
    let (vis, w, h, y_off) = extract_visible(px, w, h);

    let sat: Vec<f32> = (0..w * h)
        .map(|i| {
            let r = vis[i * 3] as f32;
            let g = vis[i * 3 + 1] as f32;
            let b = vis[i * 3 + 2] as f32;
            r.max(g).max(b) - r.min(g).min(b)
        })
        .collect();

    let x_lo = (w as f32 * 0.45) as usize;
    let x_hi = (w as f32 * 0.8) as usize;
    let mut split = x_lo;
    let mut best = f32::MAX;
    for x in x_lo..x_hi.min(w) {
        let mut s = 0f32;
        for y in 0..h {
            s += sat[y * w + x];
        }
        s /= h as f32;
        if s < best {
            best = s;
            split = x;
        }
    }

    // 左侧: HSV 蓝色系找缺口槽位 (H 95-135, S>=25, V>=120 → 0-255 标度)
    let lw = split;
    let mut holes_mask = vec![false; lw * h];
    for y in 0..h {
        for x in 0..lw {
            let i = (y * w + x) * 3;
            let (r, g, b) = (vis[i] as f32, vis[i + 1] as f32, vis[i + 2] as f32);
            let mx = r.max(g).max(b);
            let mn = r.min(g).min(b);
            let v = mx;
            let s = if mx > 0.0 { (mx - mn) / mx * 255.0 } else { 0.0 };
            let hdeg = if mx == mn {
                0.0
            } else if mx == r {
                60.0 * ((g - b) / (mx - mn)) % 360.0
            } else if mx == g {
                60.0 * ((b - r) / (mx - mn)) + 120.0
            } else {
                60.0 * ((r - g) / (mx - mn)) + 240.0
            };
            let hdeg = if hdeg < 0.0 { hdeg + 360.0 } else { hdeg };
            holes_mask[y * lw + x] = (95.0..=135.0).contains(&hdeg) && s >= 25.0 && v >= 120.0;
        }
    }
    let holes_mask = morph_open(&holes_mask, lw, h, 5);
    let holes_mask = dilate(&holes_mask, lw, h, 7);
    let holes = connected_components(&holes_mask, lw, h, 2500);
    if holes.is_empty() {
        return Err("未识别到 missing piece 目标槽位".into());
    }

    // 右侧: 背景差+饱和度找图块
    let rw = w - split;
    let mut right_bg = [0f32; 3];
    {
        let mut chans = [Vec::new(), Vec::new(), Vec::new()];
        for y in 0..80.min(h) {
            for x in 0..80.min(rw) {
                let i = (y * w + split + x) * 3;
                for c in 0..3 {
                    chans[c].push(vis[i + c] as f32);
                }
            }
        }
        for c in 0..3 {
            right_bg[c] = median_f32(&mut chans[c]);
        }
    }
    let mut pieces_mask = vec![false; rw * h];
    for y in 0..h {
        for x in 0..rw {
            let gi = y * w + split + x;
            let i = gi * 3;
            let s = sat[gi];
            let d = (vis[i] as f32 - right_bg[0]).abs()
                + (vis[i + 1] as f32 - right_bg[1]).abs()
                + (vis[i + 2] as f32 - right_bg[2]).abs();
            pieces_mask[y * rw + x] = s > 25.0 && d > 45.0;
        }
    }
    let pieces_mask = morph_open(&pieces_mask, rw, h, 3);
    let pieces_mask = dilate(&pieces_mask, rw, h, 5);
    let pieces = connected_components(&pieces_mask, rw, h, 2500);
    if pieces.is_empty() {
        return Err("未识别到 missing piece 源图块".into());
    }

    // 匹配: 形状 IoU + 角度/面积/比例惩罚
    let mut best: Option<(f32, &Comp, &Comp)> = None;
    for piece in &pieces {
        for hole in &holes {
            let resized = resize_mask(&piece.mask, piece.w as usize, piece.h as usize, hole.w as usize, hole.h as usize);
            let iou = mask_iou(&resized, &hole.mask);
            let angle_d = angle_delta(pca_angle(piece), pca_angle(hole));
            let area_pen = ((piece.area.max(1) as f64 / hole.area.max(1) as f64).ln().abs()) as f32;
            let aspect_pen = (((piece.w.max(1) as f64 / piece.h.max(1) as f64)
                / (hole.w.max(1) as f64 / hole.h.max(1) as f64))
                .ln()
                .abs()) as f32;
            let score = iou - 0.06 * angle_d - 0.20 * area_pen - 0.12 * aspect_pen;
            if best.map(|(s, _, _)| score > s).unwrap_or(true) {
                best = Some((score, piece, hole));
            }
        }
    }
    let (_, piece, hole) = best.ok_or("未找到可用匹配对")?;

    Ok(DragSolution {
        from: (split as f64 + piece.cx as f64, piece.cy as f64 + y_off as f64),
        to: (hole.cx as f64, hole.cy as f64 + y_off as f64),
    })
}

/// 按提示词路由拖拽子类型
pub fn route_drag(prompt: &str) -> Option<&'static str> {
    let p = prompt.to_lowercase();
    if p.contains("missing piece") || p.contains("complete the image") {
        return Some("missing_pieces_drag");
    }
    if p.contains("drag") || p.contains("drop") {
        return Some("pair_drag");
    }
    None
}

/// 求解入口: 路由子类型 → 对应算法
pub fn solve(prompt: &str, px: &[u8], w: usize, h: usize) -> Result<DragSolution, String> {
    match route_drag(prompt) {
        Some("missing_pieces_drag") => solve_missing_pieces(px, w, h),
        _ => solve_pair_drag(px, w, h),
    }
}

/// PNG bytes → RGB 像素 + 尺寸
pub fn decode_png(bytes: &[u8]) -> Result<(Vec<u8>, usize, usize), String> {
    let img = image::load_from_memory(bytes).map_err(|e| format!("canvas 截图解码: {e}"))?;
    let rgb: RgbImage = img.to_rgb8();
    let (w, h) = (rgb.width() as usize, rgb.height() as usize);
    Ok((rgb.into_raw(), w, h))
}
