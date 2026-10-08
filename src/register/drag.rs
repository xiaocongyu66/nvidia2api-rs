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
    if p.contains("missing piece")
        || p.contains("complete the image")
        || p.contains("complete the puzzle")
        || p.contains("framed pieces")
    {
        return Some("missing_pieces_drag");
    }
    if p.contains("letter") {
        return Some("letter_fill");
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
        Some("letter_fill") => solve_letter_fill(px, w, h),
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

// ---------------------------------------------------------------------------
// 3x3 网格自动检测 (截图模式) — 从像素实测 tile 位置, 不依赖猜测布局常量。
// 原理: tile 之间是低方差的白色缝隙, tile 内容是高方差区 →
//       逐列/逐行灰度 std, 找 3 个等距高方差带 (对齐原版 detect_label_grid)。
// ---------------------------------------------------------------------------

/// 一维 std 序列上找 count 个内容带 (超过均值为带, 合并相邻, 按宽排序取前 count)
fn runs_above(values: &[f32], count: usize) -> Option<Vec<(usize, usize)>> {
    let mean = values.iter().sum::<f32>() / values.len() as f32;
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &v) in values.iter().enumerate() {
        if v > mean {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            runs.push((s, i - 1));
        }
    }
    if let Some(s) = start.take() {
        runs.push((s, values.len() - 1));
    }
    if runs.len() < count {
        return None;
    }
    // 合并窄缝 (<4px) 分隔的带
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for r in runs {
        if let Some(last) = merged.last_mut() {
            if r.0 - last.1 <= 4 {
                last.1 = r.1;
                continue;
            }
        }
        merged.push(r);
    }
    if merged.len() < count {
        return None;
    }
    let mut by_w = merged.clone();
    by_w.sort_by_key(|(a, b)| std::cmp::Reverse(b - a + 1));
    let mut picked: Vec<(usize, usize)> = by_w.into_iter().take(count).collect();
    picked.sort();
    // 等距校验: 带宽相近 (最大/最小 > 0.55) 且间距均匀
    let widths: Vec<usize> = picked.iter().map(|(a, b)| b - a + 1).collect();
    let wmin = *widths.iter().min()?;
    let wmax = *widths.iter().max()?;
    if wmax == 0 || (wmin as f32 / wmax as f32) < 0.55 {
        return None;
    }
    Some(picked)
}

/// 在 RGB 图上检测 3x3 网格, 返回 (x0, y0, tile_w) — 每带取中点的等距网格。
/// 未检出时返回 None (调用方退回常量)。
pub fn detect_grid_3x3(px: &[u8], w: usize, h: usize) -> Option<(f64, f64, f64)> {
    // 灰度
    let gray: Vec<f32> = (0..w * h)
        .map(|i| {
            let p = &px[i * 3..i * 3 + 3];
            0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32
        })
        .collect();

    // 列 std (垂直采样中段, 避开 prompt 区与按钮区)
    let y_a = h * 30 / 100;
    let y_b = h * 75 / 100;
    let mut col_std = vec![0f32; w];
    for x in 0..w {
        let mut s = 0f64;
        let mut s2 = 0f64;
        let n = (y_b - y_a) as f64;
        for y in y_a..y_b {
            let g = gray[y * w + x] as f64;
            s += g;
            s2 += g * g;
        }
        col_std[x] = ((s2 - s * s / n).max(0.0) / n).sqrt() as f32;
    }
    let col_runs = runs_above(&col_std, 3)?;

    // 行 std (在检测到的列带范围内采样)
    let x_a = col_runs[0].0;
    let x_b = col_runs[2].1;
    let mut row_std = vec![0f32; h];
    for y in 0..h {
        let mut s = 0f64;
        let mut s2 = 0f64;
        let n = (x_b - x_a + 1) as f64;
        for x in x_a..=x_b {
            let g = gray[y * w + x] as f64;
            s += g;
            s2 += g * g;
        }
        row_std[y] = ((s2 - s * s / n).max(0.0) / n).sqrt() as f32;
    }
    let row_runs = runs_above(&row_std, 3)?;

    // 网格: tile 中心 = 带中心; 边长 = 带宽 (内容带比 tile 略窄, 加半缝修正)
    let cx = |r: (usize, usize)| (r.0 + r.1) as f64 / 2.0;
    let tile_w = (cx(col_runs[2]) - cx(col_runs[0])) / 2.0 * 1.04;
    let tile_h = (cx(row_runs[2]) - cx(row_runs[0])) / 2.0 * 1.04;
    let tile = (tile_w + tile_h) / 2.0;
    Some((cx(col_runs[0]), cx(row_runs[0]), tile))
}

// ---------------------------------------------------------------------------
// letter_fill 题型 — "Drag the letters below to fill in the blank":
// 深蓝背景上白色字母 + 白色短横空白。与 pair_drag 布局完全不同
// (字母不在左列、空白在右), 用亮度分割找两类组件。
// ---------------------------------------------------------------------------

pub fn solve_letter_fill(px: &[u8], w: usize, h: usize) -> Result<DragSolution, String> {
    // 排除顶部 prompt 文字与底部按钮条 (均在画布上下边缘带)
    let y_lo = (h as f32 * 0.16) as usize;
    let y_hi = (h as f32 * 0.88) as usize;

    let mut bright = vec![false; w * h];
    for y in y_lo..y_hi {
        for x in 0..w {
            let i = (y * w + x) * 3;
            let (r, g, b) = (px[i] as u32, px[i + 1] as u32, px[i + 2] as u32);
            let v = r.max(g).max(b);
            let mn = r.min(g).min(b);
            if v > 180 && v - mn < 50 {
                bright[y * w + x] = true;
            }
        }
    }
    let bright = morph_open(&bright, w, h, 3);
    let comps = connected_components(&bright, w, h, 60);
    if comps.is_empty() {
        return Err("letter_fill: 未检出亮色对象".into());
    }

    // 空白横线: 宽扁条 (高 ≤18, 宽高比 ≥2.8)
    let bar = comps
        .iter()
        .filter(|c| c.h <= 18 && c.w >= 25 && c.w as f32 / c.h.max(1) as f32 >= 2.8)
        .max_by_key(|c| c.w);
    // 字母: 近方块组件 (高 14..70), 排除横线自身 (h14-18 的粗横线会双重命中)
    let bar_xy = bar.map(|b| (b.x, b.y));
    let letter = comps
        .iter()
        .filter(|c| {
            Some((c.x, c.y)) != bar_xy
                && c.h >= 14
                && c.h <= 70
                && (c.w as f32 / c.h.max(1) as f32) > 0.3
                && (c.w as f32 / c.h.max(1) as f32) < 3.0
        })
        .max_by_key(|c| c.area);

    let bar = bar.ok_or_else(|| format!("letter_fill: 未识别空白横线 (comps={})", comps.len()))?;
    let letter =
        letter.ok_or_else(|| format!("letter_fill: 未识别字母 (comps={})", comps.len()))?;

    Ok(DragSolution {
        from: (letter.cx as f64, letter.cy as f64),
        to: (bar.cx as f64, bar.cy as f64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letter_fill_synthetic() {
        let (w, h) = (520usize, 409usize);
        let mut px = vec![0u8; w * h * 3];
        // 深蓝背景
        for p in px.chunks_mut(3) {
            p.copy_from_slice(&[20, 45, 90]);
        }
        let mut put = |x: usize, y: usize| {
            let i = (y * w + x) * 3;
            px[i] = 245;
            px[i + 1] = 245;
            px[i + 2] = 248;
        };
        // 顶部伪 prompt 文字带 (应被 y_lo 排除; 若误入会被当成更宽的横线)
        for y in 8..20 {
            for x in 50..470 {
                put(x, y);
            }
        }
        // 白色字母 "A" 轮廓 28x28, 中心 (299, 134)
        for y in 120..148 {
            for x in 285..313 {
                if y < 123 || y > 145 || x < 288 || x > 310 {
                    put(x, y);
                }
            }
        }
        // 白色横线 36x12, 中心 (468, 118)
        for y in 112..124 {
            for x in 450..486 {
                put(x, y);
            }
        }
        // 底部伪按钮 (应被 y_hi 排除)
        for y in 396..406 {
            for x in 380..500 {
                put(x, y);
            }
        }

        let sol = solve("Drag the letters below to fill in the blank", &px, w, h).unwrap();
        assert!(
            (sol.from.0 - 299.0).abs() < 6.0 && (sol.from.1 - 134.0).abs() < 6.0,
            "from={:?}",
            sol.from
        );
        assert!(
            (sol.to.0 - 468.0).abs() < 6.0 && (sol.to.1 - 118.0).abs() < 6.0,
            "to={:?}",
            sol.to
        );
    }

    #[test]
    fn route_letter_before_drag() {
        assert_eq!(
            route_drag("Drag the letter to the place where it fits"),
            Some("letter_fill")
        );
        assert_eq!(route_drag("Drag the matching shape into the hole"), Some("pair_drag"));
    }
}
