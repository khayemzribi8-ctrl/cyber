"""
Server-side SVG chart helpers.

Charts are rendered as inline SVG so the platform needs no charting library and
works fully offline / behind a proxy / without a CDN (spec §19, §35). Each
function returns an SVG string marked safe in templates.
"""
from __future__ import annotations

import math
from typing import Dict, List, Tuple

SEV_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
    "LOW": "#0891b2", "INFO": "#64748b", "OK": "#16a34a",
}


def _score_color(score: int) -> str:
    if score >= 80:
        return "#16a34a"
    if score >= 60:
        return "#d97706"
    if score >= 40:
        return "#ea580c"
    return "#dc2626"


def gauge(score: int, size: int = 150) -> str:
    """A 270-degree arc gauge for the security score."""
    r = size / 2 - 14
    cx = cy = size / 2
    start = 135
    sweep = 270
    color = _score_color(score)

    def pt(angle):
        a = math.radians(angle)
        return cx + r * math.cos(a), cy + r * math.sin(a)

    x0, y0 = pt(start)
    x1, y1 = pt(start + sweep)
    xv, yv = pt(start + sweep * min(max(score, 0), 100) / 100.0)
    laf = 1 if sweep > 180 else 0
    lafv = 1 if (sweep * score / 100.0) > 180 else 0
    return f'''<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" aria-label="Security score {score}">
  <path d="M {x0:.1f} {y0:.1f} A {r} {r} 0 {laf} 1 {x1:.1f} {y1:.1f}" fill="none" stroke="#e2e8f0" stroke-width="12" stroke-linecap="round"/>
  <path d="M {x0:.1f} {y0:.1f} A {r} {r} 0 {lafv} 1 {xv:.1f} {yv:.1f}" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round"/>
  <text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="30" font-weight="800" fill="#0f172a">{score}</text>
  <text x="{cx}" y="{cy+18}" text-anchor="middle" font-size="11" fill="#64748b">/ 100</text>
</svg>'''


def donut(segments: List[Tuple[str, int]], size: int = 150, thickness: int = 20) -> str:
    """Risk distribution donut. segments = [(severity, count), ...]."""
    total = sum(v for _, v in segments) or 1
    r = size / 2 - thickness / 2 - 2
    cx = cy = size / 2
    circ = 2 * math.pi * r
    offset = 0.0
    arcs = []
    for label, val in segments:
        if val <= 0:
            continue
        frac = val / total
        dash = frac * circ
        color = SEV_COLORS.get(label, "#94a3b8")
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{color}" '
            f'stroke-width="{thickness}" stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 {cx} {cy})"/>'
        )
        offset += dash
    open_total = sum(v for k, v in segments if k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    return f'''<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" aria-label="Risk distribution">
  <circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="#f1f5f9" stroke-width="{thickness}"/>
  {''.join(arcs)}
  <text x="{cx}" y="{cy-2}" text-anchor="middle" font-size="24" font-weight="800" fill="#0f172a">{open_total}</text>
  <text x="{cx}" y="{cy+16}" text-anchor="middle" font-size="10" fill="#64748b">findings</text>
</svg>'''


def sparkline(values: List[float], width: int = 220, height: int = 48,
              color: str = "#4f46e5", fill: bool = True) -> str:
    if not values:
        values = [0]
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    n = len(values)
    step = width / max(n - 1, 1)
    pts = [(i * step, height - 4 - (v - lo) / span * (height - 8)) for i, v in enumerate(values)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = ""
    if fill and n > 1:
        area = (f'<polygon points="0,{height} {line} {width},{height}" '
                f'fill="{color}" opacity="0.08"/>')
    dots = f'<circle cx="{pts[-1][0]:.1f}" cy="{pts[-1][1]:.1f}" r="3" fill="{color}"/>'
    return f'''<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" preserveAspectRatio="none" role="img">
  {area}<polyline points="{line}" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>{dots}
</svg>'''


def hbars(rows: List[Tuple[str, int, str]], max_val: int = 100) -> str:
    """Horizontal labelled bars: rows = [(label, value, color)]."""
    out = []
    for label, val, color in rows:
        pct = 0 if max_val <= 0 else min(100, 100 * val / max_val)
        out.append(
            f'<div class="bar-row"><span class="nm">{label}</span>'
            f'<span class="meter"><span style="width:{pct:.0f}%;background:{color}"></span></span>'
            f'<span class="vv">{val}</span></div>'
        )
    return "".join(out)
