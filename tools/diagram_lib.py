#!/usr/bin/env python3
"""Clean, zero-dependency, collision-verified SVG diagram engine for The Windows Trust Chain."""
from xml.sax.saxutils import escape
import math
import os
import re

FONT_SANS = '-apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif'
FONT_MONO = 'ui-monospace, "SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace'

THEMES = {
    "slate":  {"fill": "#edf1f6", "stroke": "#365378", "tag": "#284163", "ink": "#1a1a1a"},
    "teal":   {"fill": "#e6f3f1", "stroke": "#236b66", "tag": "#19524e", "ink": "#1a1a1a"},
    "green":  {"fill": "#e6f4ec", "stroke": "#2b6a4c", "tag": "#1e5139", "ink": "#1a1a1a"},
    "amber":  {"fill": "#f9f1e1", "stroke": "#b07926", "tag": "#875a14", "ink": "#1a1a1a"},
    "red":    {"fill": "#f8eaec", "stroke": "#8d2d3b", "tag": "#6e1f2b", "ink": "#1a1a1a"},
    "purple": {"fill": "#efeaf7", "stroke": "#5c4282", "tag": "#452e66", "ink": "#1a1a1a"},
    "stone":  {"fill": "#f4f1ea", "stroke": "#787167", "tag": "#524c44", "ink": "#1a1a1a"},
    "white":  {"fill": "#ffffff", "stroke": "#8c857b", "tag": "#4a453e", "ink": "#1a1a1a"},
}

NARROW_CHARS = set("ijlI1.,:;|!'`()[]{}")
WIDE_CHARS = set("mwMW@%QGOCDU")


def measure_text(text: str, size: float, mono: bool = False, bold: bool = False) -> float:
    if not text:
        return 0.0
    if mono:
        return len(text) * size * 0.62
    total = 0.0
    for ch in text:
        if ch in NARROW_CHARS:
            total += 0.33
        elif ch in WIDE_CHARS:
            total += 0.76
        elif ch.isupper():
            total += 0.66
        elif ch == " ":
            total += 0.30
        else:
            total += 0.55
    if bold:
        total *= 1.06
    return total * size * 1.08


def wrap_lines(text: str, max_width: float, size: float, mono: bool = False, bold: bool = False):
    if not text:
        return []
    out = []
    for raw_para in text.split("\n"):
        words = raw_para.split()
        if not words:
            out.append("")
            continue
        cur = words[0]
        for w in words[1:]:
            cand = f"{cur} {w}"
            if measure_text(cand, size, mono=mono, bold=bold) <= max_width:
                cur = cand
            else:
                out.append(cur)
                cur = w
        out.append(cur)
    return out


class SvgCanvas:
    def __init__(self, width: float, height: float, pad: float = 16.0):
        self.width = width
        self.height = height
        self.pad = pad
        self.bg_els = []
        self.line_els = []
        self.box_els = []
        self.label_els = []
        self.text_boxes = []   # (x0, y0, x1, y1, text, layer)
        self.line_segs = []    # (x1, y1, x2, y2, desc)
        self.pill_masks = []   # (x0, y0, x1, y1)

    def _check_prose(self, text: str):
        if "\u2014" in text:
            raise ValueError(f"Em-dash forbidden in diagram text: {text!r}")
        if " -- " in text or text.endswith("--"):
            raise ValueError(f"Double-hyphen forbidden in diagram text: {text!r}")

    def add_rect(self, x, y, w, h, fill="#ffffff", stroke="#365378", stroke_width=1.4,
                 rx=6, dash=None, layer="box"):
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        el = (f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx:.1f}" '
              f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}"{dash_attr}/>')
        if layer == "bg":
            self.bg_els.append(el)
        elif layer == "label":
            self.label_els.append(el)
        else:
            self.box_els.append(el)
        if stroke != "none" and layer != "label":
            self.line_segs.append((x, y, x + w, y, "rect-top"))
            self.line_segs.append((x, y + h, x + w, y + h, "rect-bot"))
            self.line_segs.append((x, y, x, y + h, "rect-left"))
            self.line_segs.append((x + w, y, x + w, y + h, "rect-right"))

    def add_circle(self, cx, cy, r, fill="none", stroke="#365378", stroke_width=1.4, dash=None, layer="bg"):
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        el = (f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="{fill}" '
              f'stroke="{stroke}" stroke-width="{stroke_width}"{dash_attr}/>')
        if layer == "bg":
            self.bg_els.append(el)
        else:
            self.box_els.append(el)
        if stroke != "none":
            steps = 48
            for k in range(steps):
                a0 = 2 * math.pi * k / steps
                a1 = 2 * math.pi * (k + 1) / steps
                self.line_segs.append((
                    cx + r * math.cos(a0), cy + r * math.sin(a0),
                    cx + r * math.cos(a1), cy + r * math.sin(a1),
                    "circle"
                ))

    def add_text(self, x, y, text: str, size=12.0, fill="#1a1a1a", bold=False, italic=False,
                 mono=False, anchor="start", letter_spacing=0.0, layer="box", masked=False):
        self._check_prose(text)
        if not text.strip():
            return
        ff = FONT_MONO if mono else FONT_SANS
        fw = "700" if bold else "400"
        fs = ' font-style="italic"' if italic else ""
        ls = f' letter-spacing="{letter_spacing:.2f}px"' if letter_spacing else ""
        el = (f'<text x="{x:.1f}" y="{y:.1f}" font-family=\'{ff}\' font-size="{size:.1f}" '
              f'font-weight="{fw}"{fs}{ls} fill="{fill}" text-anchor="{anchor}">{escape(text)}</text>')
        if layer == "label":
            self.label_els.append(el)
        elif layer == "bg":
            self.bg_els.append(el)
        else:
            self.box_els.append(el)

        tw = measure_text(text, size, mono=mono, bold=bold) + len(text) * letter_spacing
        if anchor == "middle":
            x0, x1 = x - tw / 2, x + tw / 2
        elif anchor == "end":
            x0, x1 = x - tw, x
        else:
            x0, x1 = x, x + tw
        # Baseline y: ascender ~0.78*size, descender ~0.20*size
        y0, y1 = y - size * 0.78, y + size * 0.20
        self.text_boxes.append((x0, y0, x1, y1, text, masked))

    def add_pill_label(self, cx, cy, text: str, size=10.5, color="#3a352f", bg="#ffffff",
                       border="#dcd6cc", bold=False, mono=False):
        """Draw centered label with an opaque rounded pill background that masks underlying lines."""
        self._check_prose(text)
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        if not lines:
            return
        lh = size * 1.28
        max_w = max(measure_text(l, size, mono=mono, bold=bold) for l in lines)
        pw = max_w + 14.0
        ph = len(lines) * lh + 6.0
        px = max(10.0, min(self.width - pw - 10.0, cx - pw / 2))
        cx = px + pw / 2
        py = cy - ph / 2
        border_attr = f'stroke="{border}" stroke-width="0.9"' if border != "none" else 'stroke="none"'
        self.label_els.append(
            f'<rect x="{px:.1f}" y="{py:.1f}" width="{pw:.1f}" height="{ph:.1f}" rx="4" fill="{bg}" {border_attr}/>'
        )
        self.pill_masks.append((px - 1.0, py - 1.0, px + pw + 1.0, py + ph + 1.0))
        start_y = py + 3.5 + size * 0.80
        for idx, l in enumerate(lines):
            self.add_text(cx, start_y + idx * lh, l, size=size, fill=color, bold=bold,
                          mono=mono, anchor="middle", layer="label", masked=True)

    def add_line(self, x1, y1, x2, y2, color="#4a5568", width=1.5, dash=None,
                 arrow_end=False, arrow_start=False, label=None, label_pos=0.5,
                 label_color=None, layer="line"):
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        # Shorten line slightly at arrowhead ends so thick shaft doesn't poke past triangle tip
        dx, dy = x2 - x1, y2 - y1
        dist = math.hypot(dx, dy)
        sx1, sy1, sx2, sy2 = x1, y1, x2, y2
        if dist > 10:
            ux, uy = dx / dist, dy / dist
            if arrow_end:
                sx2, sy2 = x2 - ux * 6.5, y2 - uy * 6.5
            if arrow_start:
                sx1, sy1 = x1 + ux * 6.5, y1 + uy * 6.5
        el = (f'<line x1="{sx1:.1f}" y1="{sy1:.1f}" x2="{sx2:.1f}" y2="{sy2:.1f}" '
              f'stroke="{color}" stroke-width="{width}"{dash_attr}/>')
        target = self.bg_els if layer == "bg" else self.line_els
        target.append(el)
        self.line_segs.append((x1, y1, x2, y2, "line"))

        if arrow_end and dist > 1:
            self._add_arrowhead(x1, y1, x2, y2, color, target)
        if arrow_start and dist > 1:
            self._add_arrowhead(x2, y2, x1, y1, color, target)
        if label:
            lx = x1 + dx * label_pos
            ly = y1 + dy * label_pos
            self.add_pill_label(lx, ly, label, size=10.2, color=label_color or color)

    def add_polyline(self, pts, color="#4a5568", width=1.5, dash=None, arrow_end=True,
                     arrow_start=False, label=None, label_seg=0, label_pos=0.5, label_color=None):
        assert len(pts) >= 2
        draw_pts = [list(p) for p in pts]
        if arrow_end:
            x1, y1 = pts[-2]
            x2, y2 = pts[-1]
            d = math.hypot(x2 - x1, y2 - y1)
            if d > 8:
                draw_pts[-1] = [x2 - (x2 - x1) / d * 6.5, y2 - (y2 - y1) / d * 6.5]
        if arrow_start:
            x1, y1 = pts[1]
            x2, y2 = pts[0]
            d = math.hypot(x2 - x1, y2 - y1)
            if d > 8:
                draw_pts[0] = [x2 - (x2 - x1) / d * 6.5, y2 - (y2 - y1) / d * 6.5]
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        pts_str = " ".join(f"{p[0]:.1f},{p[1]:.1f}" for p in draw_pts)
        self.line_els.append(
            f'<polyline points="{pts_str}" fill="none" stroke="{color}" stroke-width="{width}" '
            f'stroke-linejoin="round"{dash_attr}/>'
        )
        for i in range(len(pts) - 1):
            self.line_segs.append((pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1], "poly"))
        if arrow_end:
            self._add_arrowhead(pts[-2][0], pts[-2][1], pts[-1][0], pts[-1][1], color, self.line_els)
        if arrow_start:
            self._add_arrowhead(pts[1][0], pts[1][1], pts[0][0], pts[0][1], color, self.line_els)
        if label:
            p0, p1 = pts[label_seg], pts[label_seg + 1]
            lx = p0[0] + (p1[0] - p0[0]) * label_pos
            ly = p0[1] + (p1[1] - p0[1]) * label_pos
            self.add_pill_label(lx, ly, label, size=10.2, color=label_color or color)

    def _add_arrowhead(self, x1, y1, x2, y2, color, bucket):
        ang = math.atan2(y2 - y1, x2 - x1)
        L = 8.0
        W = 3.8
        bx = x2 - L * math.cos(ang)
        by = y2 - L * math.sin(ang)
        p1x = bx + W * math.sin(ang)
        p1y = by - W * math.cos(ang)
        p2x = bx - W * math.sin(ang)
        p2y = by + W * math.cos(ang)
        bucket.append(
            f'<polygon points="{x2:.1f},{y2:.1f} {p1x:.1f},{p1y:.1f} {p2x:.1f},{p2y:.1f}" fill="{color}"/>'
        )

    @staticmethod
    def measure_card_height(w: float, tag: str = None, title: str = None, body: str = None,
                            mono_body: bool = False, title_size: float = 12.5, body_size: float = 10.8) -> float:
        inner_w = w - 28.0
        h = 12.0
        if tag:
            t_lines = wrap_lines(tag.upper(), inner_w, 9.2, bold=True)
            h += len(t_lines) * 12.0 + 3.0
        if title:
            ti_lines = wrap_lines(title, inner_w, title_size, bold=True)
            h += len(ti_lines) * (title_size * 1.28) + (4.0 if body else 0.0)
        if body:
            bo_lines = wrap_lines(body, inner_w, body_size, mono=mono_body)
            h += len(bo_lines) * (body_size * 1.32)
        h += 12.0
        return max(h, 40.0)

    def add_card(self, x, y, w, h=None, tag: str = None, title: str = None, body: str = None,
                 theme: str = "slate", dashed: bool = False, mono_body: bool = False,
                 align: str = "left", title_size: float = 12.5, body_size: float = 10.8):
        th = THEMES[theme]
        need_h = self.measure_card_height(w, tag=tag, title=title, body=body,
                                          mono_body=mono_body, title_size=title_size, body_size=body_size)
        card_h = max(h or 0.0, need_h)
        self.add_rect(x, y, w, card_h, fill=th["fill"], stroke=th["stroke"],
                      stroke_width=1.4, rx=6, dash="5,3" if dashed else None, layer="box")
        inner_w = w - 28.0
        tx = (x + w / 2) if align == "center" else (x + 14.0)
        anc = "middle" if align == "center" else "start"
        cy = y + 12.0
        if tag:
            t_lines = wrap_lines(tag.upper(), inner_w, 9.2, bold=True)
            for l in t_lines:
                cy += 9.5
                self.add_text(tx, cy, l, size=9.2, fill=th["tag"], bold=True,
                              anchor=anc, letter_spacing=0.4)
                cy += 2.5
            cy += 3.0
        if title:
            ti_lines = wrap_lines(title, inner_w, title_size, bold=True)
            for l in ti_lines:
                cy += title_size * 0.85
                self.add_text(tx, cy, l, size=title_size, fill=th["ink"], bold=True, anchor=anc)
                cy += title_size * 0.43
            if body:
                cy += 4.0
        if body:
            bo_lines = wrap_lines(body, inner_w, body_size, mono=mono_body)
            for l in bo_lines:
                cy += body_size * 0.85
                self.add_text(tx, cy, l, size=body_size, fill="#433e38", mono=mono_body, anchor=anc)
                cy += body_size * 0.47
        return card_h

    def add_header(self, title: str, subtitle: str = None, y: float = 24.0) -> float:
        self.add_text(self.width / 2, y, title.upper(), size=11.0, fill="#365378",
                      bold=True, anchor="middle", letter_spacing=0.9)
        cur_y = y + 10.0
        if subtitle:
            lines = wrap_lines(subtitle, self.width - 60, 10.8)
            for l in lines:
                cur_y += 14.0
                self.add_text(self.width / 2, cur_y, l, size=10.8, fill="#57514a",
                              italic=True, anchor="middle")
            cur_y += 8.0
        else:
            cur_y += 6.0
        return cur_y

    def add_footer(self, text: str, y: float):
        lines = wrap_lines(text, self.width - 60, 10.5)
        cy = y + 14.0
        for l in lines:
            self.add_text(self.width / 2, cy, l, size=10.5, fill="#57514a",
                          italic=True, anchor="middle")
            cy += 14.5
        return cy

    def verify_no_collisions(self, name: str):
        # 1. Text-on-Text check
        n = len(self.text_boxes)
        for i in range(n):
            ax0, ay0, ax1, ay1, atxt, _ = self.text_boxes[i]
            for j in range(i + 1, n):
                bx0, by0, bx1, by1, btxt, _ = self.text_boxes[j]
                ox = min(ax1, bx1) - max(ax0, bx0)
                oy = min(ay1, by1) - max(ay0, by0)
                if ox > 1.5 and oy > 1.5:
                    raise AssertionError(
                        f"[{name}] TEXT OVERLAP ({ox:.1f}x{oy:.1f}px): {atxt!r} vs {btxt!r}"
                    )

        # 2. Line-through-Unmasked-Text check
        for tx0, ty0, tx1, ty1, ttxt, masked in self.text_boxes:
            if masked:
                continue
            ix0, iy0, ix1, iy1 = tx0 + 1.5, ty0 + 1.5, tx1 - 1.5, ty1 - 1.5
            if ix1 <= ix0 or iy1 <= iy0:
                continue
            for x1, y1, x2, y2, kind in self.line_segs:
                if max(x1, x2) < ix0 or min(x1, x2) > ix1 or max(y1, y2) < iy0 or min(y1, y2) > iy1:
                    continue
                for k in range(25):
                    t = k / 24.0
                    px = x1 + (x2 - x1) * t
                    py = y1 + (y2 - y1) * t
                    if ix0 < px < ix1 and iy0 < py < iy1:
                        # Check if covered by a pill mask
                        in_mask = any(mx0 <= px <= mx1 and my0 <= py <= my1 for mx0, my0, mx1, my1 in self.pill_masks)
                        if not in_mask:
                            raise AssertionError(
                                f"[{name}] LINE CUTS TEXT ({kind}): line ({x1:.0f},{y1:.0f})->({x2:.0f},{y2:.0f}) cuts {ttxt!r} at ({px:.0f},{py:.0f})"
                            )

    def save(self, out_path: str):
        # Auto-fit canvas height if elements extend deeper or leave excess space
        max_y = 60.0
        for _, _, _, y1, _, _ in self.text_boxes:
            max_y = max(max_y, y1)
        for _, y1, _, y2, _ in self.line_segs:
            max_y = max(max_y, y1, y2)
        for _, _, _, my1 in self.pill_masks:
            max_y = max(max_y, my1)
        final_h = max(self.height, max_y + 18.0)

        self.verify_no_collisions(os.path.basename(out_path))

        svg = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width:.0f} {final_h:.0f}" '
            f'width="{self.width:.0f}" height="{final_h:.0f}">',
            f'<rect x="0" y="0" width="{self.width:.0f}" height="{final_h:.0f}" fill="#ffffff"/>',
            *self.bg_els,
            *self.box_els,
            *self.line_els,
            *self.label_els,
            '</svg>\n',
        ]
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(svg))


# --- High-Level Archetype Builders ---

def build_vertical_flow(out_path: str, title: str, steps: list, side_notes: dict = None,
                        footer: str = None, width: float = 760.0, main_w: float = 460.0):
    """
    steps: list of dicts {tag, title, body, theme, dashed, edge_label, edge_color, edge_dashed}
    side_notes: optional dict mapping step_index -> {tag, title, body, theme, dashed, edge_label}
    """
    has_side = bool(side_notes)
    W = 860.0 if has_side else width
    box_x = 36.0 if has_side else (W - main_w) / 2
    box_w = 450.0 if has_side else main_w
    side_x = box_x + box_w + 96.0
    side_w = W - side_x - 32.0

    c = SvgCanvas(W, 120)
    y = c.add_header(title) + 8.0

    centers = []
    bottoms = []
    for idx, st in enumerate(steps):
        if idx > 0:
            prev_bot = bottoms[-1]
            lbl = st.get("edge_label")
            gap = 46.0 if lbl else 26.0
            ny = prev_bot + gap
            ec = st.get("edge_color", "#4a5568")
            c.add_line(box_x + box_w / 2, prev_bot, box_x + box_w / 2, ny,
                       color=ec, arrow_end=True, dash="4,3" if st.get("edge_dashed") else None,
                       label=lbl, label_color=ec)
            y = ny
        ch = c.add_card(box_x, y, box_w, tag=st.get("tag"), title=st.get("title"),
                        body=st.get("body"), theme=st.get("theme", "slate"),
                        dashed=st.get("dashed", False), mono_body=st.get("mono", False))
        mid_y = y + ch / 2
        centers.append(mid_y)
        bottoms.append(y + ch)

        if has_side and idx in side_notes:
            sn = side_notes[idx]
            sh = SvgCanvas.measure_card_height(side_w, tag=sn.get("tag"), title=sn.get("title"), body=sn.get("body"), title_size=11.5, body_size=10.2)
            sy = max(y - 4.0, mid_y - sh / 2)
            c.add_card(side_x, sy, side_w, h=sh, tag=sn.get("tag"), title=sn.get("title"),
                       body=sn.get("body"), theme=sn.get("theme", "red"),
                       dashed=sn.get("dashed", True), title_size=11.5, body_size=10.2)
            sc = sn.get("edge_color", "#8d2d3b")
            if sn.get("reverse"):
                c.add_line(side_x, sy + sh / 2, box_x + box_w, mid_y, color=sc,
                           arrow_end=True, dash="4,3", label=sn.get("edge_label"), label_color=sc)
            else:
                c.add_line(box_x + box_w, mid_y, side_x, sy + sh / 2, color=sc,
                           arrow_end=True, dash="4,3", label=sn.get("edge_label"), label_color=sc)

    end_y = bottoms[-1] + 10.0
    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_sequence(out_path: str, title: str, actors: list, messages: list,
                   boundary_after: int = None, boundary_label: str = None,
                   bottom_note: dict = None, footer: str = None, width: float = 880.0):
    """
    actors: list of {title, sub, theme}
    messages: list of (from_idx, to_idx, label, theme_or_color, dashed)
    """
    n = len(actors)
    margin = 34.0
    gap = 26.0
    act_w = (width - 2 * margin - (n - 1) * gap) / n
    c = SvgCanvas(width, 160)
    y = c.add_header(title) + 10.0

    # Reserve lifeline header space if boundary label exists
    if boundary_after is not None and boundary_label:
        y += 22.0

    act_xs = []
    max_ah = 0.0
    for i, a in enumerate(actors):
        ax = margin + i * (act_w + gap)
        act_xs.append(ax + act_w / 2)
        max_ah = max(max_ah, SvgCanvas.measure_card_height(act_w, title=a["title"], body=a.get("sub"), title_size=12.0, body_size=10.0))

    for i, a in enumerate(actors):
        ax = margin + i * (act_w + gap)
        c.add_card(ax, y, act_w, h=max_ah, title=a["title"], body=a.get("sub"),
                   theme=a.get("theme", "slate"), align="center", title_size=12.0, body_size=10.0)

    life_top = y + max_ah
    msg_y = life_top + 34.0
    msg_coords = []
    for i, (f_idx, t_idx, lbl, col, is_dash) in enumerate(messages):
        if f_idx == t_idx and "\n" not in lbl and len(lbl) > 36:
            lbl = "\n".join(wrap_lines(lbl, 230.0, 10.2))
            messages[i] = (f_idx, t_idx, lbl, col, is_dash)
        lines_cnt = len(lbl.split("\n"))
        step_h = 38.0 + (lines_cnt - 1) * 15.0
        msg_coords.append((f_idx, t_idx, lbl, col, is_dash, msg_y))
        msg_y += step_h

    life_bot = msg_y + 10.0
    for cx in act_xs:
        c.add_line(cx, life_top, cx, life_bot, color="#cbd5e1", width=1.3, layer="bg")

    if boundary_after is not None:
        bx = (act_xs[boundary_after] + act_xs[boundary_after + 1]) / 2
        c.add_line(bx, y - 6.0, bx, life_bot, color="#8d2d3b", width=1.6, dash="5,4", layer="bg")
        if boundary_label:
            c.add_pill_label(bx, y - 14.0, boundary_label, size=9.5, color="#8d2d3b",
                             bg="#f8eaec", border="#8d2d3b", bold=True)

    COLOR_MAP = {
        "slate": "#365378", "teal": "#236b66", "green": "#2b6a4c",
        "amber": "#b07926", "red": "#8d2d3b", "purple": "#5c4282",
    }
    for f_idx, t_idx, lbl, col, is_dash, my in msg_coords:
        sc = COLOR_MAP.get(col, col)
        x1, x2 = act_xs[f_idx], act_xs[t_idx]
        if f_idx == t_idx:
            # Self-call card centered on lifeline with pill mask
            c.add_pill_label(x1, my, lbl, size=10.2, color=sc, bg="#f4f1ea", border=sc)
        else:
            c.add_line(x1, my, x2, my, color=sc, width=1.6,
                       dash="5,3" if is_dash else None, arrow_end=True)
            c.add_pill_label((x1 + x2) / 2, my - 13.0, lbl, size=10.0, color="#1a1a1a",
                             bg="#ffffff", border="#dcd6cc")

    end_y = life_bot + 14.0
    if bottom_note:
        nw = width - 140.0
        nx = 70.0
        nh = c.add_card(nx, end_y, nw, tag=bottom_note.get("tag"), title=bottom_note.get("title"),
                        body=bottom_note.get("body"), theme=bottom_note.get("theme", "red"),
                        dashed=True, align="center")
        end_y += nh + 8.0
    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_split_domains(out_path: str, title: str, left: dict, right: dict,
                        bridges: list = None, boundary_label: str = None,
                        foundation: dict = None, footer: str = None, width: float = 880.0):
    """
    left / right: {label, theme, cards: [{tag, title, body, theme, dashed, mono}]}
    bridges: list of (left_card_idx, right_card_idx, dir ('lr'|'rl'|'both'), label, theme_color)
    """
    margin = 28.0
    mid_gap = 176.0
    col_w = (width - 2 * margin - mid_gap) / 2
    lx = margin
    rx = margin + col_w + mid_gap
    mid_x = lx + col_w + mid_gap / 2

    c = SvgCanvas(width, 180)
    y = c.add_header(title) + 12.0
    if boundary_label:
        y += 18.0

    # Measure internal cards for left and right containers
    def layout_col(col, cx, top_y):
        cy = top_y + 38.0
        inner_x = cx + 16.0
        inner_w = col_w - 32.0
        ys = []
        for idx, cd in enumerate(col["cards"]):
            if idx > 0:
                lbl = cd.get("in_edge")
                cy += 38.0 if lbl else 20.0
            h = SvgCanvas.measure_card_height(inner_w, tag=cd.get("tag"), title=cd.get("title"),
                                              body=cd.get("body"), mono_body=cd.get("mono", False))
            ys.append((inner_x, cy, inner_w, h, cd))
            cy += h
        total_h = (cy - top_y) + 18.0
        return ys, total_h

    l_cards, lh = layout_col(left, lx, y)
    r_cards, rh = layout_col(right, rx, y)
    box_h = max(lh, rh)

    for col, cx in ((left, lx), (right, rx)):
        th = THEMES[col.get("theme", "stone")]
        c.add_rect(cx, y, col_w, box_h, fill=th["fill"], stroke=th["stroke"],
                   stroke_width=1.4, rx=8, dash="6,3" if col.get("dashed") else None, layer="bg")
        c.add_text(cx + col_w / 2, y + 22.0, col["label"].upper(), size=10.2,
                   fill=th["tag"], bold=True, anchor="middle", letter_spacing=0.6, layer="bg")

    for cards in (l_cards, r_cards):
        for idx, (ix, iy, iw, ih, cd) in enumerate(cards):
            if idx > 0 and cd.get("in_edge"):
                prev = cards[idx - 1]
                p_bot = prev[1] + prev[3]
                c.add_line(ix + iw / 2, p_bot, ix + iw / 2, iy, color="#4a5568",
                           arrow_end=True, label=cd["in_edge"])
            elif idx > 0 and cd.get("in_arrow"):
                prev = cards[idx - 1]
                p_bot = prev[1] + prev[3]
                c.add_line(ix + iw / 2, p_bot, ix + iw / 2, iy, color="#4a5568", arrow_end=True)
            c.add_card(ix, iy, iw, h=ih, tag=cd.get("tag"), title=cd.get("title"),
                       body=cd.get("body"), theme=cd.get("theme", "white"),
                       dashed=cd.get("dashed", False), mono_body=cd.get("mono", False))

    if boundary_label:
        c.add_line(mid_x, y - 4.0, mid_x, y + box_h + 4.0, color="#8d2d3b", width=1.6, dash="5,4", layer="bg")
        c.add_pill_label(mid_x, y - 14.0, boundary_label, size=9.4, color="#8d2d3b",
                         bg="#f8eaec", border="#8d2d3b", bold=True)

    COLOR_MAP = {"slate": "#365378", "teal": "#236b66", "green": "#2b6a4c", "amber": "#b07926", "red": "#8d2d3b"}
    if bridges:
        for b_idx, (li, ri, direction, lbl, col) in enumerate(bridges):
            lc = l_cards[li]
            rc = r_cards[ri]
            ly_mid = lc[1] + lc[3] / 2 + b_idx * 4.0
            ry_mid = rc[1] + rc[3] / 2 + b_idx * 4.0
            x_left = lc[0] + lc[2]
            x_right = rc[0]
            sc = COLOR_MAP.get(col, col)
            if abs(ly_mid - ry_mid) < 8.0:
                my = (ly_mid + ry_mid) / 2
                c.add_line(x_left, my, x_right, my, color=sc, width=1.6,
                           arrow_end=(direction in ("lr", "both")),
                           arrow_start=(direction in ("rl", "both")),
                           label=lbl, label_color=sc)
            else:
                pts = [(x_left, ly_mid), (mid_x, ly_mid), (mid_x, ry_mid), (x_right, ry_mid)]
                c.add_polyline(pts, color=sc, width=1.6,
                               arrow_end=(direction in ("lr", "both")),
                               arrow_start=(direction in ("rl", "both")),
                               label=lbl, label_seg=1, label_pos=0.5, label_color=sc)

    end_y = y + box_h + 16.0
    if foundation:
        fy = end_y + 28.0
        fh = c.add_card(lx + 40.0, fy, width - 2 * margin - 80.0,
                        tag=foundation.get("tag"), title=foundation.get("title"),
                        body=foundation.get("body"), theme=foundation.get("theme", "amber"),
                        align="center")
        if foundation.get("left_label"):
            c.add_line(lx + col_w / 2, fy, lx + col_w / 2, y + box_h,
                       color="#875a14", arrow_end=True, label=foundation["left_label"])
        if foundation.get("right_label"):
            c.add_line(rx + col_w / 2, fy, rx + col_w / 2, y + box_h,
                       color="#2b6a4c", arrow_end=True, label=foundation["right_label"])
        end_y = fy + fh + 10.0

    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_horizontal_pipeline(out_path: str, title: str, stages: list,
                              under_anchor: dict = None, footer: str = None, width: float = 920.0):
    """
    stages: list of {tag, title, body, theme, edge_label}
    under_anchor: optional {target_idx, tag, title, body, theme, edge_label}
    """
    n = len(stages)
    margin = 24.0
    gaps = [58.0 if stages[i].get("edge_label") else 32.0 for i in range(1, n)]
    box_w = (width - 2 * margin - sum(gaps)) / n

    c = SvgCanvas(width, 160)
    y = c.add_header(title) + 14.0

    max_h = max(
        SvgCanvas.measure_card_height(box_w, tag=s.get("tag"), title=s.get("title"),
                                      body=s.get("body"), title_size=12.0, body_size=10.0)
        for s in stages
    )

    xs = []
    cur_x = margin
    for i, s in enumerate(stages):
        xs.append(cur_x)
        c.add_card(cur_x, y, box_w, h=max_h, tag=s.get("tag"), title=s.get("title"),
                   body=s.get("body"), theme=s.get("theme", "slate"), align="center",
                   title_size=12.0, body_size=10.0)
        if i > 0:
            prev_right = xs[i - 1] + box_w
            c.add_line(prev_right, y + max_h / 2, cur_x, y + max_h / 2,
                       color="#365378", width=1.6, arrow_end=True,
                       label=s.get("edge_label"))
        if i < n - 1:
            cur_x += box_w + gaps[i]

    end_y = y + max_h + 16.0
    if under_anchor:
        ti = under_anchor.get("target_idx", 0)
        uw = max(box_w + 50.0, 210.0)
        ux = max(margin, min(width - margin - uw, xs[ti] + box_w / 2 - uw / 2))
        uy = y + max_h + 46.0
        uh = c.add_card(ux, uy, uw, tag=under_anchor.get("tag"), title=under_anchor.get("title"),
                        body=under_anchor.get("body"), theme=under_anchor.get("theme", "red"),
                        align="center", title_size=11.5, body_size=10.0)
        c.add_line(ux + uw / 2, uy, xs[ti] + box_w / 2, y + max_h,
                   color="#8d2d3b", width=1.6, arrow_end=True,
                   label=under_anchor.get("edge_label"), label_color="#8d2d3b")
        end_y = uy + uh + 10.0

    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_fan_bands(out_path: str, title: str, bands: list, edges: list,
                    footer: str = None, width: float = 900.0):
    """
    bands: list of rows; each row is a list of node dicts {id, tag, title, body, theme, dashed, w_weight}
    edges: list of (src_id, dst_id, label, color_key, dashed)
    Connects bands top-to-bottom via clean orthogonal routing channels with zero box/text crossings.
    """
    margin = 26.0
    c = SvgCanvas(width, 180)
    y = c.add_header(title) + 12.0

    COLOR_MAP = {"slate": "#365378", "teal": "#236b66", "green": "#2b6a4c",
                 "amber": "#b07926", "red": "#8d2d3b", "purple": "#5c4282"}

    node_band = {}
    for b_idx, row in enumerate(bands):
        for nd in row:
            node_band[nd["id"]] = b_idx

    band_has_label = set()
    for src, dst, lbl, _, _ in edges:
        if lbl:
            band_has_label.add(min(node_band[src], node_band[dst]))

    coords = {}
    for b_idx, row in enumerate(bands):
        n = len(row)
        gap = 18.0 if n <= 4 else 12.0
        avail = width - 2 * margin - (n - 1) * gap
        weights = [nd.get("w_weight", 1.0) for nd in row]
        tot_w = sum(weights)
        if n == 1 and "w_weight" not in row[0]:
            nw = min(580.0, avail)
            nx = (width - nw) / 2
            nh = c.add_card(nx, y, nw, tag=row[0].get("tag"), title=row[0].get("title"),
                            body=row[0].get("body"), theme=row[0].get("theme", "slate"),
                            dashed=row[0].get("dashed", False), align=row[0].get("align", "center"),
                            mono_body=row[0].get("mono", False))
            coords[row[0]["id"]] = (nx, y, nw, nh)
            row_h = nh
        else:
            ws = [avail * (wt / tot_w) for wt in weights]
            row_h = max(
                SvgCanvas.measure_card_height(w, tag=nd.get("tag"), title=nd.get("title"),
                                              body=nd.get("body"), title_size=11.5 if n >= 4 else 12.2,
                                              body_size=10.0 if n >= 4 else 10.6,
                                              mono_body=nd.get("mono", False))
                for w, nd in zip(ws, row)
            )
            cx = margin
            for w, nd in zip(ws, row):
                c.add_card(cx, y, w, h=row_h, tag=nd.get("tag"), title=nd.get("title"),
                           body=nd.get("body"), theme=nd.get("theme", "slate"),
                           dashed=nd.get("dashed", False), align=nd.get("align", "left"),
                           title_size=11.5 if n >= 4 else 12.2,
                           body_size=10.0 if n >= 4 else 10.6,
                           mono_body=nd.get("mono", False))
                coords[nd["id"]] = (cx, y, w, row_h)
                cx += w + gap

        if b_idx < len(bands) - 1:
            y += row_h + (54.0 if b_idx in band_has_label else 38.0)
        else:
            y += row_h

    pair_counts = {}
    for src, dst, lbl, col_key, is_dash in edges:
        sx, sy, sw, sh = coords[src]
        dx, dy, dw, dh = coords[dst]
        sc = COLOR_MAP.get(col_key, col_key or "#4a5568")
        x1 = sx + sw / 2
        y1 = sy + sh
        x2 = dx + dw / 2
        y2 = dy
        pair_key = (node_band[src], node_band[dst])
        idx_in_pair = pair_counts.get(pair_key, 0)
        pair_counts[pair_key] = idx_in_pair + 1

        if abs(x1 - x2) < 6.0:
            c.add_line(x1, y1, x2, y2, color=sc, width=1.5,
                       dash="4,3" if is_dash else None, arrow_end=True,
                       label=lbl, label_color=sc)
        else:
            mid_y = (y1 + y2) / 2 + (idx_in_pair % 3 - 1) * 3.5
            pts = [(x1, y1), (x1, mid_y), (x2, mid_y), (x2, y2)]
            seg_idx = 2 if lbl and len(bands[node_band[dst]]) > len(bands[node_band[src]]) else 0
            c.add_polyline(pts, color=sc, width=1.5, dash="4,3" if is_dash else None,
                           arrow_end=True, label=lbl, label_seg=seg_idx, label_pos=0.5, label_color=sc)

    end_y = y + 12.0
    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_matrix(out_path: str, title: str, subtitle: str, row_headers: list,
                 col_headers: list, cells: list, legend: str, footer: str = None, width: float = 900.0):
    margin = 28.0
    row_hdr_w = 216.0
    n_cols = len(col_headers)
    cell_w = (width - 2 * margin - row_hdr_w) / n_cols
    hdr_h = 54.0
    cell_h = 46.0

    c = SvgCanvas(width, 200)
    y = c.add_header(title, subtitle) + 10.0

    c.add_rect(margin, y, row_hdr_w, hdr_h, fill="#f4f1ea", stroke="#bfb8ad", rx=0)
    c.add_text(margin + 12.0, y + 31.0, "Row / Column", size=10.5, fill="#524c44", bold=True)
    for j, (ch_main, ch_sub) in enumerate(col_headers):
        cx = margin + row_hdr_w + j * cell_w
        c.add_rect(cx, y, cell_w, hdr_h, fill="#f4f1ea", stroke="#bfb8ad", rx=0)
        c.add_text(cx + cell_w / 2, y + (22.0 if ch_sub else 31.0), ch_main, size=10.5,
                   fill="#1a1a1a", bold=True, anchor="middle")
        if ch_sub:
            c.add_text(cx + cell_w / 2, y + 39.0, ch_sub, size=9.2,
                       fill="#57514a", anchor="middle")

    cur_y = y + hdr_h
    for i, (rh_main, rh_sub) in enumerate(row_headers):
        c.add_rect(margin, cur_y, row_hdr_w, cell_h, fill="#faf8f5", stroke="#d4cec3", rx=0)
        c.add_text(margin + 12.0, cur_y + (20.0 if rh_sub else 28.0), rh_main, size=10.6,
                   fill="#1a1a1a", bold=True)
        if rh_sub:
            c.add_text(margin + 12.0, cur_y + 35.5, rh_sub, size=9.2, fill="#57514a")
        for j in range(n_cols):
            val, th_name = cells[i][j]
            th = THEMES[th_name]
            cx = margin + row_hdr_w + j * cell_w
            c.add_rect(cx, cur_y, cell_w, cell_h, fill=th["fill"], stroke="#d4cec3", rx=0)
            c.add_text(cx + cell_w / 2, cur_y + 28.0, val, size=10.8,
                       fill=th["tag"], bold=True, anchor="middle")
        cur_y += cell_h

    end_y = cur_y + 18.0
    if legend:
        for l in wrap_lines(legend, width - 2 * margin, 10.2):
            c.add_text(margin, end_y, l, size=10.2, fill="#3a352f")
            end_y += 14.5
    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_timeline_spine(out_path: str, title: str, entries: list, footer: str = None, width: float = 840.0):
    c = SvgCanvas(width, 180)
    y = c.add_header(title) + 14.0

    spine_x = 134.0
    card_x = 172.0
    card_w = width - card_x - 32.0

    node_ys = []
    for item in entries:
        h = c.add_card(card_x, y, card_w, tag=item.get("tag"), title=item["title"],
                       body=item.get("body"), theme=item.get("theme", "slate"))
        mid_y = y + h / 2
        node_ys.append((mid_y, item["year"], THEMES[item.get("theme", "slate")]["stroke"]))
        y += h + 18.0

    if len(node_ys) >= 2:
        c.add_line(spine_x, node_ys[0][0], spine_x, node_ys[-1][0], color="#cbd5e1", width=2.2, layer="bg")

    for mid_y, yr, col in node_ys:
        c.add_line(spine_x + 6.0, mid_y, card_x, mid_y, color=col, width=1.5)
        c.add_circle(spine_x, mid_y, 5.5, fill=col, stroke="#ffffff", stroke_width=1.5, layer="label")
        c.add_text(spine_x - 16.0, mid_y + 4.0, yr, size=10.8, fill=col, bold=True, anchor="end")

    end_y = y + 4.0
    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_dual_rail_timeline(out_path: str, title: str, left_label: str, right_label: str,
                             rows: list, footer: str = None, width: float = 900.0):
    c = SvgCanvas(width, 200)
    y = c.add_header(title) + 14.0

    mid_x = width / 2
    rail_gap = 62.0
    card_w = mid_x - rail_gap - 28.0
    lx = 28.0
    rx = mid_x + rail_gap

    c.add_text(lx + card_w / 2, y, left_label.upper(), size=10.2, fill="#8d2d3b",
               bold=True, anchor="middle", letter_spacing=0.6)
    c.add_text(rx + card_w / 2, y, right_label.upper(), size=10.2, fill="#2b6a4c",
               bold=True, anchor="middle", letter_spacing=0.6)
    y += 18.0

    spine_pts = []
    for r in rows:
        lh = rh = 0.0
        lc = r.get("left")
        rc = r.get("right")
        if lc:
            lh = SvgCanvas.measure_card_height(card_w, tag=lc.get("tag"), title=lc["title"],
                                               body=lc.get("body"), title_size=11.5, body_size=10.0)
        if rc:
            rh = SvgCanvas.measure_card_height(card_w, tag=rc.get("tag"), title=rc["title"],
                                               body=rc.get("body"), title_size=11.5, body_size=10.0)
        row_h = max(lh, rh, 44.0)
        mid_y = y + row_h / 2
        spine_pts.append((mid_y, r["year"]))

        if lc:
            cy = mid_y - lh / 2
            c.add_card(lx, cy, card_w, h=lh, tag=lc.get("tag"), title=lc["title"],
                       body=lc.get("body"), theme=lc.get("theme", "red"),
                       title_size=11.5, body_size=10.0)
            c.add_line(lx + card_w, mid_y, mid_x - 32.0, mid_y, color="#8d2d3b", width=1.4)
        if rc:
            cy = mid_y - rh / 2
            c.add_card(rx, cy, card_w, h=rh, tag=rc.get("tag"), title=rc["title"],
                       body=rc.get("body"), theme=rc.get("theme", "green"),
                       title_size=11.5, body_size=10.0)
            c.add_line(mid_x + 32.0, mid_y, rx, mid_y, color="#2b6a4c", width=1.4)

        y += row_h + 18.0

    if len(spine_pts) >= 2:
        c.add_line(mid_x, spine_pts[0][0] - 10.0, mid_x, spine_pts[-1][0] + 10.0,
                   color="#94a3b8", width=2.0, layer="bg")
    for mid_y, yr in spine_pts:
        c.add_pill_label(mid_x, mid_y, yr, size=9.6, color="#284163", bg="#edf1f6",
                         border="#365378", bold=True)

    end_y = y + 6.0
    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)

