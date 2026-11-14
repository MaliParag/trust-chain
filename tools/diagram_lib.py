#!/usr/bin/env python3
"""Clean, zero-dependency, 7-way collision- and alignment-verified SVG diagram engine."""
from xml.sax.saxutils import escape
import math
import os

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
        self.text_boxes = []      # (x0, y0, x1, y1, text, masked)
        self.line_segs = []       # (x1, y1, x2, y2, kind)
        self.connector_segs = []  # (x1, y1, x2, y2, group_id)
        self.arrow_boxes = []     # (x0, y0, x1, y1)
        self.pill_masks = []      # (x0, y0, x1, y1, text, allow_card_touch)
        self.card_boxes = []      # (x0, y0, x1, y1, title)
        self._edge_group = 0

    def next_edge_group(self) -> int:
        self._edge_group += 1
        return self._edge_group

    def _check_prose(self, text: str):
        if "\u2014" in text:
            raise ValueError(f"Em-dash forbidden in diagram text: {text!r}")
        if " -- " in text or text.endswith("--"):
            raise ValueError(f"Double-hyphen forbidden in diagram text: {text!r}")

    def add_rect(self, x, y, w, h, fill="#ffffff", stroke="#365378", stroke_width=1.4,
                 rx=6, dash=None, layer="box", is_card=False, card_title=""):
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
        if is_card:
            self.card_boxes.append((x, y, x + w, y + h, card_title))

    def add_circle(self, cx, cy, r, fill="none", stroke="#365378", stroke_width=1.4, dash=None, layer="bg"):
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        el = (f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="{fill}" '
              f'stroke="{stroke}" stroke-width="{stroke_width}"{dash_attr}/>')
        if layer == "bg":
            self.bg_els.append(el)
        elif layer == "label":
            self.label_els.append(el)
        else:
            self.box_els.append(el)
        if stroke != "none" and layer != "label":
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
        y0, y1 = y - size * 0.78, y + size * 0.20
        self.text_boxes.append((x0, y0, x1, y1, text, masked))

    def add_pill_label(self, cx, cy, text: str, size=10.2, color="#3a352f", bg="#ffffff",
                       border="#dcd6cc", bold=False, mono=False, allow_card_touch=False):
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
        self.pill_masks.append((px, py, px + pw, py + ph, text, allow_card_touch))
        start_y = py + 3.5 + size * 0.80
        for idx, l in enumerate(lines):
            self.add_text(cx, start_y + idx * lh, l, size=size, fill=color, bold=bold,
                          mono=mono, anchor="middle", layer="label", masked=True)

    def add_line(self, x1, y1, x2, y2, color="#4a5568", width=1.5, dash=None,
                 arrow_end=False, arrow_start=False, label=None, label_pos=0.5,
                 label_color=None, layer="line", is_connector=True, group_id=None):
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
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
        if is_connector and layer != "bg":
            gid = group_id if group_id is not None else self.next_edge_group()
            self.connector_segs.append((x1, y1, x2, y2, gid))

        if arrow_end and dist > 1:
            self._add_arrowhead(x1, y1, x2, y2, color, target)
        if arrow_start and dist > 1:
            self._add_arrowhead(x2, y2, x1, y1, color, target)
        if label:
            lx = x1 + dx * label_pos
            ly = y1 + dy * label_pos
            self.add_pill_label(lx, ly, label, size=10.0, color=label_color or color)

    def add_polyline(self, pts, color="#4a5568", width=1.5, dash=None, arrow_end=True,
                     arrow_start=False, label=None, label_seg=0, label_pos=0.5,
                     label_color=None, group_id=None):
        assert len(pts) >= 2
        gid = group_id if group_id is not None else self.next_edge_group()
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
            self.connector_segs.append((pts[i][0], pts[i][1], pts[i + 1][0], pts[i + 1][1], gid))
        if arrow_end:
            self._add_arrowhead(pts[-2][0], pts[-2][1], pts[-1][0], pts[-1][1], color, self.line_els)
        if arrow_start:
            self._add_arrowhead(pts[1][0], pts[1][1], pts[0][0], pts[0][1], color, self.line_els)
        if label:
            p0, p1 = pts[label_seg], pts[label_seg + 1]
            lx = p0[0] + (p1[0] - p0[0]) * label_pos
            ly = p0[1] + (p1[1] - p0[1]) * label_pos
            self.add_pill_label(lx, ly, label, size=10.0, color=label_color or color)

    def _add_arrowhead(self, x1, y1, x2, y2, color, bucket):
        ang = math.atan2(y2 - y1, x2 - x1)
        L = 8.5
        W = 4.0
        bx = x2 - L * math.cos(ang)
        by = y2 - L * math.sin(ang)
        p1x = bx + W * math.sin(ang)
        p1y = by - W * math.cos(ang)
        p2x = bx - W * math.sin(ang)
        p2y = by + W * math.cos(ang)
        bucket.append(
            f'<polygon points="{x2:.1f},{y2:.1f} {p1x:.1f},{p1y:.1f} {p2x:.1f},{p2y:.1f}" fill="{color}"/>'
        )
        self.arrow_boxes.append((min(x2, p1x, p2x), min(y2, p1y, p2y), max(x2, p1x, p2x), max(y2, p1y, p2y)))

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
                      stroke_width=1.4, rx=6, dash="5,3" if dashed else None,
                      layer="box", is_card=True, card_title=title or tag or "card")
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
                        in_mask = any(
                            mx0 - 1 <= px <= mx1 + 1 and my0 - 1 <= py <= my1 + 1
                            for mx0, my0, mx1, my1, _, _ in self.pill_masks
                        )
                        if not in_mask:
                            raise AssertionError(
                                f"[{name}] LINE CUTS TEXT ({kind}): ({x1:.0f},{y1:.0f})->({x2:.0f},{y2:.0f}) cuts {ttxt!r}"
                            )

        # 3. Pill-vs-Arrowhead collision check (3px minimum clearance!)
        for px0, py0, px1, py1, ptxt, _ in self.pill_masks:
            for ax0, ay0, ax1, ay1 in self.arrow_boxes:
                if min(px1 + 3.0, ax1) > max(px0 - 3.0, ax0) and min(py1 + 3.0, ay1) > max(py0 - 3.0, ay0):
                    raise AssertionError(
                        f"[{name}] PILL TOUCHES ARROWHEAD: pill {ptxt!r} ({px0:.0f},{py0:.0f},{px1:.0f},{py1:.0f}) hits arrowhead ({ax0:.0f},{ay0:.0f},{ax1:.0f},{ay1:.0f})"
                    )

        # 4. Pill-vs-Pill collision check
        for i in range(len(self.pill_masks)):
            px0, py0, px1, py1, ptxt, _ = self.pill_masks[i]
            for j in range(i + 1, len(self.pill_masks)):
                qx0, qy0, qx1, qy1, qtxt, _ = self.pill_masks[j]
                if min(px1 + 2, qx1) > max(px0 - 2, qx0) and min(py1 + 2, qy1) > max(py0 - 2, qy0):
                    raise AssertionError(
                        f"[{name}] PILL OVERLAPS PILL: {ptxt!r} vs {qtxt!r}"
                    )

        # 5. Edge-Pill-vs-Card & Card-vs-Card collision checks
        for px0, py0, px1, py1, ptxt, allow_touch in self.pill_masks:
            if allow_touch:
                continue
            for cx0, cy0, cx1, cy1, ctitle in self.card_boxes:
                if min(px1, cx1) - max(px0, cx0) > 1.0 and min(py1, cy1) - max(py0, cy0) > 1.0:
                    raise AssertionError(
                        f"[{name}] PILL OVERLAPS CARD: pill {ptxt!r} overlaps card {ctitle!r}"
                    )

        for i in range(len(self.card_boxes)):
            ax0, ay0, ax1, ay1, atitle = self.card_boxes[i]
            for j in range(i + 1, len(self.card_boxes)):
                bx0, by0, bx1, by1, btitle = self.card_boxes[j]
                if min(ax1 + 6.0, bx1) > max(ax0 - 6.0, bx0) and min(ay1 + 6.0, by1) > max(ay0 - 6.0, by0):
                    raise AssertionError(
                        f"[{name}] CARDS OVERLAP OR CROWD: {atitle!r} vs {btitle!r}"
                    )

        # 6. Strict orthogonality, zero card-piercing, & zero parallel double-tracks
        m = len(self.connector_segs)
        for i in range(m):
            ax1, ay1, ax2, ay2, gid_a = self.connector_segs[i]
            a_horiz = abs(ay1 - ay2) < 0.5
            a_vert = abs(ax1 - ax2) < 0.5
            if not (a_horiz or a_vert):
                raise AssertionError(
                    f"[{name}] NON-ORTHOGONAL (SLANTED) ARROW: ({ax1:.1f},{ay1:.1f})->({ax2:.1f},{ay2:.1f})"
                )
            for cx0, cy0, cx1, cy1, ctitle in self.card_boxes:
                ix0, iy0, ix1, iy1 = cx0 + 2.5, cy0 + 2.5, cx1 - 2.5, cy1 - 2.5
                if ix1 > ix0 and iy1 > iy0:
                    for k in range(1, 24):
                        t = k / 24.0
                        px = ax1 + (ax2 - ax1) * t
                        py = ay1 + (ay2 - ay1) * t
                        if ix0 < px < ix1 and iy0 < py < iy1:
                            raise AssertionError(
                                f"[{name}] ARROW CROSSES THROUGH CARD {ctitle!r}: ({ax1:.0f},{ay1:.0f})->({ax2:.0f},{ay2:.0f})"
                            )
            for j in range(i + 1, m):
                bx1, by1, bx2, by2, gid_b = self.connector_segs[j]
                if gid_a == gid_b:
                    continue
                b_horiz = abs(by1 - by2) < 0.5
                b_vert = abs(bx1 - bx2) < 0.5
                if a_horiz and b_horiz:
                    ov_x = min(max(ax1, ax2), max(bx1, bx2)) - max(min(ax1, ax2), min(bx1, bx2))
                    if ov_x > 6.0 and abs(ay1 - by1) < 12.0:
                        raise AssertionError(
                            f"[{name}] PARALLEL OVERLAPPING HORIZONTAL ARROWS (dy={abs(ay1-by1):.1f}px) at y={ay1:.0f}"
                        )
                if a_vert and b_vert:
                    ov_y = min(max(ay1, ay2), max(by1, by2)) - max(min(ay1, ay2), min(by1, by2))
                    if ov_y > 6.0 and abs(ax1 - bx1) < 12.0:
                        raise AssertionError(
                            f"[{name}] PARALLEL OVERLAPPING VERTICAL ARROWS (dx={abs(ax1-bx1):.1f}px) at x={ax1:.0f}"
                        )

    def save(self, out_path: str):
        max_y = 60.0
        for _, _, _, y1, _, _ in self.text_boxes:
            max_y = max(max_y, y1)
        for _, y1, _, y2, _ in self.line_segs:
            max_y = max(max_y, y1, y2)
        for _, _, _, my1, _, _ in self.pill_masks:
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
                        footer: str = None, width: float = 760.0, main_w: float = 470.0):
    has_side = bool(side_notes)
    W = 900.0 if has_side else width
    box_x = 34.0 if has_side else (W - main_w) / 2
    box_w = 440.0 if has_side else main_w
    side_x = box_x + box_w + 138.0
    side_w = W - side_x - 28.0

    c = SvgCanvas(W, 120)
    y = c.add_header(title) + 8.0

    bottoms = []
    for idx, st in enumerate(steps):
        if idx > 0:
            prev_bot = bottoms[-1]
            lbl = st.get("edge_label")
            gap = 58.0 if lbl else 30.0
            ny = prev_bot + gap
            ec = st.get("edge_color", "#4a5568")
            c.add_line(box_x + box_w / 2, prev_bot, box_x + box_w / 2, ny,
                       color=ec, arrow_end=True, dash="4,3" if st.get("edge_dashed") else None,
                       label=lbl, label_pos=0.44, label_color=ec)
            y = ny
        ch = c.add_card(box_x, y, box_w, tag=st.get("tag"), title=st.get("title"),
                        body=st.get("body"), theme=st.get("theme", "slate"),
                        dashed=st.get("dashed", False), mono_body=st.get("mono", False))
        mid_y = y + ch / 2
        bottoms.append(y + ch)

        if has_side and idx in side_notes:
            sn = side_notes[idx]
            sh = SvgCanvas.measure_card_height(side_w, tag=sn.get("tag"), title=sn.get("title"),
                                               body=sn.get("body"), title_size=11.5, body_size=10.2)
            sy = mid_y - sh / 2
            c.add_card(side_x, sy, side_w, h=sh, tag=sn.get("tag"), title=sn.get("title"),
                       body=sn.get("body"), theme=sn.get("theme", "red"),
                       dashed=sn.get("dashed", True), title_size=11.5, body_size=10.2)
            sc = sn.get("edge_color", "#8d2d3b")
            if sn.get("reverse"):
                c.add_line(side_x, mid_y, box_x + box_w, mid_y, color=sc,
                           arrow_end=True, dash="4,3", label=sn.get("edge_label"),
                           label_pos=0.56, label_color=sc)
            else:
                c.add_line(box_x + box_w, mid_y, side_x, mid_y, color=sc,
                           arrow_end=True, dash="4,3", label=sn.get("edge_label"),
                           label_pos=0.44, label_color=sc)

    end_y = bottoms[-1] + 10.0
    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_sequence(out_path: str, title: str, actors: list, messages: list,
                   boundary_after: int = None, boundary_label: str = None,
                   bottom_note: dict = None, footer: str = None, width: float = 900.0):
    n = len(actors)
    margin = 34.0
    gap = 28.0
    act_w = (width - 2 * margin - (n - 1) * gap) / n
    c = SvgCanvas(width, 160)
    y = c.add_header(title) + 10.0

    if boundary_after is not None and boundary_label:
        y += 26.0

    act_xs = []
    max_ah = 0.0
    for i, a in enumerate(actors):
        ax = margin + i * (act_w + gap)
        act_xs.append(ax + act_w / 2)
        max_ah = max(max_ah, SvgCanvas.measure_card_height(act_w, title=a["title"], body=a.get("sub"),
                                                           title_size=12.0, body_size=10.0))

    for i, a in enumerate(actors):
        ax = margin + i * (act_w + gap)
        c.add_card(ax, y, act_w, h=max_ah, title=a["title"], body=a.get("sub"),
                   theme=a.get("theme", "slate"), align="center", title_size=12.0, body_size=10.0)

    life_top = y + max_ah
    cur_y = life_top + 10.0
    act_span_1hop = act_w + gap
    msg_coords = []
    messages = list(messages)
    for i, (f_idx, t_idx, lbl, col, is_dash) in enumerate(messages):
        if f_idx == t_idx:
            max_lbl_w = 230.0
        else:
            max_lbl_w = max(176.0, abs(t_idx - f_idx) * act_span_1hop - 32.0)
        if "\n" not in lbl and measure_text(lbl, 9.8) > max_lbl_w:
            lbl = "\n".join(wrap_lines(lbl, max_lbl_w, 9.8))
            messages[i] = (f_idx, t_idx, lbl, col, is_dash)
        lines_cnt = len(lbl.split("\n"))
        if f_idx == t_idx:
            half_h = (lines_cnt * 13.0 + 6.0) / 2
            my = cur_y + half_h + 10.0
            cur_y = my + half_h + 10.0
        else:
            pill_h = lines_cnt * 12.8 + 6.0
            my = cur_y + pill_h + 16.0
            cur_y = my + 12.0
        msg_coords.append((f_idx, t_idx, lbl, col, is_dash, my))

    life_bot = cur_y + 10.0
    for cx in act_xs:
        c.add_line(cx, life_top, cx, life_bot, color="#cbd5e1", width=1.3, layer="bg", is_connector=False)

    if boundary_after is not None:
        bx = (act_xs[boundary_after] + act_xs[boundary_after + 1]) / 2
        c.add_line(bx, y - 4.0, bx, life_bot, color="#8d2d3b", width=1.6, dash="5,4", layer="bg", is_connector=False)
        if boundary_label:
            c.add_pill_label(bx, y - 16.0, boundary_label, size=9.5, color="#8d2d3b",
                             bg="#f8eaec", border="#8d2d3b", bold=True, allow_card_touch=True)

    COLOR_MAP = {
        "slate": "#365378", "teal": "#236b66", "green": "#2b6a4c",
        "amber": "#b07926", "red": "#8d2d3b", "purple": "#5c4282",
    }
    for f_idx, t_idx, lbl, col, is_dash, my in msg_coords:
        sc = COLOR_MAP.get(col, col)
        x1, x2 = act_xs[f_idx], act_xs[t_idx]
        if f_idx == t_idx:
            c.add_pill_label(x1, my, lbl, size=10.0, color=sc, bg="#f4f1ea", border=sc)
        else:
            c.add_line(x1, my, x2, my, color=sc, width=1.6,
                       dash="5,3" if is_dash else None, arrow_end=True)
            lines_cnt = len(lbl.split("\n"))
            pill_offset = 17.0 + (lines_cnt - 1) * 6.8
            c.add_pill_label((x1 + x2) / 2, my - pill_offset, lbl, size=9.8, color="#1a1a1a",
                             bg="#ffffff", border="#dcd6cc")

    end_y = life_bot + 16.0
    if bottom_note:
        nw = width - 120.0
        nx = 60.0
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
                        foundation: dict = None, footer: str = None, width: float = 900.0):
    """
    Two-domain split architecture with row-synchronized card heights when both
    columns have equal card counts, guaranteeing 100% horizontal bridge alignment.
    """
    margin = 26.0
    mid_gap = 200.0
    col_w = (width - 2 * margin - mid_gap) / 2
    lx = margin
    rx = margin + col_w + mid_gap
    mid_x = lx + col_w + mid_gap / 2

    c = SvgCanvas(width, 180)
    y = c.add_header(title) + 12.0
    if boundary_label:
        y += 22.0

    inner_w = col_w - 32.0
    l_defs = left["cards"]
    r_defs = right["cards"]

    if len(l_defs) == len(r_defs):
        # Synchronize row positions and heights across both domains so paired cards align to 0.0px!
        cy = y + 40.0
        l_cards, r_cards = [], []
        for idx, (lcd, rcd) in enumerate(zip(l_defs, r_defs)):
            if idx > 0:
                has_lbl = bool(lcd.get("in_edge") or rcd.get("in_edge"))
                cy += 58.0 if has_lbl else 28.0
            lh_i = SvgCanvas.measure_card_height(inner_w, tag=lcd.get("tag"), title=lcd.get("title"),
                                                 body=lcd.get("body"), mono_body=lcd.get("mono", False))
            rh_i = SvgCanvas.measure_card_height(inner_w, tag=rcd.get("tag"), title=rcd.get("title"),
                                                 body=rcd.get("body"), mono_body=rcd.get("mono", False))
            row_h = max(lh_i, rh_i)
            l_cards.append((lx + 16.0, cy, inner_w, row_h, lcd))
            r_cards.append((rx + 16.0, cy, inner_w, row_h, rcd))
            cy += row_h
        box_h = (cy - y) + 18.0
    else:
        def layout_col(col, cx, top_y):
            cy = top_y + 40.0
            ys = []
            for idx, cd in enumerate(col["cards"]):
                if idx > 0:
                    cy += 58.0 if cd.get("in_edge") else 28.0
                h = SvgCanvas.measure_card_height(inner_w, tag=cd.get("tag"), title=cd.get("title"),
                                                  body=cd.get("body"), mono_body=cd.get("mono", False))
                ys.append((cx + 16.0, cy, inner_w, h, cd))
                cy += h
            return ys, (cy - top_y) + 18.0

        l_cards, lh = layout_col(left, lx, y)
        r_cards, rh = layout_col(right, rx, y)
        box_h = max(lh, rh)

    for col, cx in ((left, lx), (right, rx)):
        th = THEMES[col.get("theme", "stone")]
        c.add_rect(cx, y, col_w, box_h, fill=th["fill"], stroke=th["stroke"],
                   stroke_width=1.4, rx=8, dash="6,3" if col.get("dashed") else None, layer="bg")
        c.add_text(cx + col_w / 2, y + 23.0, col["label"].upper(), size=10.0,
                   fill=th["tag"], bold=True, anchor="middle", letter_spacing=0.6, layer="bg")

    for cards in (l_cards, r_cards):
        for idx, (ix, iy, iw, ih, cd) in enumerate(cards):
            if idx > 0 and (cd.get("in_edge") or cd.get("in_arrow")):
                prev = cards[idx - 1]
                p_bot = prev[1] + prev[3]
                lbl = cd.get("in_edge")
                if cd.get("in_dir") == "up":
                    c.add_line(ix + iw / 2, iy, ix + iw / 2, p_bot, color="#4a5568",
                               arrow_end=True, label=lbl, label_pos=0.44)
                else:
                    c.add_line(ix + iw / 2, p_bot, ix + iw / 2, iy, color="#4a5568",
                               arrow_end=True, label=lbl, label_pos=0.44)
            c.add_card(ix, iy, iw, h=ih, tag=cd.get("tag"), title=cd.get("title"),
                       body=cd.get("body"), theme=cd.get("theme", "white"),
                       dashed=cd.get("dashed", False), mono_body=cd.get("mono", False))

    if boundary_label:
        c.add_line(mid_x, y - 4.0, mid_x, y + box_h + 4.0, color="#8d2d3b", width=1.6,
                   dash="5,4", layer="bg", is_connector=False)
        c.add_pill_label(mid_x, y - 16.0, boundary_label, size=9.4, color="#8d2d3b",
                         bg="#f8eaec", border="#8d2d3b", bold=True, allow_card_touch=True)

    COLOR_MAP = {"slate": "#365378", "teal": "#236b66", "green": "#2b6a4c", "amber": "#b07926", "red": "#8d2d3b"}
    if bridges:
        for b_idx, (li, ri, direction, lbl, col) in enumerate(bridges):
            lc = l_cards[li]
            rc = r_cards[ri]
            x_left = lc[0] + lc[2]
            x_right = rc[0]
            sc = COLOR_MAP.get(col, col)

            ov_top = max(lc[1] + 10.0, rc[1] + 10.0)
            ov_bot = min(lc[1] + lc[3] - 10.0, rc[1] + rc[3] - 10.0)
            if ov_bot >= ov_top:
                my = (ov_top + ov_bot) / 2
                lpos = 0.50 if direction == "both" else (0.46 if direction == "lr" else 0.54)
                c.add_line(x_left, my, x_right, my, color=sc, width=1.6,
                           arrow_end=(direction in ("lr", "both")),
                           arrow_start=(direction in ("rl", "both")),
                           label=lbl, label_pos=lpos, label_color=sc)
            else:
                ly_mid = lc[1] + lc[3] / 2
                ry_mid = rc[1] + rc[3] / 2
                elbow_x = mid_x + (-26.0 if b_idx % 2 == 0 else 26.0)
                pts = [(x_left, ly_mid), (elbow_x, ly_mid), (elbow_x, ry_mid), (x_right, ry_mid)]
                c.add_polyline(pts, color=sc, width=1.6,
                               arrow_end=(direction in ("lr", "both")),
                               arrow_start=(direction in ("rl", "both")),
                               label=lbl, label_seg=1, label_pos=0.5, label_color=sc)

    end_y = y + box_h + 16.0
    if foundation:
        fy = y + box_h + 58.0
        fh = c.add_card(lx + 40.0, fy, width - 2 * margin - 80.0,
                        tag=foundation.get("tag"), title=foundation.get("title"),
                        body=foundation.get("body"), theme=foundation.get("theme", "amber"),
                        align="center")
        if foundation.get("left_label"):
            c.add_line(lx + col_w / 2, fy, lx + col_w / 2, y + box_h,
                       color="#875a14", arrow_end=True, label=foundation["left_label"], label_pos=0.44)
        if foundation.get("right_label"):
            c.add_line(rx + col_w / 2, fy, rx + col_w / 2, y + box_h,
                       color="#2b6a4c", arrow_end=True, label=foundation["right_label"], label_pos=0.44)
        end_y = fy + fh + 10.0

    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_horizontal_pipeline(out_path: str, title: str, stages: list,
                              under_anchor: dict = None, footer: str = None, width: float = 920.0):
    n = len(stages)
    margin = 24.0
    gaps = [68.0 if stages[i].get("edge_label") else 32.0 for i in range(1, n)]
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
                       label=s.get("edge_label"), label_pos=0.44)
        if i < n - 1:
            cur_x += box_w + gaps[i]

    end_y = y + max_h + 16.0
    if under_anchor:
        ti = under_anchor.get("target_idx", 0)
        uw = max(box_w + 54.0, 220.0)
        ux = max(margin, min(width - margin - uw, xs[ti] + box_w / 2 - uw / 2))
        uy = y + max_h + 58.0
        uh = c.add_card(ux, uy, uw, tag=under_anchor.get("tag"), title=under_anchor.get("title"),
                        body=under_anchor.get("body"), theme=under_anchor.get("theme", "red"),
                        align="center", title_size=11.5, body_size=10.0)
        c.add_line(xs[ti] + box_w / 2, uy, xs[ti] + box_w / 2, y + max_h,
                   color="#8d2d3b", width=1.6, arrow_end=True,
                   label=under_anchor.get("edge_label"), label_pos=0.44, label_color="#8d2d3b")
        end_y = uy + uh + 10.0

    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)


def build_fan_bands(out_path: str, title: str, bands: list, edges: list,
                    footer: str = None, width: float = 920.0):
    """
    Column-aligned multi-band architecture diagram:
    - Single-card bands span the full `[margin .. width - margin]` width so outer borders
      align cleanly with multi-card rows above/below, and every vertical arrow between a
      column card and a spanning card drops STRAIGHT VERTICALLY along the column's exact center!
    - Also supports horizontal left-to-right intra-band edges when `node_band[src] == node_band[dst]`.
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

    intra_edges_by_band = {}
    inter_edges_by_pair = {}
    for e in edges:
        src, dst, lbl, col_key, is_dash = e
        bs, bd = node_band[src], node_band[dst]
        if bs == bd:
            intra_edges_by_band.setdefault(bs, []).append(e)
        else:
            inter_edges_by_pair.setdefault((bs, bd), []).append(e)

    coords = {}
    for b_idx, row in enumerate(bands):
        n = len(row)
        has_intra_lbl = any(lbl for _, _, lbl, _, _ in intra_edges_by_band.get(b_idx, []))
        if b_idx in intra_edges_by_band:
            gap = 108.0 if has_intra_lbl else 44.0
        else:
            gap = 18.0 if n <= 4 else 12.0

        avail = width - 2 * margin - (n - 1) * gap
        weights = [nd.get("w_weight", 1.0) for nd in row]
        tot_w = sum(weights)
        ws = [avail * (wt / tot_w) for wt in weights]

        row_h = max(
            SvgCanvas.measure_card_height(w, tag=nd.get("tag"), title=nd.get("title"),
                                          body=nd.get("body"),
                                          title_size=11.5 if n >= 4 else 12.4,
                                          body_size=10.0 if n >= 4 else 10.7,
                                          mono_body=nd.get("mono", False))
            for w, nd in zip(ws, row)
        )
        cx = margin
        for w, nd in zip(ws, row):
            default_align = "center" if n == 1 else "left"
            c.add_card(cx, y, w, h=row_h, tag=nd.get("tag"), title=nd.get("title"),
                       body=nd.get("body"), theme=nd.get("theme", "slate"),
                       dashed=nd.get("dashed", False), align=nd.get("align", default_align),
                       title_size=11.5 if n >= 4 else 12.4,
                       body_size=10.0 if n >= 4 else 10.7,
                       mono_body=nd.get("mono", False))
            coords[nd["id"]] = (cx, y, w, row_h)
            cx += w + gap

        if b_idx < len(bands) - 1:
            pair_edges = inter_edges_by_pair.get((b_idx, b_idx + 1), [])
            has_lbl = any(lbl for _, _, lbl, _, _ in pair_edges)
            if not pair_edges:
                v_gap = 28.0
            elif has_lbl:
                v_gap = 58.0
            else:
                v_gap = 34.0
            y += row_h + v_gap
        else:
            y += row_h

    # Render horizontal intra-band edges
    for b_idx, b_edges in intra_edges_by_band.items():
        for src, dst, lbl, col_key, is_dash in b_edges:
            sx, sy, sw, sh = coords[src]
            dx, dy, dw, dh = coords[dst]
            sc = COLOR_MAP.get(col_key, col_key or "#4a5568")
            my = sy + sh / 2
            if sx < dx:
                c.add_line(sx + sw, my, dx, my, color=sc, width=1.6,
                           dash="4,3" if is_dash else None, arrow_end=True,
                           label=lbl, label_pos=0.44, label_color=sc)
            else:
                c.add_line(sx, my, dx + dw, my, color=sc, width=1.6,
                           dash="4,3" if is_dash else None, arrow_end=True,
                           label=lbl, label_pos=0.44, label_color=sc)

    # Render vertical inter-band edges along aligned shared horizontal overlap ports!
    for (b_src, b_dst), pair_edges in inter_edges_by_pair.items():
        for src, dst, lbl, col_key, is_dash in pair_edges:
            sx, sy, sw, sh = coords[src]
            dx, dy, dw, dh = coords[dst]
            sc = COLOR_MAP.get(col_key, col_key or "#4a5568")
            y1 = sy + sh
            y2 = dy

            # If one card is narrower and sits horizontally inside the wider spanning card,
            # drop a 100% straight vertical arrow at the narrower card's exact center!
            ov_left = max(sx + 16.0, dx + 16.0)
            ov_right = min(sx + sw - 16.0, dx + dw - 16.0)
            if ov_right >= ov_left:
                if sw <= dw:
                    px = max(ov_left, min(ov_right, sx + sw / 2))
                else:
                    px = max(ov_left, min(ov_right, dx + dw / 2))
                c.add_line(px, y1, px, y2, color=sc, width=1.6,
                           dash="4,3" if is_dash else None, arrow_end=True,
                           label=lbl, label_pos=0.44, label_color=sc)
            else:
                x1, x2 = sx + sw / 2, dx + dw / 2
                mid_y = y1 + 16.0
                c.add_polyline([(x1, y1), (x1, mid_y), (x2, mid_y), (x2, y2)],
                               color=sc, width=1.6, dash="4,3" if is_dash else None,
                               arrow_end=True, label=lbl, label_seg=2, label_pos=0.44, label_color=sc)

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
        c.add_line(spine_x, node_ys[0][0], spine_x, node_ys[-1][0], color="#cbd5e1", width=2.2, layer="bg", is_connector=False)

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
                                               body=lc["body"], title_size=11.5, body_size=10.0)
        if rc:
            rh = SvgCanvas.measure_card_height(card_w, tag=rc.get("tag"), title=rc["title"],
                                               body=rc["body"], title_size=11.5, body_size=10.0)
        row_h = max(lh, rh, 44.0)
        mid_y = y + row_h / 2
        spine_pts.append((mid_y, r["year"]))

        if lc:
            cy = mid_y - lh / 2
            c.add_card(lx, cy, card_w, h=lh, tag=lc.get("tag"), title=lc["title"],
                       body=lc["body"], theme=lc.get("theme", "red"),
                       title_size=11.5, body_size=10.0)
            c.add_line(lx + card_w, mid_y, mid_x - 36.0, mid_y, color="#8d2d3b", width=1.4)
        if rc:
            cy = mid_y - rh / 2
            c.add_card(rx, cy, card_w, h=rh, tag=rc.get("tag"), title=rc["title"],
                       body=rc["body"], theme=rc.get("theme", "green"),
                       title_size=11.5, body_size=10.0)
            c.add_line(mid_x + 36.0, mid_y, rx, mid_y, color="#2b6a4c", width=1.4)

        y += row_h + 18.0

    if len(spine_pts) >= 2:
        c.add_line(mid_x, spine_pts[0][0] - 10.0, mid_x, spine_pts[-1][0] + 10.0,
                   color="#94a3b8", width=2.0, layer="bg", is_connector=False)
    for mid_y, yr in spine_pts:
        c.add_pill_label(mid_x, mid_y, yr, size=9.6, color="#284163", bg="#edf1f6",
                         border="#365378", bold=True)

    end_y = y + 6.0
    if footer:
        end_y = c.add_footer(footer, end_y)
    c.height = end_y + 14.0
    c.save(out_path)
