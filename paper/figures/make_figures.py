"""Generate the white paper's figures as SVG (run: python3 make_figures.py)."""
from pathlib import Path
from html import escape

OUT = Path(__file__).parent
FONT = "Segoe UI, Helvetica, Arial, sans-serif"
INK, INK2, MUTED, LINE = "#0b0b0b", "#52514e", "#8a8984", "#c9c8c2"
SURFACE = "#fcfcfb"
BLUE, BLUE_T = "#2a78d6", "#e3edf9"       # hidden / private
ORANGE, ORANGE_T = "#eb6834", "#fcebe3"   # visible / disclosed
GRAY, GRAY_T = "#8a8984", "#efefec"       # neutral, comparison


def svg(w, h, body):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'font-family="{FONT}" font-size="12" fill="{INK}">\n'
            f'<rect width="{w}" height="{h}" fill="{SURFACE}"/>\n'
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{INK2}"/></marker></defs>\n' + "\n".join(body) + "\n</svg>\n")


def text(x, y, s, size=12, weight="normal", fill=INK, anchor="start", style=""):
    st = f' font-style="{style}"' if style else ""
    return f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{st}>{escape(s)}</text>'


def lines(x, y, rows, size=12, gap=15, **kw):
    return [text(x, y + i * gap, r, size=size, **kw) for i, r in enumerate(rows)]


def box(x, y, w, h, fill="#ffffff", stroke=LINE, rx=4, dash=False, sw=1):
    d = ' stroke-dasharray="4 3"' if dash else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>'


def badge(x, y, label, kind):
    color, tint = {"hidden": (BLUE, BLUE_T), "visible": (ORANGE, ORANGE_T)}[kind]
    w = 7 * len(label) + 16
    return [box(x, y, w, 20, fill=tint, stroke=color, rx=10),
            text(x + w / 2, y + 14, label, size=11, weight="600", fill=INK, anchor="middle")]


# ---------------------------------------------------------------- Figure 1
def figure1():
    W, H = 830, 560
    b = [text(20, 26, "A signed photo: its parts, and what each discloses", 15, "600")]
    # The file
    b += [box(20, 44, 330, 500, fill="#ffffff", stroke=INK2), text(32, 64, "JPEG file", 12, "600")]
    rows = [  # (y, h, x, w, title, detail lines, discloses lines, badge, kind)
        (76, 52, 32, 306, "EXIF and XMP metadata", ["outside the hard binding: not signed"],
         ["Make, model, lens, capture time,", "location"], "Removed by scrubbing", "hidden"),
        (172, 60, 44, 282, "Claim", ["claim generator; instance ID;", "references to the assertions"],
         ["The signing software and its build;", "an identifier unique to the asset"], "Stays visible", "visible"),
        (240, 60, 44, 282, "Assertions", ["hard binding: the content's hash;", "actions: \"created by\", source type"],
         ["The product; whether the content is", "a capture or AI-generated"], "Stays visible", "visible"),
        (332, 34, 56, 258, "Signer certificate", [],
         ["A certificate unique to the device", "or session"], "Hidden in every mode", "hidden"),
        (372, 34, 56, 258, "Issuing CA certificate", [],
         ["The organization, often the", "product line"], "Hidden with the issuer", "hidden"),
        (412, 34, 56, 258, "Signature", [],
         ["Checkable only with the signer's key"], "Hidden in every mode", "hidden"),
        (452, 34, 56, 258, "Time-stamp token (sigTst2)", [],
         ["The time-stamp authority; the exact", "time; values the authority can match"], "Hidden; only the day kept", "hidden"),
    ]
    # containers: manifest store, claim signature
    b += [box(32, 140, 306, 356, fill="#fafaf8", stroke=INK2), text(44, 158, "C2PA manifest store", 12, "600")]
    b += [box(44, 310, 282, 182, fill="#f4f4f1", stroke=MUTED), text(56, 326, "Claim signature (COSE)", 11.5, "600", INK2)]
    b += [box(32, 506, 306, 28, fill=GRAY_T, stroke=LINE), text(44, 524, "Image data (covered by the hard binding)", 11.5, fill=INK2)]
    for (y, h, x, w, title, detail, disc, lab, kind) in rows:
        b.append(box(x, y, w, h, fill="#ffffff", stroke=ORANGE if kind == "visible" else BLUE, sw=1.5))
        b.append(text(x + 10, y + 19, title, 12, "600"))
        b += lines(x + 10, y + 35, detail, 11, 14, fill=INK2)
        cy = y + h / 2
        b.append(f'<line x1="{x + w}" y1="{cy}" x2="372" y2="{cy}" stroke="{LINE}" stroke-width="1"/>')
        b.append(f'<circle cx="372" cy="{cy}" r="2.5" fill="{INK2}"/>')
        b += lines(384, cy - 10 if len(disc) > 1 else cy - 4, disc, 11.5, 14, fill=INK)
        b += badge(610, cy - 10, lab, kind)
    return svg(W, H, b)


# ---------------------------------------------------------------- Figure 2
def figure2():
    W, H = 780, 380
    b = [text(20, 26, "Sign as today, anonymize later, verify under the verifier's policy", 15, "600")]
    lanes = [(20, "1. Sign", "the device, unchanged"), (275, "2. Anonymize", "any party, without the signer's key"),
             (530, "3. Verify", "under the verifier's own policy")]
    for x, t, sub in lanes:
        b += [box(x, 44, 230, 316, fill="#ffffff", stroke=LINE), text(x + 12, 66, t, 13.5, "600"),
              text(x + 12, 83, sub, 11.5, fill=INK2, style="italic")]

    def step(x, y, h, title, rows, stroke=LINE, fill="#ffffff"):
        out = [box(x + 12, y, 206, h, fill=fill, stroke=stroke, sw=1.5 if stroke != LINE else 1),
               text(x + 22, y + 18, title, 12, "600")]
        return out + lines(x + 22, y + 34, rows, 11, 14, fill=INK2)

    b += step(20, 98, 58, "C2PA signing", ["X.509 certificate under a", "configured trust list (ES256)"])
    b += step(20, 168, 44, "Time stamp", ["a TSA countersigns (sigTst2)"])
    b += step(20, 262, 74, "Signed asset", ["claim, assertions, signature,", "certificates, time-stamp token"], ORANGE, ORANGE_T)

    b += step(275, 98, 44, "Check the asset is in scope", ["refuse it otherwise"])
    b += step(275, 154, 58, "Prove the original signature", ["zero-knowledge proof, in a", "chosen mode"])
    b += step(275, 224, 30, "Check its own proof", [])
    b += step(275, 262, 74, "Anonymized asset", ["same claim and binding; a ZK", "signature in place, same size"], BLUE, BLUE_T)

    b += step(530, 98, 58, "Policy", ["approved trust lists and", "snapshots; coarsest time window"])
    b += step(530, 168, 58, "Check", ["claim and hard binding (c2pa);", "the proof, inputs from the asset"])
    b += step(530, 262, 74, "Result", ["signed under an approved list,", "when valid; signer not disclosed"], INK2, GRAY_T)
    # arrows
    for x1, x2, y in [(238, 287, 299), (493, 542, 299)]:
        b.append(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{INK2}" stroke-width="1.5" marker-end="url(#arrow)"/>')
    for x, ys in [(123, [(156, 168), (212, 262)]), (378, [(142, 154), (212, 224), (254, 262)]), (633, [(156, 168), (226, 262)])]:
        for y1, y2 in ys:
            b.append(f'<line x1="{x}" y1="{y1}" x2="{x}" y2="{y2 - 1}" stroke="{INK2}" stroke-width="1.2" marker-end="url(#arrow)"/>')
    b.append(text(20, 374, "Trust lists feed the anonymizer (to build the proof) and the verifier (which approves its own); the signer's key never leaves the device.", 11, fill=INK2, style="italic"))
    return svg(W, H, b)


# ---------------------------------------------------------------- Figure 3
def figure3():
    cols = ["Signed original", "Disclosed issuer", "Hidden issuer", "Hidden issuer and time stamp"]
    V, Hd = ("Visible", "visible"), ("Hidden", "hidden")
    rows = [
        ("Signer certificate, signature", [V, Hd, Hd, Hd]),
        ("Issuing CA", [V, V, ("Hidden: 1 of 28 CAs", "hidden"), ("Hidden: 1 of 28 CAs", "hidden")]),
        ("Time-stamp authority", [V, V, V, ("Hidden: 1 of 19 CAs", "hidden")]),
        ("Exact time", [V, V, V, ("Day only", "hidden")]),
        ("Token serial and imprint", [V, V, V, Hd]),
        ("Claim: generator, actions, ID", [V, V, V, V]),
        ("Content hash (hard binding)", [V, V, V, V]),
        ("EXIF and XMP (not signed)", [V, ("Removed if scrubbed", "hidden"), ("Removed if scrubbed", "hidden"), ("Removed if scrubbed", "hidden")]),
    ]
    x0, cw, rh, y0 = 210, 150, 30, 84
    W, H = x0 + cw * 4 + 20, y0 + rh * len(rows) + 108
    b = [text(20, 26, "What each mode discloses", 15, "600"),
         text(20, 44, "Membership-set sizes on the official C2PA trust lists as fetched on November 4, 2026", 11.5, fill=INK2, style="italic")]
    for i, c in enumerate(cols):
        words = c.split(" ")
        rows_ = [" ".join(words[:2]), " ".join(words[2:])] if len(c) > 18 else [c]
        b += lines(x0 + i * cw + cw / 2, y0 - 22 if len(rows_) > 1 else y0 - 10, rows_, 12, 14, weight="600", anchor="middle")
    for r, (label, cells) in enumerate(rows):
        y = y0 + r * rh
        b.append(f'<line x1="20" y1="{y}" x2="{W - 20}" y2="{y}" stroke="{LINE}"/>')
        b.append(text(20, y + 19, label, 12))
        for i, (t, kind) in enumerate(cells):
            color, tint = (BLUE, BLUE_T) if kind == "hidden" else (ORANGE, ORANGE_T)
            cx = x0 + i * cw
            b.append(box(cx + 6, y + 4, cw - 12, rh - 8, fill=tint, stroke=color, rx=3))
            b.append(text(cx + cw / 2, y + 19, t, 11, "600" if kind == "hidden" else "normal", anchor="middle"))
    y = y0 + rh * len(rows)
    b.append(f'<line x1="20" y1="{y}" x2="{W - 20}" y2="{y}" stroke="{LINE}"/>')
    needs = [["—"], ["Trust list,", "TSA trust list"], ["Approved snapshots,", "TSA trust list"], ["Approved snapshots", "of both lists"]]
    b.append(text(20, y + 22, "Verifier needs", 12, "600"))
    for i, n in enumerate(needs):
        b += lines(x0 + i * cw + cw / 2, y + 22, n, 11, 14, fill=INK2, anchor="middle")
    b += badge(20, y + 62, "Visible", "visible") + badge(100, y + 62, "Hidden or reduced", "hidden")
    return svg(W, H, b)


# ---------------------------------------------------------------- Figure 4
def figure4():
    data = [  # label, time (s) [low, high], memory GiB, M1?
        ("Disclosed issuer", (71, 81), 6.7, True),
        ("Hidden issuer", (71, 71), 6.7, True),
        ("Hidden issuer and time stamp", (91, 91), 8.5, True),
        ("Disclosed issuer, fast key path", (28, 28), 6.7, True),
        ("M0, the first prototype", (611, 611), 11.1, False),
    ]
    W, H = 820, 316
    lab_w, top, bh, gap = 200, 78, 22, 14
    b = [text(20, 26, "Per-asset anonymization on a laptop, by mode", 15, "600"),
         text(20, 44, "Milestone 1 measured in one session (median of three cold proofs); M0 for scale", 11.5, fill=INK2, style="italic")]
    panels = [(lab_w + 20, 330, "Time per asset (seconds)", 700, [0, 100, 200, 300, 400, 500, 600, 700], 1),
              (lab_w + 390, 150, "Peak memory (GiB)", 12, [0, 4, 8, 12], 2)]
    for px, pw, title, vmax, ticks, which in panels:
        b.append(text(px, top - 14, title, 12, "600"))
        for t in ticks:
            x = px + pw * t / vmax
            b.append(f'<line x1="{x}" y1="{top - 4}" x2="{x}" y2="{top + len(data) * (bh + gap) - gap + 4}" stroke="#ecebe7"/>')
            b.append(text(x, top + len(data) * (bh + gap) + 10, str(t), 10.5, fill=MUTED, anchor="middle"))
        for i, (label, (lo, hi), mem, m1) in enumerate(data):
            y = top + i * (bh + gap)
            color = BLUE if m1 else GRAY
            v = lo if which == 1 else mem
            w = max(pw * v / vmax, 2)
            b.append(f'<rect x="{px}" y="{y}" width="{w}" height="{bh}" rx="3" fill="{color}"/>')
            if which == 1 and hi > lo:  # the session's range, first to last run
                w2 = pw * hi / vmax
                b.append(f'<rect x="{px + w + 2}" y="{y}" width="{w2 - w - 2}" height="{bh}" rx="3" fill="{BLUE_T}" stroke="{BLUE}" stroke-dasharray="3 2"/>')
                end, val = px + w2, f"{lo}–{hi} s"
            else:
                end, val = px + w, (f"{lo} s" if which == 1 else f"{mem} GiB")
            b.append(text(end + 6, y + 15, val, 11.5, "600" if not m1 else "normal", fill=INK))
            if which == 1:
                b.append(text(20, y + 15, label, 12, "600" if not m1 else "normal", fill=INK if m1 else INK2))
    yb = top + len(data) * (bh + gap) + 34
    b.append(f'<rect x="20" y="{yb - 10}" width="12" height="12" rx="2" fill="{BLUE}"/>')
    b.append(text(38, yb, "Milestone 1 (third-party, gnark)", 11.5))
    b.append(f'<rect x="250" y="{yb - 10}" width="12" height="12" rx="2" fill="{GRAY}"/>')
    b.append(text(268, yb, "M0 (signer-side, circom)", 11.5))
    b.append(text(460, yb, "Dashed: first to last run of the disclosed baseline", 11, fill=INK2, style="italic"))
    return svg(W, H, b)


for name, fn in [("figure1-anatomy", figure1), ("figure2-flow", figure2), ("figure3-modes", figure3), ("figure4-performance", figure4)]:
    (OUT / f"{name}.svg").write_text(fn(), encoding="utf-8")
    print("wrote", name)
