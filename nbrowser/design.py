"""Rendered design blueprint (`nbrowser.design.v1`) and component IR (`nbrowser.components.v1`)."""

from dataclasses import dataclass, field
from typing import Any

from nott_spine import ReceiptRung, TaintClass

from .sanitize import (
    redact_asset_url_keep_path,
    redact_css_custom_property_value,
    redact_diagnostic,
    redact_svg_paint_reference,
    redact_url_reference_keep_fragment,
)
from .session import BrowserSession

DESIGN_SCHEMA = "nbrowser.design.v1"
COMPONENTS_SCHEMA = "nbrowser.components.v1"
SIG_DEPTH = 5
TEMPLATE_DEPTH = 5
MAX_COMPONENTS = 40


@dataclass
class Viewport:
    width: float = 0.0
    height: float = 0.0
    dpr: float = 1.0


@dataclass
class CustomProperty:
    name: str
    value: str


@dataclass
class Theme:
    palette: list[str] = field(default_factory=list)
    fonts: list[str] = field(default_factory=list)
    spacing: list[str] = field(default_factory=list)
    custom_properties: list[CustomProperty] = field(default_factory=list)


@dataclass
class Node:
    tag: str
    role: str | None = None
    parent: int | None = None
    bounds: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    display: str = ""
    position: str = ""
    color: str = ""
    background: str = ""
    font_size: str = ""
    font_weight: str = ""
    font_family: str = ""
    padding: str = ""
    effective_background: str = ""
    text_align: str = ""
    radius: str = ""
    border: str = ""
    shadow: str = ""
    line_height: str = ""
    letter_spacing: str = ""
    margin: str = ""
    layout_axis: str = ""
    opacity: str = ""
    text: str | None = None
    text_trailing: bool = False


@dataclass
class Asset:
    kind: str
    src: str
    width: int | None = None
    height: int | None = None
    truncated: bool | None = None


@dataclass
class SvgShape:
    tag: str
    geometry: dict[str, str] = field(default_factory=dict)


@dataclass
class InlineSvg:
    view_box: str
    width: int
    height: int
    shapes: list[SvgShape] = field(default_factory=list)
    truncated: bool | None = None


@dataclass
class AnimatedNode:
    tag: str
    transition: str = ""
    animation_name: str = ""
    animation_duration: str = ""


@dataclass
class Animations:
    animated: list[AnimatedNode] = field(default_factory=list)
    keyframes: list[str] = field(default_factory=list)


@dataclass
class DesignBlueprintEvidence:
    schema: str = DESIGN_SCHEMA
    viewport: Viewport = field(default_factory=Viewport)
    theme: Theme = field(default_factory=Theme)
    layout: list[Node] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    svgs: list[InlineSvg] = field(default_factory=list)
    animations: Animations = field(default_factory=Animations)
    truncated: bool = False
    taint: str = "page_derived"
    rung: str = "un_witnessed_local"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "viewport": {
                "width": self.viewport.width,
                "height": self.viewport.height,
                "dpr": self.viewport.dpr,
            },
            "theme": {
                "palette": self.theme.palette,
                "fonts": self.theme.fonts,
                "spacing": self.theme.spacing,
                "custom_properties": [
                    {"name": p.name, "value": p.value}
                    for p in self.theme.custom_properties
                ],
            },
            "layout": [
                {
                    "tag": n.tag,
                    "role": n.role,
                    "parent": n.parent,
                    "bounds": n.bounds,
                    "display": n.display,
                    "position": n.position,
                    "color": n.color,
                    "background": n.background,
                    "font_size": n.font_size,
                    "font_weight": n.font_weight,
                    "font_family": n.font_family,
                    "padding": n.padding,
                    "effective_background": n.effective_background,
                    "text_align": n.text_align,
                    "radius": n.radius,
                    "border": n.border,
                    "shadow": n.shadow,
                    "line_height": n.line_height,
                    "letter_spacing": n.letter_spacing,
                    "margin": n.margin,
                    "layout_axis": n.layout_axis,
                    "opacity": n.opacity,
                    "text": n.text,
                    "text_trailing": n.text_trailing,
                }
                for n in self.layout
            ],
            "assets": [
                {
                    "kind": a.kind,
                    "src": a.src,
                    "width": a.width,
                    "height": a.height,
                    "truncated": a.truncated,
                }
                for a in self.assets
            ],
            "svgs": [
                {
                    "view_box": s.view_box,
                    "width": s.width,
                    "height": s.height,
                    "shapes": [
                        {"tag": sh.tag, "geometry": sh.geometry} for sh in s.shapes
                    ],
                    "truncated": s.truncated,
                }
                for s in self.svgs
            ],
            "animations": {
                "animated": [
                    {
                        "tag": an.tag,
                        "transition": an.transition,
                        "animation_name": an.animation_name,
                        "animation_duration": an.animation_duration,
                    }
                    for an in self.animations.animated
                ],
                "keyframes": self.animations.keyframes,
            },
            "truncated": self.truncated,
            "taint": self.taint,
            "rung": self.rung,
        }


DESIGN_PROBE = r"""(() => {
  const MAXNODES = 300, MAXASSETS = 100;
  const safe = (v) => String(v == null ? '' : v).replace(/[ -  ]/g, '').slice(0, 200);
  const safeReference = (v) => {
    const clean = String(v == null ? '' : v).replace(/[ -  ]/g, '');
    return clean.length > 200 ? '[truncated-svg-reference]' : clean;
  };
  const colorFreq = {}, bgFreq = {}, fontFreq = {}, spaceSet = new Set();
  const layout = [];
  const animated = [];
  const els = [];
  const indexOf = new WeakMap();
  const bump = (m, k) => { if (k) m[k] = (m[k] || 0) + 1; };

  const axisOf = (st) => {
    const decls = [];
    if (st.display === 'flex' || st.display === 'inline-flex') {
      if (st.flexDirection && st.flexDirection !== 'row') decls.push(`flex-direction: ${st.flexDirection}`);
      if (st.flexWrap && st.flexWrap !== 'nowrap') decls.push(`flex-wrap: ${st.flexWrap}`);
    } else if (st.display === 'grid' || st.display === 'inline-grid') {
      if (st.gridTemplateColumns && st.gridTemplateColumns !== 'none') decls.push(`grid-template-columns: ${st.gridTemplateColumns}`);
    } else {
      return '';
    }
    if (st.justifyContent && st.justifyContent !== 'normal') decls.push(`justify-content: ${st.justifyContent}`);
    if (st.alignItems && st.alignItems !== 'normal') decls.push(`align-items: ${st.alignItems}`);
    if (st.gap && st.gap !== 'normal' && !st.gap.startsWith('0px')) decls.push(`gap: ${st.gap}`);
    return safe(decls.join('; '));
  };

  const customProperties = [];
  try {
    const rootStyle = getComputedStyle(document.documentElement);
    const seenProperty = new Set();
    for (const sheet of Array.from(document.styleSheets)) {
      let rules = null;
      try { rules = sheet.cssRules; } catch (e) { continue; }
      if (!rules) continue;
      for (const rule of Array.from(rules)) {
        if (!rule.style || !rule.selectorText) continue;
        if (!/(^|,)\s*(:root|html)\s*(,|$)/.test(rule.selectorText)) continue;
        for (const property of Array.from(rule.style)) {
          if (!property.startsWith('--') || seenProperty.has(property)) continue;
          seenProperty.add(property);
          const value = rootStyle.getPropertyValue(property).trim();
          if (value) customProperties.push({ name: safe(property), value: safe(value) });
          if (customProperties.length >= 200) break;
        }
        if (customProperties.length >= 200) break;
      }
      if (customProperties.length >= 200) break;
    }
  } catch (e) {}

  const all = document.body ? document.body.querySelectorAll('*') : [];
  let count = 0;
  for (const el of all) {
    if (count >= MAXNODES) break;
    let r;
    try { r = el.getBoundingClientRect(); } catch (e) { continue; }
    if (!r || r.width <= 0 || r.height <= 0) continue;
    const st = getComputedStyle(el);
    bump(colorFreq, safe(st.color));
    if (st.backgroundColor && st.backgroundColor !== 'rgba(0, 0, 0, 0)' && st.backgroundColor !== 'transparent') bump(bgFreq, safe(st.backgroundColor));
    bump(fontFreq, safe(st.fontFamily));
    [st.marginTop, st.paddingTop, st.gap].forEach((s) => { if (s && s !== '0px' && s !== 'normal') spaceSet.add(safe(s)); });
    let txt = '';
    let first = '';
    for (const nd of el.childNodes) {
      if (nd.nodeType === 3 && nd.nodeValue) { if (!first && nd.nodeValue.trim()) first = 'text'; txt += nd.nodeValue; }
      if (nd.nodeType === 1 && !first) first = 'el';
    }
    txt = txt.replace(/\s+/g, ' ').trim().slice(0, 80);
    const trailing = first === 'el';
    const transparent = (c) => !c || c === 'rgba(0, 0, 0, 0)' || c === 'transparent';
    let ebg = '';
    if (transparent(st.backgroundColor)) {
      let q = el.parentElement;
      while (q) {
        const qc = getComputedStyle(q).backgroundColor;
        if (!transparent(qc)) { ebg = safe(qc); break; }
        q = q.parentElement;
      }
    }
    indexOf.set(el, layout.length);
    els.push(el);
    layout.push({
      tag: safe(el.tagName).toLowerCase(),
      role: el.getAttribute('role') ? safe(el.getAttribute('role')) : null,
      parent: null,
      bounds: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)],
      display: safe(st.display),
      position: safe(st.position),
      color: safe(st.color),
      background: transparent(st.backgroundColor) ? '' : safe(st.backgroundColor),
      font_size: safe(st.fontSize),
      font_weight: safe(st.fontWeight),
      font_family: safe(st.fontFamily),
      padding: st.padding === '0px' ? '' : safe(st.padding),
      effective_background: ebg,
      text_align: st.textAlign === 'start' ? '' : safe(st.textAlign),
      radius: st.borderRadius === '0px' ? '' : safe(st.borderRadius),
      border: (!st.borderStyle || st.borderStyle === 'none' || st.borderWidth === '0px')
        ? '' : safe(`${st.borderWidth} ${st.borderStyle} ${st.borderColor}`),
      shadow: (!st.boxShadow || st.boxShadow === 'none') ? '' : safe(st.boxShadow),
      line_height: (!st.lineHeight || st.lineHeight === 'normal') ? '' : safe(st.lineHeight),
      letter_spacing: (!st.letterSpacing || st.letterSpacing === 'normal') ? '' : safe(st.letterSpacing),
      margin: (!st.margin || st.margin === '0px') ? '' : safe(st.margin),
      layout_axis: axisOf(st),
      opacity: (st.opacity === '' || Number(st.opacity) === 1) ? '' : safe(st.opacity),
      text: txt || null,
      text_trailing: trailing
    });
    const hasTransition = st.transitionDuration && st.transitionDuration !== '0s';
    const hasAnimation = st.animationName && st.animationName !== 'none';
    if ((hasTransition || hasAnimation) && animated.length < 60) {
      animated.push({
        tag: safe(el.tagName).toLowerCase(),
        transition: hasTransition ? safe(st.transitionProperty + ' ' + st.transitionDuration + ' ' + st.transitionTimingFunction) : '',
        animation_name: hasAnimation ? safe(st.animationName) : '',
        animation_duration: hasAnimation ? safe(st.animationDuration) : ''
      });
    }
    count++;
  }
  for (let i = 0; i < els.length; i++) {
    let p = els[i].parentElement, parent = null;
    while (p) { if (indexOf.has(p)) { parent = indexOf.get(p); break; } p = p.parentElement; }
    layout[i].parent = parent;
  }
  const top = (freq, n) => Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, n).map((e) => e[0]).filter(Boolean);
  const assets = [];
  const svgs = [];
  const imgs = document.images ? Array.from(document.images).slice(0, MAXASSETS) : [];
  for (const img of imgs) {
    const raw = String(img.currentSrc || img.src || '');
    const inline = raw.startsWith('data:');
    const cap = 512;
    const clean = inline
      ? '[inline-data-redacted]'
      : raw.replace(/[ -  ]/g, '').slice(0, cap);
    assets.push({
      kind: 'image',
      src: clean,
      width: img.naturalWidth || null,
      height: img.naturalHeight || null,
      truncated: !inline && raw.length > cap ? true : null,
    });
  }
  const SHAPE_ATTRS = {
    path: ['d'],
    circle: ['cx', 'cy', 'r'],
    rect: ['x', 'y', 'width', 'height', 'rx'],
    line: ['x1', 'y1', 'x2', 'y2'],
    polygon: ['points'],
    polyline: ['points'],
    ellipse: ['cx', 'cy', 'rx', 'ry'],
    use: ['href', 'xlink:href'],
  };
  const svgNodes = document.querySelectorAll ? document.querySelectorAll('svg') : [];
  const svgScanEnd = Math.min(svgNodes.length, MAXASSETS);
  for (let index = 0; index < svgScanEnd; index += 1) {
    const node = svgNodes[index];
    let rect;
    try { rect = node.getBoundingClientRect(); } catch (e) { continue; }
    if (!rect || rect.width <= 0 || rect.height <= 0) continue;
    const shapes = [];
    let shapeTruncated = false;
    for (const [tag, attrs] of Object.entries(SHAPE_ATTRS)) {
      for (const shape of Array.from(node.querySelectorAll(tag))) {
        if (shapes.length >= 40) { shapeTruncated = true; break; }
        const geometry = {};
        for (const attr of attrs) {
          const value = shape.getAttribute(attr);
          if (value) geometry[attr] = safeReference(value);
        }
        if (!Object.keys(geometry).length) continue;
        const fill = shape.getAttribute('fill');
        if (fill) geometry.fill = safeReference(fill);
        shapes.push({ tag, geometry });
      }
      if (shapeTruncated) break;
    }
    if (!shapes.length) continue;
    svgs.push({
      view_box: safe(node.getAttribute('viewBox') || ''),
      width: Math.round(rect.width),
      height: Math.round(rect.height),
      shapes,
      truncated: shapeTruncated ? true : null,
    });
  }
  const keyframes = [];
  try {
    for (const sheet of Array.from(document.styleSheets || [])) {
      let rules;
      try { rules = sheet.cssRules; } catch (e) { continue; }
      if (!rules) continue;
      for (const rule of Array.from(rules)) {
        if (rule.type === 7 && keyframes.length < 30) keyframes.push(safe(rule.name));
      }
    }
  } catch (e) {}
  return {
    viewport: { width: innerWidth || 0, height: innerHeight || 0, dpr: window.devicePixelRatio || 1 },
    theme: {
      palette: Array.from(new Set(top(colorFreq, 8).concat(top(bgFreq, 8)))),
      fonts: Array.from(new Set(top(fontFreq, 5))),
      spacing: Array.from(spaceSet).slice(0, 12),
      custom_properties: customProperties
    },
    layout: layout,
    assets: assets,
    svgs: svgs,
    animations: { animated: animated, keyframes: keyframes },
    truncated: count >= MAXNODES
  };
})()"""


def read_design_blueprint(
    session: BrowserSession, tab_id: str
) -> DesignBlueprintEvidence:
    raw = session.evaluate(tab_id, DESIGN_PROBE)
    if not isinstance(raw, dict):
        raw = {}

    vp_raw = raw.get("viewport", {})
    viewport = Viewport(
        width=float(vp_raw.get("width", 0.0)),
        height=float(vp_raw.get("height", 0.0)),
        dpr=float(vp_raw.get("dpr", 1.0)),
    )

    theme_raw = raw.get("theme", {})
    custom_props = [
        CustomProperty(
            name=redact_diagnostic(str(cp.get("name", ""))),
            value=redact_css_custom_property_value(str(cp.get("value", ""))),
        )
        for cp in theme_raw.get("custom_properties", [])
        if isinstance(cp, dict)
    ]
    theme = Theme(
        palette=[redact_diagnostic(str(c)) for c in theme_raw.get("palette", [])],
        fonts=[redact_diagnostic(str(f)) for f in theme_raw.get("fonts", [])],
        spacing=[redact_diagnostic(str(s)) for s in theme_raw.get("spacing", [])],
        custom_properties=custom_props,
    )

    layout: list[Node] = []
    for n in raw.get("layout", []):
        if not isinstance(n, dict):
            continue
        node = Node(
            tag=str(n.get("tag", "")),
            role=str(n["role"]) if n.get("role") is not None else None,
            parent=int(n["parent"]) if n.get("parent") is not None else None,
            bounds=list(n.get("bounds", [0, 0, 0, 0])),
            display=str(n.get("display", "")),
            position=str(n.get("position", "")),
            color=redact_diagnostic(str(n.get("color", ""))),
            background=redact_diagnostic(str(n.get("background", ""))),
            font_size=redact_diagnostic(str(n.get("font_size", ""))),
            font_weight=redact_diagnostic(str(n.get("font_weight", ""))),
            font_family=redact_diagnostic(str(n.get("font_family", ""))),
            padding=str(n.get("padding", "")),
            effective_background=redact_diagnostic(
                str(n.get("effective_background", ""))
            ),
            text_align=str(n.get("text_align", "")),
            radius=str(n.get("radius", "")),
            border=str(n.get("border", "")),
            shadow=str(n.get("shadow", "")),
            line_height=str(n.get("line_height", "")),
            letter_spacing=str(n.get("letter_spacing", "")),
            margin=str(n.get("margin", "")),
            layout_axis=str(n.get("layout_axis", "")),
            opacity=str(n.get("opacity", "")),
            text=redact_diagnostic(str(n["text"]))
            if n.get("text") is not None
            else None,
            text_trailing=bool(n.get("text_trailing", False)),
        )
        layout.append(node)

    assets: list[Asset] = []
    for a in raw.get("assets", []):
        if not isinstance(a, dict):
            continue
        src = str(a.get("src", ""))
        clean_src = (
            "[inline-data-redacted]"
            if src == "[inline-data-redacted]"
            else redact_asset_url_keep_path(src)
        )
        assets.append(
            Asset(
                kind=str(a.get("kind", "image")),
                src=clean_src,
                width=int(a["width"]) if a.get("width") is not None else None,
                height=int(a["height"]) if a.get("height") is not None else None,
                truncated=bool(a["truncated"])
                if a.get("truncated") is not None
                else None,
            )
        )

    svgs: list[InlineSvg] = []
    for s in raw.get("svgs", []):
        if not isinstance(s, dict):
            continue
        shapes: list[SvgShape] = []
        for sh in s.get("shapes", []):
            if not isinstance(sh, dict):
                continue
            geom = {
                k: redact_svg_paint_reference(str(v))
                for k, v in dict(sh.get("geometry", {})).items()
            }
            shapes.append(SvgShape(tag=str(sh.get("tag", "")), geometry=geom))
        svgs.append(
            InlineSvg(
                view_box=redact_url_reference_keep_fragment(str(s.get("view_box", ""))),
                width=int(s.get("width", 0)),
                height=int(s.get("height", 0)),
                shapes=shapes,
                truncated=bool(s["truncated"])
                if s.get("truncated") is not None
                else None,
            )
        )

    anim_raw = raw.get("animations", {})
    animated = [
        AnimatedNode(
            tag=str(an.get("tag", "")),
            transition=str(an.get("transition", "")),
            animation_name=str(an.get("animation_name", "")),
            animation_duration=str(an.get("animation_duration", "")),
        )
        for an in anim_raw.get("animated", [])
        if isinstance(an, dict)
    ]
    keyframes = [str(k) for k in anim_raw.get("keyframes", [])]
    animations = Animations(animated=animated, keyframes=keyframes)

    return DesignBlueprintEvidence(
        viewport=viewport,
        theme=theme,
        layout=layout,
        assets=assets,
        svgs=svgs,
        animations=animations,
        truncated=bool(raw.get("truncated", False)),
        taint=TaintClass.PageDerived.value,
        rung=ReceiptRung.UnwitnessedLocal.value,
    )


# -- Components IR (nbrowser.components.v1) -----------------------------------


@dataclass
class TemplateContent:
    sample: str
    variable: bool
    prop: str | None = None
    trailing: bool = False


@dataclass
class ComponentTemplate:
    tag: str
    style: list[str] = field(default_factory=list)
    content: TemplateContent | None = None
    children: list[ComponentTemplate] = field(default_factory=list)


@dataclass
class Component:
    id: str
    tag: str
    instances: int
    sample_bounds: list[int]
    template: ComponentTemplate


@dataclass
class ComponentsIR:
    schema: str = COMPONENTS_SCHEMA
    components: list[Component] = field(default_factory=list)
    covered_nodes: int = 0
    total_nodes: int = 0
    taint: str = "page_derived"
    rung: str = "un_witnessed_local"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "components": [
                {
                    "id": c.id,
                    "tag": c.tag,
                    "instances": c.instances,
                    "sample_bounds": c.sample_bounds,
                    "template": _template_to_dict(c.template),
                }
                for c in self.components
            ],
            "covered_nodes": self.covered_nodes,
            "total_nodes": self.total_nodes,
            "taint": self.taint,
            "rung": self.rung,
        }


def _template_to_dict(t: ComponentTemplate) -> dict[str, Any]:
    out: dict[str, Any] = {
        "tag": t.tag,
        "style": t.style,
        "children": [_template_to_dict(ch) for ch in t.children],
    }
    if t.content is not None:
        out["content"] = {
            "sample": t.content.sample,
            "variable": t.content.variable,
            "prop": t.content.prop,
            "trailing": t.content.trailing,
        }
    return out


def _build_children(nodes: list[Node]) -> list[list[int]]:
    children: list[list[int]] = [[] for _ in nodes]
    for index, node in enumerate(nodes):
        if (
            node.parent is not None
            and node.parent < len(nodes)
            and node.parent != index
        ):
            children[node.parent].append(index)
    return children


def _node_signature(
    index: int, nodes: list[Node], children: list[list[int]], depth: int
) -> str:
    tag = nodes[index].tag
    if depth == 0 or not children[index]:
        return tag
    child_sigs = [
        _node_signature(ch, nodes, children, depth - 1) for ch in children[index]
    ]
    return f"{tag}({','.join(child_sigs)})"


def _subtree_size(index: int, children: list[list[int]]) -> int:
    return 1 + sum(_subtree_size(ch, children) for ch in children[index])


def _mark_subtree(index: int, children: list[list[int]], consumed: list[bool]) -> None:
    consumed[index] = True
    for ch in children[index]:
        _mark_subtree(ch, children, consumed)


def _node_style_decls(node: Node) -> list[str]:
    decls: list[str] = []
    if node.display and node.display != "block":
        decls.append(f"display: {node.display}")
    if node.position and node.position != "static":
        decls.append(f"position: {node.position}")
    if node.color:
        decls.append(f"color: {node.color}")
    if node.background:
        decls.append(f"background: {node.background}")
    if node.font_size:
        decls.append(f"font-size: {node.font_size}")
    if node.font_weight and node.font_weight != "400":
        decls.append(f"font-weight: {node.font_weight}")
    if node.padding:
        decls.append(f"padding: {node.padding}")
    if node.border:
        decls.append(f"border: {node.border}")
    if node.radius:
        decls.append(f"border-radius: {node.radius}")
    if node.layout_axis:
        decls.append(node.layout_axis)
    return decls


def _template_content(
    texts: list[str], trailing: bool, prop_counter: list[int]
) -> TemplateContent | None:
    non_empty = [t for t in texts if t]
    if not non_empty:
        return None
    sample = non_empty[0]
    variable = any(t != texts[0] for t in texts)
    prop = None
    if variable:
        prop = f"text{prop_counter[0]}"
        prop_counter[0] += 1
    return TemplateContent(
        sample=sample, variable=variable, prop=prop, trailing=trailing
    )


def _build_template(
    instances: list[int],
    nodes: list[Node],
    children: list[list[int]],
    depth: int,
    prop_counter: list[int],
) -> ComponentTemplate:
    root = instances[0]
    texts = [nodes[inst].text or "" for inst in instances]
    content = _template_content(texts, nodes[root].text_trailing, prop_counter)
    child_templates: list[ComponentTemplate] = []
    if depth > 0:
        root_children_count = min(len(children[root]), 20)
        for slot in range(root_children_count):
            slot_instances: list[int] = []
            for inst in instances:
                if slot < len(children[inst]):
                    slot_instances.append(children[inst][slot])
            if slot_instances:
                child_templates.append(
                    _build_template(
                        slot_instances,
                        nodes,
                        children,
                        depth - 1,
                        prop_counter,
                    )
                )
    style = _node_style_decls(nodes[root])
    w, h = nodes[root].bounds[2], nodes[root].bounds[3]
    if w > 0 and h > 0:
        style.append(f"width: {w}px")
        style.append(f"height: {h}px")
        style.append("box-sizing: border-box")
    return ComponentTemplate(
        tag=nodes[root].tag,
        content=content,
        style=style,
        children=child_templates,
    )


def componentize(blueprint: DesignBlueprintEvidence) -> ComponentsIR:
    nodes = blueprint.layout
    children = _build_children(nodes)
    sigs = [_node_signature(i, nodes, children, SIG_DEPTH) for i in range(len(nodes))]
    sizes = [_subtree_size(i, children) for i in range(len(nodes))]

    groups: dict[str, list[int]] = {}
    for index, sig in enumerate(sigs):
        groups.setdefault(sig, []).append(index)

    candidates = [
        inst for inst in groups.values() if len(inst) >= 2 and sizes[inst[0]] >= 2
    ]
    candidates.sort(key=lambda a: (-sizes[a[0]], -len(a), a[0]))

    consumed = [False] * len(nodes)
    components: list[Component] = []
    covered = 0

    for instances in candidates:
        if len(components) >= MAX_COMPONENTS:
            break
        fresh = [i for i in instances if not consumed[i]]
        if len(fresh) < 2:
            continue
        for inst in fresh:
            _mark_subtree(inst, children, consumed)
            covered += sizes[inst]

        root = fresh[0]
        prop_counter = [0]
        template = _build_template(fresh, nodes, children, TEMPLATE_DEPTH, prop_counter)
        if nodes[root].effective_background and not any(
            decl.startswith("background:") for decl in template.style
        ):
            template.style.append(f"background: {nodes[root].effective_background}")
        components.append(
            Component(
                id=f"c{len(components)}",
                tag=nodes[root].tag,
                instances=len(fresh),
                sample_bounds=nodes[root].bounds,
                template=template,
            )
        )

    return ComponentsIR(
        components=components,
        covered_nodes=covered,
        total_nodes=len(nodes),
        taint=TaintClass.PageDerived.value,
        rung=ReceiptRung.UnwitnessedLocal.value,
    )
