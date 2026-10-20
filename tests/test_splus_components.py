"""Component extraction exercised from native blueprint trees."""

from nbrowser.design import (
    MAX_COMPONENTS,
    DesignBlueprintEvidence,
    Node,
    componentize,
)


def test_empty_and_unique_layout_have_no_components() -> None:
    for nodes in ([], [Node("main"), Node("p", parent=0, text="unique")]):
        ir = componentize(DesignBlueprintEvidence(layout=nodes))
        assert ir.to_dict() == {
            "schema": "nbrowser.components.v1",
            "components": [],
            "covered_nodes": 0,
            "total_nodes": len(nodes),
            "taint": "page_derived",
            "rung": "un_witnessed_local",
        }


def test_repeated_cards_preserve_styles_and_variable_text() -> None:
    nodes: list[Node] = []
    for label in ("Alpha", "Beta"):
        root = len(nodes)
        nodes.extend(
            [
                Node(
                    "article",
                    bounds=[0, 0, 120, 80],
                    display="flex",
                    position="relative",
                    color="red",
                    background="white",
                    font_size="12px",
                    font_weight="700",
                    padding="4px",
                    border="1px solid black",
                    radius="3px",
                    layout_axis="gap: 4px",
                    effective_background="blue",
                ),
                Node("h2", parent=root, text=label, text_trailing=True),
                Node("p", parent=root, text="constant"),
            ]
        )
    ir = componentize(DesignBlueprintEvidence(layout=nodes))
    assert (ir.covered_nodes, ir.total_nodes) == (6, 6)
    assert len(ir.components) == 1
    component = ir.to_dict()["components"][0]
    assert component["id"] == "c0"
    assert component["instances"] == 2
    assert component["sample_bounds"] == [0, 0, 120, 80]
    template = component["template"]
    assert "content" not in template
    assert template["style"] == [
        "display: flex",
        "position: relative",
        "color: red",
        "background: white",
        "font-size: 12px",
        "font-weight: 700",
        "padding: 4px",
        "border: 1px solid black",
        "border-radius: 3px",
        "gap: 4px",
        "width: 120px",
        "height: 80px",
        "box-sizing: border-box",
    ]
    assert template["children"][0]["content"] == {
        "sample": "Alpha",
        "variable": True,
        "prop": "text0",
        "trailing": True,
    }
    assert template["children"][1]["content"] == {
        "sample": "constant",
        "variable": False,
        "prop": None,
        "trailing": False,
    }


def test_parent_components_consume_nested_candidates_and_inherit_background() -> None:
    nodes: list[Node] = []
    for _ in range(2):
        root = len(nodes)
        nodes.extend(
            [
                Node(
                    "section",
                    display="block",
                    position="static",
                    font_weight="400",
                    effective_background="ivory",
                ),
                Node("article", parent=root),
                Node("span", parent=root + 1),
            ]
        )
    ir = componentize(DesignBlueprintEvidence(layout=nodes))
    assert len(ir.components) == 1
    assert ir.components[0].tag == "section"
    assert ir.components[0].template.style == ["background: ivory"]
    assert ir.covered_nodes == 6


def test_component_limit_preserves_uncovered_count() -> None:
    nodes: list[Node] = []
    for index in range(MAX_COMPONENTS + 1):
        for _ in range(2):
            root = len(nodes)
            nodes.extend([Node(f"custom-{index}"), Node("span", parent=root)])
    ir = componentize(DesignBlueprintEvidence(layout=nodes))
    assert len(ir.components) == MAX_COMPONENTS
    assert ir.covered_nodes == 4 * MAX_COMPONENTS
    assert ir.total_nodes == 4 * (MAX_COMPONENTS + 1)
    assert ir.components[-1].id == f"c{MAX_COMPONENTS - 1}"


def test_wide_components_limit_template_children_but_count_all_nodes() -> None:
    nodes: list[Node] = []
    for _ in range(2):
        root = len(nodes)
        nodes.append(Node("section", bounds=[0, 0, 0, 10]))
        nodes.extend(Node("span", parent=root) for _ in range(23))
    ir = componentize(DesignBlueprintEvidence(layout=nodes))
    assert ir.covered_nodes == 48
    assert len(ir.components[0].template.children) == 20
    assert ir.components[0].template.style == []


def test_deep_components_bound_templates_and_signature_depth() -> None:
    nodes: list[Node] = []
    for _ in range(2):
        root = len(nodes)
        nodes.append(Node("section"))
        for depth in range(7):
            nodes.append(
                Node("div", parent=root + depth, text="leaf" if depth == 6 else None)
            )
    ir = componentize(DesignBlueprintEvidence(layout=nodes))
    assert len(ir.components) == 1
    assert ir.covered_nodes == 16
    template = ir.components[0].template
    for _ in range(5):
        assert len(template.children) == 1
        template = template.children[0]
    assert template.children == []


def test_missing_text_is_variable_and_later_content_uses_next_property() -> None:
    nodes = [
        Node("article"),
        Node("p", parent=0),
        Node("h2", parent=0, text="A"),
        Node("article"),
        Node("p", parent=3, text="present"),
        Node("h2", parent=3, text="B"),
    ]
    template = (
        componentize(DesignBlueprintEvidence(layout=nodes)).components[0].template
    )
    first, second = [child.content for child in template.children]
    assert first is not None and second is not None
    assert (first.sample, first.prop, first.variable) == ("present", "text0", True)
    assert (second.sample, second.prop, second.variable) == ("A", "text1", True)
