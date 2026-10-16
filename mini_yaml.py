#!/usr/bin/env python3
"""Minimal YAML-subset parser (stdlib only).

Supports the small config shapes used by Ingenious AI GitHub Actions:
- nested mappings with 2-space indentation
- lists of scalars ("- item")
- scalar values: strings, ints, floats, booleans, null

This is NOT a general YAML parser. It is intentionally tiny so the
action has zero dependencies.
"""


def _parse_scalar(text):
    text = text.strip()
    if text in ("~", "null", "Null", "NULL"):
        return None
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def parse(text):
    """Parse a small YAML document into dicts/lists/scalars."""
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, stripped))

    def parse_block(pos, indent):
        # Decide container type from the first line at this indent.
        if pos < len(lines) and lines[pos][1].startswith("- "):
            items = []
            while pos < len(lines) and lines[pos][0] == indent and lines[pos][1].startswith("- "):
                items.append(_parse_scalar(lines[pos][1][2:]))
                pos += 1
            return items, pos
        obj = {}
        while pos < len(lines) and lines[pos][0] == indent:
            _, content = lines[pos]
            if content.startswith("- "):
                break  # belongs to an outer list; stop
            if ":" not in content:
                raise ValueError("mini_yaml: expected 'key: value', got %r" % content)
            key, _, rest = content.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest:
                obj[key] = _parse_scalar(rest)
                pos += 1
            else:
                # Nested block on following lines.
                if pos + 1 < len(lines) and lines[pos + 1][0] > indent:
                    value, pos = parse_block(pos + 1, lines[pos + 1][0])
                    obj[key] = value
                else:
                    obj[key] = None
                    pos += 1
        return obj, pos

    if not lines:
        return {}
    result, _ = parse_block(0, lines[0][0])
    return result


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return parse(fh.read())
