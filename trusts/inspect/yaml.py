"""Canonical YAML for the schema-1 authorization policy document.

One spelling, one byte profile. The dumper is a ``yaml.SafeDumper``
subclass. It does not use ``CSafeDumper``, ``FullLoader``,
``UnsafeLoader``, or custom YAML tags. Anchors and aliases are not
emitted. Acceptance of a lockfile is raw bytes from
``render_policy_sql_bytes``, not a parse.

PyYAML does not promise that ``yaml.dump`` bytes stay stable across
versions, hash seeds, or the libyaml build. These representers and the
golden files are what pin the bytes. The byte profile is CI-validated
with ``PyYAML>=6.0.3``; supported installations may use later releases and
regenerate reviewed lockfiles when the emitted bytes change.
"""

from __future__ import annotations

__all__ = []

import json
import math
import re

import yaml

_KEY_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_INT_RE = re.compile(r'^-?(?:0|[1-9][0-9]*)$')
_FLOAT_RE = re.compile(
    r'^-?(?:0|[1-9][0-9]*)\.[0-9]+(?:e[+-][0-9]+)?$'
)
# Plain keys that YAML 1.1 would resolve as bool or null. Our keys are
# identifiers; these words are rejected so a key can never be retagged.
_RESERVED_PLAIN = frozenset((
    'true', 'false', 'null', 'yes', 'no', 'on', 'off',
    'True', 'False', 'Null', 'NULL', 'YES', 'NO', 'Yes', 'No',
    'ON', 'OFF', 'On', 'Off', '~',
))
_TAG_NULL = 'tag:yaml.org,2002:null'
_TAG_BOOL = 'tag:yaml.org,2002:bool'
_TAG_INT = 'tag:yaml.org,2002:int'
_TAG_FLOAT = 'tag:yaml.org,2002:float'
_TAG_STR = 'tag:yaml.org,2002:str'
_TAG_SEQ = 'tag:yaml.org,2002:seq'
_TAG_MAP = 'tag:yaml.org,2002:map'
_LITERAL_KEYS = frozenset(('sql',))
_FLOW_MAP_KEYS = frozenset((
    'user', 'group', 'permission', 'content', 'delegate', 'sponsor',
))
_FLOW_SEQ_KEYS = frozenset(('params',))


class PolicyYamlError(ValueError):
    """The document cannot be spelled as canonical policy YAML."""


class _PlainKey(str):
    """Mapping key. Emitted as a plain identifier, never quoted."""


class _Quoted(str):
    """Scalar string. Always double-quoted so YAML 1.1 cannot retype it."""


class _SqlText(str):
    """SQL text. Emitted as a ``|-`` literal block, or the dump fails."""


class _FlowSeq(list):
    """Sequence emitted in flow style on one line. Used for ``params``."""


class _FlowMap(dict):
    """Mapping emitted in flow style. Used inside ``params``."""


def canonical_float_scalar(value):
    """Return the only plain-float spelling this codec emits.

    Finite values only. ``-0.0`` keeps its sign. Every spelling has a
    decimal point, so it cannot be read as an int. Scientific form is
    ``1.0e+16`` / ``1.0e-07`` (a dot before ``e``, exponent sign and
    digits taken from :func:`json.dumps`) because a bare ``1e+16`` is
    not a YAML 1.1 implicit float and PyYAML would emit ``!!float``.
    """
    if isinstance(value, bool) or not isinstance(value, float):
        raise PolicyYamlError(
            'Canonical float spelling requires a float, not %s.'
            % type(value).__name__
        )
    if not math.isfinite(value):
        raise PolicyYamlError(
            'Non-finite floats are tagged mappings, not plain YAML floats.'
        )
    if value == 0.0:
        if math.copysign(1.0, value) < 0:
            return '-0.0'
        return '0.0'
    text = json.dumps(value)
    if 'e' in text:
        mantissa, exponent = text.split('e', 1)
        if '.' not in mantissa:
            mantissa += '.0'
        if not re.fullmatch(r'[+-][0-9]+', exponent):
            raise PolicyYamlError(
                'JSON float exponent %r is not canonical.' % (exponent,)
            )
        text = mantissa + 'e' + exponent
    elif '.' not in text:
        text += '.0'
    if not _FLOAT_RE.fullmatch(text):
        raise PolicyYamlError('Float spelling %r is not canonical.' % (text,))
    return text


class PolicyYamlDumper(yaml.SafeDumper):
    """Pure-Python safe dumper. Aliases are never emitted."""

    def ignore_aliases(self, data):
        return True

    def increase_indent(self, flow=False, indentless=False):
        # ``indentless=False`` keeps block sequences nested under their key.
        # ``params`` is the exception: it is a one-line flow sequence.
        return super().increase_indent(flow, False)


def _represent_plain_key(dumper, value):
    return dumper.represent_scalar(_TAG_STR, value, style='')


def _represent_quoted(dumper, value):
    return dumper.represent_scalar(_TAG_STR, value, style='"')


def _represent_sql(dumper, value):
    if value == '' or '\r' in value or value.endswith('\n'):
        raise PolicyYamlError(
            'SQL must be a non-empty literal block without a trailing '
            'newline or CR.'
        )
    return dumper.represent_scalar(_TAG_STR, value, style='|')


def _represent_float(dumper, value):
    return dumper.represent_scalar(
        _TAG_FLOAT, canonical_float_scalar(value), style='',
    )


def _represent_none(dumper, value):
    del value
    return dumper.represent_scalar(_TAG_NULL, 'null', style='')


def _represent_bool(dumper, value):
    return dumper.represent_scalar(
        _TAG_BOOL, 'true' if value else 'false', style='',
    )


def _represent_int(dumper, value):
    if isinstance(value, bool):
        raise PolicyYamlError('Bool must not be emitted as an int.')
    text = str(value)
    if not _INT_RE.fullmatch(text):
        raise PolicyYamlError('Int spelling %r is not canonical.' % (text,))
    return dumper.represent_scalar(_TAG_INT, text, style='')


def _flow_prepare(value):
    if isinstance(value, dict):
        return _FlowMap(
            (key, _flow_prepare(item)) for key, item in value.items()
        )
    if isinstance(value, list):
        return _FlowSeq(_flow_prepare(item) for item in value)
    return value


def _prepare_value(key, value):
    if key in _FLOW_SEQ_KEYS:
        if not isinstance(value, list):
            raise PolicyYamlError(
                'Key %r must be a list, not %s.'
                % (key, type(value).__name__)
            )
        return _FlowSeq(_flow_prepare(item) for item in value)
    if key in _FLOW_MAP_KEYS and isinstance(value, dict):
        return _flow_prepare(value)
    if key in _LITERAL_KEYS:
        if not isinstance(value, str):
            raise PolicyYamlError(
                'Key %r must be SQL text, not %s.'
                % (key, type(value).__name__)
            )
        return _SqlText(value)
    if isinstance(value, str):
        return _Quoted(value)
    return value


def _represent_flow_seq(dumper, value):
    return dumper.represent_sequence(_TAG_SEQ, list(value), flow_style=True)


def _represent_flow_map(dumper, mapping):
    pairs = []
    for key, value in mapping.items():
        if not isinstance(key, str) or isinstance(key, bool):
            raise PolicyYamlError(
                'Policy YAML keys must be strings, not %s.'
                % type(key).__name__
            )
        if not _KEY_RE.fullmatch(key) or key in _RESERVED_PLAIN:
            raise PolicyYamlError(
                'Policy YAML key %r is not a plain identifier.' % (key,)
            )
        if isinstance(value, (_FlowMap, _FlowSeq)):
            prepared = value
        else:
            prepared = _prepare_value(key, value)
        pairs.append((_PlainKey(key), prepared))
    return dumper.represent_mapping(_TAG_MAP, pairs, flow_style=True)


def _represent_dict(dumper, mapping):
    pairs = []
    for key, value in mapping.items():
        if not isinstance(key, str) or isinstance(key, bool):
            raise PolicyYamlError(
                'Policy YAML keys must be strings, not %s.'
                % type(key).__name__
            )
        if not _KEY_RE.fullmatch(key) or key in _RESERVED_PLAIN:
            raise PolicyYamlError(
                'Policy YAML key %r is not a plain identifier.' % (key,)
            )
        pairs.append((_PlainKey(key), _prepare_value(key, value)))
    return dumper.represent_mapping(_TAG_MAP, pairs, flow_style=False)


def _reject_unknown(dumper, data):
    del dumper
    raise PolicyYamlError(
        'Policy YAML cannot encode %s. Tag it before dumping.'
        % type(data).__name__
    )


for _cls, _fn in (
    (_PlainKey, _represent_plain_key),
    (_Quoted, _represent_quoted),
    (_SqlText, _represent_sql),
    (_FlowSeq, _represent_flow_seq),
    (_FlowMap, _represent_flow_map),
    (str, _represent_quoted),
    (float, _represent_float),
    (bool, _represent_bool),
    (type(None), _represent_none),
    (int, _represent_int),
    (dict, _represent_dict),
):
    PolicyYamlDumper.add_representer(_cls, _fn)
PolicyYamlDumper.add_multi_representer(object, _reject_unknown)


def _assert_canonical_text(text):
    if text.startswith('---') or text.startswith('...'):
        raise PolicyYamlError('Policy YAML must not open with a document marker.')
    if '\r' in text:
        raise PolicyYamlError('Policy YAML must use LF endings.')
    if re.search(r'(^|\s)!!', text):
        raise PolicyYamlError('Policy YAML must not emit tags.')
    if not text.endswith('\n') or text.endswith('\n\n'):
        raise PolicyYamlError('Policy YAML must end with one LF.')
    for line in text.split('\n'):
        if line in ('---', '...'):
            raise PolicyYamlError('Policy YAML must not contain document markers.')
        stripped = line.strip()
        if stripped.startswith('sql:') and stripped != 'sql: |-':
            raise PolicyYamlError(
                'SQL must be a strip literal (`sql: |-`), not %r.' % (stripped,)
            )
        if stripped.startswith('condition:') and not (
            stripped.startswith('condition: "') and stripped.endswith('"')
        ):
            raise PolicyYamlError(
                'condition must be one double-quoted line, not %r.'
                % (stripped,)
            )
        if stripped.startswith('params:') and not (
            stripped.startswith('params: [') and stripped.endswith(']')
        ):
            raise PolicyYamlError(
                'params must be a one-line flow sequence, not %r.'
                % (stripped,)
            )
        if re.match(r'^\s*&', line) or re.match(r'^\s*\*', line):
            raise PolicyYamlError('Policy YAML must not emit anchors or aliases.')
    return text


def dump_policy_yaml(document):
    """Return canonical UTF-8 YAML bytes for one JSON-like document."""
    if not isinstance(document, dict):
        raise PolicyYamlError('Policy YAML document must be a mapping.')
    text = yaml.dump(
        document,
        Dumper=PolicyYamlDumper,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        explicit_start=False,
        explicit_end=False,
        indent=2,
        width=10**9,
        canonical=False,
    )
    _assert_canonical_text(text)
    raw = text.encode('utf-8')
    if raw.startswith(b'\xef\xbb\xbf'):
        raise PolicyYamlError('Policy YAML must not start with a byte-order mark.')
    return raw

