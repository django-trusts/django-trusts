"""Canonical YAML for the schema-1 authorization policy document.

One spelling, one byte profile. The dumper is a ``yaml.SafeDumper``
subclass and the private diagnostic loader is a ``yaml.SafeLoader``
subclass. The inverse helpers are coding aids. They are not a supported
two-directional mapping. Neither path uses ``CSafeDumper``,
``FullLoader``, ``UnsafeLoader``, or custom YAML tags. Anchors and
aliases are rejected.

PyYAML does not promise that ``yaml.dump`` bytes stay stable across
versions, hash seeds, or the libyaml build. These representers and the
golden files are what pin the bytes. The byte profile is CI-validated
with ``PyYAML>=6.0.3``; supported installations may use later releases and
regenerate reviewed lockfiles when the emitted bytes change.
"""

from __future__ import annotations

import json
import math
import re

import yaml
from yaml.composer import ComposerError
from yaml.nodes import MappingNode, ScalarNode

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
_ALLOWED_TAGS = frozenset((
    _TAG_NULL, _TAG_BOOL, _TAG_INT, _TAG_FLOAT, _TAG_STR, _TAG_SEQ, _TAG_MAP,
))
_LITERAL_KEYS = frozenset(('sql',))
_FLOW_MAP_KEYS = frozenset(('user', 'group', 'permission', 'content'))


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


def parse_canonical_float(text):
    """Inverse of :func:`canonical_float_scalar`. Rejects every other spelling."""
    if not isinstance(text, str) or not _FLOAT_RE.fullmatch(text):
        raise PolicyYamlError('Float spelling %r is not canonical.' % (text,))
    if text == '-0.0':
        value = -0.0
    elif text == '0.0':
        value = 0.0
    else:
        value = float(text)
    if canonical_float_scalar(value) != text:
        raise PolicyYamlError('Float spelling %r is not canonical.' % (text,))
    return value


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
    if key == 'params':
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


class PolicyYamlLoader(yaml.SafeLoader):
    """Private safe loader used by :func:`_load_policy_yaml`.

    Implicit YAML 1.1 bool words (``yes``/``on``), timestamps, merge
    keys, sexagesimal numbers, and non-finite float tokens are not
    resolvers here. Explicit tags, anchors, and aliases fail closed.
    Parsing is not acceptance: :func:`_load_policy_yaml` re-dumps with
    :func:`dump_policy_yaml` and rejects the payload unless the bytes
    match. ``params`` is a one-line flow sequence. Other flow
    collections and noncanonical block or chomping forms fail that
    compare. This class is a coding helper, not a public
    contract.
    """

    yaml_implicit_resolvers = {}

    def __init__(self, stream):
        super().__init__(stream)
        self._constructing_key = False

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise PolicyYamlError('Policy YAML aliases are not allowed.')
        event = self.peek_event()
        if getattr(event, 'anchor', None):
            raise PolicyYamlError('Policy YAML anchors are not allowed.')
        if getattr(event, 'tag', None):
            raise PolicyYamlError('Policy YAML explicit tags are not allowed.')
        node = super().compose_node(parent, index)
        if isinstance(node, ScalarNode) and node.tag not in _ALLOWED_TAGS:
            raise PolicyYamlError(
                'Policy YAML tag %r is not allowed.' % (node.tag,)
            )
        return node

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, MappingNode):
            raise PolicyYamlError('Policy YAML expected a mapping.')
        mapping = {}
        for key_node, value_node in node.value:
            if key_node.tag == 'tag:yaml.org,2002:merge' or (
                isinstance(key_node, ScalarNode) and key_node.value == '<<'
            ):
                raise PolicyYamlError('Policy YAML merge keys are not allowed.')
            self._constructing_key = True
            try:
                key = self.construct_object(key_node, deep=deep)
            finally:
                self._constructing_key = False
            if not isinstance(key, str):
                raise PolicyYamlError(
                    'Policy YAML keys must be strings, not %s.'
                    % type(key).__name__
                )
            if key in mapping:
                raise PolicyYamlError(
                    'Policy YAML duplicate key %r.' % (key,)
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _construct_null(loader, node):
    del loader
    if node.style is not None or node.value != 'null':
        raise PolicyYamlError('Null must be plain `null`.')
    return None


def _construct_bool(loader, node):
    del loader
    if node.style is not None or node.value not in ('true', 'false'):
        raise PolicyYamlError('Bool must be plain `true` or `false`.')
    return node.value == 'true'


def _construct_int(loader, node):
    del loader
    if node.style is not None or not _INT_RE.fullmatch(node.value or ''):
        raise PolicyYamlError('Int spelling %r is not canonical.' % (node.value,))
    return int(node.value)


def _construct_float(loader, node):
    del loader
    if node.style is not None:
        raise PolicyYamlError('Float spelling %r is not canonical.' % (node.value,))
    return parse_canonical_float(node.value)


def _construct_str(loader, node):
    if node.style == '"':
        return loader.construct_scalar(node)
    if node.style == '|':
        return loader.construct_scalar(node)
    if node.style is None and loader._constructing_key:
        value = loader.construct_scalar(node)
        if not _KEY_RE.fullmatch(value) or value in _RESERVED_PLAIN:
            raise PolicyYamlError(
                'Policy YAML key %r is not a plain identifier.' % (value,)
            )
        return value
    raise PolicyYamlError(
        'Policy YAML string must be double-quoted or a literal block.'
    )


PolicyYamlLoader.add_constructor(_TAG_NULL, _construct_null)
PolicyYamlLoader.add_constructor(_TAG_BOOL, _construct_bool)
PolicyYamlLoader.add_constructor(_TAG_INT, _construct_int)
PolicyYamlLoader.add_constructor(_TAG_FLOAT, _construct_float)
PolicyYamlLoader.add_constructor(_TAG_STR, _construct_str)

PolicyYamlLoader.add_implicit_resolver(_TAG_NULL, re.compile(r'^null$'), list('n'))
PolicyYamlLoader.add_implicit_resolver(_TAG_BOOL, re.compile(r'^(?:true|false)$'), list('tf'))
PolicyYamlLoader.add_implicit_resolver(_TAG_INT, _INT_RE, list('-0123456789'))
PolicyYamlLoader.add_implicit_resolver(_TAG_FLOAT, _FLOAT_RE, list('-0123456789'))


def _load_policy_yaml(payload):
    """Private diagnostic helper for canonical policy YAML.

    Not a supported public API and not a two-directional mapping
    contract. Tests use it for coding completeness. ``trusts.E009``
    does not call it; equality is raw bytes.

    After a successful parse, the document is written again with
    :func:`dump_policy_yaml`. The payload is accepted only when those
    bytes are identical. Flow mappings (``a: {b: 1}``), flow sequences,
    folded blocks, and any other chomping or spelling the writer does
    not emit are rejected.
    """
    if not isinstance(payload, (bytes, str)):
        raise PolicyYamlError(
            'Policy YAML payload must be bytes or text, not %s.'
            % type(payload).__name__
        )
    if isinstance(payload, bytes):
        raw = payload
        if raw.startswith(b'\xef\xbb\xbf'):
            raise PolicyYamlError('Policy YAML must not start with a byte-order mark.')
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise PolicyYamlError('Policy YAML must be UTF-8.') from exc
    else:
        text = payload
        try:
            raw = text.encode('utf-8')
        except UnicodeEncodeError as exc:
            raise PolicyYamlError('Policy YAML must be UTF-8.') from exc
    if '\r' in text or text.startswith('\ufeff'):
        raise PolicyYamlError('Policy YAML must be LF UTF-8 without a BOM.')
    if text.startswith('---') or '\n---' in text or text.startswith('...'):
        raise PolicyYamlError('Policy YAML document markers are not allowed.')
    try:
        document = yaml.load(text, Loader=PolicyYamlLoader)
    except PolicyYamlError:
        raise
    except ComposerError as exc:
        raise PolicyYamlError('Policy YAML could not be read: %s' % exc) from exc
    except yaml.YAMLError as exc:
        raise PolicyYamlError('Policy YAML could not be read: %s' % exc) from exc
    canonical = dump_policy_yaml(document)
    if raw != canonical:
        raise PolicyYamlError(
            'Policy YAML bytes are not the canonical spelling.'
        )
    return document
