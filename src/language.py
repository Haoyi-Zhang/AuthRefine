"""A closed, explicitly typed sentence language for finite authorization policies."""
from __future__ import annotations
import copy
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

DOMAINS = {'principal': 'principals', 'resource': 'resources', 'action': 'actions', 'role': 'roles'}
FIELDS = tuple(DOMAINS)
POLICY_KEYS = set(DOMAINS.values()) | {'members', 'state', 'aliases', 'rules'}

class PolicyError(ValueError):
    def __init__(self, category: str, detail: str):
        self.category = category
        super().__init__(f'{category}: {detail}')

def require(condition: bool, category: str, detail: str) -> None:
    if not condition:
        raise PolicyError(category, detail)

def unique(items: list[Any]) -> bool:
    return all(x not in items[:i] for i, x in enumerate(items))

def named(value: Any) -> bool:
    """Return whether *value* is a bounded identifier without control scalars.

    Unicode general categories Cc (control), Cf (format control), and Cs
    (surrogate) are excluded.  Python can represent lone surrogates even though
    they are not Unicode scalar values, so the explicit category check matters
    before serialization.
    """
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and all(unicodedata.category(c) not in {'Cc', 'Cf', 'Cs'} for c in value)
    )

def validate(p: Any, limits: bool = True) -> None:
    require(isinstance(p, dict) and set(p) == POLICY_KEYS, 'TYPE', 'policy fields')
    for kind, key in DOMAINS.items():
        xs = p[key]
        require(isinstance(xs, list) and all(named(x) for x in xs) and unique(xs), 'NAME', key)
        require(kind == 'role' or len(xs) > 0, 'TYPE', 'empty request domain')
    require(isinstance(p['members'], list), 'TYPE', 'membership list')
    for row in p['members']:
        require(isinstance(row, list) and len(row) == 2, 'TYPE', 'membership row')
        require(row[0] in p['principals'] and row[1] in p['roles'], 'NAME', 'membership endpoint')
    require(unique(p['members']), 'NAME', 'duplicate membership')
    require(isinstance(p['state'], list), 'TYPE', 'state list')
    for entry in p['state']:
        require(isinstance(entry, list) and len(entry) == 2 and named(entry[0]) and type(entry[1]) is bool,
                'TYPE', 'Boolean state declaration')
    bits = [row[0] for row in p['state']]
    require(unique(bits), 'NAME', 'duplicate state')
    require(isinstance(p['aliases'], list), 'TYPE', 'alias list')
    for a in p['aliases']:
        require(isinstance(a, dict) and set(a) == {'name', 'kind', 'candidates'}, 'TYPE', 'alias fields')
        require(named(a['name']) and a['kind'] in DOMAINS, 'TYPE', 'alias name and sort')
        cs = a['candidates']
        require(isinstance(cs, list) and len(cs) > 0 and unique(cs), 'NAME', 'alias candidates')
        require(all(c in p[DOMAINS[a['kind']]] for c in cs), 'NAME', 'undeclared candidate')
    require(unique([a['name'] for a in p['aliases']]), 'NAME', 'duplicate alias')
    aliases = {a['name']: a for a in p['aliases']}
    require(isinstance(p['rules'], list), 'TYPE', 'rule list')
    nodes = 0
    for r in p['rules']:
        require(isinstance(r, dict) and set(r) == {'decision', 'guard', 'updates'}, 'TYPE', 'rule fields')
        require(r['decision'] in ('allow', 'deny'), 'TYPE', 'decision')
        require(isinstance(r['guard'], list) and isinstance(r['updates'], list), 'TYPE', 'rule lists')
        nodes += 1 + len(r['guard']) + len(r['updates'])
        for atom in r['guard']:
            require(isinstance(atom, dict) and 'field' in atom, 'TYPE', 'guard atom')
            field = atom['field']
            if field == 'state':
                require(set(atom) == {'field', 'name', 'value'} and atom['name'] in bits and type(atom['value']) is bool,
                        'TYPE', 'state test')
            else:
                require(field in FIELDS, 'TYPE', 'guard sort')
                keys = set(atom)
                require(keys in ({'field', 'name', 'negated'}, {'field', 'alias', 'negated'}), 'TYPE', 'reference form')
                require(type(atom['negated']) is bool, 'TYPE', 'guard polarity')
                if 'name' in atom:
                    require(atom['name'] in p[DOMAINS[field]], 'NAME', 'undeclared literal')
                else:
                    require(atom['alias'] in aliases, 'NAME', 'undeclared alias')
                    require(aliases[atom['alias']]['kind'] == field, 'TYPE', 'alias sort mismatch')
        require(r['decision'] != 'deny' or not r['updates'], 'EFFECT', 'deny cannot update state')
        written = []
        for e in r['updates']:
            require(isinstance(e, dict) and 'name' in e and e['name'] in bits, 'NAME', 'update destination')
            require(e['name'] not in written, 'EFFECT', 'duplicate assignment')
            written.append(e['name'])
            if 'value' in e:
                require(set(e) == {'name', 'value'} and type(e['value']) is bool, 'TYPE', 'constant assignment')
            else:
                require(set(e) == {'name', 'from', 'negated'} and e['from'] in bits and type(e['negated']) is bool,
                        'TYPE', 'state-copy assignment')
    if limits:
        require(len(p['principals']) <= 16 and len(p['roles']) <= 16, 'LIMIT', 'principals or roles')
        require(len(p['resources']) <= 32 and len(p['actions']) <= 32, 'LIMIT', 'resources or actions')
        require(len(bits) <= 7 and len(aliases) <= 16 and nodes <= 256, 'LIMIT', 'state, aliases, or AST nodes')

def normalize(p: dict[str, Any], limits: bool = True) -> dict[str, Any]:
    validate(p, limits)
    p = copy.deepcopy(p)
    for key in DOMAINS.values():
        p[key].sort()
    p['members'].sort()
    p['state'].sort(key=lambda b: b[0])
    p['aliases'].sort(key=lambda a: a['name'])
    for a in p['aliases']:
        a['candidates'].sort()
    for r in p['rules']:
        r['updates'].sort(key=lambda e: e['name'])
    return p

def initial(p: dict[str, Any]) -> int:
    return sum(int(value) << i for i, (_, value) in enumerate(p['state']))

def strict_json(text: str) -> Any:
    require(len(text.encode('utf-8')) <= 32 * 1024 * 1024, 'LIMIT', 'JSON input byte size')
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, 'TYPE', 'duplicate JSON key')
            obj[key] = value
        return obj
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda x: (_ for _ in ()).throw(PolicyError('TYPE', 'nonfinite JSON value')))
    except (json.JSONDecodeError, RecursionError) as error:
        raise PolicyError('SYNTAX', 'invalid JSON') from error

def read_policy(path: str | Path) -> dict[str, Any]:
    is_json = str(path).endswith('.json')
    bound = (32 if is_json else 4) * 1024 * 1024
    with Path(path).open('rb') as stream:
        raw = stream.read(bound + 1)
    require(len(raw) <= bound, 'LIMIT', 'input byte envelope')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as error:
        raise PolicyError('SYNTAX', 'input is not UTF-8') from error
    return normalize(strict_json(text)) if is_json else parse(text)

class Parser:
    def __init__(self, text: str):
        require(len(text.encode('utf-8')) <= 4 * 1024 * 1024, 'LIMIT', 'sentence input byte size')
        self.tokens: list[tuple[str, str]] = []
        decoder = json.JSONDecoder()
        offset = 0
        while offset < len(text):
            if text[offset].isspace():
                offset += 1
            elif text[offset] == '"':
                try:
                    value, end = decoder.raw_decode(text, offset)
                except json.JSONDecodeError as error:
                    raise PolicyError('SYNTAX', f'quoted identifier at character {offset}') from error
                self.tokens.append(('quoted', value))
                offset = end
            elif text[offset] in '.,':
                self.tokens.append(('word', text[offset]))
                offset += 1
            else:
                match = re.match(r'[a-z]+', text[offset:])
                require(match is not None, 'SYNTAX', f'unrecognized character at {offset}')
                word = match.group(0)
                self.tokens.append(('word', word))
                offset += len(word)
        self.pos = 0

    def peek(self, word: str) -> bool:
        return self.pos < len(self.tokens) and self.tokens[self.pos] == ('word', word)

    def take(self, word: str) -> None:
        require(self.peek(word), 'SYNTAX', f'expected {word} at token {self.pos}')
        self.pos += 1

    def ident(self) -> str:
        require(self.pos < len(self.tokens) and self.tokens[self.pos][0] == 'quoted', 'SYNTAX', f'expected quoted identifier at token {self.pos}')
        value = self.tokens[self.pos][1]
        self.pos += 1
        return value

    def names(self, allow_none: bool = False) -> list[str]:
        if allow_none and self.peek('none'):
            self.take('none')
            return []
        result = [self.ident()]
        while self.peek(','):
            self.take(',')
            result.append(self.ident())
        return result

    def boolean(self) -> bool:
        if self.peek('true'):
            self.take('true')
            return True
        self.take('false')
        return False

    def reference(self, field: str, negated: bool) -> dict[str, Any]:
        if self.peek('alias'):
            self.take('alias')
            return {'field': field, 'alias': self.ident(), 'negated': negated}
        return {'field': field, 'name': self.ident(), 'negated': negated}

    def atom(self) -> dict[str, Any]:
        if self.peek('state'):
            self.take('state'); name = self.ident(); self.take('is')
            return {'field': 'state', 'name': name, 'value': self.boolean()}
        if self.peek('principal'):
            self.take('principal')
            if self.peek('has'):
                self.take('has'); neg = False
                if self.peek('no'):
                    self.take('no'); neg = True
                self.take('role')
                return self.reference('role', neg)
            field = 'principal'
        elif self.peek('resource'):
            self.take('resource'); field = 'resource'
        else:
            self.take('action'); field = 'action'
        self.take('is'); neg = False
        if self.peek('not'):
            self.take('not'); neg = True
        return self.reference(field, neg)

    def guard(self) -> list[dict[str, Any]]:
        if self.peek('always'):
            self.take('always')
            return []
        atoms = [self.atom()]
        while self.peek('and'):
            self.take('and'); atoms.append(self.atom())
        return atoms

    def update(self) -> dict[str, Any]:
        self.take('set'); self.take('state'); name = self.ident(); self.take('to')
        if self.peek('true') or self.peek('false'):
            return {'name': name, 'value': self.boolean()}
        neg = False
        if self.peek('not'):
            self.take('not'); neg = True
        self.take('state')
        return {'name': name, 'from': self.ident(), 'negated': neg}

    def policy(self) -> dict[str, Any]:
        p: dict[str, Any] = {'members': [], 'state': [], 'aliases': [], 'rules': []}
        for key in ('principals', 'resources', 'actions', 'roles'):
            self.take(key); self.take('are')
            p[key] = self.names(allow_none=key == 'roles'); self.take('.')
        while self.peek('principal'):
            self.take('principal'); u = self.ident(); self.take('has'); self.take('roles')
            rs = self.names(); self.take('.')
            p['members'].extend([[u, r] for r in rs])
        while self.peek('state'):
            self.take('state'); bit = self.ident(); self.take('initially'); v = self.boolean(); self.take('.')
            p['state'].append([bit, v])
        while self.peek('alias'):
            self.take('alias')
            require(self.pos < len(self.tokens) and self.tokens[self.pos][0] == 'word' and self.tokens[self.pos][1] in FIELDS,
                    'SYNTAX', 'alias sort')
            kind = self.tokens[self.pos][1]; self.pos += 1
            name = self.ident(); self.take('is'); self.take('one'); self.take('of')
            candidates = self.names(); self.take('.')
            p['aliases'].append({'name': name, 'kind': kind, 'candidates': candidates})
        while self.peek('allow') or self.peek('deny'):
            decision = 'allow' if self.peek('allow') else 'deny'
            self.take(decision); self.take('when'); guard = self.guard(); updates = []
            if decision == 'allow':
                self.take('then')
                if self.peek('keep'):
                    self.take('keep'); self.take('state')
                else:
                    updates.append(self.update())
                    while self.peek('and'):
                        self.take('and'); updates.append(self.update())
            self.take('.')
            p['rules'].append({'decision': decision, 'guard': guard, 'updates': updates})
        self.take('otherwise'); self.take('deny'); self.take('.')
        require(self.pos == len(self.tokens), 'SYNTAX', 'trailing input')
        return normalize(p)

def parse(text: str) -> dict[str, Any]:
    return Parser(text).policy()

def pretty(p: dict[str, Any], limits: bool = True) -> str:
    p = normalize(p, limits)
    quote = lambda s: json.dumps(s, ensure_ascii=False)
    join = lambda xs: ', '.join(quote(x) for x in xs)
    lines = [key + ' are ' + (join(p[key]) if p[key] else 'none') + '.' for key in ('principals', 'resources', 'actions', 'roles')]
    for u in p['principals']:
        roles = [r for member, r in p['members'] if member == u]
        if roles:
            lines.append('principal ' + quote(u) + ' has roles ' + join(roles) + '.')
    for b, v in p['state']:
        lines.append('state ' + quote(b) + ' initially ' + str(v).lower() + '.')
    for a in p['aliases']:
        lines.append('alias ' + a['kind'] + ' ' + quote(a['name']) + ' is one of ' + join(a['candidates']) + '.')
    def atom_text(a):
        if a['field'] == 'state':
            return 'state ' + quote(a['name']) + ' is ' + str(a['value']).lower()
        ref = ('alias ' + quote(a['alias'])) if 'alias' in a else quote(a['name'])
        if a['field'] == 'role':
            return 'principal has ' + ('no ' if a['negated'] else '') + 'role ' + ref
        return a['field'] + ' is ' + ('not ' if a['negated'] else '') + ref
    def update_text(e):
        rhs = str(e['value']).lower() if 'value' in e else ('not ' if e['negated'] else '') + 'state ' + quote(e['from'])
        return 'set state ' + quote(e['name']) + ' to ' + rhs
    for r in p['rules']:
        line = r['decision'] + ' when ' + (' and '.join(atom_text(a) for a in r['guard']) if r['guard'] else 'always')
        if r['decision'] == 'allow':
            line += ' then ' + (' and '.join(update_text(e) for e in r['updates']) if r['updates'] else 'keep state')
        lines.append(line + '.')
    lines.append('otherwise deny.')
    return '\n'.join(lines) + '\n'
