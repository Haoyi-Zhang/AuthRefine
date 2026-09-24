"""Finite adapters and a model-level oracle for the six frozen public examples."""
from __future__ import annotations
import csv
import configparser
import json
from pathlib import Path
from language import normalize, PolicyError, require

MODELS = ('basic', 'rbac', 'rbac_with_deny', 'rbac_with_domains', 'rbac_with_resource_roles', 'priority')
EXPECTED_MATCHER = {
    'basic': 'r.sub == p.sub && r.obj == p.obj && r.act == p.act',
    'rbac': 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act',
    'rbac_with_deny': 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act',
    'rbac_with_domains': 'g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act',
    'rbac_with_resource_roles': 'g(r.sub, p.sub) && g2(r.obj, p.obj) && r.act == p.act',
    'priority': 'g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act'}
EXPECTED_EFFECT = {name: ('priority(p.eft) || deny' if name == 'priority' else
                         'some(where (p.eft == allow)) && !some(where (p.eft == deny))' if name == 'rbac_with_deny'
                         else 'some(where (p.eft == allow))') for name in MODELS}

def read_inputs(directory, name):
    require(name in MODELS, 'SYNTAX', 'unsupported public model')
    base = Path(directory)
    model = configparser.ConfigParser(interpolation=None)
    model.read(base / (name + '_model.conf'))
    expected_request = 'sub, dom, obj, act' if name == 'rbac_with_domains' else 'sub, obj, act'
    expected_policy = expected_request + (', eft' if name in ('priority', 'rbac_with_deny') else '')
    require(model.get('request_definition', 'r') == expected_request and model.get('policy_definition', 'p') == expected_policy,
            'SYNTAX', 'unsupported request or policy schema')
    require(model.get('matchers', 'm') == EXPECTED_MATCHER[name] and model.get('policy_effect', 'e') == EXPECTED_EFFECT[name],
            'SYNTAX', 'unsupported matcher or combining rule')
    expected_sections = {'request_definition', 'policy_definition', 'policy_effect', 'matchers'}
    if name != 'basic':
        expected_sections.add('role_definition')
        role_items = dict(model.items('role_definition'))
        wanted = {'g': '_, _, _' if name == 'rbac_with_domains' else '_, _'}
        if name == 'rbac_with_resource_roles':
            wanted['g2'] = '_, _'
        require(role_items == wanted, 'SYNTAX', 'unsupported role graph')
    require(set(model.sections()) == expected_sections, 'SYNTAX', 'extra model section')
    for section, key in [('request_definition', 'r'), ('policy_definition', 'p'), ('policy_effect', 'e'), ('matchers', 'm')]:
        require(set(dict(model.items(section))) == {key}, 'SYNTAX', 'extra model expression')
    rows = []
    with (base / (name + '_policy.csv')).open(newline='', encoding='utf-8') as stream:
        for row in csv.reader(stream, skipinitialspace=True):
            if not row:
                continue
            row = [cell.strip() for cell in row]
            require(all(row), 'SYNTAX', 'empty policy cell')
            kind = row[0]
            valid = (kind == 'p' and len(row) == 1 + len(expected_policy.split(',')))
            valid = valid or (kind == 'g' and name != 'basic' and len(row) == (4 if name == 'rbac_with_domains' else 3))
            valid = valid or (kind == 'g2' and name == 'rbac_with_resource_roles' and len(row) == 3)
            require(valid, 'SYNTAX', 'unsupported policy row')
            if kind == 'p' and name in ('priority', 'rbac_with_deny'):
                require(row[-1] in ('allow', 'deny'), 'TYPE', 'public decision')
            rows.append(row)
    return rows

def closure(edges, source):
    reached = {source}
    while True:
        expanded = reached | {b for a, b in edges if a in reached}
        if expanded == reached:
            return reached
        reached = expanded

def finite_domains(name, rows):
    policies = [r[1:] for r in rows if r[0] == 'p']
    users = {r[0] for r in policies}
    for r in rows:
        if r[0] == 'g':
            users.update(r[1:3])
    object_index = 2 if name == 'rbac_with_domains' else 1
    action_index = 3 if name == 'rbac_with_domains' else 2
    objects = {r[object_index] for r in policies}
    for r in rows:
        if r[0] == 'g2':
            objects.update(r[1:3])
    actions = {r[action_index] for r in policies}
    for values in (users, objects, actions):
        require('unlisted' not in values, 'NAME', 'sentinel collision')
        values.add('unlisted')
    domains = set()
    if name == 'rbac_with_domains':
        domains = {r[1] for r in policies} | {r[3] for r in rows if r[0] == 'g'}
        require('unlisted' not in domains, 'NAME', 'domain sentinel collision')
        domains.add('unlisted')
    return sorted(users), sorted(objects), sorted(actions), sorted(domains)

def pair(x, domain):
    # JSON strings give an injective tuple encoding even when names contain punctuation.
    return json.dumps([x, domain], ensure_ascii=False, separators=(',', ':'))

def translate(name, rows):
    users, objects, actions, domains = finite_domains(name, rows)
    domain_mode = name == 'rbac_with_domains'
    policies = [r[1:] for r in rows if r[0] == 'p']
    roles = sorted({pair(r[0], r[1]) if domain_mode else r[0] for r in policies}) if name != 'basic' else []
    p = {'principals': [pair(u, d) for u in users for d in domains] if domain_mode else users,
         'resources': [pair(o, d) for o in objects for d in domains] if domain_mode else objects,
         'actions': actions, 'roles': roles, 'members': [], 'state': [], 'aliases': [], 'rules': []}
    if domain_mode:
        for u in users:
            for d in domains:
                edges = [(r[1], r[2]) for r in rows if r[0] == 'g' and r[3] == d]
                reached = closure(edges, u)
                p['members'] += [[pair(u, d), pair(role, d)] for role in reached if pair(role, d) in roles]
    elif name != 'basic':
        edges = [(r[1], r[2]) for r in rows if r[0] == 'g']
        for u in users:
            p['members'] += [[u, role] for role in closure(edges, u) if role in roles]
    if name == 'rbac_with_deny':
        policies = [r for r in policies if r[-1] == 'deny'] + [r for r in policies if r[-1] == 'allow']
    resource_edges = [(r[1], r[2]) for r in rows if r[0] == 'g2']
    for row in policies:
        if domain_mode:
            subject, domain, resource, action = row
            targets = [pair(resource, domain)]; subject = pair(subject, domain)
        else:
            subject, resource, action = row[:3]
            targets = [o for o in objects if resource in closure(resource_edges, o)] if name == 'rbac_with_resource_roles' else [resource]
        decision = row[-1] if name in ('rbac_with_deny', 'priority') else 'allow'
        for target in targets:
            guard = [{'field': 'principal' if name == 'basic' else 'role', 'name': subject, 'negated': False},
                     {'field': 'resource', 'name': target, 'negated': False},
                     {'field': 'action', 'name': action, 'negated': False}]
            p['rules'].append({'decision': decision, 'guard': guard, 'updates': []})
    return normalize(p)

def model_oracle(name, rows, request):
    """Evaluate the original finite matcher directly, without translating to rules."""
    if name == 'rbac_with_domains':
        subject, domain, resource, action = request
    else:
        subject, resource, action = request; domain = None
    def related(left, right, relation):
        # Independently structured path search, rather than the adapter's closure iteration.
        waiting = [left]; visited = set()
        while waiting:
            node = waiting.pop()
            if node == right:
                return True
            if node in visited:
                continue
            visited.add(node)
            for edge in rows:
                if edge[0] == relation and edge[1] == node:
                    if relation == 'g' and domain is not None and edge[3] != domain:
                        continue
                    waiting.append(edge[2])
        return False
    matched = []
    for row in rows:
        if row[0] != 'p':
            continue
        if name == 'rbac_with_domains':
            _, ps, pd, po, pa = row
            if pd != domain:
                continue
        else:
            _, ps, po, pa, *rest = row
        subject_match = subject == ps if name == 'basic' else related(subject, ps, 'g')
        resource_match = related(resource, po, 'g2') if name == 'rbac_with_resource_roles' else resource == po
        if subject_match and resource_match and action == pa:
            effect = row[-1] if name in ('priority', 'rbac_with_deny') else 'allow'
            matched.append(effect)
    if name == 'priority':
        return matched[0] if matched else 'deny'
    if name == 'rbac_with_deny' and 'deny' in matched:
        return 'deny'
    return 'allow' if 'allow' in matched else 'deny'

def projected_oracle(name, rows, triple):
    if name != 'rbac_with_domains':
        return model_oracle(name, rows, triple)
    subject, domain = json.loads(triple[0]); resource, other_domain = json.loads(triple[1])
    if domain != other_domain:
        return 'deny'
    return model_oracle(name, rows, [subject, domain, resource, triple[2]])

def request_embedding(name, request):
    if name != 'rbac_with_domains':
        return request
    u, d, o, a = request
    return [pair(u, d), pair(o, d), a]

def extend(p, mode):
    import copy
    p = copy.deepcopy(p)
    if mode == 'base':
        return p
    require(mode in ('one-use', 'toggle'), 'TYPE', 'extension mode')
    p['state'] = [['available', mode == 'one-use']]
    for r in p['rules']:
        if r['decision'] == 'allow':
            if mode == 'one-use':
                r['guard'].append({'field': 'state', 'name': 'available', 'value': True})
                r['updates'] = [{'name': 'available', 'value': False}]
            else:
                r['updates'] = [{'name': 'available', 'from': 'available', 'negated': True}]
    return normalize(p)
