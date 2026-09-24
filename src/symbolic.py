"""Reduced ordered finite-domain decision diagrams for authorization cells.

This backend uses the state-revealing criterion but not its concrete-support
calculation. It is a symbolic algorithm comparison, not a live engine baseline.
"""
from __future__ import annotations
from collections import deque
from checker import inspect_policy, inspect_machine, Rejected

class Diagram:
    def __init__(self, aliases, node_limit=100000, operation_limit=2000000):
        self.aliases = aliases
        self.level = {a['name']: i for i, a in enumerate(aliases)}
        self.nodes = []
        self.unique = {}
        self.memo = {}
        self.operations = 0
        self.node_limit = node_limit
        self.operation_limit = operation_limit
        self.false = self.leaf(False)
        self.true = self.leaf(True)

    def intern(self, key, node):
        if key in self.unique:
            return self.unique[key]
        if len(self.nodes) >= self.node_limit:
            raise Rejected('symbolic node budget', 'inconclusive')
        result = len(self.nodes)
        self.nodes.append(node)
        self.unique[key] = result
        return result

    def leaf(self, value):
        tag = 'bool' if type(value) is bool else 'output'
        return self.intern((tag, value), (None, value))

    def node(self, level, children):
        children = tuple(children)
        if len(set(children)) == 1:
            return children[0]
        return self.intern(('node', level, children), (level, children))

    def ite(self, guard, yes, no):
        self.operations += 1
        if self.operations > self.operation_limit:
            raise Rejected('symbolic operation budget', 'inconclusive')
        if guard == self.true: return yes
        if guard == self.false: return no
        if yes == no: return yes
        key = (guard, yes, no)
        if key in self.memo: return self.memo[key]
        level = min(self.nodes[i][0] for i in key if self.nodes[i][0] is not None)
        children = []
        for value in range(len(self.aliases[level]['candidates'])):
            lifted = [self.nodes[i][1][value] if self.nodes[i][0] == level else i for i in key]
            children.append(self.ite(*lifted))
        answer = self.node(level, children)
        self.memo[key] = answer
        return answer

    def evaluate(self, root, binding):
        while self.nodes[root][0] is not None:
            level, children = self.nodes[root]
            alias = self.aliases[level]
            root = children[alias['candidates'].index(binding[alias['name']])]
        return self.nodes[root][1]

    def differing_binding(self, root, expected):
        # Search an acyclic ordered graph; fill skipped variables canonically.
        stack = [(root, {})]
        seen = set()
        while stack:
            node, partial = stack.pop()
            if node in seen: continue
            seen.add(node)
            level, value = self.nodes[node]
            if level is None:
                if value != expected:
                    result = {a['name']: a['candidates'][0] for a in self.aliases}
                    result.update(partial)
                    return result
                continue
            alias = self.aliases[level]
            for i in reversed(range(len(value))):
                child_binding = dict(partial)
                child_binding[alias['name']] = alias['candidates'][i]
                stack.append((value[i], child_binding))
        return None


def cell(diagram, policy, state, request):
    positions = {name: i for i, (name, _) in enumerate(policy['state'])}
    old = {name: bool((state >> i) & 1) for name, i in positions.items()}
    members = set(map(tuple, policy['members']))

    def atom(atom):
        field = atom['field']
        if field == 'state':
            return diagram.leaf(old[atom['name']] == atom['value'])
        def truth(name):
            equal = ((request[0], name) in members) if field == 'role' else request[{'principal': 0, 'resource': 1, 'action': 2}[field]] == name
            return equal != atom['negated']
        if 'name' in atom:
            return diagram.leaf(truth(atom['name']))
        level = diagram.level[atom['alias']]
        return diagram.node(level, [diagram.leaf(truth(name)) for name in diagram.aliases[level]['candidates']])

    answer = diagram.leaf(('deny', state))
    for rule in reversed(policy['rules']):
        guard = diagram.true
        for a in rule['guard']:
            guard = diagram.ite(guard, atom(a), diagram.false)
            if guard == diagram.false: break
        post = dict(old)
        for effect in rule['updates']:
            post[effect['name']] = effect['value'] if 'value' in effect else old[effect['from']] != effect['negated']
        result = sum(int(post[name]) << i for name, i in positions.items())
        output = diagram.leaf((rule['decision'], result))
        answer = diagram.ite(guard, output, answer)
    return answer


def check(policy, machine):
    inspect_policy(policy)
    inspect_machine(policy, machine, compare_initial=False)
    initial = sum(int(value) << i for i, (_, value) in enumerate(policy['state']))
    if machine['observations'][machine['initial']] != initial:
        return {'equivalent': False, 'length': 0, 'operations': 0, 'nodes': 0, 'cells': 0}
    paths = {machine['initial']: []}
    queue = deque([machine['initial']])
    while queue:
        q = queue.popleft()
        for index, (_, successor) in enumerate(machine['transitions'][q]):
            if successor not in paths:
                paths[successor] = paths[q] + [index]
                queue.append(successor)
    diagram = Diagram(policy['aliases'])
    cells = 0
    for q, prefix in paths.items():
        for index, request in enumerate(machine['alphabet']):
            root = cell(diagram, policy, machine['observations'][q], request)
            decision, successor = machine['transitions'][q][index]
            expected = (decision, machine['observations'][successor])
            binding = diagram.differing_binding(root, expected)
            cells += 1
            if binding is not None:
                return {'equivalent': False, 'length': len(prefix) + 1, 'binding': binding,
                        'indices': prefix + [index], 'operations': diagram.operations,
                        'nodes': len(diagram.nodes), 'cells': cells}
    return {'equivalent': True, 'operations': diagram.operations, 'nodes': len(diagram.nodes), 'cells': cells}
