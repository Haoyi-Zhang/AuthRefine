"""Owned finite phase-lift fixtures; no native engine or enforcement service."""
from copy import deepcopy

from checker import ensure, inspect_machine, inspect_policy, integer
from compiler import compile_policy
from cases import width_case
from public_inputs import read_inputs, translate, extend


def phase_lift(policy, machine, phases):
    """Retain all complete source observations and add an internal cyclic phase.

    Every request advances phase. Decisions and successor observations come
    from the unchanged original table, so induction preserves complete traces.
    Phase is target representation state, not a discarded policy-state bit.
    """
    inspect_policy(policy)
    inspect_machine(policy, machine, compare_initial=False)
    ensure(integer(phases) and phases > 0 and phases * len(machine['observations']) <= 512,
           'phase-lift bound')
    result = deepcopy(machine)
    result['observations'] = [state for state in machine['observations'] for _ in range(phases)]
    result['initial'] = machine['initial'] * phases
    result['transitions'] = [
        [[decision, successor * phases + (phase + 1) % phases] for decision, successor in row]
        for row in machine['transitions'] for phase in range(phases)]
    inspect_machine(policy, result, compare_initial=False)
    return result


def lab_cases(public_directory):
    """Nine width controls and six static/one-use public-derived phase lifts."""
    for aliases in (1, 4, 8):
        policy = width_case(aliases)
        for phases in (1, 3, 9):
            yield f'width-{aliases}-phase-{phases}', policy, phase_lift(policy, compile_policy(policy), phases)
    for name in ('basic', 'rbac_with_deny'):
        policy = extend(translate(name, read_inputs(public_directory, name)), 'one-use')
        for phases in (1, 3, 9):
            yield f'{name}-one-use-phase-{phases}', policy, phase_lift(policy, compile_policy(policy), phases)
