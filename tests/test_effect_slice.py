from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from effect_slice import (Capability, DataRecord, Deferred, EffectInterpreter, ErrorType, RecordType,
                          SerialContext, SliceFault, extract_effect_program)
from native_casbin import AdmissionError


def interpreter(body, *, bindings=None, fields=None, limit=50000):
    source = ("class Service:\n" + "\n".join("    " + line for line in body.splitlines()) + "\n").encode()
    program = extract_effect_program(source, "Service", ["run"])
    receiver = DataRecord("receiver", fields or {})
    return EffectInterpreter(program, receiver, {"Exception": ErrorType("Exception"), "BackendError": ErrorType("BackendError"),
                                               "Unavailable": ErrorType("Unavailable"), **(bindings or {})}, limit)


class EffectSliceTests(unittest.TestCase):
    def test_break_exits_nearest_loop_and_retains_following_statements(self):
        instance = interpreter("def run(self):\n    chosen = 'none'\n    for item in self.values:\n        chosen = item\n        if item == 'stop':\n            break\n    return chosen", fields={"values": ["first", "stop", "last"]})
        self.assertEqual(instance.run("run", []), "stop")

    def test_nested_break_is_not_a_function_return(self):
        instance = interpreter("def run(self):\n    chosen = 'none'\n    for outer in self.values:\n        for inner in self.values:\n            break\n        chosen = outer\n    return chosen", fields={"values": ["first", "last"]})
        self.assertEqual(instance.run("run", []), "last")

    def test_break_cannot_escape_function_or_cross_a_closure_boundary(self):
        for body in ("def run(self):\n    break", "def run(self):\n    for item in self.values:\n        def invalid():\n            break"):
            with self.assertRaises(AdmissionError):
                interpreter(body, fields={"values": ["owned"]})

    def test_builtin_type_guards_retain_bool_as_int_semantics(self):
        for value in (True, False, 1, "member", ["member"], None, DataRecord("owned", {})):
            for name, kind in (("list", list), ("int", int), ("str", str), ("bool", bool)):
                instance = interpreter(f"def run(self):\n    return isinstance(self.value, {name})", fields={"value": value})
                self.assertEqual(instance.run("run", []), isinstance(value, kind))

    def test_explicit_separator_split_preserves_empty_segments(self):
        for text, separator in (("realm.roles", "."), ("member|admin", "|"), ("a||b|", "|"), ("", ".")):
            instance = interpreter("def run(self):\n    return self.text.split(self.separator)", fields={"text": text, "separator": separator})
            self.assertEqual(instance.run("run", []), text.split(separator))

    def test_split_rejects_unadmitted_types_and_envelopes(self):
        for text, separator in (("abc", ""), ("a" * 4097, "."), ("|" * 128, "|"), ("abc", None)):
            instance = interpreter("def run(self):\n    return self.text.split(self.separator)", fields={"text": text, "separator": separator})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_plain_container_interpolation_rejects_host_values_and_cycles(self):
        for value in (["member", "admin"], {"roles": ["member"]}, (1, True, None)):
            instance = interpreter("def run(self):\n    return f'roles={self.value}'", fields={"value": value})
            self.assertEqual(instance.run("run", []), f"roles={value}")
        cyclic = []
        cyclic.append(cyclic)
        for value in (object(), DataRecord("opaque", {}), cyclic, [Capability("opaque", lambda: None)]):
            instance = interpreter("def run(self):\n    return f'roles={self.value}'", fields={"value": value})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_type_guard_names_cannot_be_rebound(self):
        for name in ("list", "int"):
            with self.assertRaises(AdmissionError):
                interpreter(f"def run(self):\n    {name} = self.value\n    return True", fields={"value": []})

    def test_string_membership_and_nonmembership_keep_substring_semantics(self):
        for needle, text in (("a", "abc"), ("bc", "abc"), ("", "abc"), ("z", "abc"), ("字", "文字")):
            for operation in ("in", "not in"):
                instance = interpreter("def run(self):\n    return self.needle " + operation + " self.text", fields={"needle": needle, "text": text})
                expected = needle in text if operation == "in" else needle not in text
                self.assertEqual(instance.run("run", []), expected)

    def test_string_membership_evaluates_each_effectful_operand_only_once(self):
        calls = []
        def read(name, value):
            calls.append(name)
            return value
        instance = interpreter("def run(self):\n    return self.needle() in self.text()", fields={
            "needle": Capability("needle", lambda: read("needle", "a")),
            "text": Capability("text", lambda: read("text", "abc"))})
        self.assertTrue(instance.run("run", []))
        self.assertEqual(calls, ["needle", "text"])

    def test_string_membership_does_not_coerce_types_or_ignore_size_limits(self):
        for needle, text in ((True, "abc"), (1, "abc"), (None, "abc"), ("a", "x" * 4097)):
            instance = interpreter("def run(self):\n    return self.needle in self.text", fields={"needle": needle, "text": text})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_enumeration_unpacking_and_source_indexed_mapping(self):
        instance = interpreter("def run(self):\n    result = {}\n    for i, value in enumerate(self.values, 3):\n        result[f'item_{i}'] = value\n    return result", fields={"values": ["a", "b"]})
        self.assertEqual(instance.run("run", []), {"item_3": "a", "item_4": "b"})

    def test_dictionary_alias_and_nested_write_observe_same_plain_object(self):
        instance = interpreter("def run(self):\n    result = {'nested': {}}\n    alias = result['nested']\n    alias['value'] = 'x'\n    return result")
        self.assertEqual(instance.run("run", []), {"nested": {"value": "x"}})

    def test_mapping_keys_and_targets_are_not_coerced(self):
        for target in ("result[0]", "result[True]", "self.values[0]"):
            instance = interpreter("def run(self):\n    result = {}\n    " + target + " = 'x'\n    return result", fields={"values": ["a"]})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_mapping_entry_bound_allows_update_but_not_extra_key(self):
        values = {str(i): "value" for i in range(128)}
        instance = interpreter("def run(self):\n    self.values['0'] = 'new'\n    return self.values['0']", fields={"values": values})
        self.assertEqual(instance.run("run", []), "new")
        instance = interpreter("def run(self):\n    self.values['extra'] = 'x'", fields={"values": values})
        with self.assertRaises(AdmissionError):
            instance.run("run", [])

    def test_mapping_writes_reject_direct_and_indirect_cycles(self):
        for value in ("result", "{'nested': result}"):
            instance = interpreter("def run(self):\n    result = {}\n    result['cycle'] = " + value)
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_deferred_and_opaque_values_cannot_hide_inside_mapping_writes(self):
        for value in (Deferred(lambda: 1), DataRecord("opaque", {}), object()):
            instance = interpreter("def run(self):\n    result = {}\n    result['value'] = {'nested': self.value}", fields={"value": value})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_enumeration_type_start_bounds_and_shadowing_are_explicit(self):
        for expression in ("enumerate(self.values, True)", "enumerate(self.values, 1000001)", "enumerate(self.values, 1, 2)"):
            instance = interpreter("def run(self):\n    return " + expression, fields={"values": ["a"]})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])
        with self.assertRaises(AdmissionError):
            interpreter("def run(self):\n    enumerate = self.values\n    return True", fields={"values": ["a"]})

    def test_unpacking_arity_and_data_tree_budget_remain_checked(self):
        instance = interpreter("def run(self):\n    for a, b in self.values:\n        pass", fields={"values": [("one",)]})
        with self.assertRaises(AdmissionError):
            instance.run("run", [])
        deep = "x"
        for _ in range(18):
            deep = [deep]
        instance = interpreter("def run(self):\n    result = {}\n    result['value'] = self.value", fields={"value": deep})
        with self.assertRaises(AdmissionError):
            instance.run("run", [])

    def test_optional_role_and_none_equality_are_explicit_without_repeated_effects(self):
        events = []
        instance = interpreter("def run(self):\n    return self.read() == None", fields={"read": Capability("read", lambda: events.append(1))})
        self.assertTrue(instance.run("run", []))
        self.assertEqual(events, [1])
        instance = interpreter("def run(self):\n    return self.role in ('admin', 'staff')", fields={"role": None})
        self.assertFalse(instance.run("run", []))

    def test_immutable_defaults_and_keyword_only_arguments_bind_exactly(self):
        instance = interpreter("async def run(self, value=None, *, enabled=True):\n    return (value, enabled)")
        self.assertEqual(instance.run("run", []), (None, True))
        self.assertEqual(instance.run("run", ["x"], {"enabled": False}), ("x", False))
        with self.assertRaises(AdmissionError):
            instance.run("run", ["x"], {"value": "duplicate"})
        with self.assertRaises(AdmissionError):
            instance.run("run", [], {"unknown": True})

    def test_required_keyword_only_and_mutable_defaults_are_not_guessed(self):
        instance = interpreter("async def run(self, *, required):\n    return required")
        with self.assertRaises(AdmissionError):
            instance.run("run", [])
        self.assertEqual(instance.run("run", [], {"required": 7}), 7)
        for default in ("[]", "factory()", "(1,)"):
            instance = interpreter("async def run(self, value=" + default + "):\n    return value")
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_sync_serial_context_closes_on_return_and_fault(self):
        for statement in ("return True", "raise BackendError('owned')"):
            events = []
            context = SerialContext(lambda: events.append("enter"), lambda: events.append("exit"), asynchronous=False)
            instance = interpreter("def run(self):\n    with self.lock:\n        " + statement, fields={"lock": context})
            try:
                instance.run("run", [])
            except SliceFault:
                pass
            self.assertEqual(events, ["enter", "exit"])

    def test_sync_and_async_context_protocols_cannot_be_interchanged(self):
        for syntax, asynchronous in (("with", True), ("async with", False)):
            context = SerialContext(lambda: None, lambda: None, asynchronous)
            instance = interpreter("async def run(self):\n    " + syntax + " self.lock:\n        return True", fields={"lock": context})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_string_set_operations_preserve_alias_visible_in_place_updates(self):
        instance = interpreter("def run(self):\n    values = {'read'}\n    alias = values\n    values |= {'write'}\n    return alias & {'write'}")
        self.assertEqual(instance.run("run", []), {"write"})
        instance = interpreter("def run(self):\n    values = self.values\n    alias = values\n    values &= {'read'}\n    return alias", fields={"values": frozenset({"read", "write"})})
        self.assertEqual(instance.run("run", []), frozenset({"read", "write"}))

    def test_string_set_operation_bounds_and_operand_types_are_not_coerced(self):
        for values in ({1}, ["read"], set(str(i) for i in range(128))):
            instance = interpreter("def run(self):\n    return self.values | {'extra'}", fields={"values": values})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])

    def test_assertion_is_an_observable_fault_and_message_is_lazy(self):
        events = []
        instance = interpreter("def run(self):\n    assert True, self.message()\n    return True", fields={"message": Capability("message", lambda: events.append(1) or "bad")})
        self.assertTrue(instance.run("run", []))
        self.assertEqual(events, [])
        instance = interpreter("def run(self):\n    assert False, 'owned'")
        with self.assertRaises(SliceFault) as raised:
            instance.run("run", [])
        self.assertEqual(raised.exception.name, "AssertionError")

    def test_async_capability_is_deferred_until_await(self):
        calls = []
        instance = interpreter("async def run(self):\n    return await self.repo()", fields={"repo": Capability("repo", lambda: calls.append(1) or 7, True)})
        self.assertEqual(calls, [])
        self.assertEqual(instance.run("run", []), 7)
        self.assertEqual(calls, [1])

    def test_lost_await_is_not_truthy_or_executed(self):
        calls = []
        for body in ("if self.repo():\n        return True", "self.repo()\n    return True"):
            instance = interpreter("async def run(self):\n    " + body, fields={"repo": Capability("repo", lambda: calls.append(1), True)})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])
        self.assertEqual(calls, [])

    def test_typed_failure_is_caught_and_handler_assignments_survive(self):
        def fail():
            raise SliceFault("BackendError", "owned")
        instance = interpreter("async def run(self):\n    try:\n        x = await self.repo()\n    except Exception as e:\n        x = False\n    return x", fields={"repo": Capability("repo", fail, True)})
        self.assertIs(instance.run("run", []), False)

    def test_admission_or_budget_failure_cannot_be_swallowed_by_source(self):
        def reject():
            raise AdmissionError("owned budget", "inconclusive")
        instance = interpreter("async def run(self):\n    try:\n        return await self.repo()\n    except Exception:\n        return True", fields={"repo": Capability("repo", reject, True)})
        with self.assertRaises(AdmissionError):
            instance.run("run", [])

    def test_declared_raise_cause_and_bare_reraise_preserve_failure(self):
        def fail():
            raise SliceFault("BackendError", "owned")
        for handler, expected in (("raise", "BackendError"), ("raise Unavailable('backend unavailable') from e", "Unavailable")):
            instance = interpreter("async def run(self):\n    try:\n        return await self.repo()\n    except Exception as e:\n        " + handler, fields={"repo": Capability("repo", fail, True)})
            with self.assertRaises(SliceFault) as raised:
                instance.run("run", [])
            self.assertEqual(raised.exception.name, expected)

    def test_serial_context_exit_runs_on_return_and_fault(self):
        for statement in ("return 3", "raise BackendError('owned')"):
            events = []
            lock = SerialContext(lambda: events.append("enter"), lambda: events.append("exit"))
            instance = interpreter("async def run(self):\n    async with self.lock:\n        " + statement, fields={"lock": lock})
            try:
                instance.run("run", [])
            except SliceFault:
                pass
            self.assertEqual(events, ["enter", "exit"])

    def test_records_require_exact_fields_and_only_declared_field_can_change(self):
        cache = DataRecord("state", {"cache": None}, frozenset({"cache"}))
        instance = interpreter("async def run(self):\n    self.state.cache = Cache(1, 'value')\n    return self.state.cache.version", fields={"state": cache}, bindings={"Cache": RecordType("cache", ("version", "value"))})
        self.assertEqual(instance.run("run", []), 1)
        instance = interpreter("async def run(self):\n    self.state.other = 2\n    return True", fields={"state": cache})
        with self.assertRaises(AdmissionError):
            instance.run("run", [])

    def test_static_source_helper_and_sorted_subject_expansion(self):
        instance = interpreter("async def run(self):\n    return ('user:a', *(f'role:{r}' for r in sorted(self.roles)))", fields={"roles": frozenset({"z", "a"})})
        self.assertEqual(instance.run("run", []), ("user:a", "role:a", "role:z"))

    def test_escaping_generator_requires_a_separate_lifetime_translation(self):
        with self.assertRaises(AdmissionError):
            interpreter("async def run(self):\n    delayed = (x for x in self.roles)\n    return delayed", fields={"roles": frozenset({"z", "a"})})

    def test_nested_async_comprehension_and_record_constructor(self):
        rows = (DataRecord("policy", {"resource": "metric:a"}), DataRecord("policy", {"resource": "table:b"}))
        instance = interpreter("async def run(self):\n    applicable = tuple(p for p in self.rows if p.resource.startswith('metric:'))\n    async def values(prefix):\n        return frozenset(p.resource.removeprefix(prefix) for p in applicable)\n    return Result(await values('metric:'))", fields={"rows": rows}, bindings={"Result": RecordType("result", ("values",))})
        self.assertEqual(instance.run("run", []).fields["values"], frozenset({"a"}))

    def test_isinstance_uses_explicit_record_tag_not_python_reflection(self):
        instance = interpreter("async def run(self):\n    return isinstance(self.result, Success) and self.result.value is not None", fields={"result": DataRecord("success", {"value": "0"})}, bindings={"Success": RecordType("success", ("value",))})
        self.assertIs(instance.run("run", []), True)

    def test_unknown_calls_attributes_and_finally_are_unsupported(self):
        for body in ("return eval('1')", "return self.result.__class__"):
            instance = interpreter("async def run(self):\n    " + body, fields={"result": 1})
            with self.assertRaises(AdmissionError):
                instance.run("run", [])
        with self.assertRaises(AdmissionError):
            interpreter("async def run(self):\n    try:\n        return True\n    finally:\n        return False")

    def test_annotation_expressions_never_execute(self):
        instance = interpreter("async def run(self) -> dangerous[Type]:\n    return True")
        self.assertIs(instance.run("run", []), True)

    def test_source_module_side_effects_never_execute(self):
        program = extract_effect_program(b"raise RuntimeError('never run')\nclass Service:\n async def run(self):\n  return True\n", "Service", ["run"])
        self.assertTrue(EffectInterpreter(program, DataRecord("receiver", {}), {}).run("run", []))

    def test_deferred_token_cannot_be_consumed_twice(self):
        instance = interpreter("async def run(self):\n    return True")
        token = Deferred(lambda: 3)
        self.assertEqual(instance.resolve(token), 3)
        with self.assertRaises(AdmissionError):
            instance.resolve(token)

    def test_loop_and_depth_budget_remain_enforced(self):
        instance = interpreter("async def run(self):\n    for x in self.values:\n        y = x\n    return True", fields={"values": list(range(129))})
        with self.assertRaises(AdmissionError):
            instance.run("run", [])

    def test_conditional_expression_only_evaluates_selected_branch(self):
        events = []
        instance = interpreter("async def run(self):\n    return '1' if True else await self.repo()", fields={"repo": Capability("repo", lambda: events.append(1), True)})
        self.assertEqual(instance.run("run", []), "1")
        self.assertEqual(events, [])

    def test_nested_closure_observes_later_enclosing_assignment(self):
        instance = interpreter("async def run(self):\n    x = 1\n    async def read():\n        return x\n    x = 2\n    return await read()")
        self.assertEqual(instance.run("run", []), 2)

    def test_closure_inside_except_observes_later_enclosing_assignment(self):
        def fail():
            raise SliceFault("BackendError", "owned")
        instance = interpreter("async def run(self):\n    x = 1\n    try:\n        await self.repo()\n    except BackendError:\n        async def read():\n            return x\n    x = 3\n    return await read()", fields={"repo": Capability("repo", fail, True)})
        self.assertEqual(instance.run("run", []), 3)

    def test_exception_alias_uses_supplied_type_binding(self):
        def fail():
            raise SliceFault("BackendError", "owned")
        instance = interpreter("async def run(self):\n    try:\n        return await self.repo()\n    except Alias:\n        return False", fields={"repo": Capability("repo", fail, True)}, bindings={"Alias": ErrorType("BackendError")})
        self.assertIs(instance.run("run", []), False)

    def test_rebound_exception_name_is_not_silently_used_as_a_type(self):
        def fail():
            raise SliceFault("BackendError", "owned")
        instance = interpreter("async def run(self):\n    Exception = True\n    try:\n        return await self.repo()\n    except Exception:\n        return True", fields={"repo": Capability("repo", fail, True)})
        with self.assertRaises(AdmissionError):
            instance.run("run", [])

    def test_except_target_is_cleared_not_restored(self):
        def fail():
            raise SliceFault("BackendError", "owned")
        instance = interpreter("async def run(self):\n    e = 3\n    try:\n        await self.repo()\n    except BackendError as e:\n        pass\n    return e", fields={"repo": Capability("repo", fail, True)})
        with self.assertRaises(AdmissionError):
            instance.run("run", [])

    def test_module_functions_and_plain_record_getattr(self):
        program = extract_effect_program(b"def read(request):\n return getattr(request, 'user', None)\nasync def run(request):\n return read(request).get('role', 'anonymous')\n", None, (), ("read", "run"))
        instance = EffectInterpreter(program, DataRecord("module", {}), {})
        self.assertEqual(instance.run("run", [DataRecord("request", {"user": {"role": "reader"}})]), "reader")

    def test_binding_comes_from_declaration_not_parameter_name(self):
        program = extract_effect_program(b"def read(self):\n return self\n", None, (), ("read",))
        self.assertEqual(EffectInterpreter(program, DataRecord("module", {}), {}).run("read", [7]), 7)
        program = extract_effect_program(b"class Service:\n @staticmethod\n def read(self):\n  return self\n", "Service", ("read",))
        self.assertEqual(EffectInterpreter(program, DataRecord("receiver", {}), {}).run("read", [8]), 8)

    def test_static_definition_rebindings_are_rejected(self):
        for source in (b"class Service:\n async def run(self):\n  return True\nService = other\n",
                       b"getattr = other\nasync def run():\n return True\n",
                       b"async def run():\n return True\nif condition:\n run = other\n"):
            with self.assertRaises(AdmissionError):
                extract_effect_program(source, "Service", ("run",)) if b"class" in source else extract_effect_program(source, None, (), ("run",))

    def test_await_plain_native_boolean_retains_type_error(self):
        for value in (False, True):
            instance = interpreter("async def run(self):\n    return await self.native()", fields={"native": Capability("native", lambda: value)})
            with self.assertRaises(SliceFault) as raised:
                instance.run("run", [])
            self.assertEqual(raised.exception.name, "TypeError")

    def test_source_can_explicitly_catch_nonawaitable_type_error(self):
        instance = interpreter("async def run(self):\n    try:\n        return await self.native()\n    except TypeError:\n        return False", fields={"native": Capability("native", lambda: True)}, bindings={"TypeError": ErrorType("TypeError")})
        self.assertIs(instance.run("run", []), False)


if __name__ == "__main__":
    unittest.main()
