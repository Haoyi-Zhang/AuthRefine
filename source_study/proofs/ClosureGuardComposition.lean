import Lean

/- Conditional model theorem,not AST-extractor/JWT/ORM/DI/runtime soundness.
   Captured requirements and complete observed role/permission predicates are
   parameters. Native tenant gates are arbitrary supplied total predicates. -/
namespace AuthRefine.ClosureGuardComposition

def sourceAllow (adminRole adminPermission : Bool) (required : List String)
    (hasRole hasPermission : String → Bool) : Bool :=
  adminRole || adminPermission || (required.any hasRole || required.any hasPermission)

theorem source_set_contract (a b : Bool) (required : List String)
    (r p : String → Bool) :
    sourceAllow a b required r p = true ↔
      a = true ∨ b = true ∨ ∃ q ∈ required, r q = true ∨ p q = true := by
  simp only [sourceAllow, Bool.or_eq_true, List.any_eq_true]
  constructor
  · intro h
    rcases h with h | h
    · rcases h with ha | hb
      · exact Or.inl ha
      · exact Or.inr (Or.inl hb)
    · rcases h with hr | hp
      · rcases hr with ⟨q, hq, h⟩
        exact Or.inr (Or.inr ⟨q, hq, Or.inl h⟩)
      · rcases hp with ⟨q, hq, h⟩
        exact Or.inr (Or.inr ⟨q, hq, Or.inr h⟩)
  · intro h
    rcases h with ha | hb | ⟨q, hq, hr | hp⟩
    · exact Or.inl (Or.inl ha)
    · exact Or.inl (Or.inr hb)
    · exact Or.inr (Or.inl ⟨q, hq, hr⟩)
    · exact Or.inr (Or.inr ⟨q, hq, hp⟩)

def loopAllow (roles : List String) (tenant : String)
    (gate : String → String → Bool) : Bool :=
  match roles with
  | [] => false
  | r :: rs => if gate r tenant then true else loopAllow rs tenant gate

theorem native_role_loop_contract (roles : List String) (tenant : String)
    (gate : String → String → Bool) :
    loopAllow roles tenant gate = true ↔ ∃ r ∈ roles, gate r tenant = true := by
  induction roles with
  | nil => simp [loopAllow]
  | cons r rs ih =>
    simp only [loopAllow]
    cases h : gate r tenant <;> simp [h, ih]

theorem empty_roles_do_not_authorize (tenant : String)
    (gate : String → String → Bool) : loopAllow [] tenant gate = false := by rfl

end AuthRefine.ClosureGuardComposition
