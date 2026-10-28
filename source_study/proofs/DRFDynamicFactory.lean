import Lean
namespace AuthRefine.DRFDynamicFactory

/- Complete supplied project/identity/query observations only. No assertion
   about runtime Django state,ORM,router or the Python extractor. -/
def allow (authenticated superuser member collaborative owner : Bool) : Bool :=
  authenticated && (superuser || member) && (collaborative || superuser || owner)

theorem private_nonsuper_requires_all (a m o : Bool) :
    allow a false m false o = true ↔ a = true ∧ m = true ∧ o = true := by
  cases a <;> cases m <;> cases o <;> simp [allow]

theorem collaborative_still_requires_membership (a m o : Bool) :
    allow a false m true o = true ↔ a = true ∧ m = true := by
  cases a <;> cases m <;> cases o <;> simp [allow]

theorem superuser_still_requires_auth (a m c o : Bool) :
    allow a true m c o = true ↔ a = true := by
  cases a <;> simp [allow]

theorem omitted_owner_changes_private_contract :
    allow true false true false false = false ∧
    allow true false true true false = true := by decide

end AuthRefine.DRFDynamicFactory
