import Lean

/- Conditional predicates,not extractor/ORM/router soundness. -/
namespace AuthRefine.DRFGuardComposition

def routineAllow (authenticated owner template ordinaryAction safeMethod : Bool) : Bool :=
  authenticated && (owner || (template && ordinaryAction && safeMethod))

theorem routine_requires_authenticated (a o t r s : Bool)
    (h : routineAllow a o t r s = true) : a = true := by
  cases a <;> simp_all [routineAllow]

theorem logs_stats_owner_only (a o t s : Bool) :
    routineAllow a o t false s = true ↔ a = true ∧ o = true := by
  simp [routineAllow]

def memberAt (rows : List (Nat × Nat × String)) (project user : Nat)
    (roles : List String) : Prop :=
  ∃ row ∈ rows, row.1 = project ∧ row.2.1 = user ∧ row.2.2 ∈ roles

theorem membership_retains_project_user_role
    (rows : List (Nat × Nat × String)) (p u : Nat) (roles : List String)
    (h : memberAt rows p u roles) :
    ∃ role ∈ roles, (p,u,role) ∈ rows := by
  rcases h with ⟨⟨p',u',r⟩,mem,hp,hu,hr⟩
  simp only at hp hu hr
  subst p'; subst u'
  exact ⟨r,hr,mem⟩

theorem ordered_auth_membership_owner (authenticated member owner : Prop) :
    (authenticated ∧ member) ∧ owner ↔ authenticated ∧ member ∧ owner := by
  constructor
  · rintro ⟨⟨a,m⟩,o⟩; exact ⟨a,m,o⟩
  · rintro ⟨a,m,o⟩; exact ⟨⟨a,m⟩,o⟩

theorem source_or_object_contract (ap ao bp bo : Prop) :
    (ap ∧ ao) ∨ (bp ∧ bo) → (ap ∨ bp) ∧ (ao ∨ bo) := by
  intro h
  rcases h with ⟨a,o⟩ | ⟨b,o⟩
  · exact ⟨Or.inl a,Or.inl o⟩
  · exact ⟨Or.inr b,Or.inr o⟩

-- Converse is false: mix-and-match branches must not authorize an object.
theorem no_cross_branch_or_authorization :
    ¬ ((True ∧ False) ∨ (False ∧ True)) := by simp

end AuthRefine.DRFGuardComposition
