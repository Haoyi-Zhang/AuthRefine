import Lean

/- Conditional relational semantics for the selected organization gate.
   UUID equality is represented by equality of canonical strings. SQL/ORM
   execution, source extraction, identity verification, concurrency and the
   actual application's uniqueness invariant are NOT proved here. The caller
   must establish at most one membership for the queried (user, organization)
   and complete, stable role-permission observations. This is why the native
   omitted-key controls keep multi-row .first() observations unresolved. -/
namespace AuthRefine.OrganizationQueryGate

structure Row where
  user : String
  organization : String
  role : String
deriving DecidableEq

def selected : List Row → String → String → List Row
  | [], _, _ => []
  | row :: rest, user, organization =>
    if row.user = user ∧ row.organization = organization
    then row :: selected rest user organization
    else selected rest user organization

def firstAllows (rows : List Row) (permits : String → Prop) : Prop :=
  match rows with
  | [] => False
  | row :: _ => permits row.role

def sourceAllows (rows : List Row) (user organization : String)
    (permits : String → Prop) (superuser : Bool) : Prop :=
  superuser = true ∨ firstAllows (selected rows user organization) permits

def relationalContract (rows : List Row) (user organization : String)
    (permits : String → Prop) (superuser : Bool) : Prop :=
  superuser = true ∨ ∃ row, row ∈ rows ∧ row.user = user ∧
    row.organization = organization ∧ permits row.role

theorem selected_membership (rows : List Row) (row : Row)
    (user organization : String) :
    row ∈ selected rows user organization ↔
      row ∈ rows ∧ row.user = user ∧ row.organization = organization := by
  induction rows with
  | nil => simp [selected]
  | cons head tail ih =>
    by_cases matching : head.user = user ∧ head.organization = organization
    · rw [selected, if_pos matching]
      simp only [List.mem_cons]
      constructor
      · intro found
        rcases found with equal | found
        · subst row
          exact ⟨Or.inl rfl, matching⟩
        · rcases ih.mp found with ⟨member, sameUser, sameOrg⟩
          exact ⟨Or.inr member, sameUser, sameOrg⟩
      · intro ⟨found, sameUser, sameOrg⟩
        rcases found with equal | member
        · exact Or.inl equal
        · exact Or.inr (ih.mpr ⟨member, sameUser, sameOrg⟩)
    · rw [selected, if_neg matching]
      simp only [List.mem_cons]
      constructor
      · intro found
        rcases ih.mp found with ⟨member, sameUser, sameOrg⟩
        exact ⟨Or.inr member, sameUser, sameOrg⟩
      · intro ⟨found, sameUser, sameOrg⟩
        rcases found with equal | member
        · subst row
          exact False.elim (matching ⟨sameUser, sameOrg⟩)
        · exact ih.mpr ⟨member, sameUser, sameOrg⟩

theorem unique_first_is_relational (rows : List Row) (permits : String → Prop)
    (unique : rows.length ≤ 1) :
    firstAllows rows permits ↔ ∃ row, row ∈ rows ∧ permits row.role := by
  cases rows with
  | nil => simp [firstAllows]
  | cons row rest =>
    cases rest with
    | nil => simp [firstAllows]
    | cons next tail => simp at unique

theorem query_gate_refines_relational_contract (rows : List Row)
    (user organization : String) (permits : String → Prop) (superuser : Bool)
    (unique : (selected rows user organization).length ≤ 1) :
    sourceAllows rows user organization permits superuser ↔
      relationalContract rows user organization permits superuser := by
  unfold sourceAllows relationalContract
  rw [unique_first_is_relational (selected rows user organization) permits unique]
  simp only [selected_membership, and_assoc]

theorem irrelevant_row_isolation (rows : List Row) (other : Row)
    (user organization : String) (permits : String → Prop) (superuser : Bool)
    (irrelevant : other.user ≠ user ∨ other.organization ≠ organization) :
    sourceAllows (other :: rows) user organization permits superuser ↔
      sourceAllows rows user organization permits superuser := by
  rcases irrelevant with h | h
  · simp [sourceAllows, selected, h]
  · simp [sourceAllows, selected, h]

theorem superuser_bypass (rows : List Row) (user organization : String)
    (permits : String → Prop) : sourceAllows rows user organization permits true := by
  exact Or.inl rfl

#print axioms query_gate_refines_relational_contract
#print axioms irrelevant_row_isolation
#print axioms superuser_bypass
end AuthRefine.OrganizationQueryGate
