import Lean

/- A deliberately scoped observation quotient for the admitted source slice.
   A role-property read appends the same client-role list to an aliased realm
   list. Raw lists change; after the first read, membership observations do not.
   This says nothing about issuer correctness, serialization, Python extraction,
   changing claims, revocation, or a complete application. -/
namespace ClaimRoleObservation

def reads : Nat → List String → List String → List String
  | 0, realm, _clients => realm
  | n + 1, realm, clients => reads n realm clients ++ clients

theorem mem_append_iff (role : String) (left right : List String) :
    role ∈ left ++ right ↔ role ∈ left ∨ role ∈ right := by
  induction left with
  | nil => simp
  | cons head tail ih => simp [List.mem_cons, ih, or_assoc]

theorem positive_reads_membership (n : Nat) (role : String)
    (realm clients : List String) :
    role ∈ reads (n + 1) realm clients ↔ role ∈ realm ∨ role ∈ clients := by
  induction n with
  | zero => simp [reads, mem_append_iff]
  | succ n ih =>
    change (role ∈ reads (n + 1) realm clients ++ clients ↔ _)
    rw [mem_append_iff, ih]
    exact ⟨fun h => h.elim id Or.inr, fun h => Or.inl h⟩

theorem positive_reads_same_membership (a b : Nat) (role : String)
    (realm clients : List String) :
    role ∈ reads (a + 1) realm clients ↔ role ∈ reads (b + 1) realm clients := by
  rw [positive_reads_membership, positive_reads_membership]

theorem raw_list_can_change :
    reads 1 [] ["client:reader"] ≠ reads 2 [] ["client:reader"] := by
  decide

#print axioms positive_reads_membership
#print axioms positive_reads_same_membership
#print axioms raw_list_can_change
end ClaimRoleObservation
