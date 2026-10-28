import Lean

/- A declared outcome is packed into a fixed ordered Boolean vector: the
   authorization-result bit plus selected effect/error bits. Core collection
   events are not themselves authorization grants. Packing must not identify
   a denied call with an exception, or an omitted call with a completed call.
   Python packing is bound separately; no extractor/application theorem is
   claimed by this elementary representation obligation. -/
namespace AuthRefine.OutcomeObservation

def encode : List Bool → Nat
  | [] => 0
  | false :: tail => 2 * encode tail
  | true :: tail => 2 * encode tail + 1

theorem encode_injective_fixed_length (left right : List Bool)
    (lengths : left.length = right.length) (equal : encode left = encode right) :
    left = right := by
  induction left generalizing right with
  | nil =>
      cases right with
      | nil => rfl
      | cons head tail => simp at lengths
  | cons head tail ih =>
      cases right with
      | nil => simp at lengths
      | cons other rest =>
          have same_length : tail.length = rest.length := by simpa using lengths
          cases head <;> cases other
          · simp only [encode] at equal
            have same : encode tail = encode rest := by omega
            exact congrArg (List.cons false) (ih rest same_length same)
          · simp only [encode] at equal
            omega
          · simp only [encode] at equal
            omega
          · simp only [encode] at equal
            have same : encode tail = encode rest := by omega
            exact congrArg (List.cons true) (ih rest same_length same)

theorem denial_and_error_can_be_distinct : encode [false, false] ≠ encode [false, true] := by
  decide

#print axioms encode_injective_fixed_length
#print axioms denial_and_error_can_be_distinct
end AuthRefine.OutcomeObservation
