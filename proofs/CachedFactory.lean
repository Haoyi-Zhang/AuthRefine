import Lean

/- The literal table below is bound to the actual native component receipt by
   the private verification runner before compilation. This certifies the
   measured finite component and its source-backed caller protocol, not the
   Python extractor, an arbitrary file resolver or a deployed application. -/
namespace AuthRefine.CachedFactory

def protocolAdmits {P I : Type} (next : P → I → Option P) : P → List I → Prop
  | _, [] => True
  | p, i :: rest => ∃ p', next p i = some p' ∧ protocolAdmits next p' rest

def observedRun {S I O A : Type} (step : S → I → O × S) (observe : S → A) :
    S → List I → List (O × A)
  | _, [] => []
  | s, i :: rest =>
      let result := step s i
      (result.1, observe result.2) :: observedRun step observe result.2 rest

def partialRun {S I O A : Type} (step : S → I → Option (O × S)) (observe : S → A) :
    S → List I → Option (List (O × A))
  | _, [] => some []
  | s, i :: rest =>
      match step s i with
      | none => none
      | some (out, after) =>
          match partialRun step observe after rest with
          | none => none
          | some tail => some ((out, observe after) :: tail)

theorem protocol_correspondence {C A P I O : Type}
    (concrete : C → I → Option (O × C)) (abstract : A → I → O × A)
    (observe : C → A) (next : P → I → Option P) (region : C → P → Prop)
    (local_ok : ∀ c p i p', region c p → next p i = some p' →
      ∃ out after, concrete c i = some (out, after) ∧
        abstract (observe c) i = (out, observe after) ∧ region after p')
    (c : C) (p : P) (in_region : region c p) (inputs : List I)
    (admitted : protocolAdmits next p inputs) :
    partialRun concrete observe c inputs = some (observedRun abstract id (observe c) inputs) := by
  induction inputs generalizing c p with
  | nil => rfl
  | cons input rest ih =>
      obtain ⟨p', hp, remaining⟩ := admitted
      obtain ⟨out, after, hc, ha, related⟩ := local_ok c p input p' in_region hp
      have tail := ih after p' related remaining
      simp only [partialRun, hc, tail, observedRun, ha, id_eq]

structure Observation where
  loaded : Bool
  permission : Bool
  stored : Bool
deriving DecidableEq, Repr

-- BEGIN MEASURED TABLE
def observationValues : List Nat := [0, 1, 3, 4, 5, 7]
def measuredRows : List (List (Option (Bool × Nat))) :=
  [[some (true, 1), none, some (true, 0), some (true, 3), some (true, 0)],
   [some (true, 1), some (false, 1), some (true, 0), some (true, 4), some (true, 1)],
   [some (true, 2), some (true, 2), some (true, 0), some (true, 5), some (true, 2)],
   [some (true, 5), none, some (true, 3), some (true, 3), some (true, 0)],
   [some (true, 4), some (false, 4), some (true, 3), some (true, 4), some (true, 1)],
   [some (true, 5), some (true, 5), some (true, 3), some (true, 5), some (true, 2)]]
-- END MEASURED TABLE

def observe (state : Fin 6) : Observation :=
  let bits := observationValues.getD state.val 0
  ⟨bits % 2 == 1, bits / 2 % 2 == 1, bits / 4 % 2 == 1⟩

def concrete (state : Fin 6) (input : Fin 5) : Option (Bool × Fin 6) :=
  match measuredRows.get? state.val with
  | none => none
  | some row =>
      match row.get? input.val with
      | some (some (out, after)) =>
          if bound : after < 6 then some (out, ⟨after, bound⟩) else none
      | _ => none

/- Event order is acquire, authorize, clear, grant, revoke. Preparation and
   configuration events return successful completion, not an entitlement to
   administer permissions. Only authorize is the actual permission decision. -/
def abstract (state : Observation) (input : Fin 5) : Bool × Observation :=
  match input.val with
  | 0 => (true, { state with loaded := true, permission := if state.loaded then state.permission else state.stored })
  | 1 => (state.loaded && state.permission, state)
  | 2 => (true, { state with loaded := false, permission := false })
  | 3 => (true, { state with stored := true })
  | _ => (true, { state with stored := false })

def next (acquired : Bool) (input : Fin 5) : Option Bool :=
  if acquired then
    if input.val == 1 then some false else none
  else
    if input.val == 1 then none else some (input.val == 0)

def region (state : Fin 6) (acquired : Bool) : Prop :=
  acquired = true → (observe state).loaded = true

instance (state : Fin 6) (acquired : Bool) : Decidable (region state acquired) := by
  unfold region
  infer_instance

def LocalCase (c : Fin 6) (i : Fin 5) (p' : Bool) : Prop :=
  match concrete c i with
  | none => False
  | some (out, after) => abstract (observe c) i = (out, observe after) ∧ region after p'

instance (c : Fin 6) (i : Fin 5) (p' : Bool) : Decidable (LocalCase c i p') := by
  unfold LocalCase
  cases concrete c i with
  | none => infer_instance
  | some result => cases result; infer_instance

set_option maxRecDepth 4096 in
set_option maxHeartbeats 1000000 in
theorem measured_local_cells :
    ∀ c : Fin 6, ∀ p : Bool, ∀ i : Fin 5, ∀ p' : Bool,
      region c p → next p i = some p' → LocalCase c i p' := by
  decide

theorem measured_local_obligations :
    ∀ c : Fin 6, ∀ p : Bool, ∀ i : Fin 5, ∀ p' : Bool,
      region c p → next p i = some p' →
        ∃ out : Bool, ∃ after : Fin 6, concrete c i = some (out, after) ∧
          abstract (observe c) i = (out, observe after) ∧ region after p' := by
  intro c p i p' related permitted
  have checked := measured_local_cells c p i p' related permitted
  unfold LocalCase at checked
  cases concrete_step : concrete c i with
  | none => simp only [concrete_step] at checked
  | some result =>
      cases result with
      | mk out after =>
          simp only [concrete_step] at checked
          exact ⟨out, after, rfl, checked.1, checked.2⟩

theorem measured_component_traces (c : Fin 6) (p : Bool) (related : region c p)
    (inputs : List (Fin 5)) (admitted : protocolAdmits next p inputs) :
    partialRun concrete observe c inputs = some (observedRun abstract id (observe c) inputs) :=
  protocol_correspondence concrete abstract observe next region measured_local_obligations
    c p related inputs admitted

end AuthRefine.CachedFactory

#print axioms AuthRefine.CachedFactory.protocol_correspondence
#print axioms AuthRefine.CachedFactory.measured_local_obligations
#print axioms AuthRefine.CachedFactory.measured_component_traces
