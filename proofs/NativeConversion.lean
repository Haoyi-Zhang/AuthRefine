import Lean

/-
  The aggregation conversion used by the admitted native adapter.
  Row matchers are shared mathematical inputs to both sides. This does not
  verify a Python parser, arbitrary Casbin matchers, or an application's entry
  points. Native execution is checked separately against the converted table.
-/
namespace AuthRefine

structure Rule (Request : Type) where
  guard : Request → Bool
  allow : Bool

def runRules {Request : Type} : List (Rule Request) → Request → Bool
  | [], _ => false
  | rule :: rest, request =>
      if rule.guard request then rule.allow else runRules rest request

def denies {Request : Type} (rule : Rule Request) (request : Request) : Bool :=
  rule.guard request && !rule.allow

def permits {Request : Type} (rule : Rule Request) (request : Request) : Bool :=
  rule.guard request && rule.allow

def converted {Request : Type} (rules : List (Rule Request)) : List (Rule Request) :=
  rules.filter (fun rule => !rule.allow) ++ rules.filter (fun rule => rule.allow)

def denyOverrides {Request : Type} (rules : List (Rule Request)) (request : Request) : Bool :=
  rules.any (fun rule => permits rule request) &&
    !(rules.any (fun rule => denies rule request))

theorem deny_prefix {Request : Type} (rules suffix : List (Rule Request)) (request : Request) :
    runRules (rules.filter (fun rule => !rule.allow) ++ suffix) request =
      if rules.any (fun rule => denies rule request) then false else runRules suffix request := by
  induction rules with
  | nil => simp [runRules]
  | cons rule rest ih =>
      cases ha : rule.allow <;> cases hm : rule.guard request <;>
        simp [runRules, denies, ha, hm, ih]

theorem allow_filter {Request : Type} (rules : List (Rule Request)) (request : Request) :
    runRules (rules.filter (fun rule => rule.allow)) request =
      rules.any (fun rule => permits rule request) := by
  induction rules with
  | nil => simp [runRules]
  | cons rule rest ih =>
      cases ha : rule.allow <;> cases hm : rule.guard request <;>
        simp [runRules, permits, ha, hm, ih]

theorem aggregation_conversion {Request : Type} (rules : List (Rule Request)) (request : Request) :
    runRules (converted rules) request = denyOverrides rules request := by
  rw [converted, deny_prefix, allow_filter]
  unfold denyOverrides
  cases h : rules.any (fun rule => denies rule request) <;> simp [h]

def observedRun {State Input Output Observation : Type}
    (step : State → Input → Output × State) (observe : State → Observation) :
    State → List Input → List (Output × Observation)
  | _, [] => []
  | state, input :: rest =>
      let result := step state input
      (result.1, observe result.2) :: observedRun step observe result.2 rest

/- Standard lifting obligation: supplying a state map is not enough; every
   concrete step must satisfy correspondence. The theorem has no finite-test
   premise and makes no claim that instrumentation discovers such a map. -/
theorem correspondence_lifts_to_traces {Concrete Abstract Input Output : Type}
    (concrete : Concrete → Input → Output × Concrete)
    (abstract : Abstract → Input → Output × Abstract)
    (observe : Concrete → Abstract)
    (correspondence : ∀ state input,
      abstract (observe state) input =
        ((concrete state input).1, observe (concrete state input).2))
    (state : Concrete) (inputs : List Input) :
    observedRun concrete observe state inputs =
      observedRun abstract id (observe state) inputs := by
  induction inputs generalizing state with
  | nil => rfl
  | cons input rest ih =>
      simp only [observedRun, correspondence, id_eq]
      exact congrArg (fun tail =>
        ((concrete state input).1, observe (concrete state input).2) :: tail)
        (ih (concrete state input).2)

def sequence {State Input Intermediate Output : Type}
    (first : State → Input → Intermediate × State)
    (second : State → Intermediate → Output × State) (state : State) (input : Input) : Output × State :=
  let middle := first state input
  second middle.2 middle.1

/- A sequential producer/consumer composition obligation. This is not a
   concurrency theorem or a claim that two arbitrary services share state. -/
theorem sequential_composition {Concrete Abstract Input Intermediate Output : Type}
    (firstC : Concrete → Input → Intermediate × Concrete)
    (secondC : Concrete → Intermediate → Output × Concrete)
    (firstA : Abstract → Input → Intermediate × Abstract)
    (secondA : Abstract → Intermediate → Output × Abstract)
    (observe : Concrete → Abstract)
    (first_ok : ∀ state input, firstA (observe state) input =
      ((firstC state input).1, observe (firstC state input).2))
    (second_ok : ∀ state middle, secondA (observe state) middle =
      ((secondC state middle).1, observe (secondC state middle).2))
    (state : Concrete) (input : Input) :
    sequence firstA secondA (observe state) input =
      ((sequence firstC secondC state input).1, observe (sequence firstC secondC state input).2) := by
  unfold sequence
  rw [first_ok]
  exact second_ok (firstC state input).2 (firstC state input).1

end AuthRefine

#print axioms AuthRefine.aggregation_conversion
#print axioms AuthRefine.correspondence_lifts_to_traces
#print axioms AuthRefine.sequential_composition
