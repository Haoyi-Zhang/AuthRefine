import Lean

/- Conditional fixed-binding diagnosis. The source transition function is fixed
   for the entire word. A graph-distance provider must separately establish the
   rank bound. This file does not verify Python extraction, a BFS implementation,
   native libraries, concurrency, or application specifications. -/
namespace AuthRefine.Diagnosis

def finish {State Input Output : Type} (step : State → Input → Output × State) :
    State → List Input → State
  | state, [] => state
  | state, input :: rest => finish step (step state input).2 rest

def trace {State Input Output Observed : Type}
    (step : State → Input → Output × State) (observe : State → Observed) :
    State → List Input → List (Output × Observed)
  | _, [] => []
  | state, input :: rest =>
      ((step state input).1, observe (step state input).2) ::
        trace step observe (step state input).2 rest

theorem finish_append {State Input Output : Type}
    (step : State → Input → Output × State) (state : State) (first second : List Input) :
    finish step state (first ++ second) = finish step (finish step state first) second := by
  induction first generalizing state with
  | nil => rfl
  | cons input rest ih => simpa [finish] using ih (step state input).2

theorem trace_append {State Input Output Observed : Type}
    (step : State → Input → Output × State) (observe : State → Observed)
    (state : State) (first second : List Input) :
    trace step observe state (first ++ second) = trace step observe state first
      ++ trace step observe (finish step state first) second := by
  induction first generalizing state with
  | nil => rfl
  | cons input rest ih => simp [trace, finish, ih]

variable {Source Target Input Output : Type}
variable (source : Source → Input → Output × Source)
variable (target : Target → Input → Output × Target)
variable (observe : Target → Source) (initial : Target)

theorem rank_bound_from_edges (rank : Target → Nat)
    (initial_rank : rank initial = 0)
    (edge_bound : ∀ state input, rank (target state input).2 ≤ rank state + 1)
    (word : List Input) : rank (finish target initial word) ≤ word.length := by
  have general : ∀ inputs state, rank (finish target state inputs) ≤ rank state + inputs.length := by
    intro inputs
    induction inputs with
    | nil => intro state; simp [finish]
    | cons input rest ih =>
        intro state
        calc
          rank (finish target state (input :: rest)) ≤ rank (target state input).2 + rest.length :=
            ih (target state input).2
          _ ≤ (rank state + 1) + rest.length := Nat.add_le_add_right (edge_bound state input) _
          _ = rank state + (input :: rest).length := by simp [Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]
  simpa [initial_rank] using general word initial

theorem snoc_induction {A : Type} (P : List A → Prop) (base : P [])
    (step : ∀ items item, P items → P (items ++ [item])) : ∀ items, P items := by
  have extend : ∀ suffix stem, P stem → P (stem ++ suffix) := by
    intro suffix
    induction suffix with
    | nil => intro stem h; simpa using h
    | cons item rest ih =>
        intro stem h
        simpa [List.append_assoc] using ih (stem ++ [item]) (step stem item h)
  intro items
  simpa using extend items [] base

theorem matching_prefixes
    (depth : Nat) (rank : Target → Nat)
    (rank_bound : ∀ word, rank (finish target initial word) ≤ word.length)
    (local_agreement : ∀ state input, rank state < depth →
      source (observe state) input = ((target state input).1, observe (target state input).2))
    : ∀ word : List Input, word.length ≤ depth →
    finish source (observe initial) word = observe (finish target initial word) ∧
    trace source id (observe initial) word = trace target observe initial word := by
  apply snoc_induction
  · intro _; simp [finish, trace]
  · intro stem input ih short
    have hs : stem.length + 1 ≤ depth := by simpa using short
    have prefix_short : stem.length ≤ depth := Nat.le_trans (Nat.le_succ _) hs
    obtain ⟨state_equal, trace_equal⟩ := ih prefix_short
    have below : rank (finish target initial stem) < depth :=
      Nat.lt_of_le_of_lt (rank_bound stem) (Nat.lt_of_succ_le hs)
    have cell := local_agreement (finish target initial stem) input below
    constructor
    · simp [finish_append, finish, state_equal, cell]
    · simp [trace_append, trace, finish, state_equal, trace_equal, cell]

theorem first_bad_cell_is_a_shortest_fixed_binding_witness
    (depth : Nat) (rank : Target → Nat)
    (rank_bound : ∀ word, rank (finish target initial word) ≤ word.length)
    (local_agreement : ∀ state input, rank state < depth →
      source (observe state) input = ((target state input).1, observe (target state input).2))
    (stem : List Input) (prefix_length : stem.length = depth) (input : Input)
    (bad_cell : source (observe (finish target initial stem)) input ≠
      ((target (finish target initial stem) input).1,
       observe (target (finish target initial stem) input).2)) :
    trace source id (observe initial) (stem ++ [input]) ≠
      trace target observe initial (stem ++ [input]) ∧
    ∀ shorter : List Input, shorter.length < (stem ++ [input]).length →
      trace source id (observe initial) shorter = trace target observe initial shorter := by
  have same := matching_prefixes source target observe initial depth rank rank_bound
      local_agreement stem (Nat.le_of_eq prefix_length)
  constructor
  · intro equal
    rw [trace_append, trace_append, same.2] at equal
    have tails := List.append_cancel_left equal
    have parts :
        (source (finish source (observe initial) stem) input).1 =
          (target (finish target initial stem) input).1 ∧
        (source (finish source (observe initial) stem) input).2 =
          observe (target (finish target initial stem) input).2 := by
      simpa [trace] using tails
    apply bad_cell
    apply Prod.ext
    · simpa [same.1] using parts.1
    · simpa [same.1] using parts.2
  · intro shorter length_bound
    have length_bound' : shorter.length < depth + 1 := by
      simpa [List.length_append, prefix_length] using length_bound
    have bounded : shorter.length ≤ depth := Nat.le_of_lt_succ length_bound'
    exact (matching_prefixes source target observe initial depth rank rank_bound
      local_agreement shorter bounded).2

end AuthRefine.Diagnosis

#print axioms AuthRefine.Diagnosis.matching_prefixes
#print axioms AuthRefine.Diagnosis.first_bad_cell_is_a_shortest_fixed_binding_witness
#print axioms AuthRefine.Diagnosis.rank_bound_from_edges
