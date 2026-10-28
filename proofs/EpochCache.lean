import Lean

/- A cache hit is transparent under an immutable epoch-to-payload contract.
   This is not a theorem about SQL isolation, the source extractor, locks or
   the native authorization implementation. Those are separate obligations. -/
namespace EpochCache

structure Entry (Payload : Type) where
  epoch : Nat
  payload : Payload

def Valid (contents : Nat → Payload) (cache : Option (Entry Payload)) : Prop :=
  ∀ entry, cache = some entry → entry.payload = contents entry.epoch

def refresh (contents : Nat → Payload) (epoch : Nat)
    (cache : Option (Entry Payload)) : Entry Payload :=
  match cache with
  | none => ⟨epoch, contents epoch⟩
  | some entry => if entry.epoch = epoch then entry else ⟨epoch, contents epoch⟩

theorem refresh_epoch (contents : Nat → Payload) (epoch : Nat)
    (cache : Option (Entry Payload)) : (refresh contents epoch cache).epoch = epoch := by
  cases cache with
  | none => rfl
  | some entry =>
    by_cases h : entry.epoch = epoch
    · simp [refresh, h]
    · simp [refresh, h]

theorem refresh_payload (contents : Nat → Payload) (epoch : Nat)
    (cache : Option (Entry Payload)) (valid : Valid contents cache) :
    (refresh contents epoch cache).payload = contents epoch := by
  cases cache with
  | none => rfl
  | some entry =>
    by_cases h : entry.epoch = epoch
    · have same := valid entry rfl
      simpa [refresh, h] using same
    · simp [refresh, h]

theorem refresh_preserves_valid (contents : Nat → Payload) (epoch : Nat)
    (cache : Option (Entry Payload)) (valid : Valid contents cache) :
    Valid contents (some (refresh contents epoch cache)) := by
  intro entry same
  have eq : refresh contents epoch cache = entry := Option.some.inj same
  subst entry
  rw [refresh_epoch]
  exact refresh_payload contents epoch cache valid

theorem consumer_transparency (contents : Nat → Payload) (epoch : Nat)
    (cache : Option (Entry Payload)) (valid : Valid contents cache)
    (decide : Payload → Request → Bool) (request : Request) :
    decide (refresh contents epoch cache).payload request = decide (contents epoch) request := by
  rw [refresh_payload contents epoch cache valid]

def runEpochs (contents : Nat → Payload) : List Nat → Option (Entry Payload) → Option (Entry Payload)
  | [], cache => cache
  | epoch :: rest, cache => runEpochs contents rest (some (refresh contents epoch cache))

theorem arbitrary_epoch_sequence_valid (contents : Nat → Payload) (epochs : List Nat)
    (cache : Option (Entry Payload)) (valid : Valid contents cache) :
    Valid contents (runEpochs contents epochs cache) := by
  induction epochs generalizing cache with
  | nil => exact valid
  | cons epoch _rest ih =>
    exact ih _ (refresh_preserves_valid contents epoch cache valid)

-- Reusing an epoch for a different payload violates the essential premise.
example : (refresh (fun _ => false) 7 (some (Entry.mk 7 true))).payload ≠ false := by decide

#print axioms consumer_transparency
#print axioms arbitrary_epoch_sequence_valid
end EpochCache
