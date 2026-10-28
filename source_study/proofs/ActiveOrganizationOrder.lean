import Lean

/- Conditional composition AFTER the declared header parser is interpreted.
   This does not prove Python extraction, UUID parsing, framework DI, identity,
   SQL/ORM, actual membership uniqueness, logging totality or deployment.
   The supplied per-organization gate may be any total Boolean function. -/
namespace AuthRefine.ActiveOrganizationOrder

inductive Header where
  | missing
  | invalid
  | organization (id : String)
deriving DecidableEq

inductive Decision where
  | allow
  | deny
  | badRequest
deriving DecidableEq

def sourceDecision (header : Header) (superuser : Bool)
    (gate : String → Bool) : Decision :=
  match header with
  | .invalid => .badRequest
  | .missing => if superuser then .allow else .badRequest
  | .organization id => if superuser || gate id then .allow else .deny

def allowedContract (header : Header) (superuser : Bool)
    (gate : String → Bool) : Prop :=
  header ≠ .invalid ∧ (superuser = true ∨
    ∃ id, header = .organization id ∧ gate id = true)

theorem composition_refines_allow_contract (header : Header)
    (superuser : Bool) (gate : String → Bool) :
    sourceDecision header superuser gate = .allow ↔
      allowedContract header superuser gate := by
  cases header with
  | missing => cases superuser <;> simp [sourceDecision, allowedContract]
  | invalid => simp [sourceDecision, allowedContract]
  | organization id =>
    cases superuser <;> cases h : gate id <;>
      simp [sourceDecision, allowedContract, h]

theorem invalid_precedes_superuser (gate : String → Bool) :
    sourceDecision .invalid true gate = .badRequest := by
  rfl

theorem missing_superuser_bypasses (gate : String → Bool) :
    sourceDecision .missing true gate = .allow := by
  rfl

theorem other_organization_isolation (id : String) (superuser : Bool)
    (gate changed : String → Bool) (same : gate id = changed id) :
    sourceDecision (.organization id) superuser gate =
      sourceDecision (.organization id) superuser changed := by
  simp only [sourceDecision, same]

def wrongEarlyBypass (header : Header) (superuser : Bool)
    (gate : String → Bool) : Decision :=
  if superuser then .allow else sourceDecision header false gate

theorem early_bypass_is_not_equivalent (gate : String → Bool) :
    wrongEarlyBypass .invalid true gate ≠ sourceDecision .invalid true gate := by
  simp [wrongEarlyBypass, sourceDecision]

#print axioms composition_refines_allow_contract
#print axioms invalid_precedes_superuser
#print axioms missing_superuser_bypasses
#print axioms other_organization_isolation
#print axioms early_bypass_is_not_equivalent
end AuthRefine.ActiveOrganizationOrder
