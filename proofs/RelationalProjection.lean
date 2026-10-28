import Lean

/- Source descriptors are bound to these two typed projections before this
   file is checked. This theorem concerns row fields before CSV serialization,
   not arbitrary Python extraction, SQL loading, joins, or deployed services. -/
namespace AuthRefine.RelationalProjection

inductive Field where
  | subject | role | resource | action
deriving DecidableEq, Repr

inductive Term where
  | literal : String → Term
  | field : Field → Term
deriving DecidableEq, Repr

inductive Projection where
  | membership | permission
deriving DecidableEq, Repr

structure Values where
  subject : String
  role : String
  resource : String
  action : String

inductive Event where
  | membership : String → String → Event
  | permission : String → String → String → Event
deriving DecidableEq, Repr

-- BEGIN SOURCE-BOUND TERMS
def membershipTerms : List Term := [.literal "g", .field .subject, .field .role]
def permissionTerms : List Term := [.literal "p", .field .role, .field .resource, .field .action]
-- END SOURCE-BOUND TERMS

def compile (terms : List Term) : Option Projection :=
  if terms = membershipTerms then some .membership
  else if terms = permissionTerms then some .permission
  else none

def evaluate (values : Values) : Term → String
  | .literal text => text
  | .field .subject => values.subject
  | .field .role => values.role
  | .field .resource => values.resource
  | .field .action => values.action

def decode : List String → Option Event
  | [tag, subject, role] => if tag = "g" then some (.membership subject role) else none
  | [tag, role, resource, action] => if tag = "p" then some (.permission role resource action) else none
  | _ => none

def expected (projection : Projection) (values : Values) : Event :=
  match projection with
  | .membership => .membership values.subject values.role
  | .permission => .permission values.role values.resource values.action

theorem admitted_projection_sound (terms : List Term) (projection : Projection)
    (values : Values) (admitted : compile terms = some projection) :
    decode (terms.map (evaluate values)) = some (expected projection values) := by
  unfold compile at admitted
  split at admitted
  · rename_i equal
    subst terms
    cases admitted
    simp [membershipTerms, evaluate, decode, expected]
  · split at admitted
    · rename_i equal
      subst terms
      cases admitted
      simp [permissionTerms, evaluate, decode, expected]
    · contradiction

theorem swapped_membership_not_admitted :
    compile [.literal "g", .field .role, .field .subject] = none := by decide

#print axioms admitted_projection_sound
#print axioms swapped_membership_not_admitted

end AuthRefine.RelationalProjection
