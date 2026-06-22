--------------------------- MODULE ZTA_HRABAC ---------------------------
EXTENDS Integers, Sequences

(* 
  Definition of the system constants.
  Subjects represents users/entities requesting access.
  Permissions represents specific actions (e.g., read_data, approve_tx).
*)
CONSTANT Subjects, Permissions

VARIABLES 
    db_privileges,      \* Represents the compromised off-chain database state (P_off)
    blockchain_state,   \* Represents the immutable on-chain ledger state (P_on)
    system_log          \* Represents the tamper-proof on-chain execution history log

\* Grouping variables for shorthand notation in state transitions
vars == <<db_privileges, blockchain_state, system_log>>

(* 
  Initial State (Init Predicate):
  Initially, both layers are synchronized and computationally identical.
  The execution history log starts as an empty sequence.
*)
Init ==
    /\ db_privileges \in [Subjects -> SUBSET Permissions]
    /\ blockchain_state = db_privileges
    /\ system_log = << >>

(* 
  Threat Scenario / State Transition: Database Attack
  An adversary compromises the off-chain layer (P_off) and arbitrarily 
  injects an unauthorized permission 'perm' for a subject 'sub'.
  Crucially, the on-chain blockchain_state (P_on) remains unchanged.
*)
DatabaseAttack(sub, perm) ==
    /\ db_privileges' = [db_privileges EXCEPT ![sub] = db_privileges[sub] \cup {perm}]
    /\ UNCHANGED <<blockchain_state, system_log>>

(* 
  State Transition: On-Chain Policy Evaluation (Smart Contract Execution)
  The Solidity smart contract intercepts the transaction and evaluates the request.
  It strictly cross-references the request against the immutable blockchain_state.
*)
OnChainExecute(sub, perm) ==
    IF perm \in blockchain_state[sub]
    THEN \* Access Granted: The deterministic validation passes and logs "SUCCESS"
        /\ system_log' = Append(system_log, <<sub, perm, "SUCCESS">>)
        /\ UNCHANGED <<db_privileges, blockchain_state>>
    ELSE \* Access Denied: The smart contract triggers an automatic revert() operation
        /\ system_log' = Append(system_log, <<sub, perm, "REVERT">>)
        /\ UNCHANGED <<db_privileges, blockchain_state>>

(* 
  Next-State Relation:
  Defines the legal actions that can non-deterministically occur in the system.
*)
Next ==
    \/ \E sub \in Subjects, perm \in Permissions : DatabaseAttack(sub, perm)
    \/ \E sub \in Subjects, perm \in Permissions : OnChainExecute(sub, perm)

\* The structural temporal formula defining the entire system behavior
Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* 
  FORMAL SPECIFICATION OF SECURITY INVARIANT 1: Privilege Integrity
  
  Statement: An adversary operating within the compromised web layer/database (P_off)
  is strictly incapable of unilaterally escalating privileges or executing unauthorized 
  actions on-chain.
  
  Mathematical Proof Requirement: The execution log must NEVER contain a "SUCCESS" token
  for any subject-permission pair that does not explicitly exist within the immutable 
  on-chain blockchain_state, regardless of any mutations inside db_privileges.
*)

PrivilegeIntegrityInvariant ==
    \A i \in 1..Len(system_log) :
        LET event == system_log[i]
        IN (event[3] = "SUCCESS") => (event[2] \in blockchain_state[event[1]])

=============================================================================
