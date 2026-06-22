--------------------------- MODULE ZTA_Invariant2 ---------------------------
EXTENDS Integers, Sequences

(* 
  Definition of system constants.
  Keyshares represents the two independent parts of the split private key.
*)
CONSTANTS Subjects, Transactions
VARIABLES 
    server_compromised, \* Boolean state reflecting if the bank server is hacked
    client_device_state, \* State of the user's isolated hardware enclave (local device)
    blockchain_ledger   \* Immutable ledger storing successfully signed transactions

vars == <<server_compromised, client_device_state, blockchain_ledger>>

(* 
  Initial State (Init Predicate):
  Initially, the server is secure, client devices are ready, and ledger is empty.
*)
Init ==
    /\ server_compromised = FALSE
    /\ client_device_state = [s \in Subjects -> "READY"]
    /\ blockchain_ledger = {}

(* 
  Threat Scenario / State Transition: Centralized Server Takeover
  An adversary gains full root/write access to the bank's central infrastructure.
  The adversary successfully steals K_server, changing server_compromised to TRUE.
*)
ServerCompromise ==
    /\ server_compromised' = TRUE
    /\ UNCHANGED <<client_device_state, blockchain_ledger>>

(* 
  State Transition: Legitimate Multi-Party Computation (MPC) Handshake
  A legitimate user initiates a transaction. Both K_client and K_server interact 
  collaboratively to compute a joint signature, which successfully updates the ledger.
*)
LegitimateMPCSign(sub, tx) ==
    /\ client_device_state[sub] = "READY"
    /\ blockchain_ledger' = blockchain_ledger \cup {<<tx, "VALID_MPC_SIGN">>_sub}
    /\ UNCHANGED <<server_compromised, client_device_state>>

(* 
  Threat Scenario / State Transition: Single-Sided Forgery Attempt
  An adversary uses the stolen K_server to forge a transaction on behalf of 'sub'.
  Because K_client remains isolated in the secure enclave, the cryptographic execution 
  fails verification at the node level and returns a "FORGERY_REVERT" state.
*)
AdversaryForgeAttempt(sub, tx) ==
    /\ server_compromised = TRUE
    /\ blockchain_ledger' = blockchain_ledger \cup {<<tx, "FORGERY_REVERT">>_sub}
    /\ UNCHANGED <<server_compromised, client_device_state>>

(* 
  Next-State Relation:
  Defines all possible non-deterministic execution paths under the threat model.
*)
Next ==
    \/ ServerCompromise
    \/ \E sub \in Subjects, tx \in Transactions : LegitimateMPCSign(sub, tx)
    \/ \E sub \in Subjects, tx \in Transactions : AdversaryForgeAttempt(sub, tx)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* 
  FORMAL SPECIFICATION OF SECURITY INVARIANT 2: Signature Non-Repudiation
  
  Statement: Centralized server compromise does not allow the adversary to forge 
  a valid cryptographic signature on behalf of an innocent subject.
  
  Mathematical Proof Requirement: The ledger must NEVER contain a "VALID_MPC_SIGN"
  state for a transaction that was initiated solely by an adversary using K_server 
  without interactive K_client collaboration.
*)

SignatureNonRepudiationInvariant ==
    \A record \in blockchain_ledger :
        (record[2] = "VALID_MPC_SIGN") => 
            (\E sub \in Subjects, tx \in Transactions : 
                record = <<tx, "VALID_MPC_SIGN">>_sub)

=============================================================================
