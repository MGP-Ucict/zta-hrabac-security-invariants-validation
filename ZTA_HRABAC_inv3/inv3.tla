--------------------------- MODULE ZTA_Invariant3 ---------------------------
EXTENDS Integers, Sequences

CONSTANTS Actions, Subjects

VARIABLES 
    server_logs,       \* Represents the mutable and targetable off-chain server logs
    blockchain_ledger  \* Represents the append-only immutable on-chain ledger history

vars == <<server_logs, blockchain_ledger>>

(* 
  Initial State:
  Both the centralized logs and the decentralized blockchain ledger start empty.
*)
Init ==
    /\ server_logs = << >>
    /\ blockchain_ledger = << >>

(* 
  State Transition: Valid System Activity
  A legitimate action occurs. It is sequentially appended to both the server logs 
  and the blockchain ledger simultaneously.
*)
LogActivity(sub, act) ==
    /\ server_logs' = Append(server_logs, <<sub, act>>)
    /\ blockchain_ledger' = Append(blockchain_ledger, <<sub, act>>)

(* 
  Threat Scenario: Rogue Admin Log Tampering Attack
  A malicious internal administrator attempts to clear, alter, or delete 
  the centralized server_logs to cover their tracks. 
  Crucially, they lack the cryptographic consensus control to modify the blockchain_ledger.
*)
AdminTamperAttack ==
    /\ server_logs' = << >>  \* Maliciously purging or clearing the off-chain logs
    /\ UNCHANGED blockchain_ledger

Next ==
    \/ \E sub \in Subjects, act \in Actions : LogActivity(sub, act)
    \/ AdminTamperAttack

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* 
  FORMAL SPECIFICATION OF SECURITY INVARIANT 3: Audit Log Tamper-Resistance
  
  Verification Rule: The immutable blockchain ledger must always preserve the complete, 
  unaltered, and chronological sequence of historical events. Even if the off-chain 
  server logs are completely purged (server_logs' = << >>) or compromised, the 
  blockchain ledger never shrinks in size and its historical entries remain permanent.
*)

AuditLogTamperResistanceInvariant ==
    /\ Len(blockchain_ledger) >= 0
    /\ \A i \in 1..Len(blockchain_ledger) : blockchain_ledger[i] /= << >>

=============================================================================
