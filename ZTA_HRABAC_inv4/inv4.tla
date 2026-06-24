----------------------- MODULE ZTA_Invariant4 -----------------------
EXTENDS Integers

CONSTANTS 
    Tsecure,    \* The secure trust threshold zone (e.g., 80)
    Ttolerance  \* The critical tolerance threshold zone (e.g., 20)

VARIABLES 
    currentState, \* The actual operational state of the session
    trustScore,   \* The contextual trust score dynamically evaluated by the off-chain AI
    mfaVerified   \* Flag indicating if the user has successfully passed MFA in this cycle

\* Definition of all valid architectural session states
States == {"Sactive", "SMFA1", "SMFA2", "Slocked", "Slimited"}

\* Initial state configuration
Init ==
    /\ trustScore = 100
    /\ currentState = "Sactive"
    /\ mfaVerified = FALSE

\* State Transition: AI context evaluation triggers a trust score drop
EvaluateTrust ==
    /\ \E t \in 0..100 : 
        /\ trustScore' = t
        /\ IF t < Tsecure
           THEN /\ currentState' = "SMFA1"
                /\ mfaVerified' = FALSE  \* Requires new MFA validation due to trust drop
           ELSE /\ currentState' = "Sactive"
                /\ mfaVerified' = mfaVerified

\* State Transition: User fails the first MFA challenge
MFAFirstFail ==
    /\ currentState = "SMFA1"
    /\ trustScore < Tsecure
    /\ currentState' = "SMFA2"
    /\ UNCHANGED <<trustScore, mfaVerified>>

\* State Transition: User fails the second MFA challenge sequentially
MFASecondFail ==
    /\ currentState = "SMFA2"
    /\ trustScore < Tsecure
    /\ currentState' = "Slocked"
    /\ UNCHANGED <<trustScore, mfaVerified>>

\* State Transition: Successful MFA challenge when trust is critically low (Rule 4: Tcurrent <= Ttolerance)
MFASuccessLimited ==
    /\ currentState \in {"SMFA1", "SMFA2"}
    /\ trustScore <= Ttolerance
    /\ currentState' = "Slimited"
    /\ mfaVerified' = TRUE
    /\ UNCHANGED trustScore

\* State Transition: Successful MFA challenge when trust is moderately low (Rule 1: Ttolerance < Tcurrent < Tsecure)
\* At trust score 21, this rule applies and safely returns the user to Sactive
MFASuccessNormal ==
    /\ currentState \in {"SMFA1", "SMFA2"}
    /\ trustScore > Ttolerance
    /\ trustScore < Tsecure
    /\ currentState' = "Sactive"
    /\ mfaVerified' = TRUE
    /\ UNCHANGED trustScore

\* Next-state relation defining all allowed atomic transitions
Next == 
    \/ EvaluateTrust 
    \/ MFAFirstFail 
    \/ MFASecondFail 
    \/ MFASuccessLimited 
    \/ MFASuccessNormal

\* Complete system specification
Spec == Init /\ [][Next]_<<currentState, trustScore, mfaVerified>>

-----------------------------------------------------------------------------
\* CORRECTED FORMAL SPECIFICATION OF INVARIANT 4
\* If trust is compromised, the user must be in a verification state, a limited state, 
\* or can be in Sactive ONLY IF they have successfully verified their identity via MFA.
Invariant4 == 
    (trustScore < Tsecure) => 
        (currentState \in {"SMFA1", "SMFA2", "Slimited", "Slocked"} \/ (currentState = "Sactive" /\ mfaVerified = TRUE))

=============================================================================
