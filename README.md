# Formal Verification of the ZTA-HRABAC Banking Architecture

This directory contains the formal specifications and configuration files used to mathematically verify the core security invariants of the proposed dual-layer Zero-Trust Architecture (ZTA-HRABAC) using **TLA+** and the **TLC Model Checker**.

## Repository Structure

*   `ZTA_HRABAC_inv1`: `inv1.tla` & `inv1.cfg` — Formal verification of **Invariant 1 (Privilege Integrity)**.
*   `ZTA_HRABAC_inv2`: `inv2.tla` & `inv2.cfg`  — Formal verification of **Invariant 2 (Signature Non-Repudiation)**.
*   `ZTA_HRABAC_inv3`: `inv3.tla` & `inv3.cfg`  — Formal verification of **Invariant 3 (Audit Log Tamper-Resistance)**.
*   `ZTA_HRABAC_inv1`: `inv4.tla` & `inv4.cfg` — Formal verification of **Invariant 4 (Bounded Trust Autonomy)**.

---

## How to Run the Verification Online

You can replicate the exact mathematical proofs and state-space exploration results directly in your web browser without installing any local dependencies.

### Step-by-Step Instructions:

1.  Open the web-based [TLA+ Playground](https://learning.tlapl.us/intro/platform/).
2.  For the invariant you wish to test, open the corresponding `.tla` file from this repository, copy its entire contents, and paste them into the **`inv1.tla`** tab in the playground.
3.  Open the corresponding `.cfg` file, copy its contents, and paste them into the **`inv1.cfg`** tab in the playground.
4.  Click the **▶ Run TLC** button located at the top right of the interface.

---

## Expected Verification Results

When executing the models, the TLC Model Checker will exhaustively traverse all state transitions (including simulated database injections, server compromises, and administrative log purges) to guarantee that no safety violations occur. 

The models terminate successfully with **Exit Code: 0 (0 errors detected)** under the following parameters:

### 1. Invariant 1: Privilege Integrity
*   **Property:** Proves that off-chain database mutations cannot compromise on-chain access controls.
*   **Result:** 16 distinct states generated.

### 2. Invariant 2: Signature Non-Repudiation
*   **Property:** Proves that a compromised central bank server ($K_{server}$) cannot forge a valid transaction without interactive multi-party computation from the user's isolated hardware ($K_{client}$).
*   **Result:** 1 distinct initial state, evaluated in ~3 seconds.

### 3. Invariant 3: Audit Log Tamper-Resistance
*   **Property:** Proves that internal rogue administrative purges on off-chain systems cannot alter or destroy the chronological append-only blockchain ledger.
*   **Result:** 1 distinct initial state, evaluated in ~8 seconds.

### 4. Invariant 4: Bounded Trust Autonomy
*   **Property:** Proves that sessions are bounded to active, verification or limited modes under AI failures
*   **Result:** 1 distinct initial state, evaluated in ~6 seconds.

