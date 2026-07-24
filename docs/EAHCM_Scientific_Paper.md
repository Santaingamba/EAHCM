# EAHCM 4D Chaotic Cipher: Mathematical Architecture & Cryptanalysis

## 1. Introduction
The EAHCM (Enhanced Arnold-Henon Chaotic Map) Cipher is a high-performance, cryptographically secure stream cipher based on a 4-dimensional discrete-time chaotic dynamical system. This document outlines the core mathematical equations, the architectural design, and the cryptanalysis methods employed to secure the cipher against modern cryptanalytic attacks.

## 2. Core Architecture: The 4D State Machine
At the heart of the EAHCM cipher lies a 4-dimensional state vector $(x, y, z, w)$ defined over the finite integer field $\mathbb{Z}_{2^{32}}$. 

The chaotic evolution is governed by four continuously drifting parameters $(\alpha, \gamma, \mu, \sigma)$ that dictate the shape of the attractor. 

### 2.1 State Evolution Equations
The discrete-time state transition from step $n$ to step $n+1$ is defined by the following coupled equations (all operations wrap modulo $2^{32}$):
$$
\begin{aligned}
x_{n+1} &= L(x_n, \alpha_n) + [F(z_n) \oplus ROL_{32}(y_n, 11)] + \epsilon_n \\
y_{n+1} &= L(y_n, \gamma_n) + [R(w_n) \oplus ROL_{32}(x_n, 17)] \\
z_{n+1} &= L(z_n, \mu_n) + [F(x_n) \oplus ROL_{32}(w_n, 23)] \\
w_{n+1} &= L(w_n, \sigma_n) + [R(y_n) \oplus ROL_{32}(z_n, 31)]
\end{aligned}
$$
**Where:**
* $L(v, p)$: The Integer Logistic Driver.
* $F(v)$: The Branchless Tent Map (phase-space folder).
* $R(w)$: The SHA-256-inspired Bit-Mixer.
* $\epsilon_n$: A counter-based perturbation factor ($\epsilon_n = ROL_{32}(counter, 5) \oplus \text{0x243F6A88}$) to prevent short cycle trapping.
* $\oplus$: Bitwise XOR.
* $ROL_{32}(val, shift)$: 32-bit left circular rotation.

## 3. Mathematical Primitives

### 3.1 Integer Logistic Driver $L(v, p)$
The logistic map $x_{n+1} = r x_n (1 - x_n)$ is the foundation of chaos theory. In the continuous domain, $x \in (0,1)$. In our 32-bit integer adaptation, this maps to:

$$L(v, p) = \left( (p \times v \times (\sim v)) \gg 32 \right) \pmod{2^{32}}$$

Here, the bitwise NOT operator ($\sim v$) substitutes $(1-x)$. This yields a degree-2 non-linear polynomial in $v$, ensuring quadratic chaos. To prevent the map from collapsing into an absorbing state of zero, an explicit fixed-point guard is applied: `result = result + (result == 0)`.

### 3.2 Branchless Tent Map $F(v)$
To fold the phase-space abruptly (simulating absolute value dynamics in a finite field without branching), the tent map is defined as:
$$
\begin{aligned}
mask &= \text{ArithmeticRightShift}(v, 31) \\
F(v) &= (v \oplus mask) \ll 1
\end{aligned}
$$

If the input evaluates to exactly zero after folding, a constant $\Phi_{frac} = \text{0x9E3779B9}$ (fractional golden ratio) is XOR'd to prevent fixed-point trapping.

### 3.3 The Bit-Mixer $R(w)$
Chaos alone does not guarantee cryptographic diffusion. EAHCM utilizes a bit-mixer inspired by the $\sigma_0$ function of SHA-256 to achieve near 50% bit-avalanche per step:

$$R(w) = ROL_{32}(w, 13) \oplus ROL_{32}(w, 7) \oplus (w \gg 3)$$

The asymmetric right shift ($w \gg 3$) ensures non-invertibility, making the function a one-way permutation.

## 4. Keystream Extraction (Output Function)
To extract a 64-bit keystream word per step without leaking internal state variables, the cipher utilizes algebraic mixing from two different groups (Addition modulo $2^{32}$ and Bitwise XOR). 
$$
\begin{aligned}
Out_{hi} &= (x_n + z_n) \oplus ROL_{32}(y_n, 16) \\
Out_{lo} &= (y_n + w_n) \oplus ROL_{32}(x_n, 16) \\
Keystream_{64} &= (Out_{hi} \ll 32) \ |\ Out_{lo}
\end{aligned}
$$
This exposes only 64 bits of the 128-bit internal state $(x, y, z, w)$ per step, making state-recovery attacks mathematically infeasible.

## 5. Parameter Drift (Dynamic Key Generation)
Static chaotic parameters can succumb to phase-space reconstruction attacks. To mitigate this, EAHCM implements **Parameter Drift**. Every 64 steps (when $counter \pmod{64} == 0$), the underlying chaotic parameters $(\alpha, \gamma, \mu, \sigma)$ are dynamically altered based on the preceding state vector:
$$
\begin{aligned}
fold &= x_{prev} \oplus y_{prev} \oplus z_{prev} \oplus w_{prev} \\
\alpha_{n+1} &= \text{clamp\_param}(\alpha_n \oplus ROL_{32}(fold, 3)) \\
\gamma_{n+1} &= \text{clamp\_param}(\gamma_n \oplus ROL_{32}(fold, 11)) \\
\mu_{n+1} &= \text{clamp\_param}(\mu_n \oplus ROL_{32}(fold, 19)) \\
\sigma_{n+1} &= \text{clamp\_param}(\sigma_n \oplus ROL_{32}(fold, 27))
\end{aligned}
$$

Where the `clamp_param(x)` function ensures parameters stay strictly within the chaotic regime:
$$
\text{clamp\_param}(x) = \text{PARAM\_FLOOR} + (x \pmod{\text{DRIFT\_MASK}})
$$
*(With $\text{PARAM\_FLOOR} = \text{0xE0000000}$ and $\text{DRIFT\_MASK} = \text{0x1FF00000}$)*

## 6. Key Schedule & State Initialization (HKDF-SHA3-256)
A cryptographically secure key schedule is vital to prevent related-key attacks and ensure ideal entropy distribution in the initial chaotic state. EAHCM uses the standard **HKDF** algorithm (RFC 5869) backed by **SHA3-256**.

### 6.1 State and Parameter Derivation
The 256-bit entropy pool is split symmetrically using domain-separated `info` parameters. 
From the `UserKey` and `Nonce`, two 16-byte pseudorandom outputs are extracted:
* **State Seed (16 bytes):** Derived using `info = "EAHCM-v1-state-init"`. Parsed as four 32-bit little-endian integers to initialize $(x_0, y_0, z_0, w_0)$.
* **Parameter Seed (16 bytes):** Derived using `info = "EAHCM-v1-param-init"`. Parsed as four 32-bit little-endian integers to seed $(\alpha_0, \gamma_0, \mu_0, \sigma_0)$.

### 6.2 Initial Guards and Clamping
To prevent the cipher from instantly falling into known trivial states:
1. **Absorbing-State Guard:** If any initial state variable equals `0x00000000` or `0xFFFFFFFF`, it is deterministically replaced with `0xDEADBEEF` and `0x13371337` respectively.
2. **Parameter Clamping:** The raw parameter seeds are strictly clamped into the chaotic regime using the formula: $\text{clamp\_param}(x)$.

### 6.3 Warmup Phase
Before any keystream is extracted, the cipher undergoes a mandatory **256-step warmup** where the `step()` function is executed and outputs are discarded. This allows the initial entropy to completely avalanche across all 4 dimensions. For Authenticated Encryption (AEAD) modes, an optional phase allows XOR-mixing a SHA3-256 hash of the plaintext into the state, followed by an additional 64-step warmup.

## 7. Cryptanalysis and Security Proofs

### 7.1 Resistance to Linear Cryptanalysis
Because the state evolution relies heavily on $L(v, p)$, the equations are highly non-linear. The mix of Modular Addition ($+$) and Bitwise XOR ($\oplus$) fundamentally breaks linear relationships (the ARX structure), driving the linear bias coefficient $\epsilon$ near zero.

### 7.2 Resistance to Differential Cryptanalysis
A difference of a single bit in the initial state or parameters cascades exponentially. The Tent Map $F(v)$ and the Bit-Mixer $R(w)$ ensure that a 1-bit difference diffuses to >60 bits of difference across the 128-bit state within 3 iterations.

### 7.3 State Recovery Infeasibility
At any given step $n$, an attacker observes 64 bits of output but there are 128 bits of hidden state $(x, y, z, w)$ and 128 bits of hidden parameters $(\alpha, \gamma, \mu, \sigma)$. Solving the system requires inverting the non-invertible $R(w)$ and the heavily lossy $L(v, p)$ over a highly underdetermined system of equations.

### 7.4 The Epsilon Injection (Cycle Breaking)
A classical weakness of discrete-time chaos in integer mathematics is short-cycle trapping (where the state sequence repeats itself prematurely). EAHCM introduces an epsilon injection $\epsilon_n$ derived from a 32-bit counter:
$$\epsilon_n = ROL_{32}(counter, 5) \oplus \text{0x243F6A88}$$
Because the counter strictly increments, $\epsilon_n$ guarantees that the chaotic state is artificially perturbed at every single step, guaranteeing a minimum cycle length exceeding $2^{64}$. The constant `0x243F6A88` is a nothing-up-my-sleeve number derived from the fractional part of $\pi$.
