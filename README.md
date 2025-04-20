Given two graphs $G_1 = (V_1, E_1)$ and $G_2 = (V_2, E_2)$, the Graph Isomorphism (GI) problem conjectures:
> Does there exist a bijection $\phi: V_1 \rightarrow V_2$ such that $\{u, v\} \in E_1 \iff \{\phi(u), \phi(v)\} \in E_2$?

GI is considered to be  in NP but not known to be NP-complete or in P. Babai's breakthrough in 2015 established a quasipolynomial-time algorithm:

$$\text{Time complexity: } n^{O(\log^c n)} \text{ for some constant } c$$

---

### Zero-Knowledge Proof: Soundness and Completeness
Suppose the prover knows an isomorphism $\pi$ such that $G_2 = \pi(G_1)$.
Each round of the GMW protocol follows this pattern:

1. The prover then selects a random permutation $\sigma$, computes $H = \sigma(G_1)$, and commits that value to $H$.
2. The verifier then randomly selects the challenge $b \in \{0, 1\}$.
3. If $b = 0$, the prover reveals $\sigma$, to which the verifier checks whether $H = \sigma(G_1)$.  
   If $b = 1$, the prover reveals $\sigma \circ \pi^{-1}$; to which the verifier checks whether $H = \sigma \circ \pi^{-1}(G_2)$.

### Completeness
When the prover actually knows $\pi$, they can correctly respond to either challenge. This implies that, an honest verifier will always accept:

$$\ \mathbb{P}$$ [\text{Verifier accepts} \mid \text{honest prover}] = 1$$

### Soundness
Without knowledge of $\pi$, the prover can only prepare for one challenge type - not both.  
Therefore, the probability of successful deception in a single round is at most $\frac{1}{2}$. Across $t$ rounds:

$ \mathbb{P}$ $$\text{Cheating prover succeeds in all rounds}] \leq \left(\frac{1}{2}\right)^t$$

For example:  
Using $t = 10$ rounds produces a soundness error no greater than $\frac{1}{1024}$


For any verifier, there exists a simulator capable of producing transcripts indistinguishable from real protocol executions by:
- Generating a random $H$
- Anticipating a challenge $b$
- Revealing the appropriate permutation

Since the simulator requires no knowledge of the actual isomorphism, this satisfies the zero-knowledge property.

### Fiat-Shamir Heuristic (Non-Interactive)
To eliminate interaction requirements, the verifier's challenge can be substituted for with:

$$b = \text{SHA-256}(\text{commitment} \parallel \text{round index}) \pmod 2$$

This approach makes the proof independently verifiable offline, assuming the hash function behaves as a random oracle.

---

### Complexity Summary
| Aspect               | Python               | C++                   |
|----------------------|----------------------|------------------------|
| Graph size           | $n$ nodes        | $n$ nodes          |
| Time per round       | $O(n^2)$         | $O(n^2)$           |
| Commitment           | SHA-256 / hashing    | Custom SHA-256         |
| Total proof time     | $O(tn^2)$        | $O(tn^2)$          |
| Soundness error      | $2^{-t}$         | $2^{-t}$           |
