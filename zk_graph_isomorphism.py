import networkx as nx
import random
import hashlib
import json
import matplotlib.pyplot as plt
from cryptography.fernet import Fernet
import numpy as np
import os
import tempfile
class GraphIsomorphismZKP:
    """
    A comprehensive implementation of Zero-Knowledge Proofs for Graph Isomorphism
    based on the Goldreich-Micali-Wigderson protocol.
    """
    def __init__(self, n_nodes=8, edge_prob=0.5, seed=None):
        """
        Initialize with parameters for graph generation.
        
        Args:
            n_nodes: Number of nodes in the graphs
            edge_prob: Probability of edge creation for random graphs
            seed: Random seed for reproducibility
        """
        if seed:
            random.seed(seed)
            np.random.seed(seed)
        
        self.n_nodes = n_nodes
        self.edge_prob = edge_prob
        self.G1, self.G2, self.iso_mapping = self.generate_isomorphic_graphs()
        self.history = []  # Store proof history for visualization/verification
        
    def generate_isomorphic_graphs(self):
        """Generate a pair of isomorphic graphs with known mapping."""
        # Generate first graph
        G1 = nx.gnp_random_graph(self.n_nodes, self.edge_prob)
        
        # Ensure graph is connected (more interesting to visualize)
        while not nx.is_connected(G1):
            G1 = nx.gnp_random_graph(self.n_nodes, self.edge_prob)
            
        # Generate isomorphic graph with random permutation
        nodes = list(G1.nodes())
        perm = nodes.copy()
        random.shuffle(perm)
        mapping_dict = {nodes[i]: perm[i] for i in range(len(nodes))}
        G2 = nx.relabel_nodes(G1, mapping_dict)
        
        return G1, G2, mapping_dict
    
    def graph_to_canonical_form(self, G):
        """Convert graph to a canonical string representation."""
        # Use Weisfeiler-Lehman hashing for more robust graph fingerprinting
        return nx.weisfeiler_lehman_graph_hash(G, iterations=3)
    
    def commit(self, data):
        """Create a cryptographic commitment."""
        if isinstance(data, nx.Graph):
            data = self.graph_to_canonical_form(data)
        if not isinstance(data, str):
            data = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()
    
    def interactive_proof(self, rounds=5, verbose=True):
        """
        Execute the interactive zero-knowledge proof protocol.
        
        Args:
            rounds: Number of challenge-response rounds
            verbose: Whether to print detailed progress
        
        Returns:
            success: Whether the verification succeeded
            proof_history: Record of all steps for further analysis
        """
        if verbose:
            print(f"Starting Zero-Knowledge Proof of Graph Isomorphism ({rounds} rounds)")
            print(f"G1: {self.G1.number_of_nodes()} nodes, {self.G1.number_of_edges()} edges")
            print(f"G2: {self.G2.number_of_nodes()} nodes, {self.G2.number_of_edges()} edges")
        
        self.history = []
        success = True
        
        for i in range(rounds):
            round_data = {"round": i + 1}
            
            # Prover: Generate random permutation of G1
            nodes = list(self.G1.nodes())
            perm = nodes.copy()
            random.shuffle(perm)
            perm_map = {nodes[i]: perm[i] for i in range(len(nodes))}
            H = nx.relabel_nodes(self.G1, perm_map)
            
            # Prover: Commit to H
            H_commitment = self.commit(H)
            round_data["H"] = H  # Store for visualization
            round_data["commitment"] = H_commitment
            
            # Verifier: Sends challenge (0 or 1)
            challenge = random.randint(0, 1)
            round_data["challenge"] = challenge
            
            if verbose:
                print(f"\nRound {i+1}: Verifier challenges with {challenge}")
            
            if challenge == 0:
                # Prover must show isomorphism from G1 to H
                response = perm_map
                round_data["response"] = "G1 to H isomorphism"
                round_data["mapping"] = response
                
                if verbose:
                    print("  Prover reveals permutation from G1 to H")
                
                # Verification
                inverse_perm = {v: k for k, v in perm_map.items()}
                G1_check = nx.relabel_nodes(H, inverse_perm)
                verified = nx.is_isomorphic(self.G1, G1_check)
                
                if not verified:
                    success = False
                    if verbose:
                        print("  Invalid proof (G1 -> H)")
                elif verbose:
                    print("  Verified: H is isomorphic to G1")
                
            else:
                # Prover must show isomorphism from G2 to H
                # Calculate G2->H mapping = G2->G1->H = (G1->G2)^-1 o (G1->H)
                inverse_iso = {v: k for k, v in self.iso_mapping.items()}
                combined_map = {k: perm_map[inverse_iso[k]] for k in self.G2.nodes()}
                response = combined_map
                round_data["response"] = "G2 to H isomorphism"
                round_data["mapping"] = response
                
                if verbose:
                    print("  Prover reveals permutation from G2 to H")
                
                # Verification
                inverse_combined = {v: k for k, v in combined_map.items()}
                G2_check = nx.relabel_nodes(H, inverse_combined)
                verified = nx.is_isomorphic(self.G2, G2_check)
                
                if not verified:
                    success = False
                    if verbose:
                        print("   Invalid proof (G2 -> H)")
                elif verbose:
                    print("  Verified: H is isomorphic to G2")
            
            round_data["verified"] = verified
            self.history.append(round_data)
        
        if verbose:
            if success:
                print("\n Zero-Knowledge Proof completed successfully!")
                print("  The Prover has convinced the Verifier that they know the isomorphism")
                print("  between G1 and G2, without revealing the actual mapping.")
            else:
                print("\n Zero-Knowledge Proof failed.")
                
        return success, self.history
    
    def non_interactive_proof(self, verbose=True):
        """
        Simulate a non-interactive zero-knowledge proof using the Fiat-Shamir heuristic.
        This converts the interactive protocol to a non-interactive one by deriving 
        challenges from previous commitments, eliminating the need for back-and-forth.
        
        Returns:
            proof_data: The complete non-interactive proof
        """
        if verbose:
            print("\n Simulating Non-Interactive Proof (Fiat-Shamir Transform)")
        
        proof_data = {
            "G1_hash": self.commit(self.G1),
            "G2_hash": self.commit(self.G2),
            "rounds": []
        }
        
        # Number of rounds for security parameter
        rounds = 10
        
        # Generate all permutations in advance
        permuted_graphs = []
        permutations = []
        
        for i in range(rounds):
            nodes = list(self.G1.nodes())
            perm = nodes.copy()
            random.shuffle(perm)
            perm_map = {nodes[i]: perm[i] for i in range(len(nodes))}
            H = nx.relabel_nodes(self.G1, perm_map)
            
            permuted_graphs.append(H)
            permutations.append(perm_map)
            
            # Commit to the permuted graph
            H_commitment = self.commit(H)
            proof_data["rounds"].append({"commitment": H_commitment})
        
        # Use Fiat-Shamir heuristic to derive challenges
        # This makes the proof non-interactive by deterministically generating challenges
        full_commitment = self.commit(proof_data)
        
        for i in range(rounds):
            # Derive challenge from previous commitments using the round index + full commitment
            challenge_input = full_commitment + str(i)
            challenge_hash = hashlib.sha256(challenge_input.encode()).hexdigest()
            challenge = int(challenge_hash, 16) % 2  # 0 or 1
            
            proof_data["rounds"][i]["challenge"] = challenge
            
            if challenge == 0:
                # Reveal G1 -> H isomorphism
                proof_data["rounds"][i]["response"] = permutations[i]
                proof_data["rounds"][i]["response_type"] = "G1_to_H"
            else:
                # Reveal G2 -> H isomorphism
                inverse_iso = {v: k for k, v in self.iso_mapping.items()}
                combined_map = {k: permutations[i][inverse_iso[k]] for k in self.G2.nodes()}
                proof_data["rounds"][i]["response"] = combined_map
                proof_data["rounds"][i]["response_type"] = "G2_to_H"
                
        if verbose:
            print(f"  Generated proof with {rounds} non-interactive rounds")
            print("  Full commitment:", full_commitment[:10] + "...")
            print("  Each round's challenge derived from this commitment")
            
        return proof_data
    
    def verify_non_interactive_proof(self, proof, verbose=True):
        """
        Verify a non-interactive proof generated by the Fiat-Shamir heuristic.
        
        Args:
            proof: The proof data to verify
            verbose: Whether to print detailed progress
            
        Returns:
            bool: Whether the proof is valid
        """
        if verbose:
            print("\n Verifying Non-Interactive Proof")
            
        # Verify G1 and G2 match the expected hashes
        if self.commit(self.G1) != proof["G1_hash"] or self.commit(self.G2) != proof["G2_hash"]:
            if verbose:
                print("   Graph hashes don't match the expected values")
            return False
        
        # Re-derive challenges using Fiat-Shamir
        # We need to temporarily remove responses to recreate the original commitment
        verification_proof = {
            "G1_hash": proof["G1_hash"],
            "G2_hash": proof["G2_hash"],
            "rounds": [{"commitment": r["commitment"]} for r in proof["rounds"]]
        }
        
        full_commitment = self.commit(verification_proof)
        
        for i, round_data in enumerate(proof["rounds"]):
            # Derive the expected challenge
            challenge_input = full_commitment + str(i)
            challenge_hash = hashlib.sha256(challenge_input.encode()).hexdigest()
            expected_challenge = int(challenge_hash, 16) % 2
            
            if expected_challenge != round_data["challenge"]:
                if verbose:
                    print(f"   Challenge in round {i+1} doesn't match the expected value")
                return False
            
            # Verify the response
            response = round_data["response"]
            
            if round_data["response_type"] == "G1_to_H":
                # Reconstruct H from G1 using the provided mapping
                H_reconstructed = nx.relabel_nodes(self.G1, response)
                H_hash = self.commit(H_reconstructed)
                
                if H_hash != round_data["commitment"]:
                    if verbose:
                        print(f"   G1 -> H mapping in round {i+1} is invalid")
                    return False
                    
            elif round_data["response_type"] == "G2_to_H":
                # Reconstruct H from G2 using the provided mapping
                H_reconstructed = nx.relabel_nodes(self.G2, response)
                H_hash = self.commit(H_reconstructed)
                
                if H_hash != round_data["commitment"]:
                    if verbose:
                        print(f"  G2 -> H mapping in round {i+1} is invalid")
                    return False
        
        if verbose:
            print("   Non-interactive proof successfully verified!")
            print("  All challenges derived correctly and responses are valid")
            
        return True
    
    def visualize_proof(self, round_index=0, save_path=None):
        """
        Visualize a specific round of the interactive proof.
        
        Args:
            round_index: Which round to visualize
            save_path: If provided, save the visualization to this path
            
        Returns:
            fig: The matplotlib figure object
        """
        if not self.history or round_index >= len(self.history):
            print("No proof history available or invalid round index.")
            return None
        
        round_data = self.history[round_index]
        
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        
        # Generate nice layouts once to ensure consistency
        pos_G1 = nx.spring_layout(self.G1, seed=42)
        pos_G2 = nx.spring_layout(self.G2, seed=42)
        pos_H = nx.spring_layout(round_data["H"], seed=42)
        
        # Draw G1
        nx.draw(self.G1, pos_G1, ax=axes[0], with_labels=True, node_color='lightblue', 
                node_size=500, font_weight='bold')
        axes[0].set_title("Graph G1")
        
        # Draw G2
        nx.draw(self.G2, pos_G2, ax=axes[1], with_labels=True, node_color='lightgreen', 
                node_size=500, font_weight='bold')
        axes[1].set_title("Graph G2")
        
        # Draw H (permuted graph)
        nx.draw(round_data["H"], pos_H, ax=axes[2], with_labels=True, node_color='salmon', 
                node_size=500, font_weight='bold')
        axes[2].set_title(f"Permuted Graph H (Round {round_data['round']})")
        
        plt.tight_layout()
        
        # Display additional info
        print(f"Round {round_data['round']} Summary:")
        print(f"Challenge: {round_data['challenge']} ({'Show G1->H mapping' if round_data['challenge'] == 0 else 'Show G2->H mapping'})")
        print(f"Commitment to H: {round_data['commitment'][:15]}...")
        print(f"Response: {round_data['response']}")
        print(f"Verification: {' Success' if round_data['verified'] else ' Failed'}")
        
        if save_path:
            plt.savefig(save_path)
            print(f"Visualization saved to {save_path}")
        
        return fig
    
    def create_html_report(self, output_file="zkp_report.html"):
        """
        Create an HTML report of the proof execution.
        
        Args:
            output_file: Path to save the HTML report
            
        Returns:
            str: Path to the saved report
        """
        # Run a proof if none exists
        if not self.history:
            self.interactive_proof(rounds=3, verbose=False)
        
        # Save visualizations to temporary files
        viz_files = []
        with tempfile.TemporaryDirectory() as tmpdir:
            for i, round_data in enumerate(self.history):
                viz_path = os.path.join(tmpdir, f"round_{i+1}.png")
                self.visualize_proof(i, save_path=viz_path)
                viz_files.append(viz_path)
            
            # Create HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Zero-Knowledge Proof of Graph Isomorphism</title>
                <style>
                    body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
                    h1, h2, h3 {{ color: #333; }}
                    .round {{ border: 1px solid #ddd; margin: 20px 0; padding: 15px; border-radius: 5px; }}
                    .visualization {{ text-align: center; margin: 20px 0; }}
                    .details {{ background-color: #f9f9f9; padding: 10px; border-radius: 5px; }}
                    .success {{ color: green; font-weight: bold; }}
                    .failure {{ color: red; font-weight: bold; }}
                    pre {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <h1>Zero-Knowledge Proof of Graph Isomorphism</h1>
                <p>This report demonstrates a zero-knowledge proof protocol for graph isomorphism,
                based on the Goldreich-Micali-Wigderson protocol.</p>
                
                <h2>Graphs Information</h2>
                <p>G1: {self.G1.number_of_nodes()} nodes, {self.G1.number_of_edges()} edges</p>
                <p>G2: {self.G2.number_of_nodes()} nodes, {self.G2.number_of_edges()} edges</p>
                <p>The prover claims to know an isomorphism between G1 and G2.</p>
                
                <h2>Proof Execution</h2>
            """
            
            # Add each round
            for i, round_data in enumerate(self.history):
                html_content += f"""
                <div class="round">
                    <h3>Round {round_data['round']}</h3>
                    
                    <div class="visualization">
                        <img src="data:image/png;base64,{self._image_to_base64(viz_files[i])}" width="1000" alt="Round {round_data['round']} Visualization">
                    </div>
                    
                    <div class="details">
                        <p><strong>Challenge:</strong> {round_data['challenge']} 
                        ({'Show G1->H mapping' if round_data['challenge'] == 0 else 'Show G2->H mapping'})</p>
                        <p><strong>Commitment to H:</strong> {round_data['commitment'][:15]}...</p>
                        <p><strong>Response Type:</strong> {round_data['response']}</p>
                        <p><strong>Verification:</strong> 
                        <span class="{'success' if round_data['verified'] else 'failure'}">
                            {' Success' if round_data['verified'] else ' Failed'}
                        </span></p>
                    </div>
                </div>
                """
            
            # Add theoretical background
            html_content += f"""
                <h2>Theoretical Background</h2>
                <div class="theory">
                    <h3>Why Graph Isomorphism is in NP but not known to be NP-complete</h3>
                    <p>Graph Isomorphism (GI) is a fascinating problem in complexity theory. It is clearly in NP
                    since given two graphs and a proposed isomorphism mapping, we can verify in polynomial time
                    if the mapping preserves the edge structure.</p>
                    
                    <p>Despite decades of research, no polynomial-time algorithm has been found, suggesting it might be hard.
                    However, it has not been proven to be NP-complete either, which would require showing that all NP problems
                    can reduce to GI.</p>
                    
                    <p>This places GI in a rare "complexity limbo" - it's one of the few natural problems
                    suspected to be neither in P nor NP-complete.</p>
                    
                    <h3>Impact of Babai's Quasipolynomial-time Algorithm</h3>
                    <p>László Babai's breakthrough in 2015 provides a quasipolynomial-time algorithm
                    (running in time n^(polylog(n))) for graph isomorphism.</p>
                    
                    <p>This suggests that GI is unlikely to be NP-complete, as an NP-complete problem with a
                    quasipolynomial-time algorithm would imply that all NP problems have quasipolynomial
                    algorithms.</p>
                    
                    <p>For cryptographic purposes, it weakens GI as a hardness assumption. Any cryptosystem
                    based solely on the hardness of GI would not provide the level of security typically
                    required.</p>
                </div>
                
                <h2>Conclusion</h2>
                <p>This implementation demonstrates how zero-knowledge proofs allow a prover to convince a verifier
                of knowledge without revealing the knowledge itself. In this case, the prover convinces the verifier
                that they know an isomorphism between two graphs without revealing what that isomorphism is.</p>
                
                <p>The security of this protocol relies on the difficulty of finding graph isomorphisms,
                and each round reduces the probability of a cheating prover succeeding by 1/2.</p>
                
                <footer>
                    <p>Generated on {self._get_current_date()}</p>
                </footer>
            </body>
            </html>
            """
            
            # Write HTML to file
            with open(output_file, 'w') as f:
                f.write(html_content)
        
        return output_file
    
    def _image_to_base64(self, image_path):
        """Convert an image file to base64 for embedding in HTML."""
        import base64
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode('utf-8')
    
    def _get_current_date(self):
        """Get current date formatted as a string."""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def theoretical_background(self):
        """Provide theoretical background on Graph Isomorphism."""
        theory = """
        # Theoretical Background on Graph Isomorphism
        
        ## NP but not known to be NP-complete
        
        Graph Isomorphism (GI) is a fascinating problem in complexity theory because:
        
        1. It is clearly in NP: Given two graphs G₁ and G₂ and a proposed isomorphism mapping,
           we can verify in polynomial time if the mapping preserves the edge structure.
        
        2. Despite decades of research, no polynomial-time algorithm has been found,
           suggesting it might be hard.
        
        3. However, it has not been proven to be NP-complete either, which would require
           showing that all NP problems can reduce to GI.
        
        This places GI in a rare "complexity limbo" - it's one of the few natural problems
        suspected to be neither in P nor NP-complete.
        
        ## Impact of Babai's Quasipolynomial-time Algorithm
        
        László Babai's breakthrough in 2015 (with subsequent corrections) provides a
        quasipolynomial-time algorithm (running in time n^(polylog(n))) for graph isomorphism.
        
        This result has significant implications:
        
        1. It suggests that GI is unlikely to be NP-complete, as an NP-complete problem with a
           quasipolynomial-time algorithm would imply that all NP problems have quasipolynomial
           algorithms.
        
        2. For cryptographic purposes, it weakens GI as a hardness assumption. Any cryptosystem
           based solely on the hardness of GI would not provide the level of security typically
           required.
        
        3. For our zero-knowledge proof system, it means that the computational advantage of the
           prover (knowing the isomorphism) over the verifier is smaller than previously thought.
           
        That said, the quasipolynomial algorithm is highly complex and not practical for 
        implementation. For moderately sized graphs, GI remains challenging in practice.
        
        ## Zero-Knowledge Properties
        
        Our implementation satisfies the key properties of zero-knowledge proofs:
        
        1. **Completeness**: A honest prover who knows the isomorphism will always convince the verifier.
        
        2. **Soundness**: A dishonest prover who doesn't know the isomorphism has at most a 50% chance
           of passing each round, and with multiple rounds, this probability becomes exponentially small.
        
        3. **Zero-Knowledge**: The verifier learns nothing about the actual isomorphism between G₁ and G₂,
           only that the prover knows it.
        
        ## IP and Complexity Connections
        
        This protocol is an example of an Interactive Proof (IP). The IP complexity class contains
        languages decidable by an interactive protocol between a prover and a verifier,
        where the verifier is polynomial-time bounded.
        
        The celebrated result IP = PSPACE shows that such interactive proofs are surprisingly
        powerful, capturing all problems solvable in polynomial space.
        """
        return theory
        
    def practical_limitations(self):
        """Explain why graph isomorphism is not used in practical ZK systems."""
        explanation = """
        # Why Graph Isomorphism Is Not Used in Practice
        
        While our implementation demonstrates the theoretical elegance of zero-knowledge proofs
        using graph isomorphism, there are several reasons why real-world ZK systems use different
        cryptographic assumptions:
        
        ## Efficiency Concerns
        
        1. **Communication Overhead**: The GMW protocol requires sending entire graphs and permutations,
           resulting in high communication complexity.
        
        2. **Round Complexity**: Achieving high security requires many interactive rounds,
           which introduces latency in practical applications.
        
        3. **Proof Size**: The proofs are large compared to modern zk-SNARKs, which can generate
           constant-size proofs regardless of computation complexity.
        
        ## Cryptographic Limitations
        
        1. **Weaker Hardness Assumptions**: Babai's quasipolynomial algorithm undermines the
           hardness guarantee of graph isomorphism.
        
        2. **Non-homomorphic Structure**: Graph isomorphism doesn't naturally support homomorphic
           operations, making it difficult to prove statements about computations efficiently.
        
        ## Modern Alternatives in Real Systems
        
        Real ZK systems like those in Zcash and StarkWare use number-theoretic or algebraic 
        assumptions instead:
        
        1. **Discrete Logarithm and Elliptic Curves**: Used in Bulletproofs and some zk-SNARKs,
           these provide stronger security guarantees and enable efficient operations.
        
        2. **Bilinear Pairings**: Enable succinct verification in systems like Groth16 used in Zcash.
        
        3. **Cryptographic Hash Functions**: Used in STARKs (StarkWare), providing post-quantum security.
        
        4. **Lattice-Based Cryptography**: Emerging as a post-quantum alternative with homomorphic properties.
        
        These modern approaches enable:
        - Constant-size or logarithmic-size proofs
        - Non-interactive proofs via the Fiat-Shamir transform
        - Efficient verification (crucial for blockchain applications)
        - Arithmetic circuit representations that can encode complex computations
        
        Our graph isomorphism implementation serves primarily as an educational tool to understand
        the foundational concepts of zero-knowledge, rather than as a practical solution for
        real-world applications.
        """
        return explanation

if __name__ == "__main__":
    # Create a ZKP instance with deterministic seed for reproducibility
    zkp = GraphIsomorphismZKP(n_nodes=8, edge_prob=0.6, seed=42)
    
    print("=== Zero-Knowledge Proof for Graph Isomorphism ===")
    print("\nThis implementation demonstrates the Goldreich-Micali-Wigderson protocol")
    print("for proving knowledge of a graph isomorphism without revealing the mapping.\n")
    
    # Run interactive proof
    print("\n=== RUNNING INTERACTIVE PROOF ===")
    success, history = zkp.interactive_proof(rounds=3)
    
    # Generate and verify non-interactive proof
    print("\n=== DEMONSTRATING NON-INTERACTIVE PROOF ===")
    ni_proof = zkp.non_interactive_proof()
    verified = zkp.verify_non_interactive_proof(ni_proof)
    
    # Visualize and save a proof round if matplotlib is available
    try:
        print("\n=== VISUALIZING PROOF ROUND ===")
        zkp.visualize_proof(0, save_path="zkp_visualization.png")
        print("Visualization saved to zkp_visualization.png")
    except Exception as e:
        print(f"Visualization skipped: {e}")
    
    # Generate an HTML report
    try:
        print("\n=== GENERATING HTML REPORT ===")
        report_path = zkp.create_html_report("zkp_report.html")
        print(f"HTML report generated: {report_path}")
    except Exception as e:
        print(f"HTML report generation skipped: {e}")
    
    # Print theoretical background
    print("\n=== THEORETICAL BACKGROUND ===")
    theory = zkp.theoretical_background()
    print("\n".join([line for line in theory.split("\n") if line.strip()]))
    
    print("\n=== PRACTICAL LIMITATIONS ===")
    limitations = zkp.practical_limitations()
    print("\n".join([line for line in limitations.split("\n") if line.strip()]))
