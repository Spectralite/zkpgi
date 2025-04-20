// zk_graph_isomorphism.cpp
// Advanced C++ ZKP Visual + GUI + Report Version (T3)

#include <iostream>
#include <vector>
#include <unordered_map>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
// #include <openssl/sha.h>  // Replaced with pure C++ SHA-256 implementation
#include <cstdlib>

class GraphIsomorphismZKP {
public:
    GraphIsomorphismZKP(int n_nodes = 8, double edge_prob = 0.5, int seed = 0)
        : n_nodes(n_nodes), edge_prob(edge_prob) {
        if (seed != 0) {
            rng.seed(seed);
        } else {
            rng.seed(std::chrono::system_clock::now().time_since_epoch().count());
        }
        G1 = generate_connected_graph();
        generate_isomorphic_graph();
    }

    bool interactive_proof(int rounds = 5, bool verbose = true) {
        if (verbose) {
            std::cout << "Starting ZK Proof for Graph Isomorphism (" << rounds << " rounds)\n";
        }
        proof_history.clear();

        for (int round = 0; round < rounds; ++round) {
            std::unordered_map<int, int> perm = random_permutation();
            auto H = relabel_graph(G1, perm);
            std::string commitment = sha256(serialize_graph(H));

            int challenge = rand() % 2;
            bool verified = false;
            std::string response_type;

            if (challenge == 0) {
                auto G1_check = relabel_graph(H, inverse_map(perm));
                verified = is_isomorphic(G1, G1_check);
                response_type = "G1 -> H";
            } else {
                auto G2_to_G1 = inverse_map(iso_mapping);
                std::unordered_map<int, int> G2_to_H;
                for (int i = 0; i < n_nodes; ++i)
                    G2_to_H[i] = perm[G2_to_G1[i]];
                auto G2_check = relabel_graph(H, inverse_map(G2_to_H));
                verified = is_isomorphic(G2, G2_check);
                response_type = "G2 -> H";
            }

            proof_history.push_back({ round + 1, challenge, commitment, response_type, verified, H });

            if (!verified) return false;
        }

        return true;
    }

    void export_graph_to_dot(const std::vector<std::vector<bool>>& G, const std::string& path) {
        std::ofstream ofs(path);
        ofs << "graph G {\n";
        for (int i = 0; i < n_nodes; ++i)
            ofs << "  " << i << ";\n";
        for (int i = 0; i < n_nodes; ++i) {
            for (int j = i + 1; j < n_nodes; ++j) {
                if (G[i][j])
                    ofs << "  " << i << " -- " << j << ";\n";
            }
        }
        ofs << "}\n";
    }

    void export_svg_from_dot(const std::string& dot_path, const std::string& svg_path) {
        std::string command = "dot -Tsvg " + dot_path + " -o " + svg_path;
        std::system(command.c_str());
    }

    std::string encode_file_base64(const std::string& filepath) {
        std::ifstream ifs(filepath, std::ios::binary);
        std::ostringstream oss;
        oss << ifs.rdbuf();
        std::string raw = oss.str();
        static const char* base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
        int val = 0, valb = -6;
        for (unsigned char c : raw) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                result.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        while (result.size() % 4) result.push_back('=');
        return result;
    }

    void generate_html_report(const std::string& output_file) {
        std::filesystem::create_directory("graphviz_output");
        for (size_t i = 0; i < proof_history.size(); ++i) {
            auto& round = proof_history[i];
            std::string dot_path = "graphviz_output/round_" + std::to_string(i) + ".dot";
            std::string svg_path = "graphviz_output/round_" + std::to_string(i) + ".svg";
            export_graph_to_dot(round.H, dot_path);
            export_svg_from_dot(dot_path, svg_path);
        }

        std::ofstream html(output_file);
        html << "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>ZKP Report</title></head><body>\n";
        html << "<h1>Zero-Knowledge Proof Report</h1><hr/>\n";
        for (size_t i = 0; i < proof_history.size(); ++i) {
            auto& r = proof_history[i];
            std::string svg_b64 = encode_file_base64("graphviz_output/round_" + std::to_string(i) + ".svg");
            html << "<div><h2>Round " << r.round << "</h2>\n";
            html << "<p><b>Challenge:</b> " << r.challenge << "</p>\n";
            html << "<p><b>Commitment:</b> " << r.commitment.substr(0, 16) << "...</p>\n";
            html << "<p><b>Response:</b> " << r.response_type << "</p>\n";
            html << "<p><b>Status:</b> " << (r.verified ? "<span style='color:green'>Verified</span>" : "<span style='color:red'>Failed</span>") << "</p>\n";
            html << "<img src='data:image/svg+xml;base64," << svg_b64 << "' width='600'/></div><hr/>\n";
        }
        html << "</body></html>\n";
    }

private:
    int n_nodes;
    double edge_prob;
    std::vector<std::vector<bool>> G1, G2;
    std::unordered_map<int, int> iso_mapping;
    std::mt19937 rng;

    struct RoundData {
        int round;
        int challenge;
        std::string commitment;
        std::string response_type;
        bool verified;
        std::vector<std::vector<bool>> H;
    };

    std::vector<RoundData> proof_history;

    std::vector<std::vector<bool>> generate_connected_graph() {
        std::bernoulli_distribution edge(edge_prob);
        std::vector<std::vector<bool>> G(n_nodes, std::vector<bool>(n_nodes, false));
        std::vector<int> nodes(n_nodes);
        std::iota(nodes.begin(), nodes.end(), 0);
        std::shuffle(nodes.begin(), nodes.end(), rng);
        for (int i = 1; i < n_nodes; ++i) {
            int u = nodes[i];
            int v = nodes[rand() % i];
            G[u][v] = G[v][u] = true;
        }
        for (int i = 0; i < n_nodes; ++i) {
            for (int j = i + 1; j < n_nodes; ++j) {
                if (!G[i][j] && edge(rng)) {
                    G[i][j] = G[j][i] = true;
                }
            }
        }
        return G;
    }

    void generate_isomorphic_graph() {
        auto perm = random_permutation();
        iso_mapping = perm;
        G2 = relabel_graph(G1, perm);
    }

    std::unordered_map<int, int> random_permutation() {
        std::vector<int> nodes(n_nodes);
        std::iota(nodes.begin(), nodes.end(), 0);
        std::shuffle(nodes.begin(), nodes.end(), rng);
        std::unordered_map<int, int> perm;
        for (int i = 0; i < n_nodes; ++i)
            perm[i] = nodes[i];
        return perm;
    }

    std::unordered_map<int, int> inverse_map(const std::unordered_map<int, int>& m) {
        std::unordered_map<int, int> inv;
        for (const auto& p : m)
            inv[p.second] = p.first;
        return inv;
    }

    std::vector<std::vector<bool>> relabel_graph(const std::vector<std::vector<bool>>& G, const std::unordered_map<int, int>& mapping) {
        std::vector<std::vector<bool>> newG(n_nodes, std::vector<bool>(n_nodes, false));
        for (int i = 0; i < n_nodes; ++i) {
            for (int j = 0; j < n_nodes; ++j) {
                if (G[i][j]) {
                    int u = mapping.at(i);
                    int v = mapping.at(j);
                    newG[u][v] = true;
                }
            }
        }
        return newG;
    }

    bool is_isomorphic(const std::vector<std::vector<bool>>& A, const std::vector<std::vector<bool>>& B) {
        return A == B;
    }

    std::string serialize_graph(const std::vector<std::vector<bool>>& G) {
        std::ostringstream oss;
        for (const auto& row : G)
            for (bool val : row)
                oss << val;
        return oss.str();
    }

    std::string sha256(const std::string& data) {
    uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
        0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
        0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
        0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
        0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
        0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    auto rightRotate = [](uint32_t value, unsigned int count) -> uint32_t {
        return (value >> count) | (value << (32 - count));
    };

    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    std::vector<uint8_t> bytes(data.begin(), data.end());
    size_t orig_len = bytes.size() * 8;
    bytes.push_back(0x80);
    while ((bytes.size() * 8 + 64) % 512 != 0)
        bytes.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        bytes.push_back((orig_len >> (i * 8)) & 0xFF);

    for (size_t i = 0; i < bytes.size(); i += 64) {
        uint32_t w[64] = {};
        for (int j = 0; j < 16; ++j)
            w[j] = (bytes[i + 4 * j] << 24) | (bytes[i + 4 * j + 1] << 16) |
                   (bytes[i + 4 * j + 2] << 8) | (bytes[i + 4 * j + 3]);
        for (int j = 16; j < 64; ++j) {
            uint32_t s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >> 3);
            uint32_t s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        }

        uint32_t a = h0, b = h1, c = h2, d = h3;
        uint32_t e = h4, f = h5, g = h6, h = h7;
        for (int j = 0; j < 64; ++j) {
            uint32_t S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[j] + w[j];
            uint32_t S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint32_t val : {h0, h1, h2, h3, h4, h5, h6, h7})
        oss << std::setw(8) << val;
    return oss.str();
}
};

int main() {
    GraphIsomorphismZKP zkp(8, 0.6, 42);
    bool success = zkp.interactive_proof(5);
    if (success) {
        zkp.generate_html_report("zkp_report.html");
        std::cout << "Report generated: zkp_report.html\n";
    }
    return 0;
}
