# Network-Telemetry-DDoS-Attack-Characterization

**An end-to-end Machine Learning pipeline for DDoS detection, generalization stress-testing, and unsupervised behavioural profiling on flow-level network telemetry.**

---

## Authors & Equal Contribution

This project was developed jointly at **Politecnico di Torino** (January 2026). All authors contributed equally to the architecture, implementation, and experimental analysis of this pipeline:

| Author | Institutional Email | Personal Email |
| :--- | :--- | :--- |
| **Alessandro Bottazzi** | [s352421@studenti.polito.it](mailto:s352421@studenti.polito.it) | [bottazzi.personale@gmail.com](mailto:bottazzi.personale@gmail.com) 
| **Matteo De Cataldo** | [s360850@studenti.polito.it](mailto:s360850@studenti.polito.it) | [matteo.decataldo@proton.me ](mailto:matteo.decataldo@proton.me  |
| **Federico Capecelatro** | [s351649@studenti.polito.it](mailto:s351649@studenti.polito.it) | [capecelatrofederico@gmail.com](mailto:capecelatrofederico@gmail.com) |
| **Pietro Ala** | [s352318@studenti.polito.it](mailto:s352318@studenti.polito.it) | [ala.pietro63@gmail.com](mailto:ala.pietro63@gmail.com) |

---

## Project Overview

Evaluating Intrusion Detection Systems (IDS) on synthetic network captures often yields deceptively near-perfect metrics due to **temporal data leakage**, **look-ahead bias**, and **deterministic script artifacts**. 

Rather than treating DDoS classification as a static tabular benchmark, this repository implements a four-stage engineering workflow over **~64,240 network flows** spanning **12 traffic classes** (`benign` plus 11 volumetric and amplification DDoS vectors: `ddos_dns`, `ddos_ldap`, `ddos_mssql`, `ddos_netbios`, `ddos_ntp`, `ddos_snmp`, `ddos_ssdp`, `ddos_syn`, `ddos_tftp`, `ddos_udp`, and `ddos_udp_lag`):

1. **Telemetry Fingerprinting & Feature Engineering (`S1`)**: Extracting domain-specific volumetric ratios, amplification factors, and inter-arrival regularity metrics while auditing the feature space via Principal Component Analysis (PCA).
2. **Generalization Stress-Testing & Leakage Auditing (`S2`)**: Benchmarking geometric proximity (**k-Nearest Neighbors**) against hierarchical rule ensembles (**Random Forest**) across **Stratified Random Splits** (interpolation) and **Chronological Temporal Splits** (extrapolation under concept drift), culminating in an ablation study on synthetic temporal shortcuts.
3. **Unsupervised Attack Family Discovery (`S3`)**: Stripping ground-truth labels and protocol identifiers (IPs/ports) to evaluate whether **K-Means** (Euclidean vs. Cosine), **Gaussian Mixture Models (GMM)**, and **DBSCAN** can isolate attack families purely from statistical flow mechanics.
4. **Cluster Explainability & Sub-Attack Profiling (`S4`)**: Implementing an unsupervised **Permutation Importance** framework ($\Delta \text{Silhouette}$ and $1 - \text{ARI}_{\text{perm}}$) to uncover intra-class execution variants (e.g., high-rate bursts vs. low-and-slow throttled floods).

---

## Key Engineering Findings & Dataset Critique

### 1. Synthetic Dataset Audit: The `hour` Shortcut Artifact
A critical vulnerability in many lab-generated DDoS datasets is sequential attack execution. Inspection of the `Timestamp` distribution revealed that the entire capture occurred on a single day (Saturday) within a narrow **5-hour window (09:00–13:00)**. Because attack scenarios were triggered sequentially by class, extracting the `hour` feature created a deterministic proxy for the ground-truth label.
* **Gini Importance Skew**: In Random Forest models trained with `hour`, the feature absorbed **0.1642** (Stratified) and **0.1860** (Temporal) of total Mean Decrease in Impurity (MDI)—nearly double the importance of any genuine network metric.
* **Ablation Impact**: Removing `hour` caused a uniform **~10% global accuracy drop** in k-NN and reduced Temporal Random Forest accuracy from **0.96 to 0.80** (`ddos_udp` F1 dropped to `0.55`, `ddos_udp_lag` to `0.56`, and `ddos_mssql` to `0.65`). Without the timestamp shortcut, the classifier was forced to rely on genuine engineered traffic mechanics (`Bytes_per_Packet`, `Fwd_Bwd_Bytes_Ratio`, `src_port_category`, and packet length distributions).

### 2. Stratified Interpolation vs. Temporal Extrapolation
* **Look-Ahead Leakage in Random Splits**: Standard 70/30 stratified splitting brackets test flows with training flows from the exact same capture window, measuring interpolation rather than operational viability.
* **Concept Drift Exposure**: Enforcing an intra-class 70/30 **Chronological Split** (training on the first 70% "Past" flows, testing on the final 30% "Future" flows) exposed severe concept drift in `ddos_ssdp` under baseline k-NN, where Precision collapsed from **1.00 (Stratified) to 0.72 (Temporal)** as future background/UDP flows drifted into the historical SSDP manifold.
* **The `LDAP` vs. `MSSQL` Entanglement**: Across both validation splits, `ddos_ldap` and `ddos_mssql` occupy a heavily overlapping manifold. Even after tuning k-NN with Manhattan distance ($L_1$, $p=1$), which consistently outperformed Euclidean distance ($L_2$, $p=2$) in this sparse high-dimensional space, k-NN could not disentangle the two vectors. Random Forest axis-aligned hyperplane splits mitigated this overlap, raising `LDAP`/`MSSQL` F1-scores from `0.55` (Temporal k-NN baseline) to `0.84` (Temporal Tuned RF).

### 3. Why Intensity Dominates Protocol Semantics in Unsupervised Clustering
* **Failure of Angular Metrics (Cosine K-Means)**: Applying L2 normalization for Cosine K-Means yielded a near-perfect internal Silhouette score (**0.96** at $k=4$) but failed externally (**ARI = 0.10**). Because Cosine distance is magnitude-invariant, it discards traffic volume—collapsing almost all volumetric DDoS classes into a single undifferentiated cluster.
* **Variable Density Breakdown in DBSCAN**: Because `ddos_ntp` is heavily underrepresented (986 total flows vs. ~5,500–6,000 for other classes), DBSCAN ($\epsilon=1.2, \text{min\\_samples}=500$) classified **100% of `ddos_ntp` traffic as noise (`-1`)**.
* **Behavioral Sub-Attacks (GMM `diag`, $k=15$)**: Unsupervised profiling revealed that flow clustering groups attacks by **execution rate and payload size** rather than Layer-7 protocol semantics:
  * `ddos_syn` (TCP) and `ddos_tftp` (UDP) co-cluster into two distinct behavioral regimes: a **high-speed burst flood** (Cluster 1: low IAT, high Packets/s) and a **throttled/slow variant** (Cluster 7: high IAT, high Idle time).
  * `ddos_udp` and `ddos_udp_lag` split evenly between **low-rate small-packet persistence** (Cluster 2) and **high-speed volumetric flooding** alongside `ddos_snmp` and `ddos_netbios` (Cluster 10).
  * `ddos_ntp` co-clusters with `benign` traffic (Cluster 9) because its small, periodic, protocol-compliant amplification requests closely mimic legitimate background telemetry at the flow level.

---

## Pipeline Architecture & Experimental Summary

### Stage 1: Exploratory Data Analysis & Preprocessing (`S1`)
* **Behavioral Signatures**: Validated amplification factors ($\text{Bytes Received} \gg \text{Bytes Sent}$) on log-log axes and contrasted stochastic human browsing (high IAT mean/variance) against deterministic botnet tight-loops (IAT mean $\to 0$, IAT std $\to 0$)[cite: 1, 3, 23].
* **Engineered Features**:
  * *Volumetric & Asymmetry Ratios* ($\epsilon = 10^{-12}$ smoothing): `MultiplicationFactor`, `Bytes_per_Packet`, `IAT_std_on_mean`, `Fwd_Bwd_Packets_Ratio`, `Fwd_Bwd_Bytes_Ratio`[cite: 1, 3].
  * *Network Categorization*: IANA port binning (`src_port_category`, `dst_port_category` into Well-Known `0–1023`, Registered `1024–49151`, and Ephemeral `49152–65535`) and RFC 1918 private IP flags (`private_src_ip`, `private_dst_ip`)[cite: 1, 2].
* **Dimensionality Cleaning**: Dropped `SimillarHTTP`, 12 zero-variance flag/bulk columns (`Bwd PSH Flags`, `Fwd URG Flags`, `Bwd URG Flags`, `FIN Flag Count`, `PSH Flag Count`, `ECE Flag Count`, `Fwd/Bwd Avg Bytes/Bulk`, `Fwd/Bwd Avg Packets/Bulk`, `Fwd/Bwd Avg Bulk Rate`), and 3 exact duplicate columns (`Subflow Fwd Packets`, `Subflow Bwd Packets`, `Fwd Header Length.1`)[cite: 1, 3, 4].
* **PCA Diagnostic**: Standardized features via `StandardScaler`. The top 2 PCs capture **~31%** of variance, while **20 PCs capture 89.39%** of total variance (used for geometric inspection rather than model compression to preserve feature interpretability)[cite: 1, 4, 24].

### Stage 2: Supervised Classification Benchmark (`S2`)

All hyperparameter searches used `RepeatedStratifiedKFold(n_splits=5, n_repeats=3)`.

| Model & Split Strategy | Configuration | Train F1 (W) | Test Acc | Test F1 (W) | Notable Class Behavior |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **k-NN (Stratified)** | Baseline ($k=5$, `uniform`, $p=2$) | 0.95 | 0.92 | 0.92 | Severe `LDAP` (0.67 F1) & `MSSQL` (0.58 F1) confusion |
| **k-NN (Stratified)** | Tuned ($k=3$, `uniform`, $p=1$) | 0.96 | 0.93 | 0.93 | $L_1$ metric improves sparse contrast; `LDAP`/`MSSQL` overlap persists |
| **k-NN (Temporal)** | Baseline ($k=5$, `uniform`, $p=2$)| 0.95 | 0.90 | 0.89 | `SSDP` Precision drops to 0.72; `LDAP`/`MSSQL` F1 drops to 0.55 |
| **k-NN (Temporal)** | Tuned ($k=3$, `distance`, $p=1$) | 1.00 | 0.93 (CV) | 0.93 (CV) | `distance` weighting stabilizes temporal variance ($\pm 0.0023$)|
| **Random Forest (Stratified)** | Baseline (Default) | 1.00 | 0.96 | 0.96 | `LDAP` & `MSSQL` reach 0.83 F1 |
| **Random Forest (Stratified)** | Tuned (Grid Search) | 0.98 (LC) | 0.97 | 0.97 | Resolves boundary better: `LDAP` (0.87 F1), `MSSQL` (0.86 F1) |
| **Random Forest (Temporal)** | Baseline (Default) | 1.00| 0.90 | 0.90 | Drift in `SNMP` (0.67 Recall), `DNS` (0.73 Prec), `LDAP` (0.76 F1) |
| **Random Forest (Temporal)** | Tuned (`depth` $\in [13,15,20]$, `leaf` $\in [1,4]$) | 0.98 (LC) | 0.96 | 0.96 | Recovers `DNS` (0.99 F1), `SNMP` (1.00 F1), `LDAP`/`MSSQL` (0.84 F1) |
| **RF Ablation (No `hour`)** | Tuned Temporal without `hour` | ~0.87 (LC) | **0.80** | **0.80**| Exposes true difficulty without synthetic timestamp leakage |

### Stage 3 & 4: Unsupervised Clustering & Explainability (`S3` & `S4`)

| Algorithm | Preprocessing / Metric | Optimal Parameters | Clusters Found | Silhouette | ARI (vs. GT) | Structural Summary |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **K-Means** | `StandardScaler` (Euclidean) | $k=9$, `k-means++` (10 init) | 9 | 0.45 | 0.37 | Cleanly separates 3 macro-families + `DNS`; merges `NTP` & `benign` |
| **K-Means** | `normalize(l2)` (Cosine) | $k=4$, `k-means++` | 4 | 0.96 | 0.10 | High angular cohesion, but loses volumetric magnitude |
| **GMM** | `StandardScaler` (Euclidean) | $k=15$, `cv_type='diag'` (50 init) | 15 | 0.42 | **0.38** | Best granularity; isolates Fast vs. Slow sub-attacks |
| **DBSCAN** | `StandardScaler` (Ball-Tree) | $\epsilon=1.2$, `min_samples=500` | 21 (+1 noise) | 0.54| 0.25 | 25% noise ratio; discards 100% of minority `ddos_ntp` class |

* **Unsupervised Feature Importance (`S4`)**: Permuting individual features across 20 iterations demonstrated that **Control Features** (`ACK Flag Count`, `Protocol`, `Inbound`, `src_port_category`) govern **Cluster Stability** ($1 - \text{ARI}_{\text{perm}}$), whereas **Payload Size Features** (`Fwd Packet Length Mean/Max/Min`, `Min Packet Length`, `Bytes_per_Packet`, `Average Packet Size`) govern **Geometric Cohesion** ($\Delta \text{Silhouette}$).

---

---

## Repository Structure

```text
Network-Telemetry-DDoS-Attack-Characterization/
│
├── S1_Data_Visualization.ipynb       # Protocol/port distributions, amplification factor & IAT fingerprinting
├── S1_Feature_Engineering.ipynb      # Ratio features, IP/port categorization, zero-variance & duplicate pruning
├── S1_Preprocessing_PCA.ipynb        # Scree plot, PC1 loadings, 2D projection, and top-5 PC parallel coordinates
│
├── S2_stratified_kNN.ipynb           # k-NN baseline & GridSearchCV on 70/30 Stratified Split
├── S2_timesplit_kNN.ipynb            # k-NN baseline & GridSearchCV on 70/30 Chronological Split
├── S2_randomsplit_RF.ipynb           # Random Forest baseline, validation curves & GridSearchCV (Stratified)
├── S2_timesplit_RF.ipynb             # Random Forest baseline, validation curves & GridSearchCV (Temporal)
├── S2_timesplit_RF_no_hour.ipynb     # Ablation study: Temporal Random Forest removing the 'hour' leakage feature
│
├── S3_Kmeans.ipynb                   # K-Means tuning (k=2..40) comparing Euclidean vs. Cosine distance + UMAP
├── S3_GMM.ipynb                      # Gaussian Mixture Models across spherical, diag, tied, and full covariances
├── S3_DBSCAN.ipynb                   # DBSCAN grid search over eps & min_samples with noise ratio evaluation
│
├── S4_KmeansAnalysis.ipynb           # Permutation importance & intra-cluster/sub-attack profiling for K-Means
├── S4_GMMAnalysis.ipynb              # Permutation importance & intra-cluster/sub-attack profiling for GMM
├── S4_DBSCANAnalysis.ipynb           # Permutation importance & intra-cluster/sub-attack profiling for DBSCAN
│
├── CITATION.cff                      # Formal citation metadata for all four co-authors
├── LICENSE                           # MIT License
└── README.md
