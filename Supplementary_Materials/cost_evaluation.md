# Tree-sitter based path extraction:
### Average runtime per pair ≈ 0.3s

Lightweight static path extraction does not consume much time, and the time overhead mainly lies in LLM calls.

# For InterPVD(497 pairs)：

## AdvTaint(ours)

### Average number of LLM calls per  pair（2 samples) ≈ 54
### Total cost of LLM calls per pair ≈ $0.7 
(If using a commercial model API like gpt-4o-2024-08-06, Input:$3.75, output:$15)
### Total token consumption of InterPVD ≈ 82,701K   
### Average token consumption per pair ≈ 166.4K
### Average runtime per pair ≈  525s (A100 GPU）


# For RepsVul(996 pairs)

## AdvTaint(ours)

### Total token consumption ≈ 383,495K  
### Average token consumption per pair ≈ 385K

# Cost per KLOC（Comparison with baseline）

## AdvTaint(ours)

### Average number of LLM calls ≈ 80 / KLOC
### Total cost of LLM calls ≈ $1 / KLOC
(If using a commercial model API like gpt-4o-2024-08-06, Input:$3.75, output:$15)
### Average token consumption  ≈ 212.7k / KLOC
### Average runtime ≈  625s (A100 GPU）/ KLOC

## LLMxCPG
LLMxCPG needs fine-tuning, so only the cost evaluation for gptlens, vultrail, and mavul are calculated.

## GPTLens

### Average number of LLM calls ≈ 6 / KLOC
### Total cost of LLM calls ≈ $0.4 / KLOC
(If using a commercial model API like gpt-4o-2024-08-06, Input:$3.75, output:$15)
### Average token consumption  ≈ 38k / KLOC
### Average runtime ≈  326s (A100 GPU）/ KLOC

## VulTrail

### Average number of LLM calls ≈ 30 / KLOC
### Total cost of LLM calls ≈ $1.3 / KLOC
(If using a commercial model API like gpt-4o-2024-08-06, Input:$3.75, output:$15)
### Average token consumption  ≈ 244.1k / KLOC
### Average runtime ≈  946s (A100 GPU）/ KLOC


## MaVUL

### Average number of LLM calls ≈ 139 / KLOC
### Total cost of LLM calls ≈ $2.3 / KLOC
(If using a commercial model API like gpt-4o-2024-08-06, Input:$3.75, output:$15)
### Average token consumption  ≈ 362.3k / KLOC
### Average runtime ≈  3257s (A100 GPU）/ KLOC
