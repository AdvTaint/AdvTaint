# AdvTaint: Bridging Static Analysis and Adversarial LLM Reasoning for Vulnerability Detection

---

## 1. Datasets
The dataset infrastructure is organized into three distinct components:

* **InterPVD** You can download in [here](https://github.com/CGCL-codes/VulTrigger/tree/main/dataset).
We also provide a reference file for reading code ```Dataset/get_code_from_InterPVD.py```

* **ReposVul:** You can download in [here](https://github.com/Eshe0922/ReposVul).
We also provide a reference file for reading code ```Dataset/get_code_from_ReposVul.py```

* **PKCO-2025:** You can download in [here](https://github.com/qcri/llmxcpg/blob/main/data/pkco_test.json).
We also provide the original files and CVE/DIFF in```PKCO-2025```

---

## 2. Requirement
Please check all requirements in ```requirement.txt```

---

## 3. Ollama
We utilize **Ollama** to run localized Large Language Models (LLMs) to ensure data privacy and high-speed inference.

### Setup
1.  **Install Ollama:** Follow the instructions at [ollama.com](https://ollama.com).
2.  **Service Configuration:** Ensure the Ollama server is running (default: `http://localhost:11434`).
    ```bash
    ollama serve
    ```
3.  **Run Required Models:** Run the model like:
    ```bash
    ollama run gpt-oss:20b
    ```

---

## 4. Static Analysis Module
We provide static analysis scripts ```static_analysis/ts_sast.py```

We also provide the .so file(C/C++) ```static_analysis/tree_sitter/build/my-languages.so```

---

## 5. Vulnerability Detection
You can directly run ```AdvTaint.py``` for vulnerability detection. Advtaint is is supported by Langgraph.
### Model Selection
You can change model by altering:
```
vd_superviser = Ollama(model="deepseek-r1:32b", temperature=0,num_ctx=65536,keep_alive='8h',base_url="http://localhost:11434")
```

### Usage (Input/Output)
* **Input:** The path of the code files to be detected
    ```bash
    python AdvTaint.py --input /vultrigger/src_code/vul --output /vultrigger/results
    ```
    or
    ```bash
    python AdvTaint.py --input /vultrigger/src_code/vul/test.c --output ./output
    ```
* **Output:** A detailed vulnerability report including:
    * **Is_Vulnerable:** (NOT) Vulnerable.
    * **Vulnerability Type:** (e.g., Buffer Overflow).
    * **Reasoning:** The RCA of this vulnerability.
    * **Vulnerable Path:** Specific vulnerability path.

---

## 6. Evaluation
We use LLM to automatically evaluate whether the detection results conform to the ground truth.

You need to change the results path and ground truth path

### Vulnerable Results Evaluation
* **Script:** `evaluation/llm_judge_vul.py`
* **Command:** `python eval_vulnerable.py `

### Patched Results Evaluation
* **Script:** `evaluation/llm_judge_novul.py`
* **Command:** `python eval_clean.py `

---
