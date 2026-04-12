# Cybertron ML Bootstrap Kit

This directory is the zero-budget path for improving Cybertron's AI behavior without pushing heavy work onto the local laptop.

Current backend AI modules covered here:

- `risk-copilot`
- `compliance`
- `threat-intel`

## What this is

- `export-cybertron-bootstrap-dataset.js`
  - Builds a small supervised fine-tuning dataset from Cybertron's real rule-based and template-based AI fallbacks.
- `build-official-realworld-corpus.js`
  - Pulls official CISA KEV, NVD, and NIST OSCAL data into a larger grounded SFT corpus for threat, risk, and policy tasks.
- `train_cybertron_lora.py`
  - Refuses to train on CPU.
  - Loads only in a CUDA-capable environment such as a Colab GPU runtime.
- `train_h100_lora.sh`
  - H100-friendly wrapper that reuses the host PyTorch install and trains locally.
- `start_vllm_openai_lora.sh`
  - Serves the trained adapter behind an OpenAI-compatible API for Cybertron deployment.
- `requirements-colab.txt`
  - Minimal Colab-side training dependencies.
- `requirements-h100.txt`
  - H100 host dependencies without reinstalling PyTorch.

## What this is not

- This is **not** a production-quality proprietary training corpus.
- This does **not** turn Ollama into a training system.
- This does **not** justify claiming that Cybertron has a custom frontier model.

The exported dataset is a **bootstrap warm-start dataset** generated from Cybertron's own fallback logic. It is useful for:

- prompt-format conditioning
- early LoRA experiments
- eval harnesses
- safe offline regression work

It is **not** a replacement for:

- human-reviewed supervised data
- real customer-approved examples
- formal red-team / hallucination evaluation
- provider-backed production AI validation

## Local-safe workflow

Run the exporter locally:

```powershell
npm run ml:export:bootstrap --prefix workspace
```

Build the larger official-source corpus locally:

```powershell
npm run ml:build:official-corpus --prefix workspace
npm run ml:build:enterprise-corpus --prefix workspace
```

Run the trainer in environment-check mode locally:

```powershell
python workspace/ml/train_cybertron_lora.py `
  --dataset workspace/ml/data/cybertron_bootstrap_sft.jsonl `
  --check-only
```

That check path is safe on this machine. It does not load a model and it does not start CPU training.

## Colab workflow

1. Switch Colab to a GPU runtime.
2. Clone or upload the repo.
3. Install:

```bash
pip install -r workspace/ml/requirements-colab.txt
```

4. Export the dataset if needed:

```bash
node workspace/ml/export-cybertron-bootstrap-dataset.js
```

5. Train a LoRA adapter:

```bash
python workspace/ml/train_cybertron_lora.py \
  --dataset workspace/ml/data/cybertron_training_corpus.jsonl \
  --model-name TinyLlama/TinyLlama-1.1B-Chat-v1.0 \
  --output-dir /content/drive/MyDrive/Cybertron/adapters/bootstrap-risk-policy-threat \
  --max-steps 80
```

Use a small model first. This is a bootstrap experiment, not the final production model.

## Zero-dollar upgrade path with GitHub Student Pack

GitHub Models does not replace training, but it is a strong zero-cash teacher/evaluation layer.

Use it like this:

1. Export the bootstrap dataset locally.
2. Use GitHub Models with your GitHub token to synthesize stronger teacher outputs.
3. Merge bootstrap and teacher rows into a training corpus.
4. Train the adapter on Colab GPU, not on your laptop.

Example:

```powershell
gh auth login
$env:GITHUB_TOKEN = gh auth token
$env:GITHUB_MODELS_MODEL = "openai/gpt-4.1-mini"
npm run ml:github-models:teacher --prefix workspace -- --variants 3
npm run ml:build:corpus --prefix workspace
```

Then point Colab training at:

```text
workspace/ml/data/cybertron_training_corpus.jsonl
```

This corpus is the cheapest honest path for training **all currently exposed Cybertron AI modules** in one multi-task adapter.

## H100 workflow on this machine

If you have a local CUDA server with an H100, use the H100 wrapper instead of the Colab-only flow:

```bash
npm run ml:train:h100 --prefix workspace
```

Default choices:

- base model: `Qwen/Qwen2.5-3B-Instruct` by default, or any stronger public base model you pass through `MODEL_NAME`
- dataset: `workspace/ml/data/cybertron_enterprise_training_corpus.jsonl` when present, else `workspace/ml/data/cybertron_training_corpus.jsonl`, else bootstrap JSONL
- output adapter: `workspace/ml/outputs/cybertron-qwen25-3b-lora`

After training, serve the adapter with a local OpenAI-compatible vLLM endpoint:

```bash
OPENAI_API_KEY=cybertron-local-key npm run ml:serve:vllm --prefix workspace
```

If both `workspace/ml/outputs/cybertron-qwen25-14b-lora` and `workspace/ml/outputs/cybertron-qwen25-3b-lora` exist, the vLLM launcher now prefers the stronger `14B` adapter automatically. Override with `BASE_MODEL` and `ADAPTER_PATH` if you need a specific pair.

Then point Cybertron at it:

```text
LLM_PROVIDER=openai
OPENAI_BASE_URL=http://host.docker.internal:8000/v1
OPENAI_API_KEY=cybertron-local-key
OPENAI_MODEL=cybertron-local
```

This is the best zero-budget split:

- laptop: dataset export, checks, prompt iteration
- GitHub Student Pack: teacher-quality synthetic outputs and prompt iteration
- Colab GPU: actual LoRA fine-tuning

It avoids pretending the Student Pack gives you a guaranteed free GPU for long-running training.

## T4 workflow on this machine

If this machine has a Tesla T4 instead of an H100, keep the H100 flow intact and use the T4 wrapper beside it:

```bash
npm run ml:train:t4 --prefix workspace
```

T4-safe defaults:

- base model: `Qwen/Qwen2.5-1.5B-Instruct`
- output adapter: `workspace/ml/outputs/cybertron-qwen25-1_5b-t4-lora`
- quantization: 4-bit when `bitsandbytes` is available
- sequence length: `512`
- batching: `4 x 4` effective accumulation
- schedule: `80` optimizer steps by default instead of a long full-epoch run
- task balancing: downsample oversized `threat_summary` rows and upsample underrepresented `risk_explanation` / `policy_draft` rows

That balancing step matters because the enterprise corpus is threat-heavy by default. The T4 wrapper keeps one shared adapter focused on all current Cybertron analyst modules instead of letting the vulnerability-summary task dominate training.

To serve the T4 adapter explicitly after training:

```bash
BASE_MODEL=Qwen/Qwen2.5-1.5B-Instruct \
ADAPTER_PATH=workspace/ml/outputs/cybertron-qwen25-1_5b-t4-lora \
OPENAI_API_KEY=cybertron-local-key \
npm run ml:serve:vllm --prefix workspace
```

The T4 launcher also now applies smaller-memory vLLM defaults automatically:

- `--max-model-len 4096`
- `--gpu-memory-utilization 0.82`
- `--max-num-seqs 8`
- `--enforce-eager`

## Train all current Cybertron AI modules

If your goal is to train all current Cybertron AI modules, do **not** train three separate models first. On a zero-dollar budget, the correct move is one shared multi-task adapter trained on the merged corpus:

```text
workspace/ml/data/cybertron_enterprise_training_corpus.jsonl
```

That corpus currently contains:

- `risk_explanation`
- `policy_draft`
- `threat_summary`

The official-source expansion path produces:

- `workspace/ml/data/cybertron_official_realworld_sft.jsonl`
- `workspace/ml/data/cybertron_official_realworld_manifest.json`

These map directly to the current backend AI modules:

- `risk-copilot`
- `compliance`
- `threat-intel`

Train one shared adapter first. Split into specialist adapters only if evaluation later shows one module regresses another.

## Next honest step after bootstrap

Once the adapter path is proven, the higher-value work is:

1. build a human-reviewed eval set
2. capture approved output examples from real Cybertron flows
3. validate them with `npm run ml:validate:reviewed --prefix workspace -- --input ml/data/cybertron_reviewed_sft.jsonl`
4. build the stronger corpus with `npm run ml:build:enterprise-corpus --prefix workspace`
5. score groundedness and refusal behavior
6. compare the adapter against hosted APIs
7. keep the UI honest about what is LLM-generated vs template-generated
