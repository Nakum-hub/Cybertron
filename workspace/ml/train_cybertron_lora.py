#!/usr/bin/env python3
import argparse
import importlib.util
import json
import random
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="GPU-gated LoRA fine-tuning entrypoint for Cybertron bootstrap data."
    )
    parser.add_argument("--dataset", required=True, help="Path to the exported JSONL dataset.")
    parser.add_argument(
        "--model-name",
        help="Hugging Face model ID. Required for actual training; optional with --check-only.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/cybertron-lora",
        help="Directory for adapter checkpoints and tokenizer files.",
    )
    parser.add_argument("--max-steps", type=int, default=80, help="Maximum training steps.")
    parser.add_argument(
        "--num-train-epochs",
        type=float,
        default=0.0,
        help="Use epochs instead of max-steps when greater than zero.",
    )
    parser.add_argument(
        "--per-device-batch-size",
        type=int,
        default=1,
        help="Per-device batch size. Keep this low on Colab GPUs.",
    )
    parser.add_argument(
        "--gradient-accumulation-steps",
        type=int,
        default=8,
        help="Gradient accumulation steps used to simulate a larger batch.",
    )
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--max-length", type=int, default=1024)
    parser.add_argument("--lora-rank", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument(
        "--min-samples-per-task",
        type=int,
        default=0,
        help=(
            "Upsample smaller task types to at least this many rows after loading, "
            "capped by --max-oversample-factor."
        ),
    )
    parser.add_argument(
        "--max-samples-per-task",
        type=int,
        default=0,
        help="Downsample larger task types to at most this many rows before training.",
    )
    parser.add_argument(
        "--max-oversample-factor",
        type=int,
        default=8,
        help="Maximum multiple of a task's original size that balancing may create.",
    )
    parser.add_argument("--logging-steps", type=int, default=5)
    parser.add_argument("--save-steps", type=int, default=50)
    parser.add_argument("--save-total-limit", type=int, default=3)
    parser.add_argument("--warmup-ratio", type=float, default=0.03)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--no-4bit",
        action="store_true",
        help="Disable 4-bit quantization even if bitsandbytes is available.",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Print environment and dataset readiness without attempting training.",
    )
    parser.add_argument(
        "--disable-gradient-checkpointing",
        action="store_true",
        help="Disable gradient checkpointing if you explicitly want maximum speed over memory efficiency.",
    )
    return parser.parse_args()


def print_json(payload: dict) -> None:
    print(json.dumps(payload, indent=2))


def load_torch():
    if importlib.util.find_spec("torch") is None:
        return None
    import torch  # type: ignore

    return torch


def inspect_dataset(dataset_path: Path) -> dict:
    records = 0
    task_counts = {}
    with dataset_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            payload = json.loads(line)
            records += 1
            task = payload.get("taskType", "unknown")
            task_counts[task] = task_counts.get(task, 0) + 1
    return {"records": records, "taskCounts": task_counts}


def rebalance_training_rows(
    rows: list[dict],
    *,
    min_samples_per_task: int,
    max_samples_per_task: int,
    max_oversample_factor: int,
    seed: int,
) -> tuple[list[dict], dict | None]:
    if min_samples_per_task <= 0 and max_samples_per_task <= 0:
        return rows, None

    grouped: dict[str, list[dict]] = {}
    for row in rows:
        task = row.get("taskType", "unknown")
        grouped.setdefault(task, []).append(row)

    rng = random.Random(seed)
    before_counts = {task: len(task_rows) for task, task_rows in grouped.items()}
    after_counts: dict[str, int] = {}
    balanced_rows: list[dict] = []

    for task in sorted(grouped):
        task_rows = list(grouped[task])
        rng.shuffle(task_rows)

        if max_samples_per_task > 0 and len(task_rows) > max_samples_per_task:
            task_rows = rng.sample(task_rows, k=max_samples_per_task)

        current_count = len(task_rows)
        if current_count and min_samples_per_task > 0 and current_count < min_samples_per_task:
            max_allowed = current_count * max(1, max_oversample_factor)
            target_count = min(min_samples_per_task, max_allowed)
            additional_rows_needed = target_count - current_count
            if additional_rows_needed > 0:
                task_rows.extend(rng.choice(task_rows) for _ in range(additional_rows_needed))

        rng.shuffle(task_rows)
        after_counts[task] = len(task_rows)
        balanced_rows.extend(task_rows)

    rng.shuffle(balanced_rows)
    return balanced_rows, {
        "enabled": True,
        "minSamplesPerTask": min_samples_per_task,
        "maxSamplesPerTask": max_samples_per_task,
        "maxOversampleFactor": max_oversample_factor,
        "beforeTaskCounts": before_counts,
        "afterTaskCounts": after_counts,
        "effectiveRecords": len(balanced_rows),
    }


def infer_target_modules(model) -> list[str]:
    common = [
        "q_proj",
        "k_proj",
        "v_proj",
        "o_proj",
        "gate_proj",
        "up_proj",
        "down_proj",
        "query_key_value",
        "c_attn",
        "c_proj",
        "W_pack",
    ]
    seen = set()
    for name, _module in model.named_modules():
        tail = name.split(".")[-1]
        if tail in common:
            seen.add(tail)
    return [item for item in common if item in seen]


def main() -> int:
    args = parse_args()
    dataset_path = Path(args.dataset).resolve()
    output_dir = Path(args.output_dir).resolve()

    if not dataset_path.exists():
        print_json(
            {
                "ok": False,
                "message": f"Dataset not found: {dataset_path}",
            }
        )
        return 2

    dataset_info = inspect_dataset(dataset_path)
    torch = load_torch()
    gpu_ready = bool(torch and torch.cuda.is_available())
    torch_version = getattr(torch, "__version__", None) if torch else None

    env_report = {
        "ok": True,
        "mode": "check" if args.check_only else "train",
        "dataset": str(dataset_path),
        "datasetInfo": dataset_info,
        "balancing": {
            "minSamplesPerTask": args.min_samples_per_task,
            "maxSamplesPerTask": args.max_samples_per_task,
            "maxOversampleFactor": args.max_oversample_factor,
        },
        "torchVersion": torch_version,
        "gpuReady": gpu_ready,
        "cudaVersion": getattr(getattr(torch, "version", None), "cuda", None) if torch else None,
        "deviceCount": torch.cuda.device_count() if gpu_ready else 0,
        "message": None,
    }

    if args.check_only:
        env_report["message"] = (
            "Environment check only. Heavy model loading was skipped on purpose."
        )
        print_json(env_report)
        return 0

    if not torch:
        env_report["message"] = (
            "PyTorch is not installed here. Install workspace/ml/requirements-colab.txt inside Colab."
        )
        print_json(env_report)
        return 0

    if not gpu_ready:
        env_report["message"] = (
            "CUDA GPU not detected. Refusing to train on CPU to protect this machine. "
            "Switch Colab to a T4, L4, or A100 runtime and rerun there."
        )
        print_json(env_report)
        return 0

    if not args.model_name:
        print_json(
            {
                "ok": False,
                "message": "--model-name is required when training is enabled.",
            }
        )
        return 2

    try:
        from datasets import Dataset  # type: ignore
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training  # type: ignore
        from transformers import (  # type: ignore
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
            DataCollatorForLanguageModeling,
            Trainer,
            TrainingArguments,
            set_seed,
        )
    except ImportError as error:
        print_json(
            {
                "ok": False,
                "message": (
                    "Missing training dependencies. Install workspace/ml/requirements-colab.txt in Colab "
                    f"before training. Import failed: {error}"
                ),
            }
        )
        return 2

    set_seed(args.seed)
    use_bf16 = bool(torch.cuda.is_bf16_supported())
    use_4bit = not args.no_4bit and importlib.util.find_spec("bitsandbytes") is not None

    model_kwargs = {
        "device_map": "auto",
        "trust_remote_code": False,
    }

    if use_4bit:
        quantization = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16 if use_bf16 else torch.float16,
        )
        model_kwargs["quantization_config"] = quantization
    else:
        model_kwargs["torch_dtype"] = torch.bfloat16 if use_bf16 else torch.float16

    tokenizer = AutoTokenizer.from_pretrained(args.model_name, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(args.model_name, **model_kwargs)
    model.config.use_cache = False
    if args.disable_gradient_checkpointing:
        model.gradient_checkpointing_disable()
    else:
        model.gradient_checkpointing_enable()

    target_modules = infer_target_modules(model)
    if not target_modules:
        print_json(
            {
                "ok": False,
                "message": (
                    "Could not infer LoRA target modules for this model. "
                    "Pick a standard causal LM with q_proj/v_proj-style layers or extend infer_target_modules()."
                ),
            }
        )
        return 2

    if use_4bit:
        model = prepare_model_for_kbit_training(model)

    peft_config = LoraConfig(
        r=args.lora_rank,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=target_modules,
    )
    model = get_peft_model(model, peft_config)

    training_rows = []
    with dataset_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            text = row.get("text")
            if text is None:
                continue
            training_rows.append(
                {
                    "text": text,
                    "taskType": row.get("taskType", "unknown"),
                }
            )

    training_rows, balancing_summary = rebalance_training_rows(
        training_rows,
        min_samples_per_task=args.min_samples_per_task,
        max_samples_per_task=args.max_samples_per_task,
        max_oversample_factor=args.max_oversample_factor,
        seed=args.seed,
    )

    effective_task_counts = {}
    for row in training_rows:
        task = row.get("taskType", "unknown")
        effective_task_counts[task] = effective_task_counts.get(task, 0) + 1

    dataset = Dataset.from_list(training_rows)
    if "text" not in dataset.column_names:
        print_json(
            {
                "ok": False,
                "message": "Dataset must contain a 'text' field for SFT.",
            }
        )
        return 2
    if len(training_rows) == 0:
        print_json(
            {
                "ok": False,
                "message": "Dataset does not contain any usable rows with a 'text' field.",
            }
        )
        return 2

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    tokenized = dataset.map(tokenize, batched=True, remove_columns=dataset.column_names)
    collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    training_args = TrainingArguments(
        output_dir=str(output_dir),
        overwrite_output_dir=True,
        per_device_train_batch_size=args.per_device_batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.learning_rate,
        warmup_ratio=args.warmup_ratio,
        lr_scheduler_type="cosine",
        logging_steps=args.logging_steps,
        save_steps=args.save_steps,
        save_total_limit=args.save_total_limit,
        report_to="none",
        remove_unused_columns=False,
        fp16=not use_bf16,
        bf16=use_bf16,
        optim="paged_adamw_8bit" if use_4bit else "adamw_torch",
        dataloader_pin_memory=True,
    )
    if args.num_train_epochs > 0:
        training_args.num_train_epochs = args.num_train_epochs
    else:
        training_args.max_steps = args.max_steps

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized,
        data_collator=collator,
    )

    result = trainer.train()
    output_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(output_dir))
    tokenizer.save_pretrained(str(output_dir))

    summary = {
        "ok": True,
        "dataset": str(dataset_path),
        "outputDir": str(output_dir),
        "records": dataset_info["records"],
        "taskCounts": dataset_info["taskCounts"],
        "effectiveRecords": len(training_rows),
        "effectiveTaskCounts": effective_task_counts,
        "modulesCovered": sorted(dataset_info["taskCounts"].keys()),
        "modelName": args.model_name,
        "maxSteps": args.max_steps,
        "numTrainEpochs": args.num_train_epochs,
        "learningRate": args.learning_rate,
        "balancing": balancing_summary,
        "lora": {
            "rank": args.lora_rank,
            "alpha": args.lora_alpha,
            "dropout": args.lora_dropout,
            "targetModules": target_modules,
        },
        "gradientCheckpointing": not args.disable_gradient_checkpointing,
        "quantization": "4bit" if use_4bit else "disabled",
        "trainRuntimeSeconds": result.metrics.get("train_runtime"),
        "trainLoss": result.metrics.get("train_loss"),
    }

    with (output_dir / "training_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")

    print_json(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
