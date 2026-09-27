# VeriDx

[![Tests](https://github.com/rasyidred/veridx/actions/workflows/test.yml/badge.svg)](https://github.com/rasyidred/veridx/actions/workflows/test.yml)

**Verifiable AI diagnosis with zero-knowledge proofs.**

A PyTorch breast-cancer classifier is compiled into a Halo2 circuit with [EZKL](https://github.com/zkonduit/ezkl), proven locally, and verified on-chain by a generated Solidity verifier. Anyone can check that a diagnosis came from the committed model, without trusting whoever ran it and without seeing the weights.

## Why

An AI diagnosis is only as trustworthy as the party running the model. They could swap in a different model, edit the output, or skip inference altogether. VeriDx removes that trust assumption: a proof shows that *this exact model* produced *this output* for *this input*, and an Ethereum smart contract checks it.

## How it works

```mermaid
flowchart LR
    A[PyTorch BCNet<br/>trained on WDBC] --> B[ONNX graph<br/>opset 18]
    B --> C[EZKL<br/>calibrate + compile]
    C --> D[Setup<br/>KZG SRS, pk, vk]
    D --> E[Witness<br/>fixed-point inference]
    E --> F[Halo2 proof]
    D --> G[Solidity verifier<br/>Halo2Verifier.sol]
    F --> H{verifyProof}
    G --> H
    H -->|valid| I[true]
    H -->|tampered| J[revert]
```

1. **Train**: a 3-layer MLP classifies tumors as malignant or benign from 30 features (Wisconsin Diagnostic Breast Cancer dataset).
2. **Export**: the model is exported to ONNX, a fixed graph of `Gemm → Relu → Gemm → Relu → Gemm → Sigmoid`.
3. **Circuit**: EZKL calibrates fixed-point scales on real data and compiles the graph into a Halo2 circuit. The weights are baked in as constants.
4. **Prove**: EZKL runs inference inside the circuit and produces a proof, with the patient features and the prediction as public inputs.
5. **Verify on-chain**: EZKL generates a Solidity verifier, which is deployed with Foundry and called with the proof.

## Results

| Metric | Value |
|---|---|
| Model | MLP 30 → 64 → 32 → 1, 4,097 parameters |
| Test accuracy | 96.5% on 114 held-out patients |
| Circuit | input/param scale 11, logrows 18 (2^18 rows) |
| Float vs circuit output | 0.997844 vs 0.998047 (off by 0.0002, less than one 1/2048 quantization step) |
| Proving | ~9 s, proof 25 KB (proving key 1.3 GB, verifying key 0.6 MB) |
| Local verification | ~0.1 s |
| On-chain verifier | 15,194 B runtime (under the 24,576 B EIP-170 limit) |
| On-chain verification cost | ~644k gas |
| Tamper test | modified output in calldata → verifier reverts |

### Experiment: removing Sigmoid from the circuit

Same trained model, with the final Sigmoid cut from the ONNX graph. The circuit outputs the raw score (logit) and Sigmoid is applied outside the proof; the decision is unchanged (score > 0 ⇔ probability > 0.5).

| | With Sigmoid | Without Sigmoid |
|---|---|---|
| Lookup table | range [-83050, 56052] | none |
| Scale / logrows | 11 / 18 | 13 / 15 (8× fewer rows) |
| Proving time | ~9 s | 1.0 s |
| Proving key / SRS | 1.3 GB / 33.5 MB | 138 MB / 4.2 MB |
| Output vs PyTorch (0.997844) | 0.998047 | 0.997845 |
| Verifier runtime / gas | 15,194 B / 644k | 13,426 B / 576k |

Sigmoid was the only lookup-based op, so removing it shrank the circuit 8× and made the result more precise. On-chain cost fell only ~11%: verification is dominated by fixed pairing checks, not circuit size.

## Design decisions

- **Public inputs and output, `fixed` weights.** The weights are compiled into the circuit, so the verifying key, and therefore the deployed verifier, commits to this exact model without publishing it. Private weights without a commitment would let a prover invent weights that produce any output.
- **Calibration on 50 real samples, not one.** Calibrating on a single patient returned a failure with a lookup range far too narrow for other patients. 50 training rows gave a range that covers real inputs at scale 11.
- **Opset 18.** EZKL's ONNX engine (tract) is tested up to opset 18, so the export is pinned there.
- **Inference only.** The proof covers the forward pass; training is out of scope.

## Limitations and next steps

- **Feature scaling happens outside the circuit.** The proof starts from standardized features, so it doesn't prove that the raw measurements were scaled correctly. Folding the scaler into the first layer would close this gap, at some cost in precision.
- **The main pipeline still proves Sigmoid.** The experiment above shows the no-Sigmoid circuit is cheaper and more precise; switching the main verifier to it is a next step.
- **Inputs are public.** Real medical data would use `hashed` or `private` input visibility.
- **Local chain only.** Verified on Anvil; a testnet deployment is next.
- **Training isn't seeded**, so rerunning the notebook yields a new model and requires regenerating every artifact.

## Quickstart

Requirements: [uv](https://docs.astral.sh/uv/), Python 3.14, and [Foundry](https://getfoundry.sh/) for the on-chain part. Developed on Windows 11 with an NVIDIA GPU (training only; proving runs on CPU).

```powershell
git clone https://github.com/rasyidred/veridx.git
cd veridx
uv sync
uv run jupyter lab
```

**Quick check (no Python needed):** the committed proof is verified by a Foundry test, including a tampered-output case that must revert.

```powershell
cd contracts
forge test
```

**Full pipeline:** open `main.ipynb` and run it top to bottom:

| Phase | What it does |
|---|---|
| 1 | Load data, train and evaluate BCNet |
| 2 | Export to ONNX, write `input.json` |
| 3 | EZKL settings, calibration, compile, SRS, keys, witness, proof, local verify |
| 4 | Generate `Verifier.sol`, build with Foundry, deploy to Anvil, verify on-chain, tamper test |

Notes:
- The proving key (~1.3 GB) isn't committed; Phase 3 regenerates it.
- On Windows, EZKL needs the `HOME` environment variable. The notebook sets it with `os.environ.setdefault("HOME", os.path.expanduser("~"))` before the SRS step.
- The verifier compiles with `optimizer = true` (set in `contracts/foundry.toml`); without it, solc fails with "Stack too deep".

## Repository layout

```
main.ipynb        end-to-end pipeline: training → ONNX → proof → on-chain verification
artifacts/        generated files: network.onnx, settings.json, proof.json, Verifier.sol, ...
artifacts_logits/ same pipeline without Sigmoid (experiment)
contracts/        Foundry project: verifier + tests (valid proof, tampered output)
```

## Tech stack

PyTorch · scikit-learn · ONNX · EZKL (Halo2, KZG) · Solidity · Foundry · uv
