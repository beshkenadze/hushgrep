<p align="center">
  <img src="docs/branding/hushgrep-social.png" alt="Hushgrep. Find hardcoded passwords. Keep the values masked.">
</p>

# Hushgrep

Hushgrep scans a local Git working tree for hardcoded credentials, with a focus on ordinary passwords in configuration, connection strings and HTTP Basic auth. It reports file and line coordinates and replaces the matched values with [REDACTED]. It runs locally on CPU and disables live credential verification.

## GitHub Actions

Save this as `.github/workflows/hushgrep.yml` and run it from the **Actions** tab.

```yaml
name: Hushgrep
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: beshkenadze/hushgrep@v0.1.0-alpha.4
```

Open the job summary for counts, scan coverage, runtime and peak memory. Download the `hushgrep-report` artifact to view `report.html`, `report.json` and `metrics.json`. Artifacts are retained for seven days. Findings are candidates for review. A complete scan passes with findings. An incomplete scan uploads its partial report and fails.

Use the `path` input for a nested Git checkout and `artifact-name` for a different artifact name. The action downloads the Linux archive from the public release without a token and verifies its SHA-256. The Rust executable writes the reports and job summary.

## Linux CLI

Use **x86-64 Linux with glibc 2.39 or later** (for example Ubuntu 24.04), Git, libstdc++ and writable `/dev/shm`. Download the [archive](https://github.com/beshkenadze/hushgrep/releases/download/v0.1.0-alpha.4/hushgrep-linux-x86_64.tar.gz) and its [SHA-256 file](https://github.com/beshkenadze/hushgrep/releases/download/v0.1.0-alpha.4/hushgrep-linux-x86_64.tar.gz.sha256).

```sh
sha256sum -c hushgrep-linux-x86_64.tar.gz.sha256
tar -xzf hushgrep-linux-x86_64.tar.gz
./hushgrep-linux-x86_64/hushgrep /path/to/repo --report-dir hushgrep-report
```

Use `--output findings.json` for a JSON-only file or omit both output flags to print JSON to stdout. Keep the executable alongside the bundled `model`, `lib` and `bin` directories. The compressed archive is about **310 MB** and the extracted bundle is about **378 MB**. The measured peak RSS was **1.32 GiB**. The scan of 1,806 lines took about **6 minutes** on a GitHub-hosted Ubuntu runner with two logical CPUs. Time and memory are measurements on that corpus.

## What the scanner reads

The scanner reads tracked and non-ignored untracked files from the current working tree. It skips history, submodule contents, ignored untracked files, symlinks, non-UTF-8 files, files over 1 MiB and files with lines longer than 4,096 characters. Reports count skipped files. File paths containing detected secret values are also masked.

The CPU pipeline combines v10 INT8, TruffleHog 3.99.9, and URI and HTTP Basic parsing. On 12 held-out authentication and parsing test files with 111 labelled password occurrences, the hosted pipeline found 84 and produced 22 false alerts. On the same corpus the combined TruffleHog, Betterleaks and Prowl baseline found 73 with 8 false alerts. Hushgrep found 20 occurrences missed by that baseline. Exact finding ranges varied between the two tested CPU environments. [Report format and native build instructions](native/README.md)

## Licenses

| Component | License |
| --- | --- |
| Hushgrep Rust CLI, GitHub Action and v10 fine-tuning contributions | [Apache-2.0](LICENSE) |
| v10 INT8 model | Derived from [Fastino GLiNER2.5 multi-v1](https://huggingface.co/fastino/gliner2.5-multi-v1) (Apache-2.0) and the [Microsoft mDeBERTa encoder](https://huggingface.co/microsoft/mdeberta-v3-base) (MIT) |
| Bundled ONNX Runtime 1.32.0 | [MIT](https://github.com/microsoft/onnxruntime/blob/v1.32.0/LICENSE) |
| Bundled TruffleHog 3.99.9 | [AGPL-3.0](licenses/TruffleHog-LICENSE). The release includes its [corresponding source archive](https://github.com/beshkenadze/hushgrep/releases/download/v0.1.0-alpha.4/trufflehog-3.99.9-source.tar.gz). |

See [NOTICE](NOTICE) and the license files bundled with the Linux archive. Fine-tuning used synthetic and labelled examples, including examples derived from [CredData](https://github.com/Samsung/CredData).
