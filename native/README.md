# Hushgrep · local CPU scanner

Extract the Linux x86-64 archive and run the executable against the root of a Git working tree.

~~~sh
./hushgrep /path/to/repository --output findings.json
~~~

The JSON report lists one-based Unicode line and column coordinates, with exclusive end columns. Every value is replaced with `[REDACTED]`. Paths containing a detected value or a decoded URI/Basic password are masked across the report. The numeric file ID is the zero-based position among eligible paths in Git byte order. Omit `--output` to write to stdout. Output files are created privately and must be new. Exit codes are 0 for a complete scan, 2 for partial TruffleHog coverage, and 1 for a scan or invocation error. With `--timings`, stderr contains numeric scan and model initialization times.

Keep the executable beside the bundled `model`, `bin` and `lib` directories. Git and the standard x86-64 Linux system libraries including glibc and libstdc++ are required. The bundled ONNX Runtime CPU 1.32.0 runs the v10 INT8 encoder and boundary head on four threads. TruffleHog 3.99.9 runs locally with verification and updates disabled. The Rust CLI combines the model and TruffleHog spans with URI/HTTP Basic parsing and the frozen rules. All inference runs locally. The light mode omits PPLX.

This binary was built on Ubuntu 24.04 x86-64 and references glibc 2.39. The scanner processes tracked and non-ignored untracked working-tree files. It skips symlinks, special files, non-UTF-8 or NUL-containing content, files over 1 MiB, and files containing a line over 4,096 characters. Detector batches use private snapshots under `/dev/shm`. The report includes skipped-file counts. Coordinates refer to the scanned snapshots.

The CLI is licensed under Apache-2.0. The v10 weights derive from Fastino GLiNER2.5 multi-v1 (Apache-2.0) and Microsoft's mDeBERTa encoder (MIT). ONNX Runtime is MIT-licensed. The TruffleHog executable is distributed separately inside the archive under AGPL-3.0. See `licenses/` and the [corresponding TruffleHog source](https://github.com/trufflesecurity/trufflehog/tree/v3.99.9).

The archive includes the Rust crate in `source/`. Run `cargo build --locked --release` there on Linux to rebuild the CLI. Its word splitting and weighted span decoding are Rust ports of the Apache-2.0 GLiNER2 routines. Keep the same sibling asset directories when running a rebuilt executable.
