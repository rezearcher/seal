# Seal VPE — cross-language build and test targets
# https://github.com/nousresearch/seal

.PHONY: default
default: test

# ---------------------------------------------------------------------------
# Generate test vectors
# ---------------------------------------------------------------------------

.PHONY: vectors
vectors:
	python3 tests/generate_vectors.py

# ---------------------------------------------------------------------------
# Python tests
# ---------------------------------------------------------------------------

.PHONY: test-python
test-python:
	python3 -m pytest tests/ -x -q

# ---------------------------------------------------------------------------
# TypeScript tests
# ---------------------------------------------------------------------------

.PHONY: test-ts
test-ts:
	cd vpe-ts && npm test

# ---------------------------------------------------------------------------
# Go tests
# ---------------------------------------------------------------------------

.PHONY: test-go
test-go:
	cd vpe-go && go test ./vpe/...

# ---------------------------------------------------------------------------
# Rust tests
# ---------------------------------------------------------------------------

.PHONY: test-rust
test-rust:
	cd vpe-rust && cargo test

# ---------------------------------------------------------------------------
# Cross-language interop: generate vectors then run ALL suite tests
# ---------------------------------------------------------------------------

.PHONY: cross-lang-test-vectors
cross-lang-test-vectors: vectors
	@echo "=== Python ===" && python3 -m pytest tests/test_interop_vectors.py tests/test_core.py -x -q && \
	echo "" && \
	echo "=== TypeScript ===" && cd vpe-ts && npm test && \
	echo "" && \
	echo "=== Go ===" && cd ../vpe-go && go test ./vpe/... && \
	echo "" && \
	echo "=== Rust ===" && cd ../vpe-rust && cargo test && \
	echo "" && \
	echo "=== ALL TESTS PASSED ==="

# ---------------------------------------------------------------------------
# Quick test (just the interop vectors across all languages)
# ---------------------------------------------------------------------------

.PHONY: cross-lang-interop
cross-lang-interop: vectors
	@echo "=== Python interop ===" && python3 -m pytest tests/test_interop_vectors.py -x -q && \
	echo "=== TypeScript interop ===" && cd vpe-ts && npx jest tests/interop_vectors.test.ts && \
	echo "=== Go interop ===" && cd ../vpe-go && go test -run TestInteropVectorAll ./vpe/... && \
	echo "=== Rust interop ===" && cd ../vpe-rust && cargo test test_interop_all_vectors -- --nocapture && \
	echo "" && \
	echo "=== ALL INTEROP TESTS PASSED ==="
