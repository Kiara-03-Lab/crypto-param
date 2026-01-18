# CryptoParam

Plain LWE security estimator — Rust core with Python bindings.

## Install

```bash
pip install cryptoparam
```

Or build from source:
```bash
pip install maturin
maturin develop --release
```

## Usage

### Python API

```python
from cryptoparam import estimate_lwe, LweParams, SecurityEstimate

# Quick estimate
r = estimate_lwe(256, 7681, 8.0)
print(r)                    # LWE(n=256, q≈2^13, σ=8): ~73 bits (primal_usvp, β=250)
print(r.classical_bits)     # 73.0
print(r.beta)               # 250

# With sieving cost model (aggressive)
r = estimate_lwe(256, 7681, 8.0, sieving=True)
print(r.classical_bits)     # 66.25

# Using params object
params = LweParams(n=512, q=12289, sigma=10.0)
r = estimate(params)
print(r)
```

### CLI

```bash
cryptoparam 256 7681 8.0
# LWE(n=256, q≈2^13, σ=8): ~73 bits (primal_usvp, β=250)

cryptoparam 256 2**13 8.0 -v      # Verbose
cryptoparam 256 7681 8.0 --sieving  # Aggressive model
```

### Low-level Functions

```python
from cryptoparam import get_delta, get_beta, get_bkz_cost

# Root Hermite factor for BKZ-250
delta = get_delta(250)      # ~1.0045

# Block size needed for target delta
beta = get_beta(1.005)      # ~209

# BKZ cost in bits
cost = get_bkz_cost(250)            # 73.0 (core-svp)
cost = get_bkz_cost(250, sieving=True)  # 66.25
```

## What It Does

Estimates plain LWE security against the **primal uSVP attack**.

- Finds optimal BKZ block size β and lattice dimension d
- Uses Core-SVP cost model (default) or sieving model
- Rust core for speed, Python bindings for convenience

## Limitations

- **Plain LWE only** — Ring-LWE and Module-LWE have different security
- For Kyber, Dilithium, etc., use the full Lattice Estimator
- Primal attack only (no dual, hybrid, algebraic attacks)

## Performance

The Rust core is ~100x faster than pure Python for batch estimation:

```python
# Estimate 1000 parameter sets
params = [(n, 7681, 8.0) for n in range(100, 1100)]
results = [estimate_lwe(*p) for p in params]  # Fast!
```

## References

- [APS15] Albrecht, Player, Scott. "On the concrete hardness of LWE"

## License

MIT
