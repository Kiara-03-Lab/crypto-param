"""Tests for CryptoParam Python bindings."""

import pytest
from cryptoparam import (
    estimate_lwe, 
    estimate, 
    LweParams, 
    SecurityEstimate,
    get_delta, 
    get_beta, 
    get_bkz_cost
)


class TestBasicAPI:
    """Test basic Python API."""
    
    def test_estimate_lwe_returns_correct_type(self):
        r = estimate_lwe(256, 7681, 8.0)
        assert isinstance(r, SecurityEstimate)
    
    def test_estimate_lwe_attributes(self):
        r = estimate_lwe(256, 7681, 8.0)
        assert r.n == 256
        assert r.q == 7681
        assert r.sigma == 8.0
        assert r.beta > 0
        assert r.classical_bits > 0
        assert r.d > 0
        assert r.m > 0
        assert r.attack == "primal_usvp"
    
    def test_estimate_with_params_object(self):
        params = LweParams(n=256, q=7681, sigma=8.0)
        r = estimate(params)
        assert r.beta == estimate_lwe(256, 7681, 8.0).beta
    
    def test_sieving_model(self):
        r_core = estimate_lwe(256, 7681, 8.0, sieving=False)
        r_sieve = estimate_lwe(256, 7681, 8.0, sieving=True)
        # Same beta, different cost
        assert r_core.beta == r_sieve.beta
        assert r_sieve.classical_bits < r_core.classical_bits


class TestMonotonicity:
    """Security should behave monotonically with parameters."""
    
    def test_security_increases_with_n(self):
        prev = 0
        for n in [64, 128, 256, 512, 1024]:
            r = estimate_lwe(n, 12289, 8.0)
            if r.beta < 10000:
                assert r.classical_bits > prev
                prev = r.classical_bits
    
    def test_security_decreases_with_sigma(self):
        prev = float('inf')
        for sigma in [2.0, 4.0, 8.0, 16.0, 32.0]:
            r = estimate_lwe(256, 7681, sigma)
            if r.beta < 10000:
                assert r.classical_bits < prev
                prev = r.classical_bits


class TestLowLevelFunctions:
    """Test low-level math functions."""
    
    def test_delta_values(self):
        # Known reference values
        assert abs(get_delta(50) - 1.011) < 0.002
        assert abs(get_delta(100) - 1.009) < 0.002
        assert abs(get_delta(200) - 1.0062) < 0.002
    
    def test_delta_monotonic(self):
        # Delta decreases with beta
        prev = 2.0
        for beta in [50, 100, 200, 300, 400, 500]:
            d = get_delta(beta)
            assert d < prev
            prev = d
    
    def test_beta_from_delta(self):
        # Roundtrip
        for beta in [100, 200, 300, 400]:
            delta = get_delta(beta)
            recovered = get_beta(delta)
            assert abs(recovered - beta) <= 1
    
    def test_bkz_cost(self):
        assert abs(get_bkz_cost(100) - 29.2) < 0.1
        assert abs(get_bkz_cost(100, sieving=True) - 26.5) < 0.1


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_invalid_n_raises(self):
        with pytest.raises(ValueError):
            LweParams(n=0, q=100, sigma=1.0)
        with pytest.raises(ValueError):
            estimate_lwe(0, 100, 1.0)
    
    def test_invalid_q_raises(self):
        with pytest.raises(ValueError):
            LweParams(n=100, q=1, sigma=1.0)
        with pytest.raises(ValueError):
            estimate_lwe(100, 1, 1.0)
    
    def test_invalid_sigma_raises(self):
        with pytest.raises(ValueError):
            LweParams(n=100, q=100, sigma=-1.0)
        with pytest.raises(ValueError):
            estimate_lwe(100, 100, -1.0)
    
    def test_trivially_weak(self):
        r = estimate_lwe(16, 31, 5.0)
        assert r.beta <= 10
    
    def test_very_strong(self):
        r = estimate_lwe(1024, 3329, 1.0)
        assert r.beta > 1000


class TestRepr:
    """Test string representations."""
    
    def test_security_estimate_str(self):
        r = estimate_lwe(256, 7681, 8.0)
        s = str(r)
        assert "256" in s
        assert "73" in s or "72" in s or "74" in s
        assert "primal_usvp" in s
    
    def test_lwe_params_repr(self):
        p = LweParams(n=256, q=7681, sigma=8.0)
        s = repr(p)
        assert "256" in s
        assert "7681" in s


class TestMatchesPythonMVP:
    """Ensure results match our pure Python implementation."""
    
    def test_known_values(self):
        test_cases = [
            (256, 7681, 8.0, 73, 250),
            (512, 12289, 10.0, 156, 533),
            (64, 127, 3.0, 12, 40),
            (128, 1031, 5.0, 22, 75),
        ]
        for n, q, sigma, exp_bits, exp_beta in test_cases:
            r = estimate_lwe(n, q, sigma)
            assert r.beta == exp_beta, f"Beta mismatch for n={n}"
            assert abs(r.classical_bits - exp_bits) < 1.0, f"Bits mismatch for n={n}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
