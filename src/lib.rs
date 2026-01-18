//! CryptoParam - Plain LWE Security Estimator
//!
//! Rust core with Python bindings via PyO3.

use pyo3::prelude::*;
use std::f64::consts::{E, PI};

// ============================================================================
// Core Types
// ============================================================================

/// LWE problem parameters
#[pyclass]
#[derive(Debug, Clone)]
pub struct LweParams {
    #[pyo3(get)]
    pub n: usize,
    #[pyo3(get)]
    pub q: u64,
    #[pyo3(get)]
    pub sigma: f64,
}

#[pymethods]
impl LweParams {
    #[new]
    pub fn new(n: usize, q: u64, sigma: f64) -> PyResult<Self> {
        if n == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err("n must be positive"));
        }
        if q < 2 {
            return Err(pyo3::exceptions::PyValueError::new_err("q must be >= 2"));
        }
        if sigma <= 0.0 {
            return Err(pyo3::exceptions::PyValueError::new_err("sigma must be positive"));
        }
        Ok(Self { n, q, sigma })
    }
    
    fn __repr__(&self) -> String {
        format!("LweParams(n={}, q={}, sigma={})", self.n, self.q, self.sigma)
    }
}

/// Security estimation result
#[pyclass]
#[derive(Debug, Clone)]
pub struct SecurityEstimate {
    #[pyo3(get)]
    pub classical_bits: f64,
    #[pyo3(get)]
    pub beta: usize,
    #[pyo3(get)]
    pub attack: String,
    #[pyo3(get)]
    pub d: usize,
    #[pyo3(get)]
    pub m: usize,
    #[pyo3(get)]
    pub n: usize,
    #[pyo3(get)]
    pub q: u64,
    #[pyo3(get)]
    pub sigma: f64,
}

#[pymethods]
impl SecurityEstimate {
    fn __repr__(&self) -> String {
        let q_bits = (self.q as f64).log2();
        if self.beta >= 10000 {
            format!(
                "LWE(n={}, q≈2^{:.0}, σ={}): No lattice attack found",
                self.n, q_bits, self.sigma
            )
        } else {
            format!(
                "LWE(n={}, q≈2^{:.0}, σ={}): ~{:.0} bits ({}, β={})",
                self.n, q_bits, self.sigma, self.classical_bits, self.attack, self.beta
            )
        }
    }
    
    fn __str__(&self) -> String {
        self.__repr__()
    }
}

// ============================================================================
// Core Math (pure Rust, no Python overhead)
// ============================================================================

/// Root Hermite factor δ_0 achieved by BKZ-β
#[inline]
pub fn delta_0(beta: usize) -> f64 {
    if beta < 40 {
        return 1.0219 - (beta as f64 - 2.0) * (1.0219 - 1.0126) / 48.0;
    }
    let b = beta as f64;
    (b / (2.0 * PI * E)).powf(1.0 / (2.0 * b - 2.0))
}

/// Find minimum β that achieves δ(β) ≤ target_delta
#[inline]
pub fn beta_from_delta(target_delta: f64) -> usize {
    if target_delta >= 1.0219 {
        return 2;
    }
    if target_delta <= 1.0 {
        return 10000;
    }
    
    let mut lo: usize = 40;
    let mut hi: usize = 10000;
    
    while lo < hi {
        let mid = (lo + hi) / 2;
        if delta_0(mid) <= target_delta {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

/// BKZ-β cost in log2
#[inline]
pub fn bkz_cost(beta: usize, sieving: bool) -> f64 {
    if beta < 2 {
        return 0.0;
    }
    if beta >= 10000 {
        return f64::INFINITY;
    }
    let b = beta as f64;
    if sieving { 0.265 * b } else { 0.292 * b }
}

/// Find optimal attack parameters for primal uSVP
/// Returns: (optimal_beta, optimal_m, optimal_d)
pub fn primal_usvp(n: usize, q: u64, sigma: f64) -> (usize, usize, usize) {
    let mut best_beta: usize = 10000;
    let mut best_m: usize = n;
    let mut best_d: usize = 2 * n;
    
    let log_q = (q as f64).ln();
    let log_sigma = sigma.ln();
    
    let m_start = (n / 2).max(1);
    let m_end = 8 * n;
    
    for m in m_start..m_end {
        let d = m + n;
        let d_f = d as f64;
        let m_f = m as f64;
        
        let log_delta_max = (log_sigma + 0.5 * d_f.ln() - (m_f / d_f) * log_q) / d_f;
        
        if log_delta_max <= 0.0 {
            continue;
        }
        
        let delta_max = log_delta_max.exp();
        let beta = beta_from_delta(delta_max);
        
        if beta < best_beta {
            best_beta = beta;
            best_m = m;
            best_d = d;
        }
    }
    
    (best_beta, best_m, best_d)
}

/// Core estimation function
pub fn estimate_core(n: usize, q: u64, sigma: f64, sieving: bool) -> SecurityEstimate {
    let (beta, m, d) = primal_usvp(n, q, sigma);
    let bits = bkz_cost(beta, sieving);
    
    SecurityEstimate {
        classical_bits: bits,
        beta,
        attack: "primal_usvp".to_string(),
        d,
        m,
        n,
        q,
        sigma,
    }
}

// ============================================================================
// Python API
// ============================================================================

/// Estimate plain LWE security.
///
/// Args:
///     n: LWE dimension
///     q: Modulus
///     sigma: Error standard deviation
///     sieving: Use aggressive sieving cost model (default: False)
///
/// Returns:
///     SecurityEstimate with bit-security and attack details
///
/// Example:
///     >>> from cryptoparam import estimate_lwe
///     >>> r = estimate_lwe(256, 7681, 8.0)
///     >>> print(r.classical_bits)  # ~73
#[pyfunction]
#[pyo3(signature = (n, q, sigma, sieving = false))]
pub fn estimate_lwe(n: usize, q: u64, sigma: f64, sieving: bool) -> PyResult<SecurityEstimate> {
    if n == 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("n must be positive"));
    }
    if q < 2 {
        return Err(pyo3::exceptions::PyValueError::new_err("q must be >= 2"));
    }
    if sigma <= 0.0 {
        return Err(pyo3::exceptions::PyValueError::new_err("sigma must be positive"));
    }
    
    Ok(estimate_core(n, q, sigma, sieving))
}

/// Estimate security from LweParams object.
#[pyfunction]
#[pyo3(signature = (params, sieving = false))]
pub fn estimate(params: &LweParams, sieving: bool) -> SecurityEstimate {
    estimate_core(params.n, params.q, params.sigma, sieving)
}

/// Get root Hermite factor for BKZ block size.
#[pyfunction]
pub fn get_delta(beta: usize) -> f64 {
    delta_0(beta)
}

/// Get BKZ block size needed for target delta.
#[pyfunction]
pub fn get_beta(target_delta: f64) -> usize {
    beta_from_delta(target_delta)
}

/// Get BKZ cost in bits.
#[pyfunction]
#[pyo3(signature = (beta, sieving = false))]
pub fn get_bkz_cost(beta: usize, sieving: bool) -> f64 {
    bkz_cost(beta, sieving)
}

// ============================================================================
// Python Module
// ============================================================================

/// CryptoParam - Plain LWE Security Estimator
///
/// Fast Rust implementation with Python bindings.
///
/// Example:
///     >>> from cryptoparam import estimate_lwe
///     >>> r = estimate_lwe(256, 7681, 8.0)
///     >>> print(r)
///     LWE(n=256, q≈2^13, σ=8): ~73 bits (primal_usvp, β=250)
#[pymodule]
fn cryptoparam(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<LweParams>()?;
    m.add_class::<SecurityEstimate>()?;
    m.add_function(wrap_pyfunction!(estimate_lwe, m)?)?;
    m.add_function(wrap_pyfunction!(estimate, m)?)?;
    m.add_function(wrap_pyfunction!(get_delta, m)?)?;
    m.add_function(wrap_pyfunction!(get_beta, m)?)?;
    m.add_function(wrap_pyfunction!(get_bkz_cost, m)?)?;
    Ok(())
}

// ============================================================================
// Rust Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_delta_values() {
        assert!((delta_0(50) - 1.011).abs() < 0.002);
        assert!((delta_0(100) - 1.009).abs() < 0.002);
        assert!((delta_0(200) - 1.0062).abs() < 0.002);
    }
    
    #[test]
    fn test_monotonicity() {
        let mut prev = 0.0;
        for n in [64, 128, 256, 512] {
            let r = estimate_core(n, 12289, 8.0, false);
            assert!(r.classical_bits > prev || r.beta >= 10000);
            prev = r.classical_bits;
        }
    }
    
    #[test]
    fn test_sigma_sensitivity() {
        let mut prev = f64::INFINITY;
        for sigma in [2.0, 4.0, 8.0, 16.0] {
            let r = estimate_core(256, 7681, sigma, false);
            assert!(r.classical_bits < prev || prev == f64::INFINITY);
            prev = r.classical_bits;
        }
    }
    
    #[test]
    fn test_matches_python() {
        // These should match our Python MVP exactly
        let r = estimate_core(256, 7681, 8.0, false);
        assert_eq!(r.beta, 250);
        assert!((r.classical_bits - 73.0).abs() < 1.0);
        
        let r = estimate_core(512, 12289, 10.0, false);
        assert_eq!(r.beta, 533);
        assert!((r.classical_bits - 155.6).abs() < 1.0);
    }
}
