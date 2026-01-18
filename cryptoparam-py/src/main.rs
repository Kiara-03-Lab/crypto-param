//! CryptoParam CLI

use cryptoparam::{estimate_core, SecurityEstimate};
use std::env;
use std::process;

fn print_usage() {
    eprintln!("CryptoParam - Plain LWE Security Estimator");
    eprintln!();
    eprintln!("Usage: cryptoparam <n> <q> <sigma> [options]");
    eprintln!();
    eprintln!("Arguments:");
    eprintln!("  n       LWE dimension");
    eprintln!("  q       Modulus (supports 2**k notation)");
    eprintln!("  sigma   Error standard deviation");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -v, --verbose   Show detailed output");
    eprintln!("  --sieving       Use aggressive sieving cost model");
    eprintln!("  -h, --help      Show this help");
}

fn parse_number(s: &str) -> Result<u64, String> {
    if s.contains("**") {
        let parts: Vec<&str> = s.split("**").collect();
        if parts.len() == 2 {
            let base: u64 = parts[0].parse().map_err(|_| format!("Invalid: {}", s))?;
            let exp: u32 = parts[1].parse().map_err(|_| format!("Invalid: {}", s))?;
            return Ok(base.pow(exp));
        }
    }
    if s.contains('^') {
        let parts: Vec<&str> = s.split('^').collect();
        if parts.len() == 2 {
            let base: u64 = parts[0].parse().map_err(|_| format!("Invalid: {}", s))?;
            let exp: u32 = parts[1].parse().map_err(|_| format!("Invalid: {}", s))?;
            return Ok(base.pow(exp));
        }
    }
    s.parse().map_err(|_| format!("Cannot parse '{}'", s))
}

fn format_result(r: &SecurityEstimate) -> String {
    let q_bits = (r.q as f64).log2();
    if r.beta >= 10000 {
        format!(
            "LWE(n={}, q≈2^{:.0}, σ={}): No lattice attack found",
            r.n, q_bits, r.sigma
        )
    } else {
        format!(
            "LWE(n={}, q≈2^{:.0}, σ={}): ~{:.0} bits ({}, β={})",
            r.n, q_bits, r.sigma, r.classical_bits, r.attack, r.beta
        )
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 || args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        process::exit(if args.len() < 2 { 1 } else { 0 });
    }
    
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");
    let sieving = args.iter().any(|a| a == "--sieving");
    
    let positional: Vec<&String> = args[1..]
        .iter()
        .filter(|a| !a.starts_with('-'))
        .collect();
    
    if positional.len() < 3 {
        eprintln!("Error: Expected 3 arguments: n, q, sigma");
        process::exit(1);
    }
    
    let n: usize = match parse_number(positional[0]) {
        Ok(v) => v as usize,
        Err(e) => { eprintln!("Error: {}", e); process::exit(1); }
    };
    
    let q: u64 = match parse_number(positional[1]) {
        Ok(v) => v,
        Err(e) => { eprintln!("Error: {}", e); process::exit(1); }
    };
    
    let sigma: f64 = match positional[2].parse() {
        Ok(v) => v,
        Err(_) => { eprintln!("Error: Invalid sigma"); process::exit(1); }
    };
    
    if n == 0 || q < 2 || sigma <= 0.0 {
        eprintln!("Error: Invalid parameters");
        process::exit(1);
    }
    
    let result = estimate_core(n, q, sigma, sieving);
    
    if verbose {
        let q_bits = (q as f64).log2();
        let model = if sieving { "sieving" } else { "core-svp" };
        
        println!("Parameters:");
        println!("  n     = {}", n);
        println!("  q     = {} (≈2^{:.1})", q, q_bits);
        println!("  σ     = {}", sigma);
        println!();
        println!("Attack: primal uSVP");
        println!("  β     = {}", result.beta);
        println!("  d     = {}", result.d);
        println!("  m     = {}", result.m);
        println!();
        if result.beta < 10000 {
            println!("Security: {:.1} bits ({})", result.classical_bits, model);
        } else {
            println!("Security: No lattice attack found");
        }
    } else {
        println!("{}", format_result(&result));
    }
}
