# CryptoParam

## What is this?

A tool that answers: **"Is my encryption strong enough?"**

You're building something that needs to be secure (a messaging app, a wallet, a login system). You picked some security settings. This tool tells you if those settings are actually safe — or if a hacker could break them.

---

## Do I need this?

**Yes, if you're:**
- Building anything with encryption
- Choosing security parameters for a crypto library
- Learning about post-quantum cryptography
- Curious why some settings are "secure" and others aren't

**No, if you're:**
- Just using existing software (it already chose settings for you)
- Not working with cryptography at all

---

## Quickest Start (30 seconds)

1. Open `cryptoparam-sandbox.html` in your browser
2. You'll see sliders and a big number
3. The big number is your security level:
   - **128+ = Good** (use it)
   - **80-127 = Meh** (risky)
   - **Below 80 = Bad** (don't use)

That's it. Move sliders, watch the number change.

---

## What are those sliders?

Think of it like a password:

| Slider | Like... | Bigger = |
|--------|---------|----------|
| **n** (dimension) | Password length | Stronger |
| **q** (modulus) | Character variety (a-z vs a-z + 0-9 + symbols) | Stronger |
| **σ** (sigma/error) | Typos allowed | Weaker* |

*More "error" actually makes it easier to attack. Counter-intuitive, but that's the math.

---

## Where do I get these numbers?

**If you're using a library** (like liboqs, pqcrypto, Kyber):  
Check its documentation. It will list parameters like `n=512, q=3329`.

**If you're choosing yourself:**  
Start with the "Strong" preset in the sandbox, then adjust.

**If you have no idea:**  
Use these → `n=512, q=12289, sigma=10` → gives ~156 bits security → that's solid.

---

## I want to use this in my code

### Python
```bash
pip install cryptoparam-0.1.0-cp312-cp312-manylinux_2_34_x86_64.whl
```

```python
from cryptoparam import estimate_lwe

# Check if your parameters are secure
result = estimate_lwe(n=512, q=12289, sigma=10.0)

if result.classical_bits >= 128:
    print("Good to go!")
else:
    print("Too weak, increase n")
```

### Command Line
```bash
./cryptoparam-linux 512 12289 10.0
# Output: ~156 bits (primal_usvp, β=533)
```

---

## What's "bits of security"?

It's like a score:

| Bits | What it means | Real-world equivalent |
|------|--------------|----------------------|
| 256 | Unbreakable | Overkill for everything |
| 128 | Very strong | Bank-level, recommended minimum |
| 80 | Borderline | Was okay in 2010, risky now |
| 40 | Weak | A laptop can break it |
| 10 | Joke | Breaks in seconds |

**Rule of thumb:** Aim for 128+. Sleep well at night.

---

## Common Questions

**"It says 'no attack found' — is that good?"**  
Yes! It means the parameters are so strong that the attack doesn't work.

**"I tried Kyber-512 parameters and got weird results"**  
Kyber uses a different math structure (Module-LWE). This tool is for plain LWE. Kyber's security comes from additional algebraic properties we don't model here.

**"Which is better: Core-SVP or Sieving?"**  
- Core-SVP = conservative (assumes attacker is weak)
- Sieving = aggressive (assumes attacker has best algorithms)

Use Core-SVP unless you're paranoid, then use Sieving.

**"Can I trust this tool?"**  
For learning and comparison: yes. For production crypto: get it reviewed by a cryptographer too.

---

## Files in this package

| File | What to do with it |
|------|-------------------|
| `cryptoparam-sandbox.html` | Open in browser. Play with sliders. |
| `cryptoparam-linux` | Run from terminal: `./cryptoparam-linux 256 7681 8.0` |
| `*.whl` | Install with pip: `pip install *.whl` |
| `*-source.zip` | Source code if you want to build/modify |

---

## Still confused?

1. Open the sandbox HTML
2. Click "Strong" preset
3. Look at the number (should be ~156)
4. That's a secure configuration
5. Now you know what "secure" looks like

Compare your own parameters against that baseline.

---

## One more thing

This tool estimates **one specific attack** (primal lattice attack). It's usually the best attack, but crypto is complicated. For anything serious:

1. Use established libraries (don't roll your own crypto)
2. Use their recommended parameters
3. Get expert review

This tool helps you understand *why* those recommendations exist.

---

MIT License. Free to use. No warranty.
