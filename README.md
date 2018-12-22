# 0. Introduction

## 0.0 The Pitch

XORcism is a FOSS command-line tool that breaks "rotating xor" style ciphers. It is written in [Rust](https://www.rust-lang.org/), with a moderate emphasis on test cases, parallelism, running time and memory efficiency. XORcism takes about 12 seconds on a standard laptop to decrypt a full bible that's been encrypted with a 975-byte key, which you're invited to try for yourself (`xorcism tora_cipher_975.bin`).  

Xorcism supports both xor and modulo-2^32-addition based encryption. Support for modulo-947 multiplication can easily be added, if that sort of thing ever becomes popular. Usage is simple and blunt: `xorcism <INPUT_FILE>` works.

## 0.1 The Anti-Pitch

* "Vigenere cipher bearkers" exist online
* No guarantees on probability of success

## 0.2 How does it work?

## 1. Why did you write this?

1. It seemed like a good way to get better at Rust.
2. We took note of Halvar Flake's [Keynote Talk](https://www.sstic.org/media/SSTIC2018/SSTIC-actes/2018_ouverture/SSTIC2018-Slides-2018_ouverture-flake.pdf) at [SSTIC 2018](https://www.sstic.org) where he argues that tools in the RE community are closed-source, closed-binary, unit-test-free, memory-inefficient, throwaway single-threaded python "frameworks" with zero interoperability or separation of concerns, full of "deadline is tomorrow" hacks, written to check a box for a presentation that's full of non-reproducible examples and non-applicable hyperbolic claims. This tool was written to be an antithesis to everything he complained about.

#2. Technical Details

##2.1 Overview of the cipher

The modern rotating xor is a form of what's classically known as a "Vigenère cipher", after Blaise de Vigenère, a French cryptographer [who did not invent it](https://en.wikipedia.org/wiki/Stigler%27s_law_of_eponymy) in the 16th century. The cipher is described by the following formula:

![equation](https://latex.codecogs.com/gif.latex?%5Ctext%7BEnc%7D%28%5Ctext%7Bkey%7D%2C%5Ctext%7Bplaintext%7D%29_%7Bi%7D%20%3D%20%5Ctext%7Bplaintext%7D_i%20%5Coplus%20key_%7Bi%20%5Cmod%20%7C%5Ctext%7Bkey%7D%7C%7D)

The use of the xor function is a modern artifact; the original version used some oldfangled function called a _tabula recta_ where English letters were treated as the numbers 0 to 25, and encryption was simple addition modulo 26. In truth, one can use any function _f(keychar,plaitextchar)_ with the property that _f(k,f(k,p))=p_, and the principle remains the same.

The Vigenère cipher resisted decryption for hundreds of years, which earned it the Bond villain nickname _le chiffre indéchiffrable_ (the unbreakable cipher). Finally, in 1863, German cryptographer Friedrich Kasiski produced a cryptanalysis for it, the idea of which you learn in lecture 3 of Cryptography 101. The cryptanalysis proceeds as follows:

1. Figure out the key length _|k|_ using statistical properties of the ciphertext
2. Partition the ciphertext into _|k|_ parts based on the key character that was used during encryption (so for instance, if the key is 4 characters long, it will be partitioned into 4 parts -- the first with indices 0, 4, 8...; the second with indices 1, 5, 9...; the third with indices 2, 6, 10...; and the fourth with indices 3, 7, 11...).
3. Cryptanalyze each part separately
4. Re-assemble the cryptanalyzed parts

Steps 2 and 4 are trivial, and do not involve any analysis; the cryptographic work is done in steps 1 and 3. Given the existence of this algorithm, the problem of cryptanalyzing the Vigenère cipher is, academically, considered a solved problem.

## 2.2 Details of cryptanalysis

### 2.2.1 Recovering the key length

Kasiski's original strategy was looking for repeated strings in the ciphertext. He reasoned correctly that if a string repeats in the ciphertext, this is probably a result of the same plaintext bytes being encrypted by the same key bytes, given that the alternative is an unlikely coincidence.

A related, more modern method is guessing a key length _k_ and then examining the statistical properties of the individual partitions. If the key guess is correct, the partitions are expected to have statistical properties that they shouldn't otherwise. This is because every character in a given partition was encrypted with the same key character. 

To visualize this, consider the extreme case where we know that the original plaintext consisted of a single character, repeated 100 times. If we guess a key length of 4, and each of the resulting ciphertext partitions consists of a single character repeated 25 times, we are virtually certain that our key length guess was correct. The case where the plaintext character distribution is that of plain English is a less extreme variation of the same principle. Two letters picked at random out of _Lord of the Flies_ are not guaranteed to be the same, but are still much likelier than random to be the same (consider e.g. the much-better-than-random chance that we pick the pair (e,e)).

A strategy therefore suggests itself: Iterate over all possible key lengths; count the number of "coincidences" in the resulting partitions -- pairs of letters which are the same; then choose the key length that produces the largest ratio of coincidences (this is called the "kappa value"). Given that this is widely known to be the correct solution to a solved problem, we expected to be left with strictly an implementation problem.

Unfortunately, it doesn't work. When we implemented the above logic word-for-word, and tried it on a very vanilla 800-odd character ciphertext that'd been encrypted with the even more vanilla 3-character key, `key`, the algorithm failed, and insisted that the correct character length is 9 characters instead.

### 2.2.1.2 Wait, what do you mean "it didn't work"?

It is our professional opinion that when algorithms such as the above fail, people take the news with a much better attitude than they should. Suppose you tried using the quadratic formula on some quadratic equation, and got the wrong result. This would be a *big deal*. You would check your calculations many times over, and certainly you won't say "oh, well; time to tweak the formula, then".

Take a moment and consider the amount of hand-waving in the 'solution' above. It hinges on words such as 'probably', 'unlikely', 'expected to', 'virtually certain' and 'much likelier', which subtly tell you that it is a probabilistic solution -- except you don't see a single probability calculation.

This is because coincidence counting not a capital-S solution in the sense of the quadratic formula, which predictably gives the correct result every time. It's more of a recipe that, given a sane input, for a very vaguely defined sense of 'sane', will -- with some high probability, that we cannot give a rigorous bound for -- produce a result that is _almost_, but not _quite_, the correct answer.

Producing such a recipe is many times easier than producing a capital-S Solution to the standard of the quadratic formula. Take a second to think what such a solution would even look like. We imagine it'd be something like this: 

> **Theorem:** Suppose that a ciphertext ![equation](https://latex.codecogs.com/gif.latex?C) is obtained by encrypting a plaintext with character distribution ![equation](https://latex.codecogs.com/gif.latex?%5Cmathcal%7BP%7D) with properties _a,b,c_ and key character distribution ![equation](https://latex.codecogs.com/gif.latex?%5Cmathcal%7BK%7D) with properties _k,l,m_. Suppose further that the ciphertext is partitioned into ![equation](https://latex.codecogs.com/gif.latex?%7CK%7C) parts, resulting in ![equation](https://latex.codecogs.com/gif.latex?n) coincidences. Then ![equation](https://latex.codecogs.com/gif.latex?%7CK%7C) is the correct key length with probability ![equation](https://latex.codecogs.com/gif.latex?p%20%5Cgeq%20%5Ctext%7Beye-straining%20formula%7D).
> **Proof:** ...

One should stop to fully appreciate the huge gap between the original blithe suggestion of "hey, let's count coincidences" and the level of rigour described here. When we witnessed coincidence counting produce the wrong answer, it was an "oh, well" moment. If the hypothetical formula above had concluded that the wrong answer is correct with probability ![equation](https://latex.codecogs.com/gif.latex?p%20%5Cgeq%200.997), now _that_ would not have been an 'oh well' moment at all. This is the gap between _observing_ that something usually works and _knowing why_ it works.

Generally, in the landscape of solutions to problems, you don't see this level of rigor very often, but you see plenty of of "we tried X, Y, Z, and it seems to work". This is because the former is so much more difficult to derive than the latter. In our case, to produce a truly rigorous solution, you'd have to tackle questions like:

* How is the number of coincidences distributed? It's the sum of many trials with a known probability of success, but unfortunately it's not binomial, because the trials are not independent (e.g. if x=y, then x=z and y=z determine each other). In fact, it's none of your probability 101 distributions, and deriving it combinatorially from first principles appears to be not so easy.
* Suppose we do figure out how the number of coincidences for a k-partition affects the probability that the k-partition is correct; what about the way it affects the probability that some j-partition is correct? What if j divides k? What if they are coprime?

Finally, even if we successfully answer all the above questions, it would not guarantee a probability of success for any _given_ ciphertext -- only in aggregate over the space of all ciphertexts, assuming a random choice (meaning, e.g., no guarantees for adverserial input). Further, we would still have no reason to believe that pairwise coincidence counting actually exhausts the information latent in the ciphertext, and gives the best guarantee possible. In fact, our mathematical intuition says that the opposite is true: ciphertexts exist where coincidence counting will fail to reveal the correct key length, but a more involved analysis will succeed.

The reader may be tempted to call out the above preliminary analysis as truancy or negligence, due to a gnawing suspicion that these problems may be tractable, given a few days of furious formula-scribbling or maybe a few days of tenacious reading through some search results at Google Scholar. We counter that we could have easily avoided that shade by never introducing any frank discussion about limitations and theoretical underpinnings to begin with, and instead omitting the method entirely, or bluntly stating "we used technique X". We further counter that the reader should carefully consider whether the superior hypothetical open-source solution that does incorporate all that extra analysis actually exists anywhere; and what these facts imply for the academic-adjacent incentive landscape. 

To summarize, a fully involved mathematical analysis and literature review of the problem are out of our reach right now. They are definitely on the to-do list, but the involved effort was simply too much to lead with before even producing an initial release. That being the case, we had no recourse but to use that very common research methodology known as trial and error: attempt a "recipe", notice where it fails, correct it to the best of our ability, and repeat. 

The result is not a capital-S Solution, but it seems to work well enough for at least some use cases. And, inevitably, not-so-well for others; see "hall of shame", below.

### 2.2.1.3 Mitigating the Mess of Malignant Multiples

Since naive coincidence counting produced the wrong answer, we searched for clues in the actual coincidence ratios associated with each possible key length. The source of the problem became quickly apparent: the correct key length _k_ received a relatively high score, but so did _2k_, _3k_, and every multiple of _k_. Worse, the scores of multiples of _k_ were basically not distinguishable from those of the correct _k_, and would often be even higher. In retrospect, it's not too difficult to see why this happens: The partition you get from a guessed key length of (let's say) _3k_ is exactly the partition you get from guessing  _k_, only with each part broken into 3 smaller parts. Doing this shouldn't affect the ratio of coincidences (equal character pairs), since the smaller parts are still drawn from the same character distribution.

In mitigating this, our first idea was to narrow down the key length candidates to the top 10 "finalists" based on the best score, and return the minimum value among those, under the assumption that it would be the correct _k_ (the rest being multiples of it). Unfortunately, we quickly discovered that for long enough ciphertexts, there were so many possible key lengths that the higher multiples of _k_ could hog the 10 finalists all to themselves, leaving the correct answer _k_ to wallow in obscurity. Conversely, for short enough ciphertexts, there were so few candidate key lengths that they would all become finalists, and the algorithm would gleefully declare "1" the winner, even if its score was very low compared to that associated with the correct _k_.

To mitigate the first issue (too many finalists), we first tried to introduce some fancy-pants [binomial proportion confidence interval](https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval) calculation in place of the naive coincidence rate. We reasoned that this would naturally advantage coincidence ratios taken from a larger pool, and therefore shorter keys. It did, but not nearly enough to offset the original issue. We then sighed and introduced a hardcoded limit on key length guess -- a maximum of 20 characters. This worked, but came with an obvious trade-off, which we were thankfully able to mitigate later (see below, under 'too many keys').

Mitigating the second issue (too few finalists) was more of a hassle. We tried to take the top 10 _percent_ scores as finalists, only to find out again that the score of _2k_ routinely overtakes that of _k_. It quickly became apparent that:
1. Staking everything on a single guess is unnecessarily risky
2. The whole general approach of choosing finalists and minimums was fundamentally flawed; the problem stemmed from divisibility, and the solution should too

Based on the above, we finally settled on the "shoo, you multiples and your coat-tail riding" algorithm:
* For every possible key length _k_, let _coattails(k)_ be the number of possible key lengths _j_ such that _j_ divides _k_ and has a higher coincidence ratio than _k_
* Iterate over possible key lengths in lexicographic order where coattails(k) takes precedence over _score(k)_, the fewer coattails the better 
* Ask for user feedback to determine whether to proceed to the next key length or not, based on the resulting decryption

This seemed to be working well enough, so we left it alone (though see below under "what about the individual partition breaks").

# 2.2.1.4 Too many keys

As mentioned before, at some point we were motivated to limit the maximum length of key that we considered. While the original problem that motivated this was apparently resolved by the "coat-tails" algorithm, it still makes sense to limit the number of keys being checked, for performance reasons -- seeing as checking a key length guess is the most computationally intensive action present in the entire cryptanalysis of the cipher.

Happily, we were able to garner a relative win here, based on another crypto 101 concept: The _unicity distance_. This is the minimum number of ciphertext characters such that the expected number of possible plaintexts is 1. This seemed like a fairly reasonable demand before we waste computational resources on an attempted cryptanalysis (though, again, see below, under "what about the individual partition breaks). The formula of the unicity distance is:

![equation](https://latex.codecogs.com/gif.latex?U%20%3D%20H%28K%29/D)

Where _H(K)_ is the bit entropy of the key space, and _D_ is the redundancy of the plaintext in bits per character. Since XORcism has access to both the assumed plaintext distribution and the key character distribution (either provided as parameters, or assumed as build-in defaults), using this formula is feasible -- and after a bit of algebra, the following formula emerges:

![equation](https://latex.codecogs.com/gif.latex?k_%7B%5Cmax%7D%20%3D%20%5Csqrt%7B%7Cc%7C%20%5Cfrac%7BD%28P%29%7D%7BH%28K%29%7D%7D)

Where _|c|_ is the length of the original ciphertext provided to the program. (The square root factor has its source in the fact that enlarging the key makes each 

## Hall of Shame

## Usage

```
xorcism [OPTIONS] <INPUT_FILE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -c, --combination-function <COMB_FUNC>    Sets the assumed f where f(key_byte, plain_byte) = cipher_byte [default: xor]  [possible values: xor, add_mod_256]
    -k, --key-distribution <KEY_DIST>         Sets the assumed distribution of the key characters [default: uniform] [possible values: shakespeare, base64, hex, uniform]
    -o, --output_file <OUTPUT_FILE>           Sets the output file to write to [default: xorcism.out]
    -p, --plaintext-distribution <PT_DIST>    Sets the assumed distribution of the plaintext characters [default: shakespeare] [possible values: shakespeare, base64, hex, uniform]

ARGS:
    <INPUT_FILE>    Sets the input file to use
```

## History

TODO: Write history

## Questions?

@benherzog11235, benhe@checkpoint.com
