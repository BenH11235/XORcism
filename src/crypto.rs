use dist::Distribution;
use utils::{Glyph};

type Maybe<T> = Result<T,err::Msg>;

mod err {
    pub type Msg = &'static str;
    pub const ENTROPY_CALC_ERROR:&str = 
        "Failed to calculate entropy for a provided distribution";
}

pub fn unicity_coefficient<T:Glyph,K:Glyph> 
(keyspace:&impl Distribution<K>,ptspace:&impl Distribution<T>) -> Maybe<f64> {
    match (keyspace.entropy(),ptspace.redundancy()) {
        (Ok(ke),Ok(pe)) => Ok(ke / pe),
        _ => Err(err::ENTROPY_CALC_ERROR)
    }
}

   
pub mod vigenere {
    use std::iter::once;
    use std::cmp::Ordering;
    use itertools::{iterate,Itertools};
    use utils::{Glyph,ZipN,UnzipN,fcmp,Iter,with_preceding_divisors};
    use crypto::unicity_coefficient;
    use dist;
    use dist::{Distribution,kappa};
    use rayon::prelude::*;


    type Maybe<T> = Result<T,err::Msg>;

    mod err {
        pub type Msg = &'static str;
        pub const EMPTY_KEYSPACE:&str = 
            "Encountered Empty Keyspace";
        pub const MATHEMATICAL_PARADOX:&str =
            "Congratulations, you have broken mathematics";
        pub const INVALID_INPUT:&str = 
            "Function input out of range.";
        pub const KEY_SCORE_FAIL:&str = 
            "Unexpected error when computing keylength score.";
        pub const NO_FEASIBLE_KEYLEN:&str =
            "No feasible key len exists for the parameters provided.";
        pub const IMPOSSIBLE_PARAMETERS:&str = 
            "This ciphertext is theoretically impossible to break.";
    }
    
    pub fn transform<T:Glyph,K:Glyph>
    (buf:&[T], key:&[K], comb: &(impl (Fn(&T,&K) -> T) + Sync))
    -> Vec<T> {
        let keylen = key.len();
        buf
        .par_iter()
        .enumerate()
        .map(|(i,c)| comb(&c, &key[i % keylen]))
        .collect()
    }
    
    pub fn encrypt<T:Glyph,K:Glyph>
    (pt:&[T], key:&[K], comb: &(impl Fn(&T,&K) -> T + Sync))
    -> Vec<T> {
        transform(&pt,&key,&comb)
    }

    pub fn decrypt<T:Glyph,K:Glyph>
    (ct:&[T], key:&[K], comb: &(impl Fn(&T,&K) -> T + Sync))
    -> Vec<T> {
        transform(&ct,&key,&comb)
    }


    pub fn key_len_score<T:Glyph>(ct:&[T],n:usize) -> Maybe<f64> {
        if n==0 {
            return Err(err::INVALID_INPUT);
        } let shreds = ct.iter().unzipn(n);
        if let Some(s) = shreds.into_iter().next() {
            Ok(kappa(&s))
        } else {
            Err(err::MATHEMATICAL_PARADOX)
        }
    }

    pub fn likely_key_lengths<'a,T:'a+Glyph>
    (ct:&[T], max_checked_len:usize) -> Maybe<Vec<usize>> {
        let lengths_and_scores: Maybe<Vec<(usize,f64)>> = 
            iterate(1, |keylen| keylen+1)
            .take_while(|&keylen| keylen < max_checked_len)
            .map(|l| 
                 key_len_score(&ct,l)
                 .map(|s| (l,s))
                 .map_err(|_| err::KEY_SCORE_FAIL)
            ).collect();

        let (lengths,scores):(Vec<usize>,Vec<f64>) = 
            lengths_and_scores?
            .into_iter()
            .sorted_by(|&(_,s1), &(_,s2)| fcmp(s1,s2).reverse())
            .into_iter()
            .unzip();

        let suggested_lengths:Vec<usize> = 
            with_preceding_divisors(lengths.iter())
            .zip(scores)
            .sorted_by(
                |((keylen1,divisors1),score1),
                 ((keylen2,divisors2),score2)| {
                let ord = divisors1.cmp(divisors2);
                match ord {
                    Ordering::Greater | Ordering::Less => ord,
                    Ordering::Equal => fcmp(*score1,*score2).reverse()
                }
            }).into_iter()
            .map(|((l,d),s)| *l)
            .collect();
       
        Ok(suggested_lengths)
    }


    pub fn simple_xor_break<'a,T,K> (   
    ct:         &       [T],
    ptspace:    &       (impl Distribution<T> + Sync),
    keyspace:   &'a     impl Distribution<K>, 
    comb:       &       (impl Fn(&T,&K) -> T + Sync)
    ) ->          Maybe<(&'a K, Vec<T>)>
    where T: Glyph, K: Glyph {
        keyspace
        .probabilities()
        .into_par_iter()
        .map(|(k,_)| { 
            let kv:Vec<K> = once(k).cloned().collect(); 
            (k,decrypt(&ct, &kv, &comb))
        }).min_by(|(_,c1),(_,c2)| 
            dist::surprisecmp(&ptspace.surprise(c1),&ptspace.surprise(c2))
        ).ok_or(err::EMPTY_KEYSPACE)
    }
   

    //formula derived by requiring unicity distance per shred
    pub fn max_feasible_keylen<'a,T,K> (   
    ct:         &       [T],
    ptspace:    &       impl Distribution<T>,
    keyspace:   &'a     impl Distribution<K>
    ) ->        Maybe<usize>
    where T: Glyph, K: Glyph {
        let uc = unicity_coefficient(keyspace,ptspace)?;
        let res = 
            (
                ct.len() as f64
                / uc
            ).sqrt().floor() as usize;
        match res {
            0 => Err(err::NO_FEASIBLE_KEYLEN),
            _ => Ok(res)
        }
    }

    pub fn full_break<'a,T:'a,K> (   
    ct:         &'a     [T],
    ptspace:    &'a     (impl Distribution<T> + Sync),
    keyspace:   &'a     (impl Distribution<K> + Sync), 
    comb:       &'a     (impl Fn(&T,&K) -> T  + Sync) 
    ) ->        Maybe<
                    impl Iterator<
                        Item=Maybe<Vec<T>>
                    > + 'a
                >
    where T: Glyph, K: Glyph {
        let max_checked_keylen = 
            max_feasible_keylen(ct,ptspace,keyspace)
            .map_err(|_| err::IMPOSSIBLE_PARAMETERS);
        let solutions = 
            likely_key_lengths(ct,max_checked_keylen?)?
            .into_iter()
            .map(move |key_len| {
                let decrypted_shreds: Maybe<Vec<_>> = 
                    ct
                    .iter()
                    .unzipn(key_len)
                    .into_iter()
                    .map(|shred| {
                        let svec:Vec<T> = shred.cloned().collect();
                        simple_xor_break(&svec,ptspace,keyspace,comb)
                        .map(|(_,s)| s.into_iter())
                    }).collect();
                decrypted_shreds.map(|x| x.zipn().collect())
            });

        Ok(solutions)
    }
}
