#[macro_use]
extern crate derive_more;

extern crate itertools;
extern crate counter;


pub mod crypto {
    use dist::Distribution;
    use utils::Glyph;
    //takes arguments by reference so 'Vigenere Compose'
    //of non-copy types can have the same prototype
    type Maybe<T> = Result<T,err::Msg>;

    mod err {
        pub type Msg = &'static str;
        pub const ENTROPY_CALC_ERROR:&str = 
            "Failed to calculate entropy for a provided distribution";
    }
    
    pub fn unicity_coefficient<T:Glyph,K:Glyph> 
    (keyspace:&Distribution<K>,ptspace:&Distribution<T>) -> Maybe<f64> {
        match (keyspace.entropy(),ptspace.redundancy()) {
            (Ok(ke),Ok(pe)) => Ok(ke / pe),
            _ => Err(err::ENTROPY_CALC_ERROR)
        }
    }

       
    pub mod vigenere {
        use std::iter::once;
        use itertools::{iterate,Itertools};
        use utils::{Glyph,ZipN,UnzipN,fcmp,Iter};
        use crypto::unicity_coefficient;
        use dist;
        use dist::{Distribution,kappa};

        const MAXIMUM_SHRED_SAMPLE_LENGTH:usize = 50;
        const NUM_KEY_FINALISTS:usize = 10;

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
        (buf:&[T], key:&[K], comb: &impl Fn(&T,&K) -> T)
        -> Vec<T> {
            let keylen = key.len();
            buf
            .iter()
            .enumerate()
            .map(|(i,c)| comb(&c, &key[i % keylen]))
            .collect()
        }
        
        pub fn encrypt<T:Glyph,K:Glyph>
        (pt:&[T], key:&[K], comb: &impl Fn(&T,&K) -> T)
        -> Vec<T> {
            transform(&pt,&key,&comb)
        }

        pub fn decrypt<T:Glyph,K:Glyph>
        (ct:&[T], key:&[K], comb: &impl Fn(&T,&K) -> T)
        -> Vec<T> {
            transform(&ct,&key,&comb)
        }


        pub fn key_len_score<T:Glyph>(ct:&[T],n:usize) -> Maybe<f64> {
            if n==0 {
                return Err(err::INVALID_INPUT);
            } let shreds = ct.iter().unzipn(n);
            if let Some(s) = shreds.into_iter().next() {
                Ok(kappa(&s.take(MAXIMUM_SHRED_SAMPLE_LENGTH)))
            } else {
                Err(err::MATHEMATICAL_PARADOX)
            }
        }

        pub fn likely_key_lengths<'a,T:'a+Glyph>
        (ct:&[T], max_checked_len:usize) -> Maybe<impl Iter<usize>> {
            let lengths_and_scores: Maybe<Vec<(usize,f64)>> = 
                iterate(1, |keylen| keylen+1)
                .take_while(|&keylen| keylen < max_checked_len)
                .map(|l| 
                     key_len_score(&ct,l)
                     .map(|s| (l,s))
                     .map_err(|_| err::KEY_SCORE_FAIL)
                ).collect();
            
            let suggested_lengths = 
                lengths_and_scores?
                .into_iter()
                .sorted_by(|&(_,s1), &(_,s2)| fcmp(s1,s2).reverse())
                .into_iter()
                .map(|(l,_)| l)
                .take(NUM_KEY_FINALISTS);

            Ok(suggested_lengths)
        }

 
        pub fn simple_xor_break<'a,T,K> (   
        ct:         &       [T],
        ptspace:    &       Distribution<T>,
        keyspace:   &'a     Distribution<K>, 
        comb:       &       impl Fn(&T,&K) -> T)   
        ->          Maybe<(&'a K, Vec<T>)>
        where T: Glyph, K: Glyph {
            keyspace
            .probabilities()
            .into_iter()
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
        ptspace:    &       Distribution<T>,
        keyspace:   &'a     Distribution<K>
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
        ptspace:    &'a     Distribution<T>,
        keyspace:   &'a     Distribution<K>, 
        comb:       &'a     impl Fn(&T,&K) -> T   
        ) ->        Maybe<
                        impl Iter<
                            Maybe<Vec<T>>
                        > + 'a
                    >
        where T: Glyph, K: Glyph {
            let max_checked_keylen = 
                max_feasible_keylen(ct,ptspace,keyspace)
                .map_err(|_| err::IMPOSSIBLE_PARAMETERS);
            let solutions = 
                likely_key_lengths(ct,max_checked_keylen?)?
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
}


pub mod dist {
    use std::ops::Div;
    use std::cmp::Ordering;
    use std::cmp::Ordering::{Equal,Greater,Less};
    use std::collections::*;
    use std::iter::*;
    use itertools::Itertools;
    use utils::{fcmp,Glyph,Iter,approx_equal};
    use counter::Counter;

    type Maybe<T> = Result<T,err::Msg>;

    mod err {
        pub type Msg = &'static str;
        pub const PROBABILITY_OUT_OF_BOUNDS:&str =
            "Encountered `probability` less than 0 or greater than 1.";
        pub const INFINITE_SURPRISE:&str = 
            "Encountered infinitely surprising event";
        pub const MATHEMATICAL_PARADOX:&str = 
            "Congratulations, you have broken mathematics.";
        pub const MALFORMED_SURPRISE_CMP:&str =
            "Attempted comparison of malformed surprises.";
    }


    //Rust's support for newtype ergonomics isn't complete. Some things you get
    //For free, and others you need to implement. Forgive this kludginess.
    type _Prob = f64;

    #[derive(Add,Mul,AddAssign,MulAssign,Debug,Display,From,Clone,Copy,Into)]
    pub struct Prob(pub _Prob);
    impl Prob {
        fn surprise(self) -> Maybe<f64> {
            let p = self.val();
            match (fcmp(p,0.0), fcmp(p,1.0)) {
                (Less,Less)|(Greater,Greater) => 
                    Err(err::PROBABILITY_OUT_OF_BOUNDS),
                (Equal,Less) => 
                    Err(err::INFINITE_SURPRISE),
                (Greater,Less)|(Greater,Equal) =>
                    Ok(p.recip().log(2.0)),
                _ =>
                    Err(err::MATHEMATICAL_PARADOX)
            }
        }
    }

    trait GetUnderlying<T> {
        fn val(&self) -> T;
    }
    impl GetUnderlying<_Prob> for Prob {
        fn val(&self) -> _Prob {
            self.0
        }
    }

    //Completes impl Vector for Prob
    impl Div<f64> for Prob {
        type Output = Self;
        fn div(self, other:f64) -> Self {
            Prob(self.val() / other)
        }
    }

    pub fn binomial_p_estimate(trials:usize, successes:usize) -> Prob {
        let zval = 1.96; //z value for 95% confidence interval
        let naive_p = successes as f64 / trials as f64;
        Prob(
            naive_p 
            -zval 
            *(
                (
                    (naive_p * (1.0-naive_p))
                    /(trials as f64)
                ).sqrt()
            )
        )
    }


    trait Pow<T> {
        fn pow(&self,other:T) -> Self;
    }
    impl Pow<f64> for Prob {
        fn pow(&self,other:_Prob) -> Prob {
            Prob(self.val().powf(other))
        }
    }



    pub trait Distribution<T:Glyph> {
        fn probabilities(&self) -> &HashMap<T,Prob>;

        fn space_size(&self) -> usize {
            self.probabilities().len()
        }
    
        fn get(&self, key:&T) -> Prob {
            *self.probabilities()
            .get(key)
            .unwrap_or(&Prob(0.0))
        }

        fn approx_kappa(&self) -> f64 {
            self.probabilities()
            .iter()
            .map(|(_,p)| p.pow(2.0).val())
            .sum()
        }

        fn surprise(&self, events:&[T]) -> Maybe<f64> {
            events
            .iter()
            .map(|e| self.get(e).surprise())
            .fold_results(0.0, |s1,s2| s1+s2)
        }

        fn entropy(&self) -> Maybe<f64> {
            self.probabilities()
            .iter()
            .map(|(_,&p)| 
                if approx_equal(p,Prob(0.0)) {
                    Ok(0.0)
                } else {
                    p.surprise().map(|s| p.val()*s)
                }
            ).fold_results(0.0, |s1,s2| s1+s2)
        }

        fn redundancy(&self) -> Maybe<f64> {
            self.entropy().map(|e| (self.space_size() as f64).log(2.0) - e)
        }

        fn display(&self) -> String {
            let p_disp = |(i,p):(&T,&Prob)| format!("Item '{}' with probability {}", i, p);
            let items = self.probabilities().iter().map(p_disp);
            once(String::from("Distribution {"))
            .chain(items)
            .intersperse(String::from("\n"))
            .chain(once(String::from("}")))
            .collect()
        }


    }

    pub fn kappa<'a,T:'a,IT>(v:&IT) -> f64 
    where T:    Glyph,
          IT:   Iter<&'a T>
    {
        let pairs = |x:usize| (x*(x-1))/2;
        let counts:Counter<T> = 
            v
            .clone() //don't want to exhaust by computing kappa
            .cloned() //else we get a Counter<&T>
            .collect();
        let (samples,coincidences):(usize,usize) =
            counts
            .iter()
            .fold((0,0), |(s,o),(_,n)| (s+n, o+pairs(*n)));
        let opportunities:usize = pairs(samples);
        match opportunities {
            0 => f64::from(0), //fair enough value for this edge case
            _ => coincidences as f64 / opportunities as f64
        }
    }



    pub fn surprisecmp(sup1:&Maybe<f64>,sup2:&Maybe<f64>) 
    -> Ordering {
        use self::err::{INFINITE_SURPRISE, MALFORMED_SURPRISE_CMP};
        match (sup1,sup2) {
            (Ok(x1), Ok(x2)) => fcmp(*x1,*x2),
            (Err(INFINITE_SURPRISE), Ok(_x2)) => Greater,
            (Ok(_x1), Err(INFINITE_SURPRISE)) => Less,
            (Err(INFINITE_SURPRISE), Err(INFINITE_SURPRISE)) => Equal,
            _ => panic!(MALFORMED_SURPRISE_CMP) 
        }
    }

    //Maybe impl these as From<T> trait?


    pub fn from<T:Glyph>(v:&[(T,Prob)]) -> impl Distribution<T> {
        _Distribution {
            probabilities : v.into_iter().cloned().collect::<HashMap<T,Prob>>()
        }
    }
 
    pub fn from_sample<T:Glyph>(v:&[T]) -> impl Distribution<T> {
        from( 
            &v
            .iter()
            .cloned() //else we get a Counter<&T>
            .collect::<Counter<T>>()
            .most_common_ordered()
            .into_iter()
            .map(|(x,count)| (
                x,
                Prob(count as f64 / v.len() as f64)
            )).collect::<Vec<(T,Prob)>>()
        )
    }

    pub fn uniform<T: Glyph>(v:&[T]) -> impl Distribution<T> {
        let p = Prob((v.len() as f64).recip());
        from(&v.iter().cloned().zip(repeat(p)).collect::<Vec<(T,Prob)>>())
    }

    struct _Distribution<T> where T: Glyph {
        probabilities : HashMap<T,Prob>
    }
    
    impl<T> Distribution<T> for _Distribution<T> where T: Glyph {
        fn probabilities(&self) -> &HashMap<T,Prob> {
            &self.probabilities
        }
    }

    pub mod known {
        use dist::Prob;

        pub const HEX:[(u8,Prob);256] = [
            (b'0', Prob(0.045455)),
            (b'1', Prob(0.045455)),
            (b'2', Prob(0.045455)),
            (b'3', Prob(0.045455)),
            (b'4', Prob(0.045455)),
            (b'5', Prob(0.045455)),
            (b'6', Prob(0.045455)),
            (b'7', Prob(0.045455)),
            (b'8', Prob(0.045455)),
            (b'9', Prob(0.045455)),
            (b'a', Prob(0.045455)),
            (b'b', Prob(0.045455)),
            (b'c', Prob(0.045455)),
            (b'd', Prob(0.045455)),
            (b'e', Prob(0.045455)),
            (b'f', Prob(0.045455)),
            (b'A', Prob(0.045455)),
            (b'B', Prob(0.045455)),
            (b'C', Prob(0.045455)),
            (b'D', Prob(0.045455)),
            (b'E', Prob(0.045455)),
            (b'F', Prob(0.045455)),
            (b'\x00', Prob(0.000000)),
            (b'\x01', Prob(0.000000)),
            (b'\x02', Prob(0.000000)),
            (b'\x03', Prob(0.000000)),
            (b'\x04', Prob(0.000000)),
            (b'\x05', Prob(0.000000)),
            (b'\x06', Prob(0.000000)),
            (b'\x07', Prob(0.000000)),
            (b'\x08', Prob(0.000000)),
            (b'\x09', Prob(0.000000)),
            (b'\x0a', Prob(0.000000)),
            (b'\x0b', Prob(0.000000)),
            (b'\x0c', Prob(0.000000)),
            (b'\x0d', Prob(0.000000)),
            (b'\x0e', Prob(0.000000)),
            (b'\x0f', Prob(0.000000)),
            (b'\x10', Prob(0.000000)),
            (b'\x11', Prob(0.000000)),
            (b'\x12', Prob(0.000000)),
            (b'\x13', Prob(0.000000)),
            (b'\x14', Prob(0.000000)),
            (b'\x15', Prob(0.000000)),
            (b'\x16', Prob(0.000000)),
            (b'\x17', Prob(0.000000)),
            (b'\x18', Prob(0.000000)),
            (b'\x19', Prob(0.000000)),
            (b'\x1a', Prob(0.000000)),
            (b'\x1b', Prob(0.000000)),
            (b'\x1c', Prob(0.000000)),
            (b'\x1d', Prob(0.000000)),
            (b'\x1e', Prob(0.000000)),
            (b'\x1f', Prob(0.000000)),
            (b'\x20', Prob(0.000000)),
            (b'!', Prob(0.000000)),
            (b'"', Prob(0.000000)),
            (b'#', Prob(0.000000)),
            (b'$', Prob(0.000000)),
            (b'%', Prob(0.000000)),
            (b'&', Prob(0.000000)),
            (b'\'', Prob(0.000000)),
            (b'(', Prob(0.000000)),
            (b')', Prob(0.000000)),
            (b'*', Prob(0.000000)),
            (b'+', Prob(0.000000)),
            (b',', Prob(0.000000)),
            (b'-', Prob(0.000000)),
            (b'.', Prob(0.000000)),
            (b'/', Prob(0.000000)),
            (b':', Prob(0.000000)),
            (b';', Prob(0.000000)),
            (b'<', Prob(0.000000)),
            (b'=', Prob(0.000000)),
            (b'>', Prob(0.000000)),
            (b'?', Prob(0.000000)),
            (b'@', Prob(0.000000)),
            (b'G', Prob(0.000000)),
            (b'H', Prob(0.000000)),
            (b'I', Prob(0.000000)),
            (b'J', Prob(0.000000)),
            (b'K', Prob(0.000000)),
            (b'L', Prob(0.000000)),
            (b'M', Prob(0.000000)),
            (b'N', Prob(0.000000)),
            (b'O', Prob(0.000000)),
            (b'P', Prob(0.000000)),
            (b'Q', Prob(0.000000)),
            (b'R', Prob(0.000000)),
            (b'S', Prob(0.000000)),
            (b'T', Prob(0.000000)),
            (b'U', Prob(0.000000)),
            (b'V', Prob(0.000000)),
            (b'W', Prob(0.000000)),
            (b'X', Prob(0.000000)),
            (b'Y', Prob(0.000000)),
            (b'Z', Prob(0.000000)),
            (b'[', Prob(0.000000)),
            (b'\\', Prob(0.000000)),
            (b']', Prob(0.000000)),
            (b'^', Prob(0.000000)),
            (b'_', Prob(0.000000)),
            (b'`', Prob(0.000000)),
            (b'g', Prob(0.000000)),
            (b'h', Prob(0.000000)),
            (b'i', Prob(0.000000)),
            (b'j', Prob(0.000000)),
            (b'k', Prob(0.000000)),
            (b'l', Prob(0.000000)),
            (b'm', Prob(0.000000)),
            (b'n', Prob(0.000000)),
            (b'o', Prob(0.000000)),
            (b'p', Prob(0.000000)),
            (b'q', Prob(0.000000)),
            (b'r', Prob(0.000000)),
            (b's', Prob(0.000000)),
            (b't', Prob(0.000000)),
            (b'u', Prob(0.000000)),
            (b'v', Prob(0.000000)),
            (b'w', Prob(0.000000)),
            (b'x', Prob(0.000000)),
            (b'y', Prob(0.000000)),
            (b'z', Prob(0.000000)),
            (b'{', Prob(0.000000)),
            (b'|', Prob(0.000000)),
            (b'}', Prob(0.000000)),
            (b'~', Prob(0.000000)),
            (b'\x7f', Prob(0.000000)),
            (b'\x80', Prob(0.000000)),
            (b'\x81', Prob(0.000000)),
            (b'\x82', Prob(0.000000)),
            (b'\x83', Prob(0.000000)),
            (b'\x84', Prob(0.000000)),
            (b'\x85', Prob(0.000000)),
            (b'\x86', Prob(0.000000)),
            (b'\x87', Prob(0.000000)),
            (b'\x88', Prob(0.000000)),
            (b'\x89', Prob(0.000000)),
            (b'\x8a', Prob(0.000000)),
            (b'\x8b', Prob(0.000000)),
            (b'\x8c', Prob(0.000000)),
            (b'\x8d', Prob(0.000000)),
            (b'\x8e', Prob(0.000000)),
            (b'\x8f', Prob(0.000000)),
            (b'\x90', Prob(0.000000)),
            (b'\x91', Prob(0.000000)),
            (b'\x92', Prob(0.000000)),
            (b'\x93', Prob(0.000000)),
            (b'\x94', Prob(0.000000)),
            (b'\x95', Prob(0.000000)),
            (b'\x96', Prob(0.000000)),
            (b'\x97', Prob(0.000000)),
            (b'\x98', Prob(0.000000)),
            (b'\x99', Prob(0.000000)),
            (b'\x9a', Prob(0.000000)),
            (b'\x9b', Prob(0.000000)),
            (b'\x9c', Prob(0.000000)),
            (b'\x9d', Prob(0.000000)),
            (b'\x9e', Prob(0.000000)),
            (b'\x9f', Prob(0.000000)),
            (b'\xa0', Prob(0.000000)),
            (b'\xa1', Prob(0.000000)),
            (b'\xa2', Prob(0.000000)),
            (b'\xa3', Prob(0.000000)),
            (b'\xa4', Prob(0.000000)),
            (b'\xa5', Prob(0.000000)),
            (b'\xa6', Prob(0.000000)),
            (b'\xa7', Prob(0.000000)),
            (b'\xa8', Prob(0.000000)),
            (b'\xa9', Prob(0.000000)),
            (b'\xaa', Prob(0.000000)),
            (b'\xab', Prob(0.000000)),
            (b'\xac', Prob(0.000000)),
            (b'\xad', Prob(0.000000)),
            (b'\xae', Prob(0.000000)),
            (b'\xaf', Prob(0.000000)),
            (b'\xb0', Prob(0.000000)),
            (b'\xb1', Prob(0.000000)),
            (b'\xb2', Prob(0.000000)),
            (b'\xb3', Prob(0.000000)),
            (b'\xb4', Prob(0.000000)),
            (b'\xb5', Prob(0.000000)),
            (b'\xb6', Prob(0.000000)),
            (b'\xb7', Prob(0.000000)),
            (b'\xb8', Prob(0.000000)),
            (b'\xb9', Prob(0.000000)),
            (b'\xba', Prob(0.000000)),
            (b'\xbb', Prob(0.000000)),
            (b'\xbc', Prob(0.000000)),
            (b'\xbd', Prob(0.000000)),
            (b'\xbe', Prob(0.000000)),
            (b'\xbf', Prob(0.000000)),
            (b'\xc0', Prob(0.000000)),
            (b'\xc1', Prob(0.000000)),
            (b'\xc2', Prob(0.000000)),
            (b'\xc3', Prob(0.000000)),
            (b'\xc4', Prob(0.000000)),
            (b'\xc5', Prob(0.000000)),
            (b'\xc6', Prob(0.000000)),
            (b'\xc7', Prob(0.000000)),
            (b'\xc8', Prob(0.000000)),
            (b'\xc9', Prob(0.000000)),
            (b'\xca', Prob(0.000000)),
            (b'\xcb', Prob(0.000000)),
            (b'\xcc', Prob(0.000000)),
            (b'\xcd', Prob(0.000000)),
            (b'\xce', Prob(0.000000)),
            (b'\xcf', Prob(0.000000)),
            (b'\xd0', Prob(0.000000)),
            (b'\xd1', Prob(0.000000)),
            (b'\xd2', Prob(0.000000)),
            (b'\xd3', Prob(0.000000)),
            (b'\xd4', Prob(0.000000)),
            (b'\xd5', Prob(0.000000)),
            (b'\xd6', Prob(0.000000)),
            (b'\xd7', Prob(0.000000)),
            (b'\xd8', Prob(0.000000)),
            (b'\xd9', Prob(0.000000)),
            (b'\xda', Prob(0.000000)),
            (b'\xdb', Prob(0.000000)),
            (b'\xdc', Prob(0.000000)),
            (b'\xdd', Prob(0.000000)),
            (b'\xde', Prob(0.000000)),
            (b'\xdf', Prob(0.000000)),
            (b'\xe0', Prob(0.000000)),
            (b'\xe1', Prob(0.000000)),
            (b'\xe2', Prob(0.000000)),
            (b'\xe3', Prob(0.000000)),
            (b'\xe4', Prob(0.000000)),
            (b'\xe5', Prob(0.000000)),
            (b'\xe6', Prob(0.000000)),
            (b'\xe7', Prob(0.000000)),
            (b'\xe8', Prob(0.000000)),
            (b'\xe9', Prob(0.000000)),
            (b'\xea', Prob(0.000000)),
            (b'\xeb', Prob(0.000000)),
            (b'\xec', Prob(0.000000)),
            (b'\xed', Prob(0.000000)),
            (b'\xee', Prob(0.000000)),
            (b'\xef', Prob(0.000000)),
            (b'\xf0', Prob(0.000000)),
            (b'\xf1', Prob(0.000000)),
            (b'\xf2', Prob(0.000000)),
            (b'\xf3', Prob(0.000000)),
            (b'\xf4', Prob(0.000000)),
            (b'\xf5', Prob(0.000000)),
            (b'\xf6', Prob(0.000000)),
            (b'\xf7', Prob(0.000000)),
            (b'\xf8', Prob(0.000000)),
            (b'\xf9', Prob(0.000000)),
            (b'\xfa', Prob(0.000000)),
            (b'\xfb', Prob(0.000000)),
            (b'\xfc', Prob(0.000000)),
            (b'\xfd', Prob(0.000000)),
            (b'\xfe', Prob(0.000000)),
            (b'\xff', Prob(0.000000)),
        ];

        pub const BASE64:[(u8,Prob);256] = [
            (b'A', Prob(0.015625)),
            (b'B', Prob(0.015625)),
            (b'C', Prob(0.015625)),
            (b'D', Prob(0.015625)),
            (b'E', Prob(0.015625)),
            (b'F', Prob(0.015625)),
            (b'G', Prob(0.015625)),
            (b'H', Prob(0.015625)),
            (b'I', Prob(0.015625)),
            (b'J', Prob(0.015625)),
            (b'K', Prob(0.015625)),
            (b'L', Prob(0.015625)),
            (b'M', Prob(0.015625)),
            (b'N', Prob(0.015625)),
            (b'O', Prob(0.015625)),
            (b'P', Prob(0.015625)),
            (b'Q', Prob(0.015625)),
            (b'R', Prob(0.015625)),
            (b'S', Prob(0.015625)),
            (b'T', Prob(0.015625)),
            (b'U', Prob(0.015625)),
            (b'V', Prob(0.015625)),
            (b'W', Prob(0.015625)),
            (b'X', Prob(0.015625)),
            (b'Y', Prob(0.015625)),
            (b'Z', Prob(0.015625)),
            (b'a', Prob(0.015625)),
            (b'b', Prob(0.015625)),
            (b'c', Prob(0.015625)),
            (b'd', Prob(0.015625)),
            (b'e', Prob(0.015625)),
            (b'f', Prob(0.015625)),
            (b'g', Prob(0.015625)),
            (b'h', Prob(0.015625)),
            (b'i', Prob(0.015625)),
            (b'j', Prob(0.015625)),
            (b'k', Prob(0.015625)),
            (b'l', Prob(0.015625)),
            (b'm', Prob(0.015625)),
            (b'n', Prob(0.015625)),
            (b'o', Prob(0.015625)),
            (b'p', Prob(0.015625)),
            (b'q', Prob(0.015625)),
            (b'r', Prob(0.015625)),
            (b's', Prob(0.015625)),
            (b't', Prob(0.015625)),
            (b'u', Prob(0.015625)),
            (b'v', Prob(0.015625)),
            (b'w', Prob(0.015625)),
            (b'x', Prob(0.015625)),
            (b'y', Prob(0.015625)),
            (b'z', Prob(0.015625)),
            (b'0', Prob(0.015625)),
            (b'1', Prob(0.015625)),
            (b'2', Prob(0.015625)),
            (b'3', Prob(0.015625)),
            (b'4', Prob(0.015625)),
            (b'5', Prob(0.015625)),
            (b'6', Prob(0.015625)),
            (b'7', Prob(0.015625)),
            (b'8', Prob(0.015625)),
            (b'9', Prob(0.015625)),
            (b'/', Prob(0.015625)),
            (b'+', Prob(0.015625)),
            (b'\x00', Prob(0.000000)),
            (b'\x01', Prob(0.000000)),
            (b'\x02', Prob(0.000000)),
            (b'\x03', Prob(0.000000)),
            (b'\x04', Prob(0.000000)),
            (b'\x05', Prob(0.000000)),
            (b'\x06', Prob(0.000000)),
            (b'\x07', Prob(0.000000)),
            (b'\x08', Prob(0.000000)),
            (b'\x09', Prob(0.000000)),
            (b'\x0a', Prob(0.000000)),
            (b'\x0b', Prob(0.000000)),
            (b'\x0c', Prob(0.000000)),
            (b'\x0d', Prob(0.000000)),
            (b'\x0e', Prob(0.000000)),
            (b'\x0f', Prob(0.000000)),
            (b'\x10', Prob(0.000000)),
            (b'\x11', Prob(0.000000)),
            (b'\x12', Prob(0.000000)),
            (b'\x13', Prob(0.000000)),
            (b'\x14', Prob(0.000000)),
            (b'\x15', Prob(0.000000)),
            (b'\x16', Prob(0.000000)),
            (b'\x17', Prob(0.000000)),
            (b'\x18', Prob(0.000000)),
            (b'\x19', Prob(0.000000)),
            (b'\x1a', Prob(0.000000)),
            (b'\x1b', Prob(0.000000)),
            (b'\x1c', Prob(0.000000)),
            (b'\x1d', Prob(0.000000)),
            (b'\x1e', Prob(0.000000)),
            (b'\x1f', Prob(0.000000)),
            (b'\x20', Prob(0.000000)),
            (b'!', Prob(0.000000)),
            (b'"', Prob(0.000000)),
            (b'#', Prob(0.000000)),
            (b'$', Prob(0.000000)),
            (b'%', Prob(0.000000)),
            (b'&', Prob(0.000000)),
            (b'\'', Prob(0.000000)),
            (b'(', Prob(0.000000)),
            (b')', Prob(0.000000)),
            (b'*', Prob(0.000000)),
            (b',', Prob(0.000000)),
            (b'-', Prob(0.000000)),
            (b'.', Prob(0.000000)),
            (b':', Prob(0.000000)),
            (b';', Prob(0.000000)),
            (b'<', Prob(0.000000)),
            (b'=', Prob(0.000000)),
            (b'>', Prob(0.000000)),
            (b'?', Prob(0.000000)),
            (b'@', Prob(0.000000)),
            (b'[', Prob(0.000000)),
            (b'\\', Prob(0.000000)),
            (b']', Prob(0.000000)),
            (b'^', Prob(0.000000)),
            (b'_', Prob(0.000000)),
            (b'`', Prob(0.000000)),
            (b'{', Prob(0.000000)),
            (b'|', Prob(0.000000)),
            (b'}', Prob(0.000000)),
            (b'~', Prob(0.000000)),
            (b'\x7f', Prob(0.000000)),
            (b'\x80', Prob(0.000000)),
            (b'\x81', Prob(0.000000)),
            (b'\x82', Prob(0.000000)),
            (b'\x83', Prob(0.000000)),
            (b'\x84', Prob(0.000000)),
            (b'\x85', Prob(0.000000)),
            (b'\x86', Prob(0.000000)),
            (b'\x87', Prob(0.000000)),
            (b'\x88', Prob(0.000000)),
            (b'\x89', Prob(0.000000)),
            (b'\x8a', Prob(0.000000)),
            (b'\x8b', Prob(0.000000)),
            (b'\x8c', Prob(0.000000)),
            (b'\x8d', Prob(0.000000)),
            (b'\x8e', Prob(0.000000)),
            (b'\x8f', Prob(0.000000)),
            (b'\x90', Prob(0.000000)),
            (b'\x91', Prob(0.000000)),
            (b'\x92', Prob(0.000000)),
            (b'\x93', Prob(0.000000)),
            (b'\x94', Prob(0.000000)),
            (b'\x95', Prob(0.000000)),
            (b'\x96', Prob(0.000000)),
            (b'\x97', Prob(0.000000)),
            (b'\x98', Prob(0.000000)),
            (b'\x99', Prob(0.000000)),
            (b'\x9a', Prob(0.000000)),
            (b'\x9b', Prob(0.000000)),
            (b'\x9c', Prob(0.000000)),
            (b'\x9d', Prob(0.000000)),
            (b'\x9e', Prob(0.000000)),
            (b'\x9f', Prob(0.000000)),
            (b'\xa0', Prob(0.000000)),
            (b'\xa1', Prob(0.000000)),
            (b'\xa2', Prob(0.000000)),
            (b'\xa3', Prob(0.000000)),
            (b'\xa4', Prob(0.000000)),
            (b'\xa5', Prob(0.000000)),
            (b'\xa6', Prob(0.000000)),
            (b'\xa7', Prob(0.000000)),
            (b'\xa8', Prob(0.000000)),
            (b'\xa9', Prob(0.000000)),
            (b'\xaa', Prob(0.000000)),
            (b'\xab', Prob(0.000000)),
            (b'\xac', Prob(0.000000)),
            (b'\xad', Prob(0.000000)),
            (b'\xae', Prob(0.000000)),
            (b'\xaf', Prob(0.000000)),
            (b'\xb0', Prob(0.000000)),
            (b'\xb1', Prob(0.000000)),
            (b'\xb2', Prob(0.000000)),
            (b'\xb3', Prob(0.000000)),
            (b'\xb4', Prob(0.000000)),
            (b'\xb5', Prob(0.000000)),
            (b'\xb6', Prob(0.000000)),
            (b'\xb7', Prob(0.000000)),
            (b'\xb8', Prob(0.000000)),
            (b'\xb9', Prob(0.000000)),
            (b'\xba', Prob(0.000000)),
            (b'\xbb', Prob(0.000000)),
            (b'\xbc', Prob(0.000000)),
            (b'\xbd', Prob(0.000000)),
            (b'\xbe', Prob(0.000000)),
            (b'\xbf', Prob(0.000000)),
            (b'\xc0', Prob(0.000000)),
            (b'\xc1', Prob(0.000000)),
            (b'\xc2', Prob(0.000000)),
            (b'\xc3', Prob(0.000000)),
            (b'\xc4', Prob(0.000000)),
            (b'\xc5', Prob(0.000000)),
            (b'\xc6', Prob(0.000000)),
            (b'\xc7', Prob(0.000000)),
            (b'\xc8', Prob(0.000000)),
            (b'\xc9', Prob(0.000000)),
            (b'\xca', Prob(0.000000)),
            (b'\xcb', Prob(0.000000)),
            (b'\xcc', Prob(0.000000)),
            (b'\xcd', Prob(0.000000)),
            (b'\xce', Prob(0.000000)),
            (b'\xcf', Prob(0.000000)),
            (b'\xd0', Prob(0.000000)),
            (b'\xd1', Prob(0.000000)),
            (b'\xd2', Prob(0.000000)),
            (b'\xd3', Prob(0.000000)),
            (b'\xd4', Prob(0.000000)),
            (b'\xd5', Prob(0.000000)),
            (b'\xd6', Prob(0.000000)),
            (b'\xd7', Prob(0.000000)),
            (b'\xd8', Prob(0.000000)),
            (b'\xd9', Prob(0.000000)),
            (b'\xda', Prob(0.000000)),
            (b'\xdb', Prob(0.000000)),
            (b'\xdc', Prob(0.000000)),
            (b'\xdd', Prob(0.000000)),
            (b'\xde', Prob(0.000000)),
            (b'\xdf', Prob(0.000000)),
            (b'\xe0', Prob(0.000000)),
            (b'\xe1', Prob(0.000000)),
            (b'\xe2', Prob(0.000000)),
            (b'\xe3', Prob(0.000000)),
            (b'\xe4', Prob(0.000000)),
            (b'\xe5', Prob(0.000000)),
            (b'\xe6', Prob(0.000000)),
            (b'\xe7', Prob(0.000000)),
            (b'\xe8', Prob(0.000000)),
            (b'\xe9', Prob(0.000000)),
            (b'\xea', Prob(0.000000)),
            (b'\xeb', Prob(0.000000)),
            (b'\xec', Prob(0.000000)),
            (b'\xed', Prob(0.000000)),
            (b'\xee', Prob(0.000000)),
            (b'\xef', Prob(0.000000)),
            (b'\xf0', Prob(0.000000)),
            (b'\xf1', Prob(0.000000)),
            (b'\xf2', Prob(0.000000)),
            (b'\xf3', Prob(0.000000)),
            (b'\xf4', Prob(0.000000)),
            (b'\xf5', Prob(0.000000)),
            (b'\xf6', Prob(0.000000)),
            (b'\xf7', Prob(0.000000)),
            (b'\xf8', Prob(0.000000)),
            (b'\xf9', Prob(0.000000)),
            (b'\xfa', Prob(0.000000)),
            (b'\xfb', Prob(0.000000)),
            (b'\xfc', Prob(0.000000)),
            (b'\xfd', Prob(0.000000)),
            (b'\xfe', Prob(0.000000)),
            (b'\xff', Prob(0.000000)),
        ];

        pub const SHAKESPEARE:[(u8,Prob);256] = [
            (b'\x20', Prob(0.237062)),
            (b'e', Prob(0.074131)),
            (b't', Prob(0.053126)),
            (b'o', Prob(0.051554)),
            (b'a', Prob(0.044825)),
            (b'h', Prob(0.040014)),
            (b'n', Prob(0.039560)),
            (b's', Prob(0.039386)),
            (b'r', Prob(0.038272)),
            (b'i', Prob(0.036309)),
            (b'l', Prob(0.026778)),
            (b'd', Prob(0.024510)),
            (b'\x0a', Prob(0.022802)),
            (b'u', Prob(0.021036)),
            (b'm', Prob(0.017511)),
            (b'y', Prob(0.015623)),
            (b',', Prob(0.015238)),
            (b'.', Prob(0.014295)),
            (b'w', Prob(0.013355)),
            (b'f', Prob(0.012605)),
            (b'c', Prob(0.012218)),
            (b'g', Prob(0.010449)),
            (b'I', Prob(0.010224)),
            (b'b', Prob(0.008527)),
            (b'p', Prob(0.008524)),
            (b'A', Prob(0.008150)),
            (b'E', Prob(0.007802)),
            (b'T', Prob(0.007292)),
            (b'S', Prob(0.006231)),
            (b'v', Prob(0.006227)),
            (b'O', Prob(0.006084)),
            (b'\'', Prob(0.005692)),
            (b'k', Prob(0.005352)),
            (b'R', Prob(0.005308)),
            (b'N', Prob(0.005009)),
            (b'L', Prob(0.004371)),
            (b'C', Prob(0.003938)),
            (b'H', Prob(0.003382)),
            (b';', Prob(0.003151)),
            (b'W', Prob(0.003022)),
            (b'M', Prob(0.002908)),
            (b'D', Prob(0.002873)),
            (b'B', Prob(0.002824)),
            (b'U', Prob(0.002589)),
            (b'P', Prob(0.002187)),
            (b'F', Prob(0.002146)),
            (b'G', Prob(0.002045)),
            (b'?', Prob(0.001919)),
            (b'Y', Prob(0.001667)),
            (b'!', Prob(0.001620)),
            (b'-', Prob(0.001479)),
            (b'K', Prob(0.001135)),
            (b'x', Prob(0.000859)),
            (b'V', Prob(0.000656)),
            (b'j', Prob(0.000497)),
            (b'q', Prob(0.000440)),
            (b'[', Prob(0.000382)),
            (b']', Prob(0.000381)),
            (b'J', Prob(0.000379)),
            (b':', Prob(0.000335)),
            (b'Q', Prob(0.000216)),
            (b'z', Prob(0.000201)),
            (b'9', Prob(0.000174)),
            (b'1', Prob(0.000170)),
            (b')', Prob(0.000115)),
            (b'(', Prob(0.000115)),
            (b'X', Prob(0.000111)),
            (b'Z', Prob(0.000097)),
            (b'"', Prob(0.000086)),
            (b'<', Prob(0.000086)),
            (b'>', Prob(0.000081)),
            (b'2', Prob(0.000067)),
            (b'3', Prob(0.000060)),
            (b'0', Prob(0.000055)),
            (b'4', Prob(0.000017)),
            (b'5', Prob(0.000015)),
            (b'_', Prob(0.000013)),
            (b'*', Prob(0.000012)),
            (b'6', Prob(0.000012)),
            (b'7', Prob(0.000008)),
            (b'8', Prob(0.000007)),
            (b'|', Prob(0.000006)),
            (b'&', Prob(0.000004)),
            (b'@', Prob(0.000001)),
            (b'/', Prob(0.000001)),
            (b'}', Prob(0.000000)),
            (b'`', Prob(0.000000)),
            (b'#', Prob(0.000000)),
            (b'~', Prob(0.000000)),
            (b'%', Prob(0.000000)),
            (b'=', Prob(0.000000)),
            (b'\x00', Prob(0.000000)),
            (b'\x01', Prob(0.000000)),
            (b'\x02', Prob(0.000000)),
            (b'\x03', Prob(0.000000)),
            (b'\x04', Prob(0.000000)),
            (b'\x05', Prob(0.000000)),
            (b'\x06', Prob(0.000000)),
            (b'\x07', Prob(0.000000)),
            (b'\x08', Prob(0.000000)),
            (b'\x09', Prob(0.000000)),
            (b'\x0b', Prob(0.000000)),
            (b'\x0c', Prob(0.000000)),
            (b'\x0d', Prob(0.000000)),
            (b'\x0e', Prob(0.000000)),
            (b'\x0f', Prob(0.000000)),
            (b'\x10', Prob(0.000000)),
            (b'\x11', Prob(0.000000)),
            (b'\x12', Prob(0.000000)),
            (b'\x13', Prob(0.000000)),
            (b'\x14', Prob(0.000000)),
            (b'\x15', Prob(0.000000)),
            (b'\x16', Prob(0.000000)),
            (b'\x17', Prob(0.000000)),
            (b'\x18', Prob(0.000000)),
            (b'\x19', Prob(0.000000)),
            (b'\x1a', Prob(0.000000)),
            (b'\x1b', Prob(0.000000)),
            (b'\x1c', Prob(0.000000)),
            (b'\x1d', Prob(0.000000)),
            (b'\x1e', Prob(0.000000)),
            (b'\x1f', Prob(0.000000)),
            (b'$', Prob(0.000000)),
            (b'+', Prob(0.000000)),
            (b'\\', Prob(0.000000)),
            (b'^', Prob(0.000000)),
            (b'{', Prob(0.000000)),
            (b'\x7f', Prob(0.000000)),
            (b'\x80', Prob(0.000000)),
            (b'\x81', Prob(0.000000)),
            (b'\x82', Prob(0.000000)),
            (b'\x83', Prob(0.000000)),
            (b'\x84', Prob(0.000000)),
            (b'\x85', Prob(0.000000)),
            (b'\x86', Prob(0.000000)),
            (b'\x87', Prob(0.000000)),
            (b'\x88', Prob(0.000000)),
            (b'\x89', Prob(0.000000)),
            (b'\x8a', Prob(0.000000)),
            (b'\x8b', Prob(0.000000)),
            (b'\x8c', Prob(0.000000)),
            (b'\x8d', Prob(0.000000)),
            (b'\x8e', Prob(0.000000)),
            (b'\x8f', Prob(0.000000)),
            (b'\x90', Prob(0.000000)),
            (b'\x91', Prob(0.000000)),
            (b'\x92', Prob(0.000000)),
            (b'\x93', Prob(0.000000)),
            (b'\x94', Prob(0.000000)),
            (b'\x95', Prob(0.000000)),
            (b'\x96', Prob(0.000000)),
            (b'\x97', Prob(0.000000)),
            (b'\x98', Prob(0.000000)),
            (b'\x99', Prob(0.000000)),
            (b'\x9a', Prob(0.000000)),
            (b'\x9b', Prob(0.000000)),
            (b'\x9c', Prob(0.000000)),
            (b'\x9d', Prob(0.000000)),
            (b'\x9e', Prob(0.000000)),
            (b'\x9f', Prob(0.000000)),
            (b'\xa0', Prob(0.000000)),
            (b'\xa1', Prob(0.000000)),
            (b'\xa2', Prob(0.000000)),
            (b'\xa3', Prob(0.000000)),
            (b'\xa4', Prob(0.000000)),
            (b'\xa5', Prob(0.000000)),
            (b'\xa6', Prob(0.000000)),
            (b'\xa7', Prob(0.000000)),
            (b'\xa8', Prob(0.000000)),
            (b'\xa9', Prob(0.000000)),
            (b'\xaa', Prob(0.000000)),
            (b'\xab', Prob(0.000000)),
            (b'\xac', Prob(0.000000)),
            (b'\xad', Prob(0.000000)),
            (b'\xae', Prob(0.000000)),
            (b'\xaf', Prob(0.000000)),
            (b'\xb0', Prob(0.000000)),
            (b'\xb1', Prob(0.000000)),
            (b'\xb2', Prob(0.000000)),
            (b'\xb3', Prob(0.000000)),
            (b'\xb4', Prob(0.000000)),
            (b'\xb5', Prob(0.000000)),
            (b'\xb6', Prob(0.000000)),
            (b'\xb7', Prob(0.000000)),
            (b'\xb8', Prob(0.000000)),
            (b'\xb9', Prob(0.000000)),
            (b'\xba', Prob(0.000000)),
            (b'\xbb', Prob(0.000000)),
            (b'\xbc', Prob(0.000000)),
            (b'\xbd', Prob(0.000000)),
            (b'\xbe', Prob(0.000000)),
            (b'\xbf', Prob(0.000000)),
            (b'\xc0', Prob(0.000000)),
            (b'\xc1', Prob(0.000000)),
            (b'\xc2', Prob(0.000000)),
            (b'\xc3', Prob(0.000000)),
            (b'\xc4', Prob(0.000000)),
            (b'\xc5', Prob(0.000000)),
            (b'\xc6', Prob(0.000000)),
            (b'\xc7', Prob(0.000000)),
            (b'\xc8', Prob(0.000000)),
            (b'\xc9', Prob(0.000000)),
            (b'\xca', Prob(0.000000)),
            (b'\xcb', Prob(0.000000)),
            (b'\xcc', Prob(0.000000)),
            (b'\xcd', Prob(0.000000)),
            (b'\xce', Prob(0.000000)),
            (b'\xcf', Prob(0.000000)),
            (b'\xd0', Prob(0.000000)),
            (b'\xd1', Prob(0.000000)),
            (b'\xd2', Prob(0.000000)),
            (b'\xd3', Prob(0.000000)),
            (b'\xd4', Prob(0.000000)),
            (b'\xd5', Prob(0.000000)),
            (b'\xd6', Prob(0.000000)),
            (b'\xd7', Prob(0.000000)),
            (b'\xd8', Prob(0.000000)),
            (b'\xd9', Prob(0.000000)),
            (b'\xda', Prob(0.000000)),
            (b'\xdb', Prob(0.000000)),
            (b'\xdc', Prob(0.000000)),
            (b'\xdd', Prob(0.000000)),
            (b'\xde', Prob(0.000000)),
            (b'\xdf', Prob(0.000000)),
            (b'\xe0', Prob(0.000000)),
            (b'\xe1', Prob(0.000000)),
            (b'\xe2', Prob(0.000000)),
            (b'\xe3', Prob(0.000000)),
            (b'\xe4', Prob(0.000000)),
            (b'\xe5', Prob(0.000000)),
            (b'\xe6', Prob(0.000000)),
            (b'\xe7', Prob(0.000000)),
            (b'\xe8', Prob(0.000000)),
            (b'\xe9', Prob(0.000000)),
            (b'\xea', Prob(0.000000)),
            (b'\xeb', Prob(0.000000)),
            (b'\xec', Prob(0.000000)),
            (b'\xed', Prob(0.000000)),
            (b'\xee', Prob(0.000000)),
            (b'\xef', Prob(0.000000)),
            (b'\xf0', Prob(0.000000)),
            (b'\xf1', Prob(0.000000)),
            (b'\xf2', Prob(0.000000)),
            (b'\xf3', Prob(0.000000)),
            (b'\xf4', Prob(0.000000)),
            (b'\xf5', Prob(0.000000)),
            (b'\xf6', Prob(0.000000)),
            (b'\xf7', Prob(0.000000)),
            (b'\xf8', Prob(0.000000)),
            (b'\xf9', Prob(0.000000)),
            (b'\xfa', Prob(0.000000)),
            (b'\xfb', Prob(0.000000)),
            (b'\xfc', Prob(0.000000)),
            (b'\xfd', Prob(0.000000)),
            (b'\xfe', Prob(0.000000)),
            (b'\xff', Prob(0.000000)),
        ];    
    }
}

mod utils {
    use std::ops::{Add,Div,Mul};
    use itertools::{Itertools,iterate};
    use std::cmp::Ordering;
    use std::fmt::{Display,Debug};
    use std::hash::Hash;
    use std::f64::EPSILON;
    use itertools::Step;

    pub fn xor(x1:&u8,x2:&u8) -> u8 {
        x1 ^ x2
    }

        
    //Definition of vector trait 
    
    pub trait Vector : 
        From<f64>
        +Add<Self,Output=Self>
        +Mul<f64,Output=Self>
        +Div<f64,Output=Self> 
        {}

    impl<T> Vector for T 
    where T :   
        From<f64>
        +Add<Self,Output=Self>
        +Mul<f64,Output=Self>
        +Div<f64,Output=Self> 
        {}

    //Kludge to shorten Iterator<Item=X>, see Rust RFC #1733
    pub trait Iter<X> : Iterator<Item=X>+Clone {}
    impl<X,T:Clone> Iter<X> for T where T: Iterator<Item=X> {}
    
    pub trait Glyph: Eq+Hash+Clone+Ord+Display+Debug {}
    impl<T> Glyph for T where T:Eq+Hash+Clone+Ord+Display+Debug {}

    pub trait Average<T> : Clone {
        fn average(&self) -> T; 
    }

    impl<'a,T:'a,TV> Average<T> for TV
    where   TV:Iter<&'a T>+Clone,
            T:Copy+Vector {
        fn average(&self) -> T {
            let (sum,len) = 
                self
                .clone() //Don't want to exhaust the iterator here
                .fold(
                    (T::from(0.0),0.0), 
                    |(cur_sum,cur_len),&next| (cur_sum+next,cur_len+1.0)
                );
            sum / len
        }
    }
        
    #[allow(dead_code)]    
    pub fn approx_equal<T>(target:T,result:T) -> bool 
    where f64: From<T> {
        (f64::from(result)-f64::from(target)).abs() < EPSILON
    }


    pub fn fcmp(x:f64,y:f64) -> Ordering {
        if x.is_nan() || y.is_nan() {
            panic!("Encountered NaN while comparing floats");
        } else if x>y {
            Ordering::Greater
        } else if y>x {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }

    pub trait FMax<'a,T:'a> {
        fn fmax(&'a self, &Fn(&T)->f64) -> &'a T; 
    }

    impl<'a,T:'a,TV> FMax<'a,T> for TV
    where TV: Iter<&'a T>+Clone {
        fn fmax(&'a self, f:&Fn(&T)->f64) -> &'a T {
            self
            .clone() //Don't want to exhaust the iterator
            .max_by(|x1,x2| {
                let (f1, f2) = (f(x1),f(x2));
                if approx_equal(f1,f2) {
                    Ordering::Greater //default to earlier element in case of tie
                } else {
                    fcmp(f1,f2)
                }
            }).unwrap() //Panic on NaNs
        }
    }

    pub struct _ZipN<TI> {
        iters : Vec<TI>,
        i : usize
    }

    pub trait ZipN<TI> {
        fn zipn(self) -> _ZipN<TI>;
    }

    impl<TI> ZipN<TI> for Vec<TI> {
        fn zipn(self) -> _ZipN<TI> {
            _ZipN {iters:self, i:0}
        }
    }

    impl<T,TI> Iterator for _ZipN<TI> 
    where TI: Iterator<Item=T> {
        type Item = T;

        fn next(&mut self) -> Option<T> {
            let val = self.iters[self.i].next();
            self.i = (self.i+1) % self.iters.len();
            val
        }
    }

    pub trait UnzipN : Sized+Clone {
        fn unzipn(self,usize) -> Vec<Step<Self>>; //No `impl trait` in traits =(
    }

    impl<T,TI> UnzipN for TI
    where TI: Iterator<Item=T>+Sized+Clone {
        fn unzipn(self,m:usize) -> Vec<Step<TI>> {
        iterate(0, |i| i+1)
        .take(m)
        .map(|r| 
            self
            .clone() //Need to construct m iterators from one
            .dropping(r)
            .step(m)
        ).collect()

        }
    }

}




#[cfg(test)]
mod tests {
    use utils;
    use utils::{Average,FMax,ZipN,UnzipN,xor};
    use dist;
    use dist::{Prob,Distribution,binomial_p_estimate,kappa};
    use dist::known::{SHAKESPEARE,HEX,BASE64};
    use crypto::{vigenere};
    use itertools::{iterate,assert_equal};
   
    pub const SAMPLE_TEXT:&[u8] = b"Moloch is introduced as the answer to a question -- C. S. Lewis' question in Hierarchy of Philosophers -- what does it? Earth could be fair, and all men glad and wise. Instead we have prisons, smokestacks, asylums. What sphinx of cement and aluminum breaks open their skulls and eats up their imagination?\n\nAnd Ginsberg answers: Moloch does it.\n\nThere's a passage in the Pincipia Discordia where Malaclypse complains to the Goddess about the evils of human society. \"Everyone is hurting each other, the planet is rampant with injustices, whole societies plunder groups of their own people, mothers imprison sons, children perish while brothers war.\"\n\nThe Goddess answers: \"What is the matter with that, if it's what you want to do?\"\n\nMalaclypse: \"But nobody wants it! Everybody hates it!\"\n\nGoddess: \"Oh. Well, then stop.\"";

    pub const SAMPLE_TEXT_BASE64:&[u8] = b"TW9sb2NoIGlzIGludHJvZHVjZWQgYXMgdGhlIGFuc3dlciB0byBhIHF1ZXN0aW9uIC0tIEMuIFMuIExld2lzJyBxdWVzdGlvbiBpbiBIaWVyYXJjaHkgb2YgUGhpbG9zb3BoZXJzIC0tIHdoYXQgZG9lcyBpdD8gRWFydGggY291bGQgYmUgZmFpciwgYW5kIGFsbCBtZW4gZ2xhZCBhbmQgd2lzZS4gSW5zdGVhZCB3ZSBoYXZlIHByaXNvbnMsIHNtb2tlc3RhY2tzLCBhc3lsdW1zLiBXaGF0IHNwaGlueCBvZiBjZW1lbnQgYW5kIGFsdW1pbnVtIGJyZWFrcyBvcGVuIHRoZWlyIHNrdWxscyBhbmQgZWF0cyB1cCB0aGVpciBpbWFnaW5hdGlvbj8KCkFuZCBHaW5zYmVyZyBhbnN3ZXJzOiBNb2xvY2ggZG9lcyBpdC4KClRoZXJlJ3MgYSBwYXNzYWdlIGluIHRoZSBQaW5jaXBpYSBEaXNjb3JkaWEgd2hlcmUgTWFsYWNseXBzZSBjb21wbGFpbnMgdG8gdGhlIEdvZGRlc3MgYWJvdXQgdGhlIGV2aWxzIG9mIGh1bWFuIHNvY2lldHkuICJFdmVyeW9uZSBpcyBodXJ0aW5nIGVhY2ggb3RoZXIsIHRoZSBwbGFuZXQgaXMgcmFtcGFudCB3aXRoIGluanVzdGljZXMsIHdob2xlIHNvY2lldGllcyBwbHVuZGVyIGdyb3VwcyBvZiB0aGVpciBvd24gcGVvcGxlLCBtb3RoZXJzIGltcHJpc29uIHNvbnMsIGNoaWxkcmVuIHBlcmlzaCB3aGlsZSBicm90aGVycyB3YXIuIgoKVGhlIEdvZGRlc3MgYW5zd2VyczogIldoYXQgaXMgdGhlIG1hdHRlciB3aXRoIHRoYXQsIGlmIGl0J3Mgd2hhdCB5b3Ugd2FudCB0byBkbz8iCgpNYWxhY2x5cHNlOiAiQnV0IG5vYm9keSB3YW50cyBpdCEgRXZlcnlib2R5IGhhdGVzIGl0ISIKCkdvZGRlc3M6ICJPaC4gV2VsbCwgdGhlbiBzdG9wLiI=";
  
    #[test]
    fn zipn_test() {
        let vec_of_iters = 
            iterate(1, |i| i+1)
            .take(3)
            .map(|i|
                 iterate(1, move |j| j+i)
                 .take(3)
            ).collect::<Vec<_>>();

        let zipped = vec_of_iters.zipn();
        let zipped2 = vec![1,1,1,2,3,4,3,5,7].into_iter();
        assert_equal(zipped,zipped2);
    }

    #[test]
    fn unzipn_test() {
        let shreds1:Vec<Vec<u32>> = 
            iterate(0, |x| x+1)
            .take(3)
            .map(|r| 
                 iterate(0, |x| x+1)
                 .take(10)
                 .map(|x| 3*x+r)
                 .collect()
            ).collect();
        let v:Vec<u32> = iterate(0, |x| x+1).take(30).collect();
        let shreds2:Vec<Vec<u32>> =
            v.iter().unzipn(3)
            .into_iter()
            .map(|shred| shred.cloned().collect())
            .collect();
        assert_eq!(shreds1,shreds2);
    }

    #[test]
    fn approx_kappa_test() {
        let ud = dist::uniform(&iterate(0, |x| x+1).take(10).collect::<Vec<i32>>());
        assert!(
            utils::approx_equal(
                ud.approx_kappa(),
                0.1
            )
        )
    }

    #[test]
    fn exact_kappa_test() {
        let samples:Vec<usize> = 
            iterate(0, |x| x+1).take(5).cycle().take(50).collect();
        assert!(
            utils::approx_equal(
                kappa(&samples.iter()),
                0.183_673_469_387_755
            )
        )
    }

    #[test]
    fn get_dist_from_sample_test() {
        let samples:Vec<i32> = 
            iterate(0, |x| x+1)
            .take(30)
            .map(|x| (x*x) % 5)
            .collect();
        let computed_dist = dist::from_sample(&samples);
        assert!(
            utils::approx_equal(
                computed_dist.get(&4),
                Prob(0.4)
            )
        )
    }

    #[test]
    fn average_test() {
        let v:Vec<f64> = iterate(0 as f64,|x| x+1.0).take(10).collect();
        let ave = v.iter().average();
        assert_eq!(ave,4.5);
    }

    #[test]
    fn fmax_test() {
        struct Blorb {x:i32,y:i32};
        fn skeeve(b: &Blorb) -> f64 {
            (b.x as f64) / (b.y as f64)
        }
        let v:Vec<Blorb> = vec![Blorb{x:2,y:2},Blorb{x:2,y:1},Blorb{x:10,y:7}];
        let vit = v.iter();
        let chosen = vit.fmax(&skeeve);
        assert_eq!(chosen.x + chosen.y, 3);
    }

    #[test]
    fn encrypt_decrypt_test() {
        let pt_initial = b"helloworld";
        let key = b"key";
        let ct = vigenere::encrypt(pt_initial,key,&|x,y| x^y);
        let pt_final = vigenere::decrypt(&ct,key,&|x,y| x^y);
        assert_eq!(pt_initial.to_vec(), pt_final);
    }

    #[test]
    fn guess_keylen_test() {
        let key = b"longerkey";
        let pt = SAMPLE_TEXT;
        let ct = vigenere::encrypt(pt,key,&|x,y| x^y);
        let likely_lengths = vigenere::likely_key_lengths(&ct,20);
        assert!(likely_lengths.unwrap().any(|l| l==key.len()));
    }

    #[test]
    fn compile_distribution_test() {
        let d = dist::from(&SHAKESPEARE);
        utils::approx_equal(
            d.get(&b'a'), 
            Prob(0.044825042106379775)
        );
    }

    #[cfg(ignore)]
    #[test]
    fn display_distribution_test() {
        let d = dist::from(&SHAKESPEARE);
        println!("{}",d.display());
    }

    #[test]
    fn simple_xor_break_test() {
        let pt = SAMPLE_TEXT;
        let key =  b"k";
        let ct = vigenere::encrypt(pt,key,&xor);
        let ptspace = dist::from(&SHAKESPEARE);
        let keyspace = dist::uniform(&(0..=255).collect::<Vec<u8>>());
        let (key2, pt2) = 
            vigenere::simple_xor_break(&ct,&ptspace,&keyspace,&|x,y| x^y)
            .unwrap();
        assert_eq!(key[0],*key2);
        assert_eq!(pt.to_vec(), pt2);
    }

    #[test]
    fn full_break_test() {
        let pt = SAMPLE_TEXT;
        let key = b"key";
        let ct = vigenere::encrypt(pt,key,&xor);
        let ptspace = dist::from(&SHAKESPEARE);
        let keyspace = dist::uniform(&(0..=255).collect::<Vec<u8>>());
        let pt2 = 
            vigenere::full_break(&ct, &ptspace, &keyspace, &xor)
            .unwrap().next().unwrap().unwrap();
        assert_eq!(pt.to_vec(), pt2);
    }
    
    #[test]
    #[cfg(ignore)]
    fn full_break_base64_test() {
        let pt = SAMPLE_TEXT_BASE64;
        let key = b"key";
        let ct = vigenere::encrypt(pt,key,&xor);
        let ptspace = dist::from(&BASE64);
        let keyspace = dist::uniform(&(0..=255).collect::<Vec<u8>>());
        let solutions = 
            vigenere::full_break(&ct, &ptspace, &keyspace, &xor).unwrap();
        assert!(solutions.clone().any(|x| x==Ok(pt.to_vec())));
    }


    #[test]
    fn binomial_p_estimate_test() {
        let trials = 50;
        let successes = 29;
        let est_prob = binomial_p_estimate(trials,successes);
        utils::approx_equal(est_prob, Prob(0.44));
    }

}


fn main() {
    ;
}
