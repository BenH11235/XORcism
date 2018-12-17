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
        use utils::{Glyph,ZipN,UnzipN,fcmp};
        use crypto::unicity_coefficient;
        use dist;
        use dist::{Distribution,kappa};

        const MAXIMUM_SHRED_SAMPLE_LENGTH:usize = 50;
        const PERCENTAGE_OF_GRADUATING_KEYS:usize = 10;

        type Maybe<T> = Result<T,err::Msg>;

        mod err {
            pub type Msg = &'static str;
            pub const EMPTY_KEYSPACE:&str = 
                "Encountered Empty Keyspace";
            pub const CIPHERTEXT_TOO_SHORT:&str = 
                "Minimum ciphertext length is 20 characters.";
            pub const MATHEMATICAL_PARADOX:&str =
                "Congratulations, you have broken mathematics";
            pub const INVALID_INPUT:&str = 
                "Function input out of range.";
            pub const KEY_SCORE_FAIL:&str = 
                "Unexpected error when computing keylength score.";
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

        pub fn guess_key_length<T:Glyph>(ct:&[T], max_checked_len:usize) -> Maybe<usize> {
            let num_finalists = 
                (max_checked_len as f64 / PERCENTAGE_OF_GRADUATING_KEYS as f64)
                .ceil() as usize;
           
            let lengths_and_scores: Maybe<Vec<(usize,f64)>> = 
                iterate(1, |keylen| keylen+1)
                .take_while(|&keylen| keylen < max_checked_len)
                .map(|l| 
                     key_len_score(&ct,l)
                     .map(|s| (l,s))
                     .map_err(|_| err::KEY_SCORE_FAIL)
                ).collect();
            
            lengths_and_scores?
            .iter()
            .sorted_by(|&(_,s1), &(_,s2)| fcmp(*s1,*s2).reverse())
            .iter()
            .map(|(l,_)| l)
            .take(num_finalists)
            .min()
            .cloned()
            .ok_or(err::CIPHERTEXT_TOO_SHORT)
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
                ).sqrt().floor();
            Ok(res as usize)
        }

        pub fn full_break<'a,T,K> (   
        ct:         &       [T],
        ptspace:    &       Distribution<T>,
        keyspace:   &'a     Distribution<K>, 
        comb:       &       impl Fn(&T,&K) -> T   
        ) ->        Maybe<(Vec<T>,usize)>
        where T: Glyph, K: Glyph {
            let max_checked_keylen = max_feasible_keylen(ct,ptspace,keyspace)?;
            if max_checked_keylen == 0 {
                return Err(err::IMPOSSIBLE_PARAMETERS)
            };

            let klen_guess = guess_key_length(ct,max_checked_keylen)?;
            let derived_shreds : Maybe<Vec<_>> = 
                ct
                .iter()
                .unzipn(klen_guess)
                .into_iter()
                .map(|shred| {
                    let svec:Vec<T> = shred.cloned().collect();
                    simple_xor_break(&svec,ptspace,keyspace,comb)
                    .map(|(_,s)| s.into_iter())
                }).collect();

            Ok((derived_shreds?.zipn().collect(), max_checked_keylen))
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

        pub const HEX:[(u8,Prob);16] = [
            (b'0', Prob(0.0625)),
            (b'1', Prob(0.0625)),
            (b'2', Prob(0.0625)),
            (b'3', Prob(0.0625)),
            (b'4', Prob(0.0625)),
            (b'5', Prob(0.0625)),
            (b'6', Prob(0.0625)),
            (b'7', Prob(0.0625)),
            (b'8', Prob(0.0625)),
            (b'9', Prob(0.0625)),
            (b'A', Prob(0.0625)),
            (b'B', Prob(0.0625)),
            (b'C', Prob(0.0625)),
            (b'D', Prob(0.0625)),
            (b'E', Prob(0.0625)),
            (b'F', Prob(0.0625))
        ];

        pub const BASE64:[(u8,Prob);64] = [
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
            (b'+', Prob(0.015625)),
            (b'/', Prob(0.015625))
        ];

        pub const SHAKESPEARE:[(u8,Prob);91] = [
            (b' ', Prob(0.237_062_444_956_660_62)),
            (b'e', Prob(0.074_130_862_579_396_6)),
            (b't', Prob(0.053_126_498_319_317_414)),
            (b'o', Prob(0.051_553_818_393_209_924)),
            (b'a', Prob(0.044_825_042_106_379_775)),
            (b'h', Prob(0.040_014_297_756_457_76)),
            (b'n', Prob(0.039_559_569_008_018_94)),
            (b's', Prob(0.039_386_251_765_463_294)),
            (b'r', Prob(0.038_271_598_378_879_19)),
            (b'i', Prob(0.036_309_412_683_561_006)),
            (b'l', Prob(0.026_778_246_817_310_985)),
            (b'd', Prob(0.024_509_732_972_359_564)),
            (b'\n', Prob(0.022_801_660_401_168_957)),
            (b'u', Prob(0.021_035_876_485_998_403)),
            (b'm', Prob(0.017_511_270_659_058_054)),
            (b'y', Prob(0.015_622_552_420_679_421)),
            (b',', Prob(0.015_238_359_759_327_207)),
            (b'.', Prob(0.014_295_008_298_524_843)),
            (b'w', Prob(0.013_354_954_628_807_049)),
            (b'f', Prob(0.012_605_439_999_530_98)),
            (b'c', Prob(0.012_217_949_547_094_197)),
            (b'g', Prob(0.010_449_417_472_686_504)),
            (b'I', Prob(0.010_224_251_625_856_808)),
            (b'b', Prob(0.008_527_171_691_614_762)),
            (b'p', Prob(0.008_523_873_900_530_193)),
            (b'A', Prob(0.008_150_307_454_894_921)),
            (b'E', Prob(0.007_801_657_653_009_72)),
            (b'T', Prob(0.007_291_782_509_212_288)),
            (b'S', Prob(0.006_231_176_254_291_938)),
            (b'v', Prob(0.006_227_145_620_744_132)),
            (b'O', Prob(0.006_084_241_340_412_836)),
            (b'\'', Prob(0.005_692_170_622_580_818)),
            (b'k', Prob(0.005_351_948_509_022_848)),
            (b'R', Prob(0.005_307_611_539_996_984)),
            (b'N', Prob(0.005_008_611_814_996_119)),
            (b'L', Prob(0.004_371_038_871_979_566_5)),
            (b'C', Prob(0.003_938_478_608_053_682_5)),
            (b'H', Prob(0.003_382_434_389_072_292_7)),
            (b';', Prob(0.003_151_039_381_305_078_7)),
            (b'W', Prob(0.003_022_242_318_391_103)),
            (b'M', Prob(0.002_907_918_894_126_066)),
            (b'D', Prob(0.002_873_292_087_738_098_4)),
            (b'B', Prob(0.002_823_825_221_469_572_6)),
            (b'U', Prob(0.002_588_582_790_770_362_2)),
            (b'P', Prob(0.002_187_351_542_147_877)),
            (b'F', Prob(0.002_145_945_942_974_963)),
            (b'G', Prob(0.002_045_363_314_895_627_5)),
            (b'?', Prob(0.001_919_314_411_218_792_2)),
            (b'Y', Prob(0.001_667_033_393_249_311_6)),
            (b'!', Prob(0.001_620_314_686_217_926_5)),
            (b'-', Prob(0.001_479_242_512_044_723_9)),
            (b'K', Prob(0.001_135_172_975_554_757_2)),
            (b'x', Prob(0.000_858_891_366_914_251_3)),
            (b'V', Prob(0.000_655_894_004_597_487_2)),
            (b'j', Prob(0.000_496_867_190_074_967_9)),
            (b'q', Prob(0.000_440_438_320_405_686_9)),
            (b'[', Prob(0.000_381_994_133_962_503)),
            (b']', Prob(0.000_380_528_449_036_028_2)),
            (b'J', Prob(0.000_378_696_342_877_934_63)),
            (b':', Prob(0.000_334_725_795_083_689_7)),
            (b'Q', Prob(0.000_215_822_105_423_418_97)),
            (b'z', Prob(0.000_201_348_466_774_48)),
            (b'9', Prob(0.000_173_683_663_787_267_55)),
            (b'1', Prob(0.000_170_019_451_471_080_48)),
            (b')', Prob(0.000_115_239_477_344_083_64)),
            (b'(', Prob(0.000_115_056_266_728_274_29)),
            (b'X', Prob(0.000_111_025_633_180_468_51)),
            (b'Z', Prob(0.000_097_468_047_610_576_31)),
            (b'"', Prob(0.000_086_108_989_430_396_36)),
            (b'<', Prob(0.000_085_742_568_198_777_65)),
            (b'>', Prob(0.000_080_795_881_571_925_1)),
            (b'2', Prob(0.000_067_055_085_386_223_55)),
            (b'3', Prob(0.000_060_459_503_217_086_81)),
            (b'0', Prob(0.000_054_779_974_126_996_84)),
            (b'4', Prob(0.000_017_038_587_270_269_92)),
            (b'5', Prob(0.000_015_023_270_496_367_025)),
            (b'_', Prob(0.000_013_007_953_722_464_131)),
            (b'*', Prob(0.000_011_542_268_795_989_3)),
            (b'6', Prob(0.000_011_542_268_795_989_3)),
            (b'7', Prob(0.000_007_511_635_248_183_512)),
            (b'8', Prob(0.000_007_328_424_632_374_159)),
            (b'|', Prob(0.000_006_045_950_321_708_681)),
            (b'&', Prob(0.000_003_847_422_931_996_433_5)),
            (b'@', Prob(0.000_001_465_684_926_474_831_8)),
            (b'/', Prob(0.000_000_916_053_079_046_769_8)),
            (b'}', Prob(0.000_000_366_421_231_618_707_95)),
            (b'`', Prob(0.000_000_183_210_615_809_353_98)),
            (b'#', Prob(0.000_000_183_210_615_809_353_98)),
            (b'~', Prob(0.000_000_183_210_615_809_353_98)),
            (b'%', Prob(0.000_000_183_210_615_809_353_98)),
            (b'=', Prob(0.000_000_183_210_615_809_353_98))
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
    use utils::{Average,FMax,ZipN,UnzipN};
    use dist;
    use dist::{Prob,Distribution,binomial_p_estimate,kappa};
    use crypto::{vigenere};
    use itertools::{iterate,assert_equal};
   
    pub const SAMPLE_TEXT:&[u8] = b"Moloch is introduced as the answer to a question -- C. S. Lewis' question in Hierarchy of Philosophers -- what does it? Earth could be fair, and all men glad and wise. Instead we have prisons, smokestacks, asylums. What sphinx of cement and aluminum breaks open their skulls and eats up their imagination?\n\nAnd Ginsberg answers: Moloch does it.\n\nThere's a passage in the Pincipia Discordia where Malaclypse complains to the Goddess about the evils of human society. \"Everyone is hurting each other, the planet is rampant with injustices, whole societies plunder groups of their own people, mothers imprison sons, children perish while brothers war.\"\n\nThe Goddess answers: \"What is the matter with that, if it's what you want to do?\"\n\nMalaclypse: \"But nobody wants it! Everybody hates it!\"\n\nGoddess: \"Oh. Well, then stop.\"";
  
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
        let g_klen = vigenere::guess_key_length(&ct,20);
        assert_eq!(g_klen, Ok(key.len()));
    }

    use dist::known::SHAKESPEARE;
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
        let ct = vigenere::encrypt(pt,key,&|x,y| x^y);
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
        let ct = vigenere::encrypt(pt,key,&|x,y| x^y);
        let ptspace = dist::from(&SHAKESPEARE);
        let keyspace = dist::uniform(&(0..=255).collect::<Vec<u8>>());
        let (pt2, _) = 
            vigenere::full_break(&ct, &ptspace, &keyspace, &|x,y| x^y)
            .unwrap();
        assert_eq!(pt.to_vec(), pt2);
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
