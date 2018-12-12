#[macro_use]
extern crate derive_more;

extern crate itertools;
extern crate counter;


pub mod crypto {
    //takes arguments by reference so 'Vigenere Compose'
    //of non-copy types can have the same prototype
    pub fn chrxor(c1:&char, c2:&char) -> char {
        ((*c1 as u8) ^ (*c2 as u8)) as char
    }
    
    pub fn strxor(s1:&str,s2:&str) -> String {
        s1.chars().zip(s2.chars())
        .map(|(c1,c2)| chrxor(&c1,&c2))
        .collect()
    }
       
    pub mod vigenere {
        use std::iter::once;
        use itertools::{iterate,Itertools};
        use utils::{Average,FMax,Glyph,ZipN,UnzipN,fcmp};
        use dist;
        use dist::{Distribution,kappa};

        mod err {
            pub type Msg = &'static str;
            pub const EMPTY_KEYSPACE:&str = 
                "Encountered Empty Keyspace";
            pub const CIPHERTEXT_TOO_SHORT:&str = 
                "Minimum ciphertext length is 20 characters.";
            pub const MATHEMATICAL_PARADOX:&str =
                "Congratulations, you have broken mathematics";
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


        pub fn key_len_score<T:Glyph>(ct:&[T],n:usize) -> f64 {
            let scores = 
            ct
            .iter()
            .unzipn(n)
            .iter()
            .map(|shred| 
                kappa(&shred.clone().collect::<Vec<&T>>())
            ).collect::<Vec<f64>>();
            scores.iter().average()
        }

        pub fn guess_key_length<T:Glyph>(ct:&[T]) -> Result<usize,err::Msg> {
            let max_checked_len = (ct.len() as f64 / 20 as f64).floor() as usize;
            if max_checked_len == 0 {
                return Err(err::CIPHERTEXT_TOO_SHORT);
            } let num_finalists = 
                (max_checked_len as f64 / 10 as f64).ceil() as usize;
            let ksc = |l| key_len_score(&ct,l);
            iterate(1, |keylen| keylen+1)
            .take_while(|&keylen| keylen < max_checked_len)
            .sorted_by(|&l1, &l2| fcmp(ksc(l1),ksc(l2)).reverse())
            .iter()
            .take(num_finalists)
            .min()
            .map(|x| *x)
            .ok_or(err::MATHEMATICAL_PARADOX)
        }

 
        pub fn simple_xor_break<'a,T,K> (   
        ct:         &       [T],
        ptspace:    &       Distribution<T>,
        keyspace:   &'a     Distribution<K>, 
        comb:       &       impl Fn(&T,&K) -> T)   
        ->          Result<(&'a K, Vec<T>),err::Msg>
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

        pub fn full_break<'a,T,K> (   
        ct:         &       [T],
        ptspace:    &       Distribution<T>,
        keyspace:   &'a     Distribution<K>, 
        comb:       &       impl Fn(&T,&K) -> T)   
        ->          Result<Vec<T>,err::Msg>
        where T: Glyph, K: Glyph {
            let klen_guess = guess_key_length(ct)?;
            let derived_pt =
                ct
                .iter()
                .unzipn(klen_guess)
                .into_iter()
                .map(|shred| {
                    let svec:Vec<T> = shred.cloned().collect();
                    let (_, s) = simple_xor_break(&svec,ptspace,keyspace,comb).unwrap();
                    s.into_iter()
                }).collect::<Vec<_>>()
                .zipn()
                .collect();
            Ok(derived_pt)
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
    use utils::{fcmp,Glyph};
    use counter::Counter;

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
        fn surprise(self) -> Result<f64,err::Msg> {
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

        fn surprise(&self, events:&[T]) -> Result<f64,err::Msg> {
            events
            .iter()
            .map(|e| self.get(e).surprise())
            .fold_results(0.0, |s1,s2| s1+s2)
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

    pub fn kappa<T:Glyph>(v:&[T]) -> f64 {
        let pairs = |x:usize| (x*(x-1))/2;
        let coincidences:usize = 
            v
            .iter()
            .cloned() //else we get a Counter<&T>
            .collect::<Counter<T>>()
            .iter()
            .map(|(_,n)| pairs(*n))
            .sum();
        let possible_coincidences = pairs(v.len());
        coincidences as f64 / possible_coincidences as f64
    }



    pub fn surprisecmp(sup1:&Result<f64,err::Msg>,sup2:&Result<f64,err::Msg>) 
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

        pub const SHAKESPEARE:[(char,Prob);91] = [
            (' ', Prob(0.237_062_444_956_660_62)),
            ('e', Prob(0.074_130_862_579_396_6)),
            ('t', Prob(0.053_126_498_319_317_414)),
            ('o', Prob(0.051_553_818_393_209_924)),
            ('a', Prob(0.044_825_042_106_379_775)),
            ('h', Prob(0.040_014_297_756_457_76)),
            ('n', Prob(0.039_559_569_008_018_94)),
            ('s', Prob(0.039_386_251_765_463_294)),
            ('r', Prob(0.038_271_598_378_879_19)),
            ('i', Prob(0.036_309_412_683_561_006)),
            ('l', Prob(0.026_778_246_817_310_985)),
            ('d', Prob(0.024_509_732_972_359_564)),
            ('\n', Prob(0.022_801_660_401_168_957)),
            ('u', Prob(0.021_035_876_485_998_403)),
            ('m', Prob(0.017_511_270_659_058_054)),
            ('y', Prob(0.015_622_552_420_679_421)),
            (',', Prob(0.015_238_359_759_327_207)),
            ('.', Prob(0.014_295_008_298_524_843)),
            ('w', Prob(0.013_354_954_628_807_049)),
            ('f', Prob(0.012_605_439_999_530_98)),
            ('c', Prob(0.012_217_949_547_094_197)),
            ('g', Prob(0.010_449_417_472_686_504)),
            ('I', Prob(0.010_224_251_625_856_808)),
            ('b', Prob(0.008_527_171_691_614_762)),
            ('p', Prob(0.008_523_873_900_530_193)),
            ('A', Prob(0.008_150_307_454_894_921)),
            ('E', Prob(0.007_801_657_653_009_72)),
            ('T', Prob(0.007_291_782_509_212_288)),
            ('S', Prob(0.006_231_176_254_291_938)),
            ('v', Prob(0.006_227_145_620_744_132)),
            ('O', Prob(0.006_084_241_340_412_836)),
            ('\'', Prob(0.005_692_170_622_580_818)),
            ('k', Prob(0.005_351_948_509_022_848)),
            ('R', Prob(0.005_307_611_539_996_984)),
            ('N', Prob(0.005_008_611_814_996_119)),
            ('L', Prob(0.004_371_038_871_979_566_5)),
            ('C', Prob(0.003_938_478_608_053_682_5)),
            ('H', Prob(0.003_382_434_389_072_292_7)),
            (';', Prob(0.003_151_039_381_305_078_7)),
            ('W', Prob(0.003_022_242_318_391_103)),
            ('M', Prob(0.002_907_918_894_126_066)),
            ('D', Prob(0.002_873_292_087_738_098_4)),
            ('B', Prob(0.002_823_825_221_469_572_6)),
            ('U', Prob(0.002_588_582_790_770_362_2)),
            ('P', Prob(0.002_187_351_542_147_877)),
            ('F', Prob(0.002_145_945_942_974_963)),
            ('G', Prob(0.002_045_363_314_895_627_5)),
            ('?', Prob(0.001_919_314_411_218_792_2)),
            ('Y', Prob(0.001_667_033_393_249_311_6)),
            ('!', Prob(0.001_620_314_686_217_926_5)),
            ('-', Prob(0.001_479_242_512_044_723_9)),
            ('K', Prob(0.001_135_172_975_554_757_2)),
            ('x', Prob(0.000_858_891_366_914_251_3)),
            ('V', Prob(0.000_655_894_004_597_487_2)),
            ('j', Prob(0.000_496_867_190_074_967_9)),
            ('q', Prob(0.000_440_438_320_405_686_9)),
            ('[', Prob(0.000_381_994_133_962_503)),
            (']', Prob(0.000_380_528_449_036_028_2)),
            ('J', Prob(0.000_378_696_342_877_934_63)),
            (':', Prob(0.000_334_725_795_083_689_7)),
            ('Q', Prob(0.000_215_822_105_423_418_97)),
            ('z', Prob(0.000_201_348_466_774_48)),
            ('9', Prob(0.000_173_683_663_787_267_55)),
            ('1', Prob(0.000_170_019_451_471_080_48)),
            (')', Prob(0.000_115_239_477_344_083_64)),
            ('(', Prob(0.000_115_056_266_728_274_29)),
            ('X', Prob(0.000_111_025_633_180_468_51)),
            ('Z', Prob(0.000_097_468_047_610_576_31)),
            ('"', Prob(0.000_086_108_989_430_396_36)),
            ('<', Prob(0.000_085_742_568_198_777_65)),
            ('>', Prob(0.000_080_795_881_571_925_1)),
            ('2', Prob(0.000_067_055_085_386_223_55)),
            ('3', Prob(0.000_060_459_503_217_086_81)),
            ('0', Prob(0.000_054_779_974_126_996_84)),
            ('4', Prob(0.000_017_038_587_270_269_92)),
            ('5', Prob(0.000_015_023_270_496_367_025)),
            ('_', Prob(0.000_013_007_953_722_464_131)),
            ('*', Prob(0.000_011_542_268_795_989_3)),
            ('6', Prob(0.000_011_542_268_795_989_3)),
            ('7', Prob(0.000_007_511_635_248_183_512)),
            ('8', Prob(0.000_007_328_424_632_374_159)),
            ('|', Prob(0.000_006_045_950_321_708_681)),
            ('&', Prob(0.000_003_847_422_931_996_433_5)),
            ('@', Prob(0.000_001_465_684_926_474_831_8)),
            ('/', Prob(0.000_000_916_053_079_046_769_8)),
            ('}', Prob(0.000_000_366_421_231_618_707_95)),
            ('`', Prob(0.000_000_183_210_615_809_353_98)),
            ('#', Prob(0.000_000_183_210_615_809_353_98)),
            ('~', Prob(0.000_000_183_210_615_809_353_98)),
            ('%', Prob(0.000_000_183_210_615_809_353_98)),
            ('=', Prob(0.000_000_183_210_615_809_353_98))
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
    use crypto;
    use crypto::{vigenere,chrxor};
    use std::iter::repeat;
    use itertools::{iterate,assert_equal};
   
    pub const SAMPLE_TEXT:&str = "Moloch is introduced as the answer to a question -- C. S. Lewis' question in Hierarchy of Philosophers -- what does it? Earth could be fair, and all men glad and wise. Instead we have prisons, smokestacks, asylums. What sphinx of cement and aluminum breaks open their skulls and eats up their imagination?\n\nAnd Ginsberg answers: Moloch does it.\n\nThere's a passage in the Pincipia Discordia where Malaclypse complains to the Goddess about the evils of human society. \"Everyone is hurting each other, the planet is rampant with injustices, whole societies plunder groups of their own people, mothers imprison sons, children perish while brothers war.\"\n\nThe Goddess answers: \"What is the matter with that, if it's what you want to do?\"\n\nMalaclypse: \"But nobody wants it! Everybody hates it!\"\n\nGoddess: \"Oh. Well, then stop.\"";
  
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
                kappa(&samples),
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
        let pt_initial:Vec<char> = "helloworld".chars().collect();
        let key:Vec<char> = "key".chars().collect();
        let ct = vigenere::encrypt(&pt_initial,&key,&chrxor);
        let pt_final = vigenere::decrypt(&ct,&key,&chrxor);
        assert_eq!(pt_initial, pt_final);
    }

    #[test]
    fn guess_keylen_test() {
        let pt:Vec<char> = SAMPLE_TEXT.chars().collect();
        let key:Vec<char> = "longerkey".chars().collect();
        let ct = vigenere::encrypt(&pt,&key,&chrxor);
        let g_klen = vigenere::guess_key_length(&ct);
        assert_eq!(g_klen, Ok(key.len()));
    }

    use dist::known::SHAKESPEARE;
    #[test]
    fn compile_distribution_test() {
        let d = dist::from(&SHAKESPEARE);
        utils::approx_equal(
            d.get(&'a'), 
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
        let pt:Vec<char> = SAMPLE_TEXT.chars().collect();
        let key:Vec<char> = "k".chars().collect();
        let ct = vigenere::encrypt(&pt,&key,&chrxor);
        let ptspace = dist::from(&SHAKESPEARE);
        let keyspace = dist::uniform(
            &(0..=255)
            .map(|x| char::from(x))
            .collect::<Vec<char>>()
        );
        let (key2, pt2) = 
            vigenere::simple_xor_break(&ct,&ptspace,&keyspace,&chrxor).unwrap();
        assert_eq!(key[0],*key2);
        assert_eq!(pt,pt2);
    }

    #[test]
    fn full_break_test() {
        let pt:Vec<char> = SAMPLE_TEXT.chars().collect();
        let key:Vec<char> = "key".chars().collect();
        let ct = vigenere::encrypt(&pt,&key,&chrxor);
        let ptspace = dist::from(&SHAKESPEARE);
        let keyspace = dist::uniform(
            &(0..=255)
            .map(|x| char::from(x))
            .collect::<Vec<char>>()
        );
        let pt2 = vigenere::full_break(&ct,&ptspace,&keyspace,&chrxor).unwrap();
        assert_eq!(pt,pt2);
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
}
