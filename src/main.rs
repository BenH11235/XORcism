extern crate itertools;
extern crate counter;


pub mod crypto {
    
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
        use itertools::iterate;
        use utils::{shred,Average,FMax,Glyph};
        use dist;
        use dist::Distribution;

        mod err {
            pub const EMPTY_KEYSPACE:&str = "Encountered Empty Keyspace";
        }
        
        pub fn transform<IMG:Glyph,KEYCHAR:Glyph>
        (buf:&[IMG], key:&[KEYCHAR], comb: &impl Fn(&IMG,&KEYCHAR) -> IMG)
        -> Vec<IMG> {
            let keylen = key.len();
            buf
            .iter()
            .enumerate()
            .map(|(i,c)| comb(&c, &key[i % keylen]))
            .collect()
        }
        
        pub fn encrypt<IMG:Glyph,KEYCHAR:Glyph>
        (pt:&[IMG], key:&[KEYCHAR], comb: &impl Fn(&IMG,&KEYCHAR) -> IMG)
        -> Vec<IMG> {
            transform(&pt,&key,&comb)
        }

        pub fn decrypt<IMG:Glyph,KEYCHAR:Glyph>
        (ct:&[IMG], key:&[KEYCHAR], comb: &impl Fn(&IMG,&KEYCHAR) -> IMG)
        -> Vec<IMG> {
            transform(&ct,&key,&comb)
        }

        pub fn key_len_score<IMG:Glyph>(ct:&[IMG],n:&usize) -> f64 {
            let indices_of_coincidence:Vec<f64> = 
                shred(&ct.iter(),*n)
                .iter()
                .map(|shred|
                    dist::from_sample(
                        & shred.clone().cloned().collect::<Vec<IMG>>()
                    ).index_of_coincidence()
                ).collect();
            indices_of_coincidence.iter().average()
        }
        pub fn guess_key_length<IMG:Glyph>(ct:&[IMG]) -> usize {
            let max_checked_len = (ct.len() as f64 / 5.0).floor() as usize;
            iterate(1, |keylen| keylen+1)
            .take_while(|&keylen| keylen < max_checked_len)
            .collect::<Vec<usize>>().iter() //TODO: Get rid of this
            .fmax(&|keylen:&usize| key_len_score(&ct,keylen))
            .clone()
        }

 
        pub fn simple_xor_break<'a,IMG,KEYCHAR> (   
        ct:         &       [IMG],
        ptspace:    &       Distribution<IMG>,
        keyspace:   &'a     Distribution<KEYCHAR>, 
        comb:       &       impl Fn(&IMG,&KEYCHAR) -> IMG)   
        ->          Result<(&'a KEYCHAR, Vec<IMG>),&'static str>
        where IMG: Glyph, KEYCHAR: Glyph {
            keyspace
            .probabilities()
            .into_iter()
            .map(|(k,_)| { 
                let kv:Vec<KEYCHAR> = once(k).cloned().collect(); 
                (k,decrypt(&ct, &kv, &comb))
            }).min_by(|(_,c1),(_,c2)| 
                dist::surprisecmp(&ptspace.surprise(c1),&ptspace.surprise(c2))
            ).ok_or(err::EMPTY_KEYSPACE)
        }

    }
}


pub mod dist {
    use std::cmp::*;
    use std::collections::*;
    use std::iter::*;
    use itertools::Itertools;
    use utils::{fcmp,Glyph};
    use counter::Counter;

    mod err {
        pub const INFINITE_SURPRISE:&str = 
            "Encountered infinitely surprising event";
        pub const UNEXPECTED_ERROR:&str =
            "A function returned an unexpected error.";
    }


    pub trait Distribution<IMG:Glyph> {
        fn probabilities(&self) -> &HashMap<IMG,f64>;
    /*
        fn outcomes<'a>(&'a self) -> &'a [&'a IMG] {
            &
            self.probabilities()
            .into_iter()
            .map(|(x,_p)| x)
            .collect::<Vec<&'a IMG>>()
        }

        */

        fn get(&self, key:&IMG) -> Option<f64> {
            self.probabilities().get(key).cloned()
        }

        fn index_of_coincidence(&self) -> f64 {
            self.probabilities().iter().map(|(_,p)| p.powf(2.0)).sum()
        }

        //fn pointwise(&self, f: Fn(IMG)->IMG) -> impl Distribution {
        //}
        fn surprise(&self, events:&[IMG]) -> Result<f64,&'static str> {
            events
            .iter()
            .map(|e| 
                self.probabilities()
                .get(e)
            ).fold_options(0.0, |a,b:&f64| a+b.recip().log(2.0))
            .ok_or(err::INFINITE_SURPRISE)
        }

        fn display(&self) -> String {
            let p_disp = |(i,p):(&IMG,&f64)| format!("Item '{}' with probability {}", i, p);
            let items = self.probabilities().iter().map(p_disp);
            once(String::from("Distribution {"))
            .chain(items)
            .intersperse(String::from("\n"))
            .chain(once(String::from("}")))
            .collect()
        }


    }



    pub fn surprisecmp(sup1:&Result<f64,&str>,sup2:&Result<f64,&str>) 
    -> Ordering {
        use self::err::{INFINITE_SURPRISE, UNEXPECTED_ERROR};
        match (sup1,sup2) {
            (Ok(x1), Ok(x2)) => fcmp(*x1,*x2),
            (Err(INFINITE_SURPRISE), Ok(_x2)) => Ordering::Greater,
            (Ok(_x1), Err(INFINITE_SURPRISE)) => Ordering::Less,
            (Err(INFINITE_SURPRISE), Err(INFINITE_SURPRISE)) => Ordering::Equal,
            _ => panic!(UNEXPECTED_ERROR) 
        }
    }

    //Maybe impl these as From<T> trait?


    pub fn from<IMG:Glyph>(v:&[(IMG,f64)]) -> impl Distribution<IMG> {
        _Distribution {
            probabilities : v.into_iter().cloned().collect::<HashMap<IMG,f64>>()
        }
    }
 
    pub fn from_sample<IMG:Glyph>(v:&[IMG]) -> impl Distribution<IMG> {
        from( 
            &v
            .iter()
            .cloned() //else we get a Counter<&IMG>
            .collect::<Counter<IMG>>()
            .most_common_ordered()
            .into_iter()
            .map(|(x,count)| (
                x,
                count as f64 / v.len() as f64
            )).collect::<Vec<(IMG,f64)>>()
        )
    }

    pub fn uniform<IMG: Glyph>(v:&[IMG]) -> impl Distribution<IMG> {
        let p = (v.len() as f64).recip();
        from(&v.iter().cloned().zip(repeat(p)).collect::<Vec<(IMG,f64)>>())
    }

    struct _Distribution<IMG> where IMG: Glyph {
        probabilities : HashMap<IMG,f64>
    }
    
    impl<IMG> Distribution<IMG> for _Distribution<IMG> where IMG: Glyph {
        fn probabilities(&self) -> &HashMap<IMG,f64> {
            &self.probabilities
        }
    }

    pub mod known {

        pub const SHAKESPEARE:[(char,f64);91] = [
            (' ', 0.237_062_444_956_660_62),
            ('e', 0.074_130_862_579_396_6),
            ('t', 0.053_126_498_319_317_414),
            ('o', 0.051_553_818_393_209_924),
            ('a', 0.044_825_042_106_379_775),
            ('h', 0.040_014_297_756_457_76),
            ('n', 0.039_559_569_008_018_94),
            ('s', 0.039_386_251_765_463_294),
            ('r', 0.038_271_598_378_879_19),
            ('i', 0.036_309_412_683_561_006),
            ('l', 0.026_778_246_817_310_985),
            ('d', 0.024_509_732_972_359_564),
            ('\n', 0.022_801_660_401_168_957),
            ('u', 0.021_035_876_485_998_403),
            ('m', 0.017_511_270_659_058_054),
            ('y', 0.015_622_552_420_679_421),
            (',', 0.015_238_359_759_327_207),
            ('.', 0.014_295_008_298_524_843),
            ('w', 0.013_354_954_628_807_049),
            ('f', 0.012_605_439_999_530_98),
            ('c', 0.012_217_949_547_094_197),
            ('g', 0.010_449_417_472_686_504),
            ('I', 0.010_224_251_625_856_808),
            ('b', 0.008_527_171_691_614_762),
            ('p', 0.008_523_873_900_530_193),
            ('A', 0.008_150_307_454_894_921),
            ('E', 0.007_801_657_653_009_72),
            ('T', 0.007_291_782_509_212_288),
            ('S', 0.006_231_176_254_291_938),
            ('v', 0.006_227_145_620_744_132),
            ('O', 0.006_084_241_340_412_836),
            ('\'', 0.005_692_170_622_580_818),
            ('k', 0.005_351_948_509_022_848),
            ('R', 0.005_307_611_539_996_984),
            ('N', 0.005_008_611_814_996_119),
            ('L', 0.004_371_038_871_979_566_5),
            ('C', 0.003_938_478_608_053_682_5),
            ('H', 0.003_382_434_389_072_292_7),
            (';', 0.003_151_039_381_305_078_7),
            ('W', 0.003_022_242_318_391_103),
            ('M', 0.002_907_918_894_126_066),
            ('D', 0.002_873_292_087_738_098_4),
            ('B', 0.002_823_825_221_469_572_6),
            ('U', 0.002_588_582_790_770_362_2),
            ('P', 0.002_187_351_542_147_877),
            ('F', 0.002_145_945_942_974_963),
            ('G', 0.002_045_363_314_895_627_5),
            ('?', 0.001_919_314_411_218_792_2),
            ('Y', 0.001_667_033_393_249_311_6),
            ('!', 0.001_620_314_686_217_926_5),
            ('-', 0.001_479_242_512_044_723_9),
            ('K', 0.001_135_172_975_554_757_2),
            ('x', 0.000_858_891_366_914_251_3),
            ('V', 0.000_655_894_004_597_487_2),
            ('j', 0.000_496_867_190_074_967_9),
            ('q', 0.000_440_438_320_405_686_9),
            ('[', 0.000_381_994_133_962_503),
            (']', 0.000_380_528_449_036_028_2),
            ('J', 0.000_378_696_342_877_934_63),
            (':', 0.000_334_725_795_083_689_7),
            ('Q', 0.000_215_822_105_423_418_97),
            ('z', 0.000_201_348_466_774_48),
            ('9', 0.000_173_683_663_787_267_55),
            ('1', 0.000_170_019_451_471_080_48),
            (')', 0.000_115_239_477_344_083_64),
            ('(', 0.000_115_056_266_728_274_29),
            ('X', 0.000_111_025_633_180_468_51),
            ('Z', 0.000_097_468_047_610_576_31),
            ('"', 0.000_086_108_989_430_396_36),
            ('<', 0.000_085_742_568_198_777_65),
            ('>', 0.000_080_795_881_571_925_1),
            ('2', 0.000_067_055_085_386_223_55),
            ('3', 0.000_060_459_503_217_086_81),
            ('0', 0.000_054_779_974_126_996_84),
            ('4', 0.000_017_038_587_270_269_92),
            ('5', 0.000_015_023_270_496_367_025),
            ('_', 0.000_013_007_953_722_464_131),
            ('*', 0.000_011_542_268_795_989_3),
            ('6', 0.000_011_542_268_795_989_3),
            ('7', 0.000_007_511_635_248_183_512),
            ('8', 0.000_007_328_424_632_374_159),
            ('|', 0.000_006_045_950_321_708_681),
            ('&', 0.000_003_847_422_931_996_433_5),
            ('@', 0.000_001_465_684_926_474_831_8),
            ('/', 0.000_000_916_053_079_046_769_8),
            ('}', 0.000_000_366_421_231_618_707_95),
            ('`', 0.000_000_183_210_615_809_353_98),
            ('#', 0.000_000_183_210_615_809_353_98),
            ('~', 0.000_000_183_210_615_809_353_98),
            ('%', 0.000_000_183_210_615_809_353_98),
            ('=', 0.000_000_183_210_615_809_353_98)
            ];
    }
}

mod utils {
    use std::ops::{Add,Div,Mul};
    use itertools::{Itertools,iterate};
    use std::cmp::Ordering;
    use std::fmt::{Display,Debug};
    use std::hash::Hash;

        
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

    //Change into trait so we can v.shreds(3)
    //Maybe a more descriptive name?
    pub fn shred<'a,X:'a>(s: &impl Iter<&'a X>, m: usize) -> Vec<impl Iter<&'a X>> {
        iterate(0, |i| i+1)
        .take(m)
        .map(|r| 
            s
            .clone() //Need to construct m iterators from one
            .dropping(r)
            .step(m)
        ).collect()
    }

    
    #[allow(dead_code)]    
    pub fn approx_equal(target:f64,result:f64) -> bool {
        (result-target).abs() < std::f64::EPSILON
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
}




#[cfg(test)]
mod tests {
    use utils;
    use utils::{Average,FMax};
    use dist;
    use dist::Distribution;
    use crypto::{vigenere,chrxor};
    use std::iter::repeat;
    use itertools::{iterate};
    
    #[test]
    fn shred_test() {
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
            utils::shred(&v.iter(),3)
            .into_iter()
            .map(|shred| shred.cloned().collect())
            .collect();
        assert_eq!(shreds1,shreds2);
    }

    #[test]
    fn coincidence_test() {
        let ud = dist::uniform(&iterate(0, |x| x+1).take(10).collect::<Vec<i32>>());
        assert!(
            utils::approx_equal(
                ud.index_of_coincidence(),
                0.1
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
                *computed_dist.probabilities().get(&4).unwrap(),
                0.4
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
        let pt_initial = vec!['h', 'e', 'l', 'l', 'o', 'w', 'o','r', 'l', 'd'];
        let key = vec!['k', 'e', 'y'];
        let ct = vigenere::encrypt(&pt_initial,&key,&chrxor);
        let pt_final = vigenere::decrypt(&ct,&key,&chrxor);
        assert_eq!(pt_initial, pt_final);
    }

    #[test]
    fn guess_keylen_test() {
        let pt:Vec<char> = repeat('A').take(80).collect();        
        let key = vec!['i', 'a', 'm', 'a', 'k', 'e', 'y'];
        let ct = vigenere::encrypt(&pt,&key,&chrxor);
        let g_klen = vigenere::guess_key_length(&ct);
        assert_eq!(g_klen, key.len());
    }

    use dist::known::SHAKESPEARE;
    #[test]
    fn compile_distribution_test() {
        let d = dist::from(&SHAKESPEARE);
        utils::approx_equal(
            *d.probabilities().get(&'a').unwrap(), 
            0.044825042106379775
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
        let pt:Vec<char> = 
            "It was the best of times, it was the worst of times."
            .chars().collect();
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


}


fn main() {
}
