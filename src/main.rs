extern crate itertools;
extern crate counter;


/*
fn vigenere_attack<G>(
ct: impl Iterator<Item=G>, 
ptd: impl Distribution<G>
) -> Vec<G> {
    ct
    .shred(guess_key_length(&ct))
    .map(|shred| freq_xor_attack(shred,ptd))
    .mend()
}
*/


//TODO: Add error handling for case of infinite surprise

pub mod crypto {
    
    pub fn chrxor(c1:&char, c2:&char) -> char {
        ((*c1 as u8) ^ (*c2 as u8)) as char
    }

    pub fn strxor(s1:&String,s2:&String) -> String {
        s1.chars().zip(s2.chars())
        .map(|(c1,c2)| chrxor(&c1,&c2))
        .collect()
    }
    
    pub mod vigenere {
        use std::iter::once;
        use itertools::iterate;
        use utils::{shred,Average,FMax};
        use std::hash::Hash;
        use dist;
        use dist::Distribution;

        mod err {
            pub const EMPTY_KEYSPACE:&str = "Encountered Empty Keyspace";
        }
        
        pub fn transform
        <IMG:Clone+Ord+Hash,KEYCHAR:Clone+Ord+Hash>
        (buf:&Vec<IMG>, key:&Vec<KEYCHAR>, comb: &impl Fn(&IMG,&KEYCHAR) -> IMG)
        -> Vec<IMG> {
            let keylen = key.len();
            buf
            .iter()
            .enumerate()
            .map(|(i,c)| comb(&c, &key[i % keylen]))
            .collect()
        }
        
        pub fn encrypt
        <IMG:Clone+Ord+Hash,KEYCHAR:Clone+Ord+Hash>
        (pt:&Vec<IMG>, key:&Vec<KEYCHAR>, comb: &impl Fn(&IMG,&KEYCHAR) -> IMG)
        -> Vec<IMG> {
            transform(&pt,&key,&comb)
        }

        pub fn decrypt
        <IMG:Clone+Ord+Hash,KEYCHAR:Clone+Ord+Hash>
        (ct:&Vec<IMG>, key:&Vec<KEYCHAR>, comb: &impl Fn(&IMG,&KEYCHAR) -> IMG)
        -> Vec<IMG> {
            transform(&ct,&key,&comb)
        }

        pub fn key_len_score<IMG:Clone+Ord+Hash>(ct:&Vec<IMG>,n:&usize) -> f64 {
            let indices_of_coincidence:Vec<f64> = 
                shred(ct.iter(),*n)
                .iter()
                .map(|shred|
                    dist::from_sample(
                        & shred.clone().collect()
                    ).index_of_coincidence()
                ).collect();
            indices_of_coincidence.iter().average()
        }
        pub fn guess_key_length<IMG:Clone+Ord+Hash>(ct:&Vec<IMG>) -> usize {
            let max_checked_len = (ct.len() as f64 / 5.0).floor() as usize;
            iterate(1, |keylen| keylen+1)
            .take_while(|&keylen| keylen < max_checked_len)
            .collect::<Vec<usize>>().iter() //TODO: Get rid of this
            .fmax(&|keylen:&usize| key_len_score(&ct,keylen))
            .clone()
        }
 
        pub fn simple_xor_break<'a,IMG,KEYCHAR> (   
        ct:         &       Vec<IMG>,
        ptspace:    &       Distribution<IMG>,
        keyspace:   &'a     Distribution<KEYCHAR>, 
        comb:       &       impl Fn(&IMG,&KEYCHAR) -> IMG)   
        ->          Result<(&'a KEYCHAR, Vec<IMG>),&'static str>
        where
        IMG:        Clone+Ord+Hash,
        KEYCHAR:    Clone+Ord+Hash {
            keyspace
            .outcomes()
            .into_iter()
            .map(|k| { 
                let kv:Vec<KEYCHAR> = once(k).cloned().collect(); 
                (k,decrypt(&ct, &kv, &comb))
            }).min_by(|(_,c1),(_,c2)| 
                dist::surprisecmp(&ptspace.surprise(c1),&ptspace.surprise(c2))
            ).ok_or(err::EMPTY_KEYSPACE)
        }

    }
}


pub mod dist {
    use std::clone::*;
    use std::cmp::*;
    use std::hash::*;
    use std::collections::*;
    use std::iter::*;
    use itertools::Itertools;
    use utils::fcmp;
    use counter::Counter;

    mod err {
        pub const INFINITE_SURPRISE:&str = 
            "Encountered infinitely surprising event";
        pub const UNEXPECTED_ERROR:&str =
            "A function returned an unexpected error.";
    }


    pub trait Distribution<IMG:Eq+Hash+Clone> {
        fn probabilities(&self) -> &HashMap<IMG,f64>;

        fn outcomes(&self) -> Vec<&IMG> {
            self.probabilities()
            .iter()
            .map(|(x,_p)| x)
            .collect()
        }

        fn get(&self, key:&IMG) -> Option<f64> {
            self.probabilities().get(key).cloned()
        }

        fn index_of_coincidence(&self) -> f64 {
            self.probabilities().iter().map(|(_,p)| p.powf(2.0)).sum()
        }

        //fn pointwise(&self, f: Fn(IMG)->IMG) -> impl Distribution {
        //}
        fn surprise(&self, events:&Vec<IMG>) -> Result<f64,&'static str> {
            events
            .iter()
            .map(|e| 
                self.probabilities()
                .get(e)
            ).fold_options(0.0, |a,b:&f64| a+b.recip().log(2.0))
            .ok_or(err::INFINITE_SURPRISE)
        }


    }



    pub fn surprisecmp(sup1:&Result<f64,&str>,sup2:&Result<f64,&str>) 
    -> Ordering {
        use self::err::{INFINITE_SURPRISE, UNEXPECTED_ERROR};
        match (sup1,sup2) {
            (Ok(x1), Ok(x2)) => fcmp(&x1,&x2),
            (Err(INFINITE_SURPRISE), Ok(_x2)) => Ordering::Greater,
            (Ok(_x1), Err(INFINITE_SURPRISE)) => Ordering::Less,
            (Err(INFINITE_SURPRISE), Err(INFINITE_SURPRISE)) => Ordering::Equal,
            _ => panic!(UNEXPECTED_ERROR) 
        }
    }

    //Maybe impl these as From<T> trait?

   
    pub fn from<IMG:Eq+Hash+Clone>(v:&[(IMG,f64)]) -> impl Distribution<IMG> {
        from_vector(v.iter().cloned().collect())
    }


    fn from_vector<IMG:Eq+Hash+Clone>(v:Vec<(IMG,f64)>) -> impl Distribution<IMG> {
        _Distribution {
            probabilities : v.into_iter().collect::<HashMap<IMG,f64>>()
        }
    }
 
    pub fn from_sample<IMG:Eq+Hash+Clone+Ord>(v:&Vec<IMG>) -> impl Distribution<IMG> {
        from_vector( 
            v
            .iter()
            .cloned() //else we get a Counter<&IMG>
            .collect::<Counter<IMG>>()
            .most_common_ordered()
            .into_iter()
            .map(|(x,count)| (
                x,
                count as f64 / v.len() as f64
            )).collect()
        )
    }

    pub fn uniform<IMG:Eq+Hash+Clone>(v:Vec<IMG>) -> impl Distribution<IMG> {
        let p = (v.len() as f64).recip();
        from_vector(v.into_iter().zip(repeat(p)).collect())
    }

    
    struct _Distribution<IMG> {
        probabilities : HashMap<IMG,f64>
    }
    
    impl<IMG> Distribution<IMG> for _Distribution<IMG> where IMG:Eq+Hash+Clone {
        fn probabilities(&self) -> &HashMap<IMG,f64> {
            &self.probabilities
        }
    }

    pub mod known {

        pub const SHAKESPEARE:[(char,f64);91] = [
            (' ', 0.23706244495666062),
            ('e', 0.0741308625793966),
            ('t', 0.053126498319317414),
            ('o', 0.051553818393209924),
            ('a', 0.044825042106379775),
            ('h', 0.04001429775645776),
            ('n', 0.03955956900801894),
            ('s', 0.039386251765463294),
            ('r', 0.03827159837887919),
            ('i', 0.036309412683561006),
            ('l', 0.026778246817310985),
            ('d', 0.024509732972359564),
            ('\n', 0.022801660401168957),
            ('u', 0.021035876485998403),
            ('m', 0.017511270659058054),
            ('y', 0.015622552420679421),
            (',', 0.015238359759327207),
            ('.', 0.014295008298524843),
            ('w', 0.013354954628807049),
            ('f', 0.01260543999953098),
            ('c', 0.012217949547094197),
            ('g', 0.010449417472686504),
            ('I', 0.010224251625856808),
            ('b', 0.008527171691614762),
            ('p', 0.008523873900530193),
            ('A', 0.008150307454894921),
            ('E', 0.00780165765300972),
            ('T', 0.007291782509212288),
            ('S', 0.006231176254291938),
            ('v', 0.006227145620744132),
            ('O', 0.006084241340412836),
            ('\'', 0.005692170622580818),
            ('k', 0.005351948509022848),
            ('R', 0.005307611539996984),
            ('N', 0.005008611814996119),
            ('L', 0.0043710388719795665),
            ('C', 0.0039384786080536825),
            ('H', 0.0033824343890722927),
            (';', 0.0031510393813050787),
            ('W', 0.003022242318391103),
            ('M', 0.002907918894126066),
            ('D', 0.0028732920877380984),
            ('B', 0.0028238252214695726),
            ('U', 0.0025885827907703622),
            ('P', 0.002187351542147877),
            ('F', 0.002145945942974963),
            ('G', 0.0020453633148956275),
            ('?', 0.0019193144112187922),
            ('Y', 0.0016670333932493116),
            ('!', 0.0016203146862179265),
            ('-', 0.0014792425120447239),
            ('K', 0.0011351729755547572),
            ('x', 0.0008588913669142513),
            ('V', 0.0006558940045974872),
            ('j', 0.0004968671900749679),
            ('q', 0.0004404383204056869),
            ('[', 0.000381994133962503),
            (']', 0.0003805284490360282),
            ('J', 0.00037869634287793463),
            (':', 0.0003347257950836897),
            ('Q', 0.00021582210542341897),
            ('z', 0.00020134846677448),
            ('9', 0.00017368366378726755),
            ('1', 0.00017001945147108048),
            (')', 0.00011523947734408364),
            ('(', 0.00011505626672827429),
            ('X', 0.00011102563318046851),
            ('Z', 9.746804761057631e-05),
            ('"', 8.610898943039636e-05),
            ('<', 8.574256819877765e-05),
            ('>', 8.07958815719251e-05),
            ('2', 6.705508538622355e-05),
            ('3', 6.045950321708681e-05),
            ('0', 5.477997412699684e-05),
            ('4', 1.703858727026992e-05),
            ('5', 1.5023270496367025e-05),
            ('_', 1.3007953722464131e-05),
            ('*', 1.15422687959893e-05),
            ('6', 1.15422687959893e-05),
            ('7', 7.511635248183512e-06),
            ('8', 7.328424632374159e-06),
            ('|', 6.045950321708681e-06),
            ('&', 3.8474229319964335e-06),
            ('@', 1.4656849264748318e-06),
            ('/', 9.160530790467698e-07),
            ('}', 3.6642123161870795e-07),
            ('`', 1.8321061580935398e-07),
            ('#', 1.8321061580935398e-07),
            ('~', 1.8321061580935398e-07),
            ('%', 1.8321061580935398e-07),
            ('=', 1.8321061580935398e-07)
            ];
    }
}

mod utils {
    use std::ops::{Add,Div,Mul};
    use itertools::{Itertools,iterate};
    use std::cmp::Ordering;

        
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
    pub fn shred<'a,X:'a>(s: impl Iter<&'a X>, m: usize) -> Vec<impl Iter<&'a X>> {
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
    pub fn approx_equal(target:&f64,result:&f64) -> bool {
        (result-target).abs() / result < 0.001
    }


    pub fn fcmp(x:&f64,y:&f64) -> Ordering {
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
                if f1 == f2 {
                    Ordering::Greater //default to earlier element in case of tie
                } else {
                    fcmp(&f1,&f2)
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
    use crypto;
    use crypto::{vigenere,chrxor};
    use std::iter::repeat;
    use itertools::{assert_equal,iterate};
    
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
            utils::shred(v.iter(),3)
            .into_iter()
            .map(|shred| shred.cloned().collect())
            .collect();
        assert_eq!(shreds1,shreds2);
    }

    #[test]
    fn coincidence_test() {
        let ud = dist::uniform(iterate(0, |x| x+1).take(10).collect());
        assert!(
            utils::approx_equal(
                &ud.index_of_coincidence(),
                &0.1
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
                computed_dist.probabilities().get(&4).unwrap(),
                &0.4
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
            d.probabilities().get(&'a').unwrap(), 
            &0.044825042106379775
        );
    }
    
}




fn main() {
}

