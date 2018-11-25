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

mod crypto {
    
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
        use utils::{shred,Iter,Average,fcmp};
        use std::cmp::Ordering;
        use std::hash::Hash;
        use dist;
        use dist::Distribution;
        
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
            let max_checked_keylen = (ct.len() as f64 / 5.0).floor() as usize;
            (1_usize..=max_checked_keylen)
            .max_by(|i1,i2| {
                    let score1 = key_len_score(ct,i1);
                    let score2 = key_len_score(ct,i2);
                    if score1 == score2 {
                        Ordering::Greater //shorter key size breaks tie
                    } else {
                        fcmp(&score1,&score2).unwrap()
                    }
            }).unwrap()
        }

 
        pub fn simple_xor_break<'a,IMG,KEYCHAR> (   
        ct:         &       Vec<IMG>,
        ptspace:    &       Distribution<IMG>,
        keyspace:   &'a     Distribution<KEYCHAR>, 
        comb:       &       impl Fn(&IMG,&KEYCHAR) -> IMG)   
        ->          (&'a KEYCHAR, Vec<IMG>)
        where
        IMG:        Clone+Ord+Hash,
        KEYCHAR:    Clone+Ord+Hash {
            keyspace
            .outcomes()
            .into_iter()
            .map(|k| { 
                let kv:Vec<KEYCHAR> = once(k).cloned().collect(); 
                (k,decrypt(&ct, &kv, &comb))
            })
            .min_by(|(k1,c1),(k2,c2)| {
                let sup1 = ptspace.surprise(c1);
                let sup2 = ptspace.surprise(c2);
                fcmp(&sup1,&sup2).unwrap()
            }).unwrap()
        }

    }
}


mod dist {
    use std::clone::*;
    use std::cmp::*;
    use std::hash::*;
    use std::collections::*;
    use std::iter::*;
    use utils::Iter;
    use counter::Counter;

    pub trait Distribution<IMG:Eq+Hash+Clone> {
        fn probabilities(&self) -> &HashMap<IMG,f64>;

        fn outcomes(&self) -> Vec<&IMG> {
            self.probabilities()
            .iter()
            .map(|(x,p)| x)
            .collect()
        }

        fn index_of_coincidence(&self) -> f64 {
            self.probabilities().iter().map(|(_,p)| p.powf(2.0)).sum()
        }

        //fn pointwise(&self, f: Fn(IMG)->IMG) -> impl Distribution {
        //}
        fn surprise(&self, events:&Vec<IMG>) -> f64 {
            events
            .iter()
            .map(|e| 
                self.probabilities()
                .get(e).unwrap()
            ).fold(0.0, |a,b:&f64| a+b.recip().log(2.0))
        }
    }
    

    pub fn from_vector<IMG:Eq+Hash+Clone>(v:Vec<(IMG,f64)>) -> impl Distribution<IMG> {
        _Distribution {
            probabilities : v.into_iter().collect::<HashMap<IMG,f64>>()
        }
    }
 
    pub fn from_sample<IMG:Eq+Hash+Clone+Ord>(v:&Vec<IMG>) -> impl Distribution<IMG> {
        let N = v.len() as f64;
        from_vector( 
            v
            .iter()
            .cloned()
            .collect::<Counter<_>>()
            .most_common_ordered()
            .into_iter()
            .map(|(x,n)| (x,(n as f64)/N))
            .collect()
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
}

mod utils {
    use std::marker::Sized;
    use std::ops::{Add,Div,Mul};
    use std::iter::Sum;
    use itertools::Itertools;
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
            T:Copy+Vector
    {
        fn average(&self) -> T {
            let (sum,len) = self.clone().fold(
                (T::from(0.0),0.0), 
                |(cur_sum,cur_len),&summand| (cur_sum+summand,cur_len+1.0)
            );
            sum / len
        }
    }

    pub fn shred<'a,X:'a>(s: impl Iter<&'a X>, m: usize) -> Vec<impl Iter<&'a X>> {
        (0..m)
        .map(|r|
            s
            .clone()
            .enumerate()
            .filter(move |(n,_)| (n % m) == r)
            .map(|(_,x)| x)
        ).collect()
    }
        
    pub fn approx_equal(target:&f64,result:&f64) -> bool {
        (result-target).abs() / result < 0.001
    }

    pub fn fcmp(x:&f64,y:&f64) -> Option<Ordering> {
        if x.is_nan() || y.is_nan() {
            None
        } else if x>y {
            Some(Ordering::Greater)
        } else if y>x {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Equal)
        }
    }

    /*

    pub trait MinByKeyF<T,KEY> {
        fn min_by_key_f(&self, KEY) -> T; 
    }

    impl<T,TV,KEY> MinByKeyF<T> for TV {
        fn min_by_float(&self, f:KEY) -> T 
        where 
        Key: Fn(T) -> f64,


        */

}



#[cfg(test)]
mod tests {
    use utils;
    use utils::Average;
    use dist;
    use dist::Distribution;
    use crypto;
    use crypto::{vigenere,chrxor};
    use itertools::assert_equal;
    
    #[test]
    fn shred_test() {
        let shreds1:Vec<Vec<u32>> = 
            (0..3)
            .map(|r| 
                 (0..10)
                 .map(|x| 3*x+r)
                 .collect()
            ).collect();
        let v:Vec<u32> = (0..30).collect();
        let shreds2:Vec<Vec<u32>> =
            utils::shred(v.iter(),3)
            .into_iter()
            .map(|shred| shred.cloned().collect())
            .collect();
        assert_eq!(shreds1,shreds2);
    }

    #[test]
    fn coincidence_test() {
        let ud = dist::uniform((0..10).collect());
        assert!(
            utils::approx_equal(
                &ud.index_of_coincidence(),
                &0.1
            )
        )
    }

    #[test]
    fn get_dist_from_sample_test() {
        let samples:Vec<i32> = (0..30).map(|x| (x*x) % 5).collect();
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
        let v:Vec<f64> = (0..10).map(|x| x as f64).collect();
        let ave = v.iter().average();
        assert_eq!(ave,4.5);
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
        let pt:Vec<char> = (0..80).map(|_| 'A').collect();        
        let key = vec!['i', 'a', 'm', 'a', 'k', 'e', 'y'];
        let ct = vigenere::encrypt(&pt,&key,&chrxor);
        let g_klen = vigenere::guess_key_length(&ct);
        assert_eq!(g_klen, key.len());
    }
    
}

fn main() {
}

