use std::ops::{Add,Div,Mul};
use itertools::{Itertools,iterate};
use std::cmp::Ordering;
use std::fmt::{Display,Debug};
use std::collections::HashSet;
use std::hash::Hash;
use std::f64::EPSILON;
use itertools::Step;

//these take arguments by reference so 'Vigenere Compose'
//of non-copy types can have the same prototype

pub fn xor(x1:&u8,x2:&u8) -> u8 {
    x1 ^ x2
}

pub fn add(x1:&u8,x2:&u8) -> u8 {
    ((u32::from(*x1) + u32::from(*x2)) % 256) as u8
}

pub fn with_preceding_divisors<'a>(nums: impl Iter<&'a usize>+Clone) 
-> impl Iter<(&'a usize,usize)> {
    nums.clone()
    .enumerate()
    .map(move |(i,x)|
         (
            x,
            nums.clone()
            .take(i)
            .filter(|y| x % *y == 0)
            .count()
        )
    )
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

pub trait Glyph: Eq+Hash+Clone+Ord+Display+Debug+Send+Sync {}
impl<T> Glyph for T where T:Eq+Hash+Clone+Ord+Display+Debug+Send+Sync {}

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

pub struct _QuickUnique<T,TI> 
where T:Eq+Hash+Clone, TI: Iterator<Item=T> {
    iter: TI,
    seen: HashSet<T>
}

pub trait QuickUnique<T,TI>
where T:Eq+Hash+Clone, TI: Iterator<Item=T> {
    fn unique(self) -> _QuickUnique<T,TI>;
}

impl<T,TI> QuickUnique<T,TI> for TI 
where T:Eq+Hash+Clone, TI: Iterator<Item=T> {
    fn unique(self) -> _QuickUnique<T,TI> {
        _QuickUnique { iter:self, seen:HashSet::new() }
        }
}

impl<T,TI> Iterator for _QuickUnique<T,TI>
where T:Eq+Hash+Clone, TI: Iterator<Item=T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        loop {
            let _candidate = self.iter.next();
            match _candidate {
                None => {
                    return None;
                } Some(candidate) => {
                    if !self.seen.contains(&candidate) {
                        self.seen.insert(candidate.clone());
                        return Some(candidate);
                    }
                }
            }
        }
    }
}

