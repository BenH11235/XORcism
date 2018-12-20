use utils;
use utils::{Average,FMax,ZipN,UnzipN,xor,add};
use dist;
use dist::{Prob,Distribution,binomial_p_estimate,kappa};
use dist::known::{SHAKESPEARE,HEX,BASE64,UNIFORM};
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
    let ct = vigenere::encrypt(pt_initial,key,&xor);
    let pt_final = vigenere::decrypt(&ct,key,&xor);
    assert_eq!(pt_initial.to_vec(), pt_final);
}

#[test]
fn guess_keylen_test() {
    let key = b"longerkey";
    let pt = SAMPLE_TEXT;
    let ct = vigenere::encrypt(pt,key,&xor);
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
    let keyspace = dist::from(&UNIFORM);
    let (key2, pt2) = 
        vigenere::simple_xor_break(&ct,&ptspace,&keyspace,&xor)
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
    let keyspace = dist::from(&UNIFORM);
    let pt2 = 
        vigenere::full_break(&ct, &ptspace, &keyspace, &xor)
        .unwrap().next().unwrap().unwrap();
    assert_eq!(pt.to_vec(), pt2);
}

#[test]
fn full_break_add_test() {
    let pt = SAMPLE_TEXT;
    let key = b"key";
    let ct = vigenere::encrypt(pt,key,&add);
    let ptspace = dist::from(&SHAKESPEARE);
    let keyspace = dist::from(&UNIFORM);
    let pt2 = 
        vigenere::full_break(&ct, &ptspace, &keyspace, &add)
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
    let keyspace = dist::from(&UNIFORM);
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

