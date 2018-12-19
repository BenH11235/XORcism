#[macro_use]
extern crate derive_more;
extern crate itertools;
extern crate counter;
extern crate clap;


mod cli;
mod crypto;
mod dist;
mod builtin;
mod utils;

#[cfg(test)]
mod tests;

fn main() {

    mod err {

        use std::process::exit;
        use std::fmt::Display;
        use std::fs::File;

        pub fn quit<T:Display>(e:T) {
            println!("Error: {}", e);
            exit(1);
        }

    }
    use crypto::vigenere;
    use std::fs::File;
    use std::io::{Read,Write};
    
    let args = cli::args();


    let getarg = |argname| {
        match args.value_of(argname) {
            Some(arg) => Some(arg),
            None => {
                let msg = format!("missing argument {} despite CLI guarantee",argname);
                err::quit(msg);
                None
            }
        }.unwrap()
    };
              
    let ptspace =   builtin::dist::by_name(getarg("plaintext_distribution"));
    let keyspace =  builtin::dist::by_name(getarg("key_distribution"));
    let comb =      builtin::comb::by_name(getarg("combination_function"));
    let input_file_name = getarg("input_file");
    let output_file_name = getarg("output_file");
    
    let input_file = match File::open(input_file_name) {
        Ok(x) => Some(x),
        Err(e) => {err::quit(e); None}
    }.unwrap();

    let mut output_file = match File::create(output_file_name) {
        Ok(x) => Some(x),
        Err(e) => {err::quit(e); None}
    }.unwrap();

    let ct: Vec<u8> = 
        input_file.bytes().collect::<Result<Vec<u8>,std::io::Error>>().unwrap();

    let solutions = 
        vigenere::full_break(&ct, &ptspace, &keyspace, &comb).unwrap();

    output_file.write_all(&solutions.clone().next().unwrap().unwrap());
    
}
