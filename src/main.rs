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
    use crypto::vigenere;
    use std::fs::File;
    use std::io::{Read,Write};
    
    let args = cli::args();
    
    let ptspace = 
        builtin::dist::by_name(args.value_of("plaintext_distribution").unwrap());
    let keyspace =     
        builtin::dist::by_name(args.value_of("key_distribution").unwrap());
    let comb = 
        builtin::comb::by_name(args.value_of("combination_function").unwrap());
    let input_file_name = 
        args.value_of("input_file").unwrap();
    let output_file_name =
        args.value_of("output_file").unwrap();
    
    let mut input_file = File::open(input_file_name).unwrap();
    let ct: Vec<u8> = input_file.bytes().collect::<Result<Vec<u8>,std::io::Error>>().unwrap();

    let solutions = 
        vigenere::full_break(&ct, &ptspace, &keyspace, &comb).unwrap();

    let mut output_file = File::create(output_file_name).unwrap();
    output_file.write_all(&solutions.clone().next().unwrap().unwrap());
    
}
