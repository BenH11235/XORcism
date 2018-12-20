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

use crypto::vigenere;
use std::fs::File;
use std::io::{Read,Write};
use err::ok_or_exit;
use cli::GetArg;

    mod err {
        use std::fmt::Display;
        use std::fs::File;

        pub const SHOULD_NOT_REACH_HERE:&str = 
            "Execution should very definitely not have reached where it did";

        pub fn exit<T:Display>(e:T) {
            println!("Error: {}", e);
            std::process::exit(1);
        }

        pub fn ok_or_exit<T,E:Display>(res:Result<T,E>) -> T {
            match res {
                Ok(x) => Some(x),
                Err(e) => {exit(e); None}
            }.expect(SHOULD_NOT_REACH_HERE)
        }

    }


fn main() -> Result<(),String> {
        
    let args = cli::args();
        
    let ciphertext = 
        File::open(args.get("input_file_name")?)
        .map_err(|e| format!("Could not open input file: {}",e))?
        .bytes()
        .collect::<Result<Vec<u8>,std::io::Error>>()
        .map_err(|e| format!("Could not read input file: {}",e))?;
        
    let pt_dist =  builtin::dist::by_name(args.get("plaintext_distribution")?)?;
    let key_dist = builtin::dist::by_name(args.get("key_distribution")?)?;
    let comb_func = builtin::comb::by_name(args.get("combination_function")?)?;

    let solutions = 
        vigenere::full_break(&ciphertext, &pt_dist, &key_dist, &comb_func)
        .map_err(|e| format!("Break attempt failed: {}", e))?;
    
    File::create(args.get("output_file_name")?)
    .map_err(|e| format!("Could not create output file: {}", e))?
    .write_all(&solutions.clone().next().unwrap().unwrap());

    Ok(())
    
}
