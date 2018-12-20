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
use std::io::{self,Read,Write};
use cli::GetArg;
use itertools::Itertools;

fn main() -> Result<(),String> {
    let args = cli::args();
        
    let ciphertext = 
        File::open(args.get("input_file")?)
        .map_err(|e| format!("Failed to open input file: {}",e))?
        .bytes()
        .collect::<Result<Vec<u8>,std::io::Error>>()
        .map_err(|e| format!("Failed to read input file: {}",e))?;
        
    let pt_dist =  builtin::dist::by_name(args.get("plaintext_distribution")?)?;
    let key_dist = builtin::dist::by_name(args.get("key_distribution")?)?;
    let comb_func = builtin::comb::by_name(args.get("combination_function")?)?;

    let mut chosen_solution: Result<Vec<u8>,&'static str> = 
        Err("None of the proposed solutions were accepted.");
    let mut cmd: String = String::new();

    let solutions = 
        vigenere::full_break(&ciphertext, &pt_dist, &key_dist, &comb_func)
        .map_err(|e| format!("Failed to break ciphertext: {}", e))?
        .dedup();

    let stdin = io::stdin();
    'choose_solution: for solution in solutions {
        let proposed_solution = 
            solution
            .map_err(|e| 
                format!("Failed to compute possible solution: {}",e)
            )?;

        println!("Proposed solution (peek):");
        { 
            let peek = String::from_utf8_lossy(&proposed_solution[..100]);
            println!("{}", peek);
        }

        'get_cmd: loop {
            cmd.clear();
            println!("(a)ccept or try (n)ext solution?");
            stdin.read_line(&mut cmd);
            match cmd.as_str().trim() {
                "a" => {
                    chosen_solution = Ok(proposed_solution);
                    break 'choose_solution;
                }, "n" => {
                    continue 'choose_solution;
                }, _ => {
                    println!("Invalid command.");
                    continue 'get_cmd;
                }
            }
        }
    }
    
    File::create(args.get("output_file")?)
    .map_err(|e| format!("Failed to create output file: {}", e))?
    .write_all(&chosen_solution?)
    .map_err(|e| format!("Failed to write to output file: {}",e))?;

    Ok(())
    
}
