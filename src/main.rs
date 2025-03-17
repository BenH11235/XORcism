#[macro_use]
extern crate derive_more;
extern crate itertools;
extern crate counter;
extern crate clap;
extern crate rayon;

mod cli;
mod crypto;
mod dist;
mod builtin;
mod utils;

#[cfg(test)]
mod tests;

use crypto::vigenere;
use std::fs::File;
use std::cmp::min;
use std::io::{self,Read,Write};
use cli::GetArg;
use utils::QuickUnique;

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

    let mut solutions = 
        vigenere::full_break(&ciphertext, &pt_dist, &key_dist, &comb_func)
        .map_err(|e| format!("Failed to break ciphertext: {}", e))?
        .unique();

    //Non Interactive Mode

    if !args.is_present("interactive_mode") {
        let proposed_solution = 
            solutions
            .next()
            .ok_or(format!("No solutions found"))?
            .map_err(|e| 
                format!("Failed to compute possible solution: {}",e)
            )?;
        println!("{}", String::from_utf8_lossy(&proposed_solution));
        return Ok(());
    }

    //Interactive mode

    let stdin = io::stdin();
    'choose_solution: for solution in solutions {
        let proposed_solution = 
            solution
            .map_err(|e| 
                format!("Failed to compute possible solution: {}",e)
            )?;

        println!("Proposed solution (peek of first 500 characters):");
        println!("---------");
        { 
            let peek_len = min(proposed_solution.len(),500);
            let peek = String::from_utf8_lossy(&proposed_solution[..peek_len]);
            println!("{}", peek);
        }
        println!("---------");


        'get_cmd: loop {
            cmd.clear();
            println!("(a)ccept or try (n)ext solution?");
            stdin.read_line(&mut cmd)
            .map_err(|e| format!("Failed to read command: {}",e))?;
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
