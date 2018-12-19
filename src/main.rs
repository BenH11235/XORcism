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

    use crypto::vigenere;
    use std::fs::File;
    use std::io::{Read,Write};
    use err::ok_or_exit;
    
    let args = cli::args();


    let get_arg_or_exit = |argname| {
        let res = 
            args.value_of(argname)
            .ok_or(format!("Missing argument {}",argname));
        ok_or_exit(res)
    };
    
    let ptspace_name = get_arg_or_exit("plaintext_distribution");
    let keyspace_name = get_arg_or_exit("key_distribution");
    let comb_func_name = get_arg_or_exit("combination_function");
    let input_file_name = get_arg_or_exit("input_file");
    let output_file_name = get_arg_or_exit("output_file");

    let ptspace =   builtin::dist::by_name(ptspace_name);
    let keyspace =  builtin::dist::by_name(keyspace_name);
    let comb_func = builtin::comb::by_name(comb_func_name);
    let input_file = 
        File::open(input_file_name)
        .map_err(|e| format!("Could not open input file: {}",e))?;
        
    let mut output_file = 
        File::create(output_file_name)
        .map_err(|e| format!("Could not create output file: {}", e))?;

    let _ct: Result<Vec<u8>,std::io::Error> = input_file.bytes().collect();
    let ct = _ct.map_err(|e| format!("Could not read input file: {}",e))?;

    let solutions = 
        vigenere::full_break(&ct, &ptspace, &keyspace, &comb_func)
        .map_err(|e| format!("Break attempt failed: {}", e))?;

    output_file.write_all(&solutions.clone().next().unwrap().unwrap());
    Ok(())
    
}
