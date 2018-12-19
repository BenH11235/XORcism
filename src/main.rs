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

        use std::process::exit;
        use std::fmt::Display;
        use std::fs::File;

        pub const SHOULD_NOT_REACH_HERE:&str = 
            "Execution should very definitely not have reached where it did";

        pub fn quit<T:Display>(e:T) {
            println!("Error: {}", e);
            exit(1);
        }

        pub fn exit_on_error<T,E:Display>(res:Result<T,E>) -> T {
            match res {
                Ok(x) => Some(x),
                Err(e) => {quit(e); None}
            }.expect(SHOULD_NOT_REACH_HERE)
        }

    }


fn main() {

    use crypto::vigenere;
    use std::fs::File;
    use std::io::{Read,Write};
    use err::exit_on_error;
    
    let args = cli::args();


    let exit_on_missing_arg = |argname| {
        let res = match args.value_of(argname) {
            Some(arg) => Ok(arg),
            None => Err(format!("missing argument {} despite CLI guarantee",argname))
        }; 
        exit_on_error(res)
    };
    
    let ptspace_name = exit_on_missing_arg("plaintext_distribution");
    let keyspace_name = exit_on_missing_arg("key_distribution");
    let comb_func_name = exit_on_missing_arg("combination_function");
    let input_file_name = exit_on_missing_arg("input_file");
    let output_file_name = exit_on_missing_arg("output_file");

    let ptspace =   builtin::dist::by_name(ptspace_name);
    let keyspace =  builtin::dist::by_name(keyspace_name);
    let comb_func = builtin::comb::by_name(comb_func_name);
    let input_file = exit_on_error(File::open(input_file_name));
    let mut output_file = exit_on_error(File::create(output_file_name));

    let ct: Vec<u8> = 
        input_file.bytes().collect::<Result<Vec<u8>,std::io::Error>>().unwrap();

    let solutions = 
        vigenere::full_break(&ct, &ptspace, &keyspace, &comb_func).unwrap();

    output_file.write_all(&solutions.clone().next().unwrap().unwrap());
    
}
