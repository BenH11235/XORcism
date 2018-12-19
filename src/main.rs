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


fn main() {

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
    let input_file = ok_or_exit(File::open(input_file_name));
    let mut output_file = ok_or_exit(File::create(output_file_name));

    let ct: Vec<u8> = 
        input_file.bytes().collect::<Result<Vec<u8>,std::io::Error>>().unwrap();

    let solutions = 
        vigenere::full_break(&ct, &ptspace, &keyspace, &comb_func).unwrap();

    output_file.write_all(&solutions.clone().next().unwrap().unwrap());
    
}
