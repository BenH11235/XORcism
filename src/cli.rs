use clap::{Arg,App,ArgMatches};
use builtin::{dist,comb};
use std::io::{self,Read};

pub fn args() -> ArgMatches<'static> { 
    App::new("XORcism")
    .version("0.1")
    .author("Ben Herzog <benherzog11235@gmail.com>")
    .about("Breaks vigenere-like ciphers")
        .arg(Arg::with_name("input_file")
            .value_name("INPUT_FILE")
            .help("Sets the input file to use")
            .required(true)
            .index(1))
        .arg(Arg::with_name("output_file")
            .short("-o")
            .long("--output_file")
            .value_name("OUTPUT_FILE")
            .help("Sets the output file to write to")
            .default_value("xorcism.out")
        )
        .arg(Arg::with_name("plaintext_distribution")
            .short("-ptd")
            .long("--plaintext-distribution")
            .value_name("PT_DIST")
            .help("Sets the assumed distribution of the plaintext characters")
            .possible_values(&dist::names())
            .default_value("shakespeare")
        )
        .arg(Arg::with_name("key_distribution")
            .short("-kd")
            .long("--key-distribution")
            .value_name("KEY_DIST")
            .help("Sets the assumed distribution of the key characters")
            .possible_values(&dist::names())
            .default_value("uniform")
        )
        .arg(Arg::with_name("combination_function")
            .short("-cf")
            .long("--combination-function")
            .value_name("COMB_FUNC")
            .help("Sets the assumed f where f(key_byte, plain_byte) = cipher_byte")
            .possible_values(&comb::names())
            .default_value("xor")
        )
        .get_matches()
}

pub trait GetArg<'a> {
    fn get(&self,argname:&str) -> Result<&str,String>;
}

impl<'a> GetArg<'a> for ArgMatches<'a> {
    fn get(&self,argname:&str) -> Result<&str,String> {
        self.value_of(argname)
        .ok_or(format!("Failed to resolve argument {}",argname))
    }
}


