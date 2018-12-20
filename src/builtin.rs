
pub mod comb {
        use utils;
        use rayon::prelude::*;

        type CombFunc = fn(&u8,&u8)->u8;
        
        pub const BY_NAME:[(&str, CombFunc) ; 2] = [
            ("xor", utils::xor),
            ("add_mod_256", utils::add)
        ];
        
        pub fn by_name(lookup:&str) -> Result<impl Fn(&u8,&u8) -> u8 + Send + Sync, String> {
            BY_NAME
            .par_iter()
            .find_any(|(n,_)| n==&lookup)
            .map(|(_,d)| d)
            .ok_or_else(||
                format!("Failed to resolve built-in combination function {}",lookup)
            )
        }

        pub fn names() -> Vec<&'static str> { 
            BY_NAME
            .into_iter()
            .cloned()
            .map(|(n,_)| n)
            .collect()
        }


    }

pub mod dist {

    use rayon::prelude::*;
    
    pub const BY_NAME:[(&str,&[(u8,::dist::Prob)]) ; 4] = [
        ("shakespeare", &::dist::known::SHAKESPEARE),
        ("base64", &::dist::known::BASE64),
        ("hex", &::dist::known::HEX),
        ("uniform", &::dist::known::UNIFORM)
    ];

    //no stable support for compile-time hashmaps, so here we are...
    pub fn by_name(lookup:&str) -> 
    Result<impl ::dist::Distribution<u8>, String> {
        BY_NAME
        .par_iter()
        .find_any(|(n,_)| n==&lookup)
        .map(|(_,d)| ::dist::from(d))
        .ok_or_else(||
            format!("Failed to resolve built-in distribution {}",lookup)
        )
    }

    pub fn names() -> Vec<&'static str> { 
        BY_NAME
        .into_iter()
        .cloned()
        .map(|(n,_)| n)
        .collect()
    }

}

