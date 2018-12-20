pub mod comb {
        use utils;
        
        pub const BY_NAME:[(&str, &Fn(&u8,&u8)->u8);2] = [
            ("xor", &utils::xor),
            ("add_mod_256", &utils::add)
        ];
        
        pub fn by_name(lookup:&str) -> Result<impl Fn(&u8,&u8) -> u8, String> {
            BY_NAME
            .iter()
            .filter(|(n,d)| n==&lookup)
            .map(|(n,d)| d)
            .next()
            .ok_or(
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
    use std::collections::HashMap;

    pub const BY_NAME:[(&str,&[(u8,::dist::Prob)]);4] = [
        ("shakespeare", &::dist::known::SHAKESPEARE),
        ("base64", &::dist::known::BASE64),
        ("hex", &::dist::known::HEX),
        ("uniform", &::dist::known::UNIFORM)
    ];

    //no stable support for compile-time hashmaps, so here we are...
    pub fn by_name(lookup:&str) -> 
    Result<impl ::dist::Distribution<u8>, String> {
        BY_NAME
        .iter()
        .filter(|(n,d)| n==&lookup)
        .map(|(n,d)| d)
        .next()
        .map(|keyval_pairs| ::dist::from(keyval_pairs))
        .ok_or(format!("Failed to resolve built-in distribution {}",lookup))
    }

    pub fn names() -> Vec<&'static str> { 
        BY_NAME
        .into_iter()
        .cloned()
        .map(|(n,_)| n)
        .collect()
    }

}

