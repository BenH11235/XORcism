pub mod comb {
        use utils;
        
        pub const BY_NAME:[(&str, &Fn(&u8,&u8)->u8);2] = [
            ("xor", &utils::xor),
            ("add_mod_256", &utils::add)
        ];
        
        pub fn by_name(lookup:&str) -> impl Fn(&u8,&u8) -> u8 {
            BY_NAME
            .iter()
            .filter(|(n,d)| n==&lookup)
            .map(|(n,d)| d)
            .next()
            .unwrap()
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
        use ::dist as _d;
        use std::collections::HashMap;

        pub const BY_NAME:[(&str,&[(u8,_d::Prob)]);4] = [
            ("shakespeare", &_d::known::SHAKESPEARE),
            ("base64", &_d::known::BASE64),
            ("hex", &_d::known::HEX),
            ("uniform", &_d::known::UNIFORM)
        ];

        //no stable support for compile-time hashmaps, so here we are...
        pub fn by_name(lookup:&str) -> impl _d::Distribution<u8> {
            let keyval_pairs: &[(u8,_d::Prob)] = 
                BY_NAME
                .iter()
                .filter(|(n,d)| n==&lookup)
                .map(|(n,d)| d)
                .next()
                .unwrap();
            _d::from(keyval_pairs)
        }

        pub fn names() -> Vec<&'static str> { 
            BY_NAME
            .into_iter()
            .cloned()
            .map(|(n,_)| n)
            .collect()
        }

    }

