use std::fmt;

pub mod ipv4 {
    use crate::*;

    type Result<T> = std::result::Result<T, InvalidAddrErr>;

    #[derive(Debug, Clone)]
    pub struct InvalidAddrErr;

    impl fmt::Display for InvalidAddrErr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "invalid ipv4 address string")
        }
    }

    // valid_ipv4 will parse a string and return a Result indicating if
    // the string is a valid RFC 791 IPv4 address. If the address is valid
    // the bool will be true. If it is not valid, an Err will be returned.
    pub fn valid_ipv4(ipstr: &str) -> Result<bool> {
        // A valid IPv4 address can be at most 15 characters in it's
        // string representation. e.g., 100.100.100.101. It must be
        // at least 7 characters in it's string representation, i.e.
        // 1.1.1.1
        if ipstr.len() > 15 || ipstr.len() < 7 {
            return Err(InvalidAddrErr);
        }

        // This algorithm runs in O(N) time where N is the number of digits represented by characters
        // in ipstr. We are looking for up to 4 "blocks", where a block is a set of 3 numbers delineated on
        // at least one end by a separator character, the "dot" (.). We will iterate through the characters
        // in the string and check each one as it comes, ensuring that this character does not invalidate the
        // address string.
        let mut block_count = 1;
        let mut block: [char; 3] = ['\0'; 3];
        let mut pos = 0;

        // iterate character by character through the address string. If any invalidations are found,
        // return immediately.
        for c in ipstr.chars() {
            // if the character is not a digit or a dot, the address is invalid.
            if !c.is_ascii_digit() && c != '.' {
                return Err(InvalidAddrErr);
            }

            // dots ('.') represent a seperator character in the address string,
            // and most of the validation logic happens at a separation point.
            if c == '.' {
                // if we have a dot and we already have seen 4 blocks, the address is invalid.
                if block_count == 4 {
                    return Err(InvalidAddrErr);
                }

                // if we have a dot and the previous character is a dot -- which we will know because
                // the block will have a null character in it's first position, the address is invalid.
                if block[0] == '\0' {
                    return Err(InvalidAddrErr);
                }

                // check if the block has three characters. if the last character is a null character,
                // we only have two characters, and so any two digits [0-9] make up a valid block.
                if block[2] != '\0' {
                    // if we have three characters in the block, we need to make sure
                    // that the first character is not greater than 2. We have already
                    // checked previously that the first character:
                    // a) is not '0'
                    // b) that it is a valid digit.
                    if block[0] > '2' {
                        return Err(InvalidAddrErr);
                    }

                    // if the first character is a 2, we need to make sure that the
                    // subsequent digits are not exceeding 255.
                    if block[0] == '2' && (block[1] > '5' || (block[1] == '5' && block[2] > '5')) {
                        return Err(InvalidAddrErr);
                    }
                }

                // if all the separator validation logic steps are successful,
                // we can start parsing a new block. increment the block counter,
                // reset the block, and set our reader position (pos) to 0.
                block_count += 1;
                block = ['\0'; 3];
                pos = 0;
                continue;
            }

            // if the reader position is at character 4, the address is invalid.
            if pos == 3 {
                return Err(InvalidAddrErr);
            }

            // if we get here, this is a valid character in the address! track it
            // in the block and update our position to the next character.
            block[pos] = c;
            pos += 1;
        }

        Ok(true)
    }

    #[cfg(test)]
    mod net_tests {
        use super::valid_ipv4;

        #[test]
        fn test_valid_ip() {
            let valids = Vec::from([
                "127.0.0.1",
                "192.168.0.9",
                "10.0.0.1",
                "255.255.255.255",
                "2.255.99.254",
            ]);
            let invalids = Vec::from([
                "295.34.1.5.",
                "215.0",
                "215",
                ".10.256.0.9",
                "365",
                "365.1.0.9",
                "10.256.0.1",
                "10.358.0.1",
            ]);

            for addr in valids {
                let r = valid_ipv4(addr);
                if r.is_err() {
                    panic!(
                        "correctness error: {} failed but should have succeeded",
                        addr
                    );
                }
            }

            for addr in invalids {
                let r = valid_ipv4(addr);
                if r.is_ok() {
                    panic!(
                        "correctness error: {} succeeded but should have failed",
                        addr
                    );
                }
            }
        }
    }
}
