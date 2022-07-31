#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[derive(Debug)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        assert!(5 <= key.len() && key.len() <= 256);

        let mut rc4 = Rc4 {
            s: [0; 256],
            i: 0,
            j: 0,
        };

        for (i, b) in rc4.s.iter_mut().enumerate() {
            *b = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(rc4.s[i]).wrapping_add(key[i % key.len()]);

            rc4.s.swap(i, j as usize);
        }

        rc4
    }

    pub fn apply_keystream_static(key: &[u8], data: &mut [u8]) {
        let mut rc4 = Rc4::new(key);
        rc4.apply_keystream(data);
    }

    pub fn prga_next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];

        k
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for b_ptr in data {
            *b_ptr ^= self.prga_next();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rc4;

    #[test]
    fn sanity_check_static_api() {
        #[rustfmt::skip]
        let key: [u8; 16] = [
            0x4b, 0x8e, 0x29, 0x87, 0x80, 0x95, 0x96, 0xa3,
            0xbb, 0x23, 0x82, 0x49, 0x9f, 0x1c, 0xe7, 0xc2,
        ];

        #[rustfmt::skip]
        let plaintext = [
            0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
            0x72, 0x6c, 0x64, 0x21,
        ];

        let mut msg: [u8; 12] = plaintext.clone();
        Rc4::apply_keystream_static(&key, &mut msg);
        assert_ne!(msg, plaintext);

        Rc4::apply_keystream_static(&key, &mut msg);
        assert_eq!(msg, plaintext);
    }
}
