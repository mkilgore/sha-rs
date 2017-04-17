
extern crate byteorder;

use std::*;
use self::byteorder::*;

pub struct Sha512 {
    working_hash: [u64; 8],
    total_data_len: u64,
    tmp_data: [u8; 128],
    tmp_data_len: usize,

    hash: [u8; 64],
}

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[inline(always)]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn big_sig0(x: u64) -> u64 {
    u64::rotate_right(x, 28) ^ u64::rotate_right(x, 34) ^ u64::rotate_right(x, 39)
}

#[inline(always)]
fn big_sig1(x: u64) -> u64 {
    u64::rotate_right(x, 14) ^ u64::rotate_right(x, 18) ^ u64::rotate_right(x, 41)
}

#[inline(always)]
fn little_sig0(x: u64) -> u64 {
    u64::rotate_right(x, 1) ^ u64::rotate_right(x, 8) ^ (x >> 7)
}

#[inline(always)]
fn little_sig1(x: u64) -> u64 {
    u64::rotate_right(x, 19) ^ u64::rotate_right(x, 61) ^ (x >> 6)
}

impl Sha512 {
    pub fn new() -> Sha512 {
        Sha512 {
            working_hash: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            total_data_len: 0,
            tmp_data: [0; 128],
            tmp_data_len: 0,
            hash: [0; 64],
        }
    }

    fn hash_data(&mut self) {
        let data: &[u8; 128] = &self.tmp_data;
        let mut var: [u64; 8];
        let mut t1: u64;
        let mut t2: u64;
        let mut m: [u64; 80] = [0; 80];

        for i in 0..(128 / 8) {
            m[i] = BigEndian::read_u64(&data[i * 8..i * 8 + 8]);
        }

        for i in 16..80 {
            m[i] = little_sig1(m[i - 2])
                  .wrapping_add(m[i - 7])
                  .wrapping_add(little_sig0(m[i - 15]))
                  .wrapping_add(m[i - 16]);
        }

        var = self.working_hash;

        for i in 0..80 {
            t1 = var[7]
                .wrapping_add(big_sig1(var[4]))
                .wrapping_add(ch(var[4], var[5], var[6]))
                .wrapping_add(K512[i])
                .wrapping_add(m[i]);

            t2 = big_sig0(var[0])
                .wrapping_add(maj(var[0], var[1], var[2]));

            var[7] = var[6];
            var[6] = var[5];
            var[5] = var[4];
            var[4] = var[3].wrapping_add(t1);
            var[3] = var[2];
            var[2] = var[1];
            var[1] = var[0];
            var[0] = t1.wrapping_add(t2);
        }

        for i in 0..8 {
            self.working_hash[i] = self.working_hash[i].wrapping_add(var[i]);
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_data_len += data.len() as u64;

        for d in data.iter() {
            self.tmp_data[self.tmp_data_len] = *d;
            self.tmp_data_len += 1;

            if self.tmp_data_len == 128 {
                self.hash_data();
                self.tmp_data_len = 0;
            }
        }
    }

    pub fn finish<'a>(&'a mut self) -> &'a[u8; 64] {
        if self.tmp_data_len < 128 - 16 {
            self.tmp_data[self.tmp_data_len] = 0x80;
            self.tmp_data_len += 1;
            for i in self.tmp_data_len..(128 - 16) {
                self.tmp_data[i] = 0x00;
            }
        } else {
            self.tmp_data[self.tmp_data_len] = 0x80;
            self.tmp_data_len += 1;

            for i in self.tmp_data_len..128 {
                self.tmp_data[i] = 0x00;
            }

            self.hash_data();

            self.tmp_data.clone_from_slice(&[0; (128 - 16)]);
        }

        for i in (128 - 16)..(128 - 8) {
            self.tmp_data[i] = 0;
        }

        BigEndian::write_u64(&mut self.tmp_data[(128 - 8)..128], self.total_data_len * 8);
        self.hash_data();

        for i in 0..8 {
            BigEndian::write_u64(&mut self.hash[i*8..i*8+8], self.working_hash[i]);
        }

        &self.hash
    }

    pub fn get_hash<'a>(&'a mut self) -> &'a[u8; 64] {
        &self.hash
    }
}
