
extern crate byteorder;

use std::*;
use self::byteorder::*;

pub struct Sha256 {
    working_hash: [u32; 8],
    total_data_len: u64,
    tmp_data: [u8; 64],
    tmp_data_len: usize,

    hash: [u8; 32],
}

const K256: [u32; 64] = [
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];

#[inline(always)]
fn sig0(val: u32) -> u32 {
    u32::rotate_right(val, 7) ^ u32::rotate_right(val, 18) ^ (val >> 3)
}

#[inline(always)]
fn sig1(val: u32) -> u32 {
    u32::rotate_right(val, 17) ^ u32::rotate_right(val, 19) ^ (val >> 10)
}

#[inline(always)]
fn ep0(val: u32) -> u32 {
    u32::rotate_right(val, 2) ^ u32::rotate_right(val, 13) ^ u32::rotate_right(val, 22)
}

#[inline(always)]
fn ep1(val: u32) -> u32 {
    u32::rotate_right(val, 6) ^ u32::rotate_right(val, 11) ^ u32::rotate_right(val, 25)
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 { working_hash: [
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ],
        total_data_len: 0,
        tmp_data: [0; 64],
        tmp_data_len: 0,
        hash: [0; 32]}
    }

    fn hash_data(&mut self) {
        let data: &[u8; 64] = &self.tmp_data;
        let mut var: [u32; 8];
        let mut t1: u32;
        let mut t2: u32;
        let mut m: [u32; 64] = [0; 64];

        for i in 0..(64 / 4) {
            m[i] = BigEndian::read_u32(&data[i * 4..i * 4 + 4]);
        }

        for i in 16..64 {
            m[i] = sig1(m[i - 2])
                  .wrapping_add(m[i - 7])
                  .wrapping_add(sig0(m[i - 15]))
                  .wrapping_add(m[i - 16]);
        }

        var = self.working_hash;

        for i in 0..64 {
            t1 = var[7]
                .wrapping_add(ep1(var[4]))
                .wrapping_add(ch(var[4], var[5], var[6]))
                .wrapping_add(K256[i])
                .wrapping_add(m[i]);

            t2 = ep0(var[0])
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

            if self.tmp_data_len == 64 {
                self.hash_data();
                self.tmp_data_len = 0;
            }
        }
    }

    pub fn finish<'a>(&'a mut self) -> &'a[u8; 32] {
        if self.tmp_data_len < 56 {
            self.tmp_data[self.tmp_data_len] = 0x80;
            self.tmp_data_len += 1;
            for i in self.tmp_data_len..56 {
                self.tmp_data[i] = 0x00;
            }
        } else {
            self.tmp_data[self.tmp_data_len] = 0x80;
            self.tmp_data_len += 1;

            for i in self.tmp_data_len..64 {
                self.tmp_data[i] = 0x00;
            }

            self.hash_data();

            self.tmp_data.clone_from_slice(&[0; 56]);
        }

        BigEndian::write_u64(&mut self.tmp_data[56..64], self.total_data_len * 8);
        self.hash_data();

        for i in 0..8 {
            BigEndian::write_u32(&mut self.hash[i*4..i*4+4], self.working_hash[i]);
        }

        &self.hash
    }

    pub fn get_hash<'a>(&'a mut self) -> &'a[u8; 32] {
        &self.hash
    }
}

