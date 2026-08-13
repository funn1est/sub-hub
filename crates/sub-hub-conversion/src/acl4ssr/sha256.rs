const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

pub(super) struct Hasher {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Hasher {
    pub(super) const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    pub(super) fn update(&mut self, mut input: &[u8]) -> Result<(), ()> {
        self.total_bytes = self
            .total_bytes
            .checked_add(u64::try_from(input.len()).map_err(|_| ())?)
            .ok_or(())?;
        if self.buffer_len != 0 {
            let copied = (64 - self.buffer_len).min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + copied]
                .copy_from_slice(&input[..copied]);
            self.buffer_len += copied;
            input = &input[copied..];
            if self.buffer_len == 64 {
                compress(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            } else {
                return Ok(());
            }
        }
        let mut chunks = input.chunks_exact(64);
        for chunk in &mut chunks {
            compress(&mut self.state, chunk);
        }
        let remainder = chunks.remainder();
        self.buffer[..remainder.len()].copy_from_slice(remainder);
        self.buffer_len = remainder.len();
        Ok(())
    }

    pub(super) fn finalize(mut self) -> Result<[u8; 32], ()> {
        let bit_length = self.total_bytes.checked_mul(8).ok_or(())?;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            compress(&mut self.state, &self.buffer);
            self.buffer = [0; 64];
        } else {
            self.buffer[self.buffer_len..56].fill(0);
        }
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        compress(&mut self.state, &self.buffer);

        let mut output = [0; 32];
        for (word, bytes) in self.state.iter().zip(output.chunks_exact_mut(4)) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        Ok(output)
    }
}

#[cfg(test)]
pub(super) fn digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher
        .update(input)
        .expect("an in-memory Rust slice length fits SHA-256");
    hasher
        .finalize()
        .expect("an in-memory Rust slice length fits SHA-256")
}

fn compress(state: &mut [u32; 8], chunk: &[u8]) {
    let mut schedule = [0_u32; 64];
    for (index, bytes) in chunk.chunks_exact(4).enumerate() {
        schedule[index] = u32::from_be_bytes(bytes.try_into().expect("four-byte chunk"));
    }
    for index in 16..64 {
        let s0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let s1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(s0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(s1);
    }

    let [
        mut work_0,
        mut work_1,
        mut work_2,
        mut work_3,
        mut work_4,
        mut work_5,
        mut work_6,
        mut work_7,
    ] = *state;
    for index in 0..64 {
        let sum1 = work_4.rotate_right(6) ^ work_4.rotate_right(11) ^ work_4.rotate_right(25);
        let choice = (work_4 & work_5) ^ ((!work_4) & work_6);
        let temporary1 = work_7
            .wrapping_add(sum1)
            .wrapping_add(choice)
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        let sum0 = work_0.rotate_right(2) ^ work_0.rotate_right(13) ^ work_0.rotate_right(22);
        let majority = (work_0 & work_1) ^ (work_0 & work_2) ^ (work_1 & work_2);
        let temporary2 = sum0.wrapping_add(majority);
        work_7 = work_6;
        work_6 = work_5;
        work_5 = work_4;
        work_4 = work_3.wrapping_add(temporary1);
        work_3 = work_2;
        work_2 = work_1;
        work_1 = work_0;
        work_0 = temporary1.wrapping_add(temporary2);
    }
    state[0] = state[0].wrapping_add(work_0);
    state[1] = state[1].wrapping_add(work_1);
    state[2] = state[2].wrapping_add(work_2);
    state[3] = state[3].wrapping_add(work_3);
    state[4] = state[4].wrapping_add(work_4);
    state[5] = state[5].wrapping_add(work_5);
    state[6] = state[6].wrapping_add(work_6);
    state[7] = state[7].wrapping_add(work_7);
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{Hasher, digest};

    #[test]
    fn matches_fips_vectors() {
        assert_eq!(
            hex(digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut chunked = Hasher::new();
        chunked.update(b"a").unwrap();
        chunked.update(b"b").unwrap();
        chunked.update(b"c").unwrap();
        assert_eq!(chunked.finalize().unwrap(), digest(b"abc"));
        let boundary = vec![b'x'; 65];
        let mut chunked = Hasher::new();
        for byte in &boundary {
            chunked.update(std::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(chunked.finalize().unwrap(), digest(&boundary));
    }

    fn hex(bytes: [u8; 32]) -> String {
        let mut output = String::with_capacity(64);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
