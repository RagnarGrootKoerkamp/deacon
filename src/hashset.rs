//! A dense_hash_set for u64 keys.
//!
//! Compared to std::collections::HashSet<u64>, this uses a different layout: no metadata table, just plain data.
//! This is similar to Google's dense_hash_map, which predates the SwissTable design. By avoiding a metadata table,
//! we may need to do longer probe sequences (each probe is 8 bytes, not 1 byte), but on the other hand we only take
//! 1 cache miss per access, not 2.

use std::hash::{BuildHasher, BuildHasherDefault};
use std::mem::transmute;
type S = wide::i64x4;

use rustc_hash::FxHashMap;
use wide::CmpEq;

type Hasher = BuildHasherDefault<rustc_hash::FxHasher>;

pub struct U64HashSet {
    table: Box<[Bucket]>,
    len: usize,
    has_zero: bool,
    hits: usize,
    skips: usize,
    probelen: FxHashMap<usize, usize>,
    last_bucket_i: usize,
    last_bucket_j: usize,
    last_empty: usize,
}

impl IntoIterator for &U64HashSet {
    type Item = u64;

    type IntoIter = impl Iterator<Item = u64>;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::repeat_n(0, self.has_zero as usize).chain(
            self.table
                .iter()
                .flat_map(|b| b.0.iter().copied())
                .filter(|x| *x != 0),
        )
    }
}

const BUCKET_SIZE: usize = 8;

#[derive(Clone, Copy)]
#[repr(align(64))] // Cache line alignment
struct Bucket([u64; BUCKET_SIZE]);

impl U64HashSet {
    pub fn with_capacity(n: usize) -> Self {
        eprintln!("N        {n}");
        eprintln!("NEXT 2^k {}", n.next_power_of_two());
        let capacity = n * 18 / 10;
        eprintln!("CAPACITY {capacity}");
        // TODO: integer overflow...
        let num_buckets = capacity.div_ceil(BUCKET_SIZE);
        let table = vec![Bucket([0u64; BUCKET_SIZE]); num_buckets].into_boxed_slice();
        Self {
            table,
            len: 0,
            has_zero: false,
            hits: 0,
            skips: 0,
            probelen: Default::default(),
            last_bucket_i: 0,
            last_bucket_j: 0,
            last_empty: 0,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len + self.has_zero as usize
    }

    pub fn stats(&self) {
        let mut counts = [0; 9];

        eprintln!("Size    : {}", self.len);
        eprintln!("hits    : {}", self.hits);
        eprintln!("Skips   : {}", self.skips);
        eprintln!("Skips/el: {}", self.skips as f32 / self.hits as f32);

        let mut sum = 0;
        let mut cnt = 0;
        for bucket in &self.table {
            let [h1, h2]: &[S; 2] = unsafe { transmute(&bucket.0) };
            let c0 = h1.cmp_eq(S::ZERO).move_mask().count_ones() as usize;
            let c1 = h2.cmp_eq(S::ZERO).move_mask().count_ones() as usize;
            let elems = BUCKET_SIZE - c0 - c1;
            counts[elems] += 1;
            cnt += 1;
            sum += elems;
        }
        for i in 0..=8 {
            eprintln!("{i}: {:>9}", counts[i]);
        }
        eprintln!("buckets {cnt}");
        eprintln!("slots   {}", cnt * BUCKET_SIZE);
        eprintln!("sum {sum}");
        eprintln!("avg {}", sum as f32 / cnt as f32);

        let mut probes: Vec<(_, _)> = self.probelen.iter().collect();
        probes.sort();
        for (len, count) in probes {
            eprintln!("{len:>4} => {count:>9}");
        }
    }

    #[inline(always)]
    pub fn prefetch(&self, key: u64) {
        let hash64 = Hasher::default().hash_one(key);
        let bucket_i = (hash64 as usize).widening_mul(self.table.len()).1;
        // Safety: bucket_mask is correct because the number of buckets is a power of 2.
        unsafe {
            std::intrinsics::prefetch_write_data::<_, 0>(self.table.get_unchecked(bucket_i)
                as *const Bucket
                as *const u8)
        };
    }

    #[inline(always)]
    pub fn contains(&self, key: u64) -> bool {
        if key == 0 {
            return self.has_zero;
        }
        let hash64 = Hasher::default().hash_one(key);
        let mut bucket_i = (hash64 as usize).widening_mul(self.table.len()).1;

        // type S = wide::u64x4;
        type S = wide::i64x4;
        let keys = S::splat(key as i64);

        let mut i = 1;
        loop {
            use std::mem::transmute;
            // Safety: bucket_mask is correct because the number of buckets is a power of 2.
            let bucket = unsafe { self.table.get_unchecked(bucket_i) };
            let [h1, h2]: &[S; 2] = unsafe { transmute(&bucket.0) };
            let mask = (h1.cmp_eq(keys) | h2.cmp_eq(keys)).move_mask() as u8;
            if mask > 0 {
                return true;
            }
            let has_zero = (h1.cmp_eq(S::ZERO) | h2.cmp_eq(S::ZERO)).move_mask() as u8;
            if has_zero > 0 {
                return false;
            }

            bucket_i += 1;
            i += 1;
            if bucket_i >= self.table.len() {
                bucket_i -= self.table.len();
            }
        }
    }

    #[inline(always)]
    pub fn insert(&mut self, key: u64) {
        if key == 0 {
            self.len += !self.has_zero as usize;
            self.has_zero = true;
            return;
        }
        let hash64 = Hasher::default().hash_one(key);
        let mut bucket_i = (hash64 as usize).widening_mul(self.table.len()).1;

        let mut i = 1;
        loop {
            // Safety: bucket_mask is correct because the number of buckets is a power of 2.
            let bucket = unsafe { self.table.get_unchecked_mut(bucket_i) };
            for element_i in 0..BUCKET_SIZE {
                let element = &mut bucket.0[element_i];
                if *element == 0 {
                    self.hits += 1;
                    // *self.probelen.entry(i).or_default()+=1;
                    *element = key;
                    self.len += 1;
                    return;
                }
                if *element == key {
                    return;
                }
            }
            bucket_i += 1;
            i += 1;
            self.skips += 1;
            if bucket_i >= self.table.len() {
                bucket_i -= self.table.len();
            }
        }
    }

    #[inline(always)]
    pub fn insert_new(&mut self, key: u64) {
        if key == 0 {
            self.len += !self.has_zero as usize;
            self.has_zero = true;
            return;
        }
        let hash64 = Hasher::default().hash_one(key);
        let mut bucket_i = (hash64 as usize).widening_mul(self.table.len()).1;

        let mut i = 1;
        loop {
            // Safety: bucket_mask is correct because the number of buckets is a power of 2.
            let bucket = unsafe { self.table.get_unchecked_mut(bucket_i) };
            let [h1, h2]: &[S; 2] = unsafe { transmute(&bucket.0) };
            let c0 = h1.cmp_eq(S::ZERO).move_mask().count_ones() as usize;
            let c1 = h2.cmp_eq(S::ZERO).move_mask().count_ones() as usize;
            let taken = BUCKET_SIZE - c0 - c1;

            if taken < BUCKET_SIZE {
                let element_i = taken;
                let element = &mut bucket.0[element_i];
                if *element == 0 {
                    self.hits += 1;
                    // *self.probelen.entry(i).or_default()+=1;
                    *element = key;
                    self.len += 1;
                    return;
                }
                panic!();
            }

            bucket_i += 1;
            i += 1;
            self.skips += 1;
            if bucket_i >= self.table.len() {
                bucket_i -= self.table.len();
            }
        }
    }

    #[inline(always)]
    pub fn insert_in_order(&mut self, key: u64) {
        if key == 0 {
            self.len += !self.has_zero as usize;
            self.has_zero = true;
            return;
        }
        let hash64 = Hasher::default().hash_one(key);
        let bucket_i = (hash64 as usize).widening_mul(self.table.len()).1;
        assert!(
            self.last_empty == 0 || bucket_i > self.last_empty,
            "bucket_i {bucket_i}\nlast empty {}\nlast i {}\nlast j {}",
            self.last_empty,
            self.last_bucket_i,
            self.last_bucket_j
        );
        if self.last_bucket_j == BUCKET_SIZE {
            self.last_bucket_j = 0;
            self.last_bucket_i += 1;
        }
        // same bucket?
        if bucket_i > self.last_bucket_i {
            self.last_empty = bucket_i - 1;
            self.last_bucket_j = 0;
            self.last_bucket_i = bucket_i;
        } else {
            self.last_bucket_j += 1;
        }
        self.table[self.last_bucket_i].0[self.last_bucket_j] = key;
    }
}
