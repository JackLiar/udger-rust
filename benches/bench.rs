#![feature(test)]

extern crate test;

use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::str::FromStr;
use test::Bencher;

use anyhow::Result;
use rand::{self, Rng};

use udger::Udger;

#[bench]
fn parse_ua(b: &mut Bencher) -> Result<()> {
    let mut udger = Udger::new();
    let db_path = PathBuf::from_str(&"data/udgerdb_v3_full.dat")?;
    let cache_size = 6000;
    udger.init(db_path, cache_size)?;
    let mut data = udger.alloc_udger_data()?;

    let file = File::open("data/ua_10000.txt")?;
    let uas: Vec<String> = io::BufReader::new(file)
        .lines()
        .map(|line| line.unwrap())
        .collect();
    let mut rng = rand::thread_rng();
    let size = uas.len();
    let mut total_iter_cnt = 0;

    println!("total user-agnet count: {}", size);
    println!("udger cache size: {}", cache_size);
    println!("start benching");
    b.iter(|| {
        let i = rng.gen_range(0..size);
        let ua = &uas[i];
        udger.parse_ua(ua, &mut data).unwrap();
        total_iter_cnt += 1;
    });
    println!("total iterations: {}", total_iter_cnt);

    Ok(())
}
