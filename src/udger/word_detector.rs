use std::collections::HashMap;

use anyhow::{anyhow, Result};
use hyperscan::prelude::*;

pub struct WordDetectorScratch {
    pub name: String,
    pub raw: Scratch,
}

impl WordDetectorScratch {
    pub fn new(name: String, scratch: Scratch) -> WordDetectorScratch {
        WordDetectorScratch {
            name: name,
            raw: scratch,
        }
    }
}

#[derive(Default)]
pub struct WordDetector {
    pub name: String,
    db: Option<hyperscan::BlockDatabase>,
    id_count_map: HashMap<u16, u16>,
}

impl WordDetector {
    /// Create a new WordDetector
    pub fn new() -> WordDetector {
        WordDetector::default()
    }

    /// Initialize a WordDetector
    ///
    /// # Arguments
    pub fn init<'a, I>(&mut self, ids: I, words: Patterns, counts: I) -> Result<()>
    where
        I: Iterator<Item = &'a u16>,
    {
        let tup = ids.zip(counts);
        tup.for_each(|(id, count)| {
            self.id_count_map.insert(*id, *count);
        });
        self.db = Some(words.build()?);
        Ok(())
    }

    /// Allocate hyperscan scratch for regular expression matching
    pub fn alloc_scratch(&self) -> Result<WordDetectorScratch> {
        match &self.db {
            None => Err(anyhow!("WordDetector's database is None")),
            Some(db) => Ok(WordDetectorScratch::new(
                self.name.clone(),
                db.alloc_scratch()?,
            )),
        }
    }

    /// Match words table
    ///
    /// If User-Agent match any word, return all the matched words' ids.
    pub fn get_word_ids<T>(&self, ua: &T, scratch: &mut WordDetectorScratch) -> Result<Vec<u16>>
    where
        T: AsRef<[u8]>,
    {
        let mut id_counts = Vec::new();

        match &self.db {
            None => {}
            Some(db) => {
                db.scan(ua.as_ref(), &mut scratch.raw, |id, _from, _to, _flag| {
                    let count = match self.id_count_map.get(&(id as u16)) {
                        None => return Matching::Continue,
                        Some(count) => *count,
                    };
                    id_counts.push((id as u16, count));
                    Matching::Continue
                })?;
            }
        }

        // sort ids by sequence, decreasing order
        id_counts.sort_by(|s, o| {
            if s.1 > o.1 {
                std::cmp::Ordering::Less
            } else if s.1 < o.1 {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });

        Ok(id_counts.iter().map(|(id, _)| *id).collect())
    }
}

#[cfg(test)]
mod tests {
    use hyperscan::{ExprExt, PatternFlags};

    use super::*;

    #[test]
    fn test_get_word_ids() {
        let mut detector = WordDetector::new();
        let words = vec![
            Pattern {
                expression: String::from("regex"),
                flags: PatternFlags::CASELESS,
                id: Some(123 as usize),
                ext: ExprExt::default(),
                som: None,
            },
            Pattern {
                expression: String::from("ex"),
                flags: PatternFlags::CASELESS,
                id: Some(321 as usize),
                ext: ExprExt::default(),
                som: None,
            },
        ];
        let ids = vec![123, 321];
        let counts = vec![1, 100];

        detector
            .init(ids.iter(), Patterns::from(words), counts.iter())
            .unwrap();

        let mut scratch = detector.alloc_scratch().unwrap();

        let ids = detector
            .get_word_ids(
                &String::from("This is a sentence contains the word regex"),
                &mut scratch,
            )
            .unwrap();

        assert!(matches!(ids.iter().find(|id| **id == 123), Some(_)));
        assert!(matches!(ids.iter().find(|id| **id == 321), Some(_)));
        assert_eq!(*ids.get(0).unwrap(), 321);
        assert_eq!(*ids.get(1).unwrap(), 123);
    }
}
