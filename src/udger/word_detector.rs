use anyhow::{anyhow, Result};
use hyperscan::prelude::*;
use hyperscan::{ExprExt, PatternFlags};
use rusqlite::{params, Connection};

use std::collections::HashMap;
use std::fmt;

pub type WordID = u16;

#[derive(Clone)]
pub struct Word {
    pub id: i32,
    pub word: String, // !! ascii character only !!
}

impl Word {
    pub fn new(id: i32, word: String) -> Word {
        Word { id, word }
    }
}

impl fmt::Display for Word {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {})", self.id, self.word)
    }
}

pub struct WordDetector {
    pub name: String,
    word_dic: HashMap<String, Vec<Word>>,
    db: Option<hyperscan::BlockDatabase>,
}

impl WordDetector {
    /// Create a new WordDetector
    pub fn new() -> WordDetector {
        WordDetector {
            name: String::new(),
            word_dic: HashMap::new(),
            db: None,
        }
    }

    /// Initialize a WordDetector
    ///
    /// # Arguments
    pub fn init(&mut self, words: Patterns) -> Result<()> {
        self.db = Some(words.build()?);
        Ok(())
    }

    /// Allocate hyperscan scratch for regular expression matching
    pub fn alloc_scratch(&mut self) -> Result<Scratch> {
        match &self.db {
            None => Err(anyhow!("WordDetector's database is None")),
            Some(db) => Ok(db.alloc_scratch()?),
        }
    }

    /// Match words table
    ///
    /// If User-Agent match any word, return all the matched words' ids.
    pub fn get_word_ids<T>(&self, ua: T, scratch: &mut Scratch) -> Result<Vec<WordID>>
    where
        T: AsRef<[u8]>,
    {
        let mut ids = Vec::new();

        match &self.db {
            None => {}
            Some(db) => {
                db.scan(ua.as_ref(), scratch, |id, _, _, _| {
                    ids.push(id as u16);
                    Matching::Continue
                })?;
            }
        }

        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_word_ids() {
        let mut detector = WordDetector::new();
        let words = vec![Pattern {
            expression: String::from("regex"),
            flags: PatternFlags::CASELESS,
            id: Some(123 as usize),
            ext: ExprExt::default(),
            som: None,
        }];

        detector.init(Patterns::from(words)).unwrap();

        let mut scratch = detector.alloc_scratch().unwrap();

        let ids = detector
            .get_word_ids(
                &String::from("This is a sentence contains the word regex"),
                &mut scratch,
            )
            .unwrap();

        assert!(matches!(ids.iter().find(|id| **id == 123), Some(_)));
    }
}
