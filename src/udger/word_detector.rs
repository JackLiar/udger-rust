use anyhow::{anyhow, Result};
use hyperscan::prelude::*;

pub type WordID = u16;

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
}

impl WordDetector {
    /// Create a new WordDetector
    pub fn new() -> WordDetector {
        WordDetector::default()
    }

    /// Initialize a WordDetector
    ///
    /// # Arguments
    pub fn init(&mut self, words: Patterns) -> Result<()> {
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
    pub fn get_word_ids<T>(&self, ua: T, scratch: &mut WordDetectorScratch) -> Result<Vec<WordID>>
    where
        T: AsRef<[u8]>,
    {
        let mut ids = Vec::new();

        match &self.db {
            None => {}
            Some(db) => {
                db.scan(ua.as_ref(), &mut scratch.raw, |id, _, _, _| {
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
    use hyperscan::{ExprExt, PatternFlags};

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
