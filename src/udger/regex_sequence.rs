use std::collections::HashMap;

use anyhow::{anyhow, Result};
use hyperscan::chimera::prelude::*;
use hyperscan::chimera::Flags;

pub struct RegexSequenceScratch {
    /// Scratch name
    pub name: String,
    raw: Scratch,
}

impl RegexSequenceScratch {
    pub fn new(name: String, scratch: Scratch) -> RegexSequenceScratch {
        RegexSequenceScratch { name, raw: scratch }
    }

    pub fn raw(&mut self) -> &mut Scratch {
        &mut self.raw
    }
}

#[derive(Default)]
pub struct RegexSequence {
    pub name: String,
    db: Option<Database>,
    id_word_map: HashMap<u16, Vec<u16>>,
    id_sequence_map: HashMap<u16, u16>,
    rowid_id_map: HashMap<u16, u16>,
}

impl RegexSequence {
    pub fn new() -> RegexSequence {
        RegexSequence::default()
    }

    /// Initialize a RegexSequence
    pub fn init<'a, R, I, S>(
        &mut self,
        rowids: I,
        ids: I,
        regexes: S,
        sequences: I,
        word1s: I,
        word2s: I,
    ) -> Result<()>
    where
        R: AsRef<str>,
        I: Iterator<Item = &'a u16>,
        S: Iterator<Item = R>,
    {
        let mut patterns = Vec::new();
        let tup = rowids
            .zip(ids)
            .zip(regexes)
            .zip(sequences)
            .zip(word1s)
            .zip(word2s);
        tup.for_each(|(((((rowid, id), regex), seq), word1), word2)| {
            patterns.push(Pattern {
                expression: String::from(regex.as_ref()),
                flags: Flags::CASELESS,
                id: Some(*rowid as usize),
            });

            // add new entry for <id, sequence> map
            self.id_sequence_map.insert(*rowid, *seq);

            // add word entry for <id, word> map
            let mut word_vec = Vec::new();
            if *word1 != 0 {
                word_vec.push(*word1);
            }
            if *word2 != 0 {
                word_vec.push(*word2);
            }
            self.id_word_map.insert(*rowid, word_vec);
            self.rowid_id_map.insert(*rowid, *id);
        });

        self.db = Some(Patterns::from(patterns).build()?);

        Ok(())
    }

    pub fn alloc_scratch(&self) -> Result<RegexSequenceScratch> {
        match &self.db {
            None => Err(anyhow!(format!(
                "RegexSequenceScratch {}'s database is None",
                self.name
            ))),
            Some(db) => Ok(RegexSequenceScratch::new(
                self.name.clone(),
                db.alloc_scratch()?,
            )),
        }
    }

    pub fn get_row_id<'a, T, I>(
        &self,
        ua: T,
        scratch: &mut RegexSequenceScratch,
        word_ids: &I,
    ) -> Result<Option<u16>>
    where
        T: AsRef<[u8]>,
        I: Iterator<Item = &'a u16> + Clone,
    {
        if word_ids.clone().count() == 0 {
            return Ok(None);
        }

        let mut id_seqs = Vec::new();

        match &self.db {
            None => {}
            Some(db) => {
                db.scan(
                    ua.as_ref(),
                    &mut scratch.raw(),
                    |id, _from, _to, _size, _captured| {
                        let seq = match self.id_sequence_map.get(&(id as u16)) {
                            // if no matching id is found, continue matching
                            None => return Matching::Continue,
                            Some(seq) => *seq,
                        };

                        id_seqs.push((id as u16, seq));

                        Matching::Continue
                    },
                    |_err_type, _id| Matching::Continue,
                )?;
            }
        }

        if id_seqs.len() <= 0 {
            return Ok(None);
        }

        // sort ids by sequence
        id_seqs.sort_by(|s, o| {
            if s.1 < o.1 {
                std::cmp::Ordering::Less
            } else if s.1 > o.1 {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });

        for item in &id_seqs {
            let word_vec = match self.id_word_map.get(&item.0) {
                None => continue,
                Some(vec) => vec,
            };

            let mut found_word_count = 0;
            for wid in word_ids.clone() {
                match (*word_vec).iter().find(|id| **id == *wid) {
                    None => {}
                    Some(_) => found_word_count += 1,
                }
            }
            if found_word_count == word_vec.len() {
                return Ok(Some(item.0));
            }
        }

        Ok(None)
    }

    /// Get actual id by row number
    pub fn get_id(&self, row_id: u16) -> Option<u16> {
        match self.rowid_id_map.get(&row_id) {
            None => None,
            Some(id) => Some(*id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_word_ids() {
        let mut regex_seq = RegexSequence::new();

        let rowids: Vec<u16> = vec![0];
        let ids: Vec<u16> = vec![1];
        let regexes = vec![r"(regex)"];
        let sequences: Vec<u16> = vec![10];
        let word1s: Vec<u16> = vec![1];
        let word2s: Vec<u16> = vec![3];

        regex_seq
            .init(
                rowids.iter(),
                ids.iter(),
                regexes.iter(),
                sequences.iter(),
                word1s.iter(),
                word2s.iter(),
            )
            .unwrap();

        let mut scratch = regex_seq.alloc_scratch().unwrap();

        let word_ids: Vec<u16> = vec![1, 2, 3];
        let id = regex_seq
            .get_row_id(
                "This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, Some(_)));
        assert_eq!(id.unwrap(), 0);
    }

    #[test]
    fn test_get_word_ids_returns_none() {
        let mut regex_seq = RegexSequence::new();

        let rowids: Vec<u16> = vec![0];
        let ids: Vec<u16> = vec![1];
        let regexes = vec![r"(regexes)"];
        let sequences: Vec<u16> = vec![10];
        let word1s: Vec<u16> = vec![1];
        let word2s: Vec<u16> = vec![3];

        regex_seq
            .init(
                rowids.iter(),
                ids.iter(),
                regexes.iter(),
                sequences.iter(),
                word1s.iter(),
                word2s.iter(),
            )
            .unwrap();

        let mut scratch = regex_seq.alloc_scratch().unwrap();

        let word_ids: Vec<u16> = vec![1, 2, 3];
        let id = regex_seq
            .get_row_id(
                "This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, None));
    }

    #[test]
    fn test_get_word_ids_multiple_id() {
        let mut regex_seq = RegexSequence::new();

        let rowids: Vec<u16> = vec![0, 1];
        let ids: Vec<u16> = vec![1, 2];
        let regexes = vec![r"(regex)", r"\s(regex)"];
        let sequences: Vec<u16> = vec![10, 20];
        let word1s: Vec<u16> = vec![1, 1];
        let word2s: Vec<u16> = vec![3, 2];

        regex_seq
            .init(
                rowids.iter(),
                ids.iter(),
                regexes.iter(),
                sequences.iter(),
                word1s.iter(),
                word2s.iter(),
            )
            .unwrap();

        let mut scratch = regex_seq.alloc_scratch().unwrap();

        let word_ids: Vec<u16> = vec![1, 2, 3];
        let id = regex_seq
            .get_row_id(
                "This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, Some(_)));
    }

    #[test]
    fn test_get_id() {
        let mut regex_seq = RegexSequence::new();

        let rowids: Vec<u16> = vec![0, 1];
        let ids: Vec<u16> = vec![1, 2];
        let regexes = vec![r"(regex)", r"\s(regex)"];
        let sequences: Vec<u16> = vec![10, 20];
        let word1s: Vec<u16> = vec![1, 1];
        let word2s: Vec<u16> = vec![3, 2];

        regex_seq
            .init(
                rowids.iter(),
                ids.iter(),
                regexes.iter(),
                sequences.iter(),
                word1s.iter(),
                word2s.iter(),
            )
            .unwrap();

        assert!(matches!(regex_seq.get_id(1), Some(id) if id == 2));
    }
}
