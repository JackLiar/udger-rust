use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use hyperscan::chimera::prelude::*;

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

pub trait RegexSequenceTrait: Default {
    fn new() -> Self {
        Self::default()
    }

    fn db(&self) -> &Option<Database>;

    fn name(&self) -> &String;

    fn rowid_sequence_map(&self) -> &HashMap<u16, u16>;

    fn alloc_scratch(&self) -> Result<RegexSequenceScratch> {
        match &self.db() {
            None => Err(anyhow!(format!(
                "RegexSequenceScratch {}'s database is None",
                self.name()
            ))),
            Some(db) => Ok(RegexSequenceScratch::new(
                self.name().clone(),
                db.alloc_scratch()?,
            )),
        }
    }

    fn get_ids<T>(&self, ua: &T, scratch: &mut RegexSequenceScratch) -> Result<Vec<u16>>
    where
        T: AsRef<[u8]>,
    {
        let mut id_seqs = Vec::new();
        match &self.db() {
            None => {}
            Some(db) => {
                db.scan(
                    ua.as_ref(),
                    &mut scratch.raw(),
                    |id, _from, _to, _size, _captured| {
                        let seq = match self.rowid_sequence_map().get(&(id as u16)) {
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

        // sort ids by sequence
        id_seqs.sort_by(|s, o| {
            if s.1 > o.1 {
                std::cmp::Ordering::Less
            } else if s.1 < o.1 {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });

        Ok(id_seqs.iter().map(|(id, _)| *id).collect())
    }
}

#[derive(Default)]
pub struct RegexSequence {
    pub name: String,
    db: Option<Database>,
    id_word_map: HashMap<u16, Vec<u16>>,
    rowid_sequence_map: HashMap<u16, u16>,
    rowid_id_map: HashMap<u16, u16>,
}

impl RegexSequenceTrait for RegexSequence {
    fn db(&self) -> &Option<Database> {
        &self.db
    }

    fn name(&self) -> &String {
        &self.name
    }

    fn rowid_sequence_map(&self) -> &HashMap<u16, u16> {
        &self.rowid_sequence_map
    }
}

impl RegexSequence {
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
            let mut pattern = match Pattern::from_str(regex.as_ref()) {
                Ok(ptrn) => ptrn,
                Err(err) => {
                    eprintln!("{:?}", err);
                    return ();
                }
            };
            pattern.id = Some(*rowid as usize);
            patterns.push(pattern);

            // add new entry for <id, sequence> map
            self.rowid_sequence_map.insert(*rowid, *seq);

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
        ua: &T,
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

        let ids = self.get_ids(ua, scratch)?;

        for id in &ids {
            let word_vec = match self.id_word_map.get(&id) {
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
                return Ok(Some(*id));
            }
        }

        Ok(None)
    }

    /// Get the actual id column of the sqlite table
    pub fn get_id(&self, rowid: u16) -> Option<u16> {
        match self.rowid_id_map.get(&rowid) {
            None => None,
            Some(id) => Some(*id),
        }
    }
}

#[derive(Default)]
pub struct DeviceBrandRegexSequence {
    pub name: String,
    db: Option<Database>,
    rowid_code_map: HashMap<u16, [String; 2]>,
    rowid_sequence_map: HashMap<u16, u16>,
    rowid_id_map: HashMap<u16, u16>,
}

impl RegexSequenceTrait for DeviceBrandRegexSequence {
    fn db(&self) -> &Option<Database> {
        &self.db
    }

    fn name(&self) -> &String {
        &self.name
    }

    fn rowid_sequence_map(&self) -> &HashMap<u16, u16> {
        &self.rowid_sequence_map
    }
}

impl DeviceBrandRegexSequence {
    pub fn init<'a, R, I, S>(
        &mut self,
        rowids: I,
        ids: I,
        regexes: S,
        sequences: I,
        os_family_codes: S,
        os_codes: S,
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
            .zip(os_family_codes)
            .zip(os_codes);
        tup.for_each(|(((((rowid, id), regex), seq), os_family_code), os_code)| {
            let mut pattern = match Pattern::from_str(regex.as_ref()) {
                Ok(ptrn) => ptrn,
                Err(err) => {
                    eprintln!("{:?}", err);
                    return ();
                }
            };
            pattern.id = Some(*rowid as usize);
            patterns.push(pattern);

            // add new entry for <id, sequence> map
            self.rowid_sequence_map.insert(*rowid, *seq);

            // add code entry for <id, word> map
            let codes = [
                os_family_code.as_ref().to_string(),
                os_code.as_ref().to_string(),
            ];
            self.rowid_code_map.insert(*rowid, codes);
            self.rowid_id_map.insert(*rowid, *id);
        });

        self.db = Some(Patterns::from(patterns).build()?);

        Ok(())
    }

    pub fn get_id<'a, T, S>(
        &self,
        ua: &T,
        scratch: &mut RegexSequenceScratch,
        os_family_code: &S,
        os_code: &S,
    ) -> Result<Option<u16>>
    where
        T: AsRef<[u8]>,
        S: AsRef<str>,
    {
        let id_seqs = self.get_ids(ua, scratch)?;

        for item in &id_seqs {
            let codes = match self.rowid_code_map.get(&item) {
                None => continue,
                Some(arr) => arr,
            };

            if os_family_code.as_ref().to_string() == codes[0]
                && os_code.as_ref().to_string() == codes[1]
            {
                return match self.rowid_id_map.get(&item) {
                    None => Ok(None),
                    Some(id) => Ok(Some(*id)),
                };
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_row_id() {
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
                &"This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, Some(_)));
        assert_eq!(id.unwrap(), 0);
    }

    #[test]
    fn test_get_row_id_returns_none() {
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
                &"This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, None));
    }

    #[test]
    fn test_get_row_id_multiple_word_id() {
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
                &"This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, Some(_)));
    }

    #[test]
    fn test_device_name_get_id() {
        let mut regex_seq = DeviceBrandRegexSequence::new();

        let rowids: Vec<u16> = vec![0, 1];
        let ids: Vec<u16> = vec![1, 2];
        let regexes = vec![
            r"Mozilla.*Android.*; ([0-9a-z\.\_\-\/]+).*",
            r"(iPhone|iPad|iTab|iPod)",
        ];
        let sequences: Vec<u16> = vec![10, 20];
        let os_family_codes = vec!["android", "ios"];
        let os_codes = vec!["-all-", "-all-"];

        regex_seq
            .init(
                rowids.iter(),
                ids.iter(),
                regexes.iter(),
                sequences.iter(),
                os_family_codes.iter(),
                os_codes.iter(),
            )
            .unwrap();

        let mut scratch = regex_seq.alloc_scratch().unwrap();
        let id = regex_seq
            .get_id(
                &"iPhone 12",
                &mut scratch,
                &String::from("ios"),
                &String::from("-all-"),
            )
            .unwrap();

        assert!(matches!(id, Some(expected) if expected == 2));
    }
}
