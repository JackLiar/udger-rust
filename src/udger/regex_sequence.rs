use std::collections::HashMap;
use std::ops::Range;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use hyperscan::chimera::prelude::*;
use hyperscan::chimera::Capture;

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
    pub need_capture: bool,
    db: Option<Database>,
    id_word_map: HashMap<u16, Vec<u16>>,
    rowid_sequence_map: HashMap<u16, u16>,
    rowid_id_map: HashMap<u16, u16>,
}

impl RegexSequence {
    fn db(&self) -> &Option<Database> {
        &self.db
    }

    fn rowid_sequence_map(&self) -> &HashMap<u16, u16> {
        &self.rowid_sequence_map
    }

    fn get_ids<T>(
        &self,
        ua: &T,
        scratch: &mut RegexSequenceScratch,
    ) -> Result<Vec<(u16, Option<Range<usize>>)>>
    where
        T: AsRef<[u8]>,
    {
        let mut id_seqs = Vec::new();
        if let Some(db) = &self.db() {
            db.scan(
                ua.as_ref(),
                scratch.raw(),
                |id, _from, _to, _size, captured| {
                    let seq = match self.rowid_sequence_map().get(&(id as u16)) {
                        // if no matching id is found, continue matching
                        None => return Matching::Continue,
                        Some(seq) => *seq,
                    };

                    let captures: &[Capture] = match captured {
                        None => {
                            id_seqs.push(((id as u16, None), seq));
                            return Matching::Continue;
                        }
                        Some(captures) => captures,
                    };
                    let range = captures.get(1).map(|cap| cap.range());

                    id_seqs.push(((id as u16, range), seq));

                    Matching::Continue
                },
                |_err_type, _id| Matching::Continue,
            )?;
        }

        // sort ids by sequence
        id_seqs.sort_by(|s, o| s.1.cmp(&o.1));

        Ok(id_seqs.iter().map(|(id, _)| id.clone()).collect())
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
            let mut pattern = match Pattern::from_str(regex.as_ref()) {
                Ok(ptrn) => ptrn,
                Err(_err) => {
                    return;
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

        if self.need_capture {
            self.db = Some(Patterns::from(patterns).with_groups()?);
        } else {
            self.db = Some(Patterns::from(patterns).build()?);
        }

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

    pub fn get_row_id_and_capture<'a, T, I>(
        &self,
        ua: &T,
        scratch: &mut RegexSequenceScratch,
        word_ids: &I,
    ) -> Result<Option<(u16, Option<Range<usize>>)>>
    where
        T: AsRef<[u8]>,
        I: Iterator<Item = &'a u16> + Clone,
    {
        if word_ids.clone().count() == 0 {
            return Ok(None);
        }

        let ids = self.get_ids(ua, scratch)?;

        for (id, range) in &ids {
            let word_vec = match self.id_word_map.get(id) {
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
            if found_word_count >= word_vec.len() {
                return Ok(Some((*id, range.clone())));
            }
        }

        Ok(None)
    }

    /// Get the actual id column of the sqlite table
    pub fn get_id(&self, rowid: u16) -> Option<u16> {
        self.rowid_id_map.get(&rowid).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_row_id() {
        let mut regex_seq = RegexSequence::default();

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
            .get_row_id_and_capture(
                &"This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, Some(_)));
        assert_eq!(id.unwrap().0, 0);
    }

    #[test]
    fn test_get_row_id_returns_none() {
        let mut regex_seq = RegexSequence::default();

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
            .get_row_id_and_capture(
                &"This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, None));
    }

    #[test]
    fn test_get_row_id_multiple_word_id() {
        let mut regex_seq = RegexSequence::default();

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
            .get_row_id_and_capture(
                &"This is a sentence contains the word regex",
                &mut scratch,
                &word_ids.iter(),
            )
            .unwrap();

        assert!(matches!(id, Some(_)));
    }
}
