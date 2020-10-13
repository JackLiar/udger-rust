use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use hyperscan::prelude::{Pattern, Patterns};
use hyperscan::{ExprExt, PatternFlags};
use rusqlite::{params, Connection, Error};

use crate::ffi::UaInfo;

mod regex_sequence;
mod sql;
mod word_detector;

use self::regex_sequence::{RegexSequence, RegexSequenceScratch};
use self::word_detector::{WordDetector, WordDetectorScratch};

const UNRECOGNIZED: &str = "unrecognized";

pub struct UdgerData {
    pub app_word_scratch: WordDetectorScratch,
    pub client_word_scratch: WordDetectorScratch,
    pub device_word_scratch: WordDetectorScratch,
    pub os_word_scratch: WordDetectorScratch,

    pub app_regex_scratch: RegexSequenceScratch,
    pub client_regex_scratch: RegexSequenceScratch,
    pub device_class_regex_scratch: RegexSequenceScratch,
    pub device_name_regex_scratch: RegexSequenceScratch,
    pub os_regex_scratch: RegexSequenceScratch,
}

#[derive(Default)]
pub struct Udger {
    capacity: u16,
    conn: Option<Connection>,

    application_words_detector: WordDetector,
    client_words_detector: WordDetector,
    device_class_words_detector: WordDetector,
    os_words_detector: WordDetector,

    application_regexes: RegexSequence,
    client_regexes: RegexSequence,
    device_class_regexes: RegexSequence,
    device_name_regexes: RegexSequence,
    os_regexes: RegexSequence,

    os_family_codes: Vec<String>,
    os_codes: Vec<String>,
    device_name_os_family_code_map: HashMap<u16, String>,
    device_name_os_code_map: HashMap<u16, String>,
}

impl Udger {
    pub fn new() -> Udger {
        let mut udger = Udger::default();
        udger.capacity = 10000;
        udger.application_words_detector.name = String::from("application_words_detector");
        udger.client_words_detector.name = String::from("client_words_detector");
        udger.device_class_words_detector.name = String::from("device_class_words_detector");
        udger.os_words_detector.name = String::from("os_words_detector");
        udger.application_regexes.name = String::from("application_regexes");
        udger.client_regexes.name = String::from("client_regexes");
        udger.device_class_regexes.name = String::from("device_class_regexes");
        udger.device_name_regexes.name = String::from("device_name_regexes");
        udger.os_regexes.name = String::from("os_regexes");
        udger
    }

    pub fn init(&mut self, db_path: PathBuf, capacity: u16) -> Result<()> {
        println!("Initializing Udger");
        self.capacity = capacity;

        let conn = Connection::open(db_path)?;

        Udger::init_word_detector(
            &mut self.application_words_detector,
            &String::from("udger_application_regex_words"),
            &conn,
        )?;

        Udger::init_word_detector(
            &mut self.client_words_detector,
            &String::from("udger_client_regex_words"),
            &conn,
        )?;

        Udger::init_word_detector(
            &mut self.device_class_words_detector,
            &String::from("udger_deviceclass_regex_words"),
            &conn,
        )?;

        Udger::init_word_detector(
            &mut self.os_words_detector,
            &String::from("udger_os_regex_words"),
            &conn,
        )?;

        Udger::init_regex_sequence(
            &mut self.application_regexes,
            &String::from("udger_application_regex"),
            &String::from("application_id"),
            &String::from("word_id"),
            &String::from("word2_id"),
            &conn,
        )?;

        Udger::init_regex_sequence(
            &mut self.client_regexes,
            &String::from("udger_client_regex"),
            &String::from("client_id"),
            &String::from("word_id"),
            &String::from("word2_id"),
            &conn,
        )?;

        Udger::init_regex_sequence(
            &mut self.device_class_regexes,
            &String::from("udger_deviceclass_regex"),
            &String::from("deviceclass_id"),
            &String::from("word_id"),
            &String::from("word2_id"),
            &conn,
        )?;

        self.init_device_name_regex_sequence(
            &String::from("udger_devicename_regex"),
            &String::from("id"),
            &String::from("os_family_code"),
            &String::from("os_code"),
            &conn,
        )?;

        Udger::init_regex_sequence(
            &mut self.os_regexes,
            &String::from("udger_os_regex"),
            &String::from("os_id"),
            &String::from("word_id"),
            &String::from("word2_id"),
            &conn,
        )?;

        self.conn = Some(conn);
        println!("Finish initializing Udger");

        Ok(())
    }

    fn init_word_detector(
        detector: &mut WordDetector,
        table: &String,
        conn: &Connection,
    ) -> Result<()> {
        let mut stmt = conn.prepare(format!("SELECT id, word FROM {}", table).as_str())?;
        let words: Vec<Pattern> = stmt
            .query_map(params![], |row| {
                let expression: String = row.get(1)?;
                let id: i32 = row.get(0)?;
                Ok(Pattern {
                    expression,
                    flags: PatternFlags::CASELESS,
                    id: Some(id as usize),
                    ext: ExprExt::default(),
                    som: None,
                })
            })?
            .map(|e| e.unwrap())
            .collect();

        detector.init(Patterns::from(words))?;
        Ok(())
    }

    fn init_regex_sequence(
        seq: &mut RegexSequence,
        table: &String,
        id_column_name: &String,
        column1: &String,
        column2: &String,
        conn: &Connection,
    ) -> Result<()> {
        let mut stmt = conn.prepare(
            format!(
                "SELECT rowid, {}, regstring, sequence, {}, {} FROM {} ORDER BY sequence;",
                id_column_name, column1, column2, table
            )
            .as_str(),
        )?;
        let rows = stmt.query_map(params![], |row| {
            let rowid: i32 = row.get(0)?;
            let id: i32 = row.get(1)?;
            let expression: String = row.get(2)?;
            let expression = match expression.strip_prefix("/") {
                None => expression.as_str(),
                Some(expr) => expr,
            };
            let expression = match expression.strip_suffix("/si") {
                None => expression,
                Some(expr) => expr,
            };
            let sequence: i32 = row.get(3)?;
            let word1: i32 = row.get(4)?;
            let word2: i32 = row.get(5)?;
            Ok((rowid, id, expression.to_string(), sequence, word1, word2))
        })?;

        let mut rowids = Vec::new();
        let mut ids = Vec::new();
        let mut regexes: Vec<String> = Vec::new();
        let mut sequences: Vec<u16> = Vec::new();
        let mut word1s: Vec<u16> = Vec::new();
        let mut word2s: Vec<u16> = Vec::new();
        for (_i, row) in rows.enumerate() {
            let row = match row {
                Err(err) => return Err(anyhow!(err)),
                Ok(r) => r,
            };
            rowids.push(row.0 as u16);
            ids.push(row.1 as u16);
            regexes.push(row.2.clone());
            sequences.push(row.3 as u16);
            word1s.push(row.4 as u16);
            word2s.push(row.5 as u16);
        }

        seq.init(
            rowids.iter(),
            ids.iter(),
            regexes.iter(),
            sequences.iter(),
            word1s.iter(),
            word2s.iter(),
        )?;

        Ok(())
    }

    /// Initialize device name regex sequence
    ///
    /// Since device name regex table's structure is different from other regex tables,
    /// we use a specifc function to initialize it. For convenience and consistency,
    /// use the same api of init_regex_sequence
    fn init_device_name_regex_sequence(
        &mut self,
        table: &String,
        id_column_name: &String,
        column1: &String,
        column2: &String,
        conn: &Connection,
    ) -> Result<()> {
        let seq = &mut self.device_name_regexes;
        let mut stmt = conn.prepare(
            format!(
                "SELECT rowid, {}, regstring, sequence, {}, {} FROM {} ORDER BY sequence;",
                id_column_name, column1, column2, table
            )
            .as_str(),
        )?;
        let rows = stmt.query_map(params![], |row| {
            let rowid: i32 = row.get(0)?;
            let id: i32 = row.get(1)?;
            let expression: String = row.get(2)?;
            let expression = match expression.strip_prefix("/") {
                None => expression.as_str(),
                Some(expr) => expr,
            };
            let expression = match expression.strip_suffix("/si") {
                None => expression,
                Some(expr) => expr,
            };
            let sequence: i32 = row.get(3)?;
            let os_family_code: String = row.get(4)?;
            let os_code: String = row.get(5)?;
            Ok((
                rowid,
                id,
                expression.to_string(),
                sequence,
                os_family_code,
                os_code,
            ))
        })?;

        let mut rowids = Vec::new();
        let mut ids = Vec::new();
        let mut regexes: Vec<String> = Vec::new();
        let mut sequences: Vec<u16> = Vec::new();
        for (_i, row) in rows.enumerate() {
            let row = match row {
                Err(err) => return Err(anyhow!(err)),
                Ok(r) => r,
            };
            rowids.push(row.0 as u16);
            ids.push(row.1 as u16);
            regexes.push(row.2.clone());
            sequences.push(row.3 as u16);
            self.os_family_codes.push(row.4.clone());
            self.os_codes.push(row.5.clone());
        }

        let range1 = (0..self.os_family_codes.len() as u16).collect::<Vec<u16>>();
        let range2 = (0..self.os_codes.len() as u16).collect::<Vec<u16>>();
        seq.init(
            rowids.iter(),
            ids.iter(),
            regexes.iter(),
            sequences.iter(),
            range1.iter(),
            range2.iter(),
        )?;

        Ok(())
    }

    pub fn alloc_udger_data(&self) -> Result<UdgerData> {
        Ok(UdgerData {
            app_word_scratch: self.application_words_detector.alloc_scratch()?,
            client_word_scratch: self.client_words_detector.alloc_scratch()?,
            device_word_scratch: self.device_class_words_detector.alloc_scratch()?,
            os_word_scratch: self.os_words_detector.alloc_scratch()?,
            app_regex_scratch: self.application_regexes.alloc_scratch()?,
            client_regex_scratch: self.client_regexes.alloc_scratch()?,
            device_class_regex_scratch: self.device_class_regexes.alloc_scratch()?,
            device_name_regex_scratch: self.device_name_regexes.alloc_scratch()?,
            os_regex_scratch: self.os_regexes.alloc_scratch()?,
        })
    }

    fn detect_client<T>(&self, ua: &T, data: &mut UdgerData, info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        let mut stmt = match &self.conn {
            None => return Err(anyhow!(format!("Udger sqlite Connection is None"))),
            Some(conn) => conn.prepare(sql::SQL_CRAWLER)?,
        };

        // If any rows are returned, is classified as crawler
        // If error is not QueryReturnedNoRows, return the original error
        // Otherwise continue
        match stmt.query_row(params![ua.as_ref()], |row| {
            info.class_id = 99;
            info.client_id = -1;
            info.ua_class = row.get(2)?;
            info.ua_class_code = row.get(3)?;
            info.ua = row.get(4)?;
            info.ua_engine = row.get(5).unwrap_or_default();
            info.ua_version = row.get(6)?;
            info.ua_version_major = row.get(7)?;
            info.crawler_last_seen = row.get(8)?;
            info.crawler_respect_robotstxt = row.get(9)?;
            info.crawler_category = row.get(10)?;
            info.crawler_category_code = row.get(11)?;
            info.ua_uptodate_current_version = row.get(12).unwrap_or_default();
            info.ua_family = row.get(13)?;
            info.ua_family_code = row.get(14)?;
            #[cfg(homepage)]
            {
                info.ua_family_homepage = row.get(15)?;
                info.ua_family_vendor_code_homepage = row.get(20)?;
            }
            #[cfg(icon)]
            {
                info.ua_family_icon = row.get(16)?;
                info.ua_family_icon_big = row.get(17)?;
            }
            info.ua_family_vendor = row.get(18)?;
            info.ua_family_vendor_code = row.get(19)?;
            #[cfg(url)]
            {
                info.ua_family_info_url = row.get(21)?;
            }
            Ok(())
        }) {
            Err(err) => {
                match err {
                    Error::QueryReturnedNoRows => {}
                    _ => return Err(anyhow!(err)),
                };
            }
            Ok(_) => {}
        };

        let word_ids = self
            .client_words_detector
            .get_word_ids(&ua.as_ref(), &mut data.client_word_scratch)?;

        if word_ids.len() == 0 {
            info.ua_class = String::from(UNRECOGNIZED);
            info.ua_class_code = String::from(UNRECOGNIZED);
            return Ok(());
        }

        let row_id = match self.client_regexes.get_row_id(
            &ua.as_ref(),
            &mut data.client_regex_scratch,
            word_ids.iter(),
        )? {
            None => return Ok(()),
            Some(rid) => rid,
        };

        stmt = match &self.conn {
            None => return Err(anyhow!(format!("Udger sqlite Connection is None"))),
            Some(conn) => conn.prepare(sql::SQL_CLIENT)?,
        };
        match stmt.query_row(params![row_id], |row| {
            info.client_id = row.get(1)?;
            info.class_id = row.get(2)?;
            info.ua_class = row.get(3)?;
            info.ua_class_code = row.get(4)?;
            Ok(())
        }) {
            Err(err) => {
                match err {
                    Error::QueryReturnedNoRows => {}
                    _ => return Err(anyhow!(err)),
                };
            }
            Ok(_) => {}
        };

        Ok(())
    }

    fn detect_os<T>(&self, ua: &T, data: &mut UdgerData, _info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        self.os_words_detector
            .get_word_ids(&ua.as_ref(), &mut data.os_word_scratch)?;
        Ok(())
    }

    fn detect_device<T>(&self, ua: &T, data: &mut UdgerData, _info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        self.device_class_words_detector
            .get_word_ids(&ua.as_ref(), &mut data.device_word_scratch)?;
        Ok(())
    }

    fn detect_application<T>(&self, ua: &T, data: &mut UdgerData, _info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        self.application_words_detector
            .get_word_ids(&ua.as_ref(), &mut data.app_word_scratch)?;
        Ok(())
    }

    pub fn parse_ua<T>(&self, ua: T, data: &mut UdgerData, info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        unsafe {
            // We need to find a better way/strategy to handle un-utf8 input
            let buf: &str = ua.as_ref();
            let vec = Vec::from_raw_parts(buf.as_ptr() as *mut u8, buf.len(), buf.len());
            info.ua = String::from_utf8_lossy(&vec).to_owned().to_string();
        }
        self.detect_client(&ua, data, info)?;
        self.detect_os(&ua, data, info)?;
        self.detect_application(&ua, data, info)?;
        self.detect_device(&ua, data, info)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_application() {}

    #[test]
    fn test_detect_client() {
        let mut udger = Udger::new();
        udger
            .init(PathBuf::from("./data/udgerdb_v3_test.dat"), 10000)
            .unwrap();

        let mut data = udger.alloc_udger_data().unwrap();
        let mut info = UaInfo::default();
        let ua = String::from(
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        );
        udger.detect_client(&ua, &mut data, &mut info).unwrap();

        assert_eq!(info.ua_class, "Browser");
        assert_eq!(info.ua_class_code, "browser");

        let ua = String::from("Googlebot/2.1 (+http://www.google.com/bot.html)");
        udger.detect_client(&ua, &mut data, &mut info).unwrap();
        assert_eq!(info.crawler_category, "Search engine bot");
        assert_eq!(info.crawler_category_code, "search_engine_bot");
        assert_eq!(info.crawler_last_seen, "2017-01-06 08:57:43");
        assert_eq!(info.crawler_respect_robotstxt, "yes");
    }
}
