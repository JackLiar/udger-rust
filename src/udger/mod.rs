use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::{anyhow, Result};
use hyperscan::prelude::{Pattern, Patterns};
use hyperscan::{ExprExt, PatternFlags};
use regex::Regex;
use rusqlite::{params, Connection, Error};

use crate::ffi::UaInfo;

mod regex_sequence;
mod sql;
mod word_detector;

use self::regex_sequence::{RegexSequence, RegexSequenceScratch};
use self::word_detector::{WordDetector, WordDetectorScratch};

const UNRECOGNIZED: &str = "unrecognized";

pub struct UdgerData {
    conn: Connection,
    #[cfg(application)]
    pub app_word_scratch: WordDetectorScratch,
    pub client_word_scratch: WordDetectorScratch,
    pub device_word_scratch: WordDetectorScratch,
    pub os_word_scratch: WordDetectorScratch,

    #[cfg(application)]
    pub app_regex_scratch: RegexSequenceScratch,
    pub client_regex_scratch: RegexSequenceScratch,
    pub device_class_regex_scratch: RegexSequenceScratch,
    pub device_name_regex_scratch: RegexSequenceScratch,
    pub os_regex_scratch: RegexSequenceScratch,

    cache: clru::CLruCache<String, Rc<UaInfo>>,
}

impl UdgerData {
    #[inline]
    pub fn get(&mut self, ua: &String) -> Option<Rc<UaInfo>> {
        match self.cache.get(ua) {
            Some(cached) => Some(cached.clone()),
            None => None,
        }
    }

    #[inline]
    pub fn set(&mut self, ua: &String, info: Rc<UaInfo>) {
        self.cache.put(ua.clone(), info);
    }
}

#[derive(Default)]
pub struct Udger {
    capacity: usize,
    db_fpath: PathBuf,

    #[cfg(application)]
    application_words_detector: WordDetector,
    client_words_detector: WordDetector,
    device_class_words_detector: WordDetector,
    os_words_detector: WordDetector,

    #[cfg(application)]
    application_regexes: RegexSequence,
    client_regexes: RegexSequence,
    device_class_regexes: RegexSequence,
    device_name_regexes: RegexSequence,
    os_regexes: RegexSequence,

    /// include all os_codes and os_family_codes
    os_codes: HashMap<String, usize>,
}

impl Udger {
    pub fn new() -> Udger {
        let mut udger = Udger::default();
        udger.capacity = 10000;
        udger.client_words_detector.name = String::from("client_words_detector");
        udger.device_class_words_detector.name = String::from("device_class_words_detector");
        udger.os_words_detector.name = String::from("os_words_detector");
        udger.client_regexes.name = String::from("client_regexes");
        udger.device_class_regexes.name = String::from("device_class_regexes");
        udger.device_name_regexes.name = String::from("device_name_regexes");
        udger.device_name_regexes.need_capture = true;
        udger.os_regexes.name = String::from("os_regexes");
        #[cfg(application)]
        {
            udger.application_words_detector.name = String::from("application_words_detector");
            udger.application_regexes.name = String::from("application_regexes");
        }
        udger
    }

    pub fn init(&mut self, db_fpath: PathBuf, capacity: usize) -> Result<()> {
        println!("Initializing Udger");
        self.capacity = capacity;
        self.db_fpath = db_fpath;

        let conn = Connection::open(&self.db_fpath)?;

        #[cfg(application)]
        {
            Udger::init_word_detector(
                &mut self.application_words_detector,
                &String::from("udger_application_regex_words"),
                &conn,
            )?;
        }

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

        #[cfg(application)]
        {
            Udger::init_regex_sequence(
                &mut self.application_regexes,
                &String::from("udger_application_regex"),
                &String::from("application_id"),
                &String::from("word_id"),
                &String::from("word2_id"),
                &conn,
            )?;
        }

        self.client_regexes.need_capture = true;
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

        println!("Finish initializing Udger");

        Ok(())
    }

    fn init_word_detector(
        detector: &mut WordDetector,
        table: &String,
        conn: &Connection,
    ) -> Result<()> {
        let mut stmt = conn.prepare(format!("SELECT id, word, count FROM {}", table).as_str())?;
        let mut rows = stmt.query(params![])?;
        let mut words = Vec::new();
        let mut ids = Vec::new();
        let mut counts = Vec::new();
        while let Some(row) = rows.next()? {
            let id: i32 = row.get(0)?;
            let expression: String = row.get(1)?;
            let count: i32 = row.get(2)?;
            let pattern = Pattern {
                expression,
                flags: PatternFlags::CASELESS | PatternFlags::ALLOWEMPTY,
                id: Some(id as usize),
                ext: ExprExt::default(),
                som: None,
            };
            words.push(pattern);
            ids.push(id as u16);
            counts.push(count as u16);
        }

        detector.init(ids.iter(), Patterns::from(words), counts.iter())?;
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
        let suffix_regex = Regex::new(r"\s?$")?;
        let rows = stmt.query_map(params![], |row| {
            let rowid: i32 = row.get(0)?;
            let id: i32 = row.get(1)?;
            let expression: String = row.get(2)?;
            let expression = suffix_regex.replace(expression.as_ref(), "").to_string();
            let expression = match expression.strip_suffix(" ") {
                None => expression,
                Some(expr) => expr.to_string(),
            };
            let sequence: i32 = row.get(3)?;
            let word1: i32 = row.get(4)?;
            let word2: i32 = row.get(5)?;
            Ok((rowid, id, expression, sequence, word1, word2))
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
        let mut stmt = conn.prepare(
            format!(
                "SELECT rowid, {}, regstring, sequence, {}, {} FROM {} ORDER BY sequence;",
                id_column_name, column1, column2, table
            )
            .as_str(),
        )?;
        let suffix_regex = Regex::new(r"\s?$")?;
        let rows = stmt.query_map(params![], |row| {
            let rowid: i32 = row.get(0)?;
            let id: i32 = row.get(1)?;
            let expression: String = row.get(2)?;
            let expression = suffix_regex.replace(expression.as_ref(), "").to_string();
            let sequence: i32 = row.get(3)?;
            let os_family_code: String = row.get(4)?;
            let os_code: String = row.get(5)?;
            Ok((rowid, id, expression, sequence, os_family_code, os_code))
        })?;

        let mut rowids = Vec::new();
        let mut ids = Vec::new();
        let mut regexes: Vec<String> = Vec::new();
        let mut sequences: Vec<u16> = Vec::new();
        let mut os_family_codes = Vec::new();
        let mut os_codes = Vec::new();
        let mut code_set = HashSet::new();
        for (_i, row) in rows.enumerate() {
            let row = match row {
                Err(err) => return Err(anyhow!(err)),
                Ok(r) => r,
            };
            rowids.push(row.0 as u16);
            ids.push(row.1 as u16);
            regexes.push(row.2.clone());
            sequences.push(row.3 as u16);
            os_family_codes.push(row.4.clone());
            os_codes.push(row.5.clone());
            // combine all the os_codes and os_family_codes, except "-all-"
            // !!! we asume there are no conflict between os_code and os_family_codes !!!
            code_set.insert(row.4.clone());
            if row.5 != "-all-" {
                code_set.insert(row.5.clone());
            }
        }
        // now convert all os_codes and os_family_codes to "word_id"
        for (i, code) in code_set.iter().enumerate() {
            self.os_codes.insert(code.clone(), i + 1);
        }
        let range1 = os_family_codes
            .iter()
            .map(|code| *self.os_codes.get(code).unwrap() as u16)
            .collect::<Vec<u16>>();
        let range2 = os_codes
            .iter()
            .map(|code| {
                // if code is "-all-" return 0 which would be filtered then
                if code != "-all-" {
                    *self.os_codes.get(code).unwrap() as u16
                } else {
                    0
                }
            })
            .collect::<Vec<u16>>();

        self.device_name_regexes.init(
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
        let capacity = NonZeroUsize::new(self.capacity).ok_or(anyhow!(
            "LRU cache size is zero, please make sure it's greater than zero"
        ))?;

        Ok(UdgerData {
            conn: Connection::open(&self.db_fpath)?,
            #[cfg(application)]
            app_word_scratch: self.application_words_detector.alloc_scratch()?,
            client_word_scratch: self.client_words_detector.alloc_scratch()?,
            device_word_scratch: self.device_class_words_detector.alloc_scratch()?,
            os_word_scratch: self.os_words_detector.alloc_scratch()?,
            #[cfg(application)]
            app_regex_scratch: self.application_regexes.alloc_scratch()?,
            client_regex_scratch: self.client_regexes.alloc_scratch()?,
            device_class_regex_scratch: self.device_class_regexes.alloc_scratch()?,
            device_name_regex_scratch: self.device_name_regexes.alloc_scratch()?,
            os_regex_scratch: self.os_regexes.alloc_scratch()?,
            cache: clru::CLruCache::new(capacity),
        })
    }

    fn detect_client<T>(&self, ua: &T, data: &mut UdgerData, info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        let stmt = &mut data.conn.prepare(sql::SQL_CRAWLER)?;

        // If any rows are returned, is classified as crawler
        // If error is not QueryReturnedNoRows, return the original error
        // Otherwise continue
        match stmt.query_row(params![ua.as_ref()], |row| {
            info.class_id = None;
            info.client_id = None;
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
            Ok(_) => return Ok(()),
        };

        let word_ids = self
            .client_words_detector
            .get_word_ids(&ua.as_ref(), &mut data.client_word_scratch)?;

        let (row_id, range) = match self.client_regexes.get_row_id_and_capture(
            &ua.as_ref(),
            &mut data.client_regex_scratch,
            &word_ids.iter(),
        )? {
            None => {
                info.ua_class = String::from(UNRECOGNIZED);
                info.ua_class_code = String::from(UNRECOGNIZED);
                return Ok(());
            }
            Some(v) => v,
        };

        let stmt = &mut data.conn.prepare(sql::SQL_CLIENT)?;
        match stmt.query_row(params![row_id], |row| {
            info.client_id = row.get(1)?;
            info.class_id = row.get(2)?;
            info.ua_class = row.get(3)?;
            info.ua_class_code = row.get(4)?;
            info.ua = row.get(5)?;
            info.ua_engine = row.get(6)?;
            info.ua_version = row.get(7).unwrap_or_default();
            info.ua_version_major = row.get(8).unwrap_or_default();
            info.crawler_last_seen = row.get(9).unwrap_or_default();
            info.crawler_respect_robotstxt = row.get(10).unwrap_or_default();
            info.crawler_category = row.get(11).unwrap_or_default();
            info.crawler_category_code = row.get(12).unwrap_or_default();
            info.ua_uptodate_current_version = row.get(13)?;
            info.ua_family = row.get(14)?;
            info.ua_family_code = row.get(15)?;
            #[cfg(homepage)]
            {
                info.ua_family_code_homepage = row.get(16)?;
            }
            #[cfg(icon)]
            {
                info.ua_family_code_icon = row.get(17)?;
                info.ua_family_code_icon_big = row.get(18)?;
                info.ua_family_vendor_homepage = row.get(21)?;
            }
            info.ua_family_vendor = row.get(19)?;
            info.ua_family_vendor_code = row.get(20)?;
            #[cfg(url)]
            {
                info.ua_family_info_url = row.get(22)?;
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

        match range {
            None => {}
            Some(range) => {
                info.ua_version = (&ua.as_ref()[range]).to_string();
                info.ua.extend([' '].iter());
                info.ua.extend(info.ua_version.chars());
                let split: Vec<&str> = info.ua_version.split('.').collect();
                info.ua_version_major = split[0].to_string();
            }
        };

        Ok(())
    }

    fn detect_os<T>(&self, ua: &T, data: &mut UdgerData, info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        let word_ids = self
            .os_words_detector
            .get_word_ids(&ua.as_ref(), &mut data.os_word_scratch)?;

        let (row_id, _) = match self.os_regexes.get_row_id_and_capture(
            &ua.as_ref(),
            &mut data.os_regex_scratch,
            &word_ids.iter(),
        )? {
            None => return Ok(()),
            Some(rid) => rid,
        };

        let stmt = &mut data.conn.prepare(&sql::SQL_OS)?;
        match stmt.query_row(params![row_id], |row| {
            info.os_family = row.get(1)?;
            info.os_family_code = row.get(2)?;
            info.os = row.get(3)?;
            info.os_code = row.get(4)?;
            #[cfg(homepage)]
            {
                info.os_homepage = row.get(5)?;
                info.os_family_vendor_homepage = row.get(10)?;
            }
            #[cfg(icon)]
            {
                info.os_icon = row.get(6)?;
                info.os_icon_big = row.get(7)?;
            }
            info.os_family_vendor = row.get(8)?;
            info.os_family_vendor_code = row.get(9)?;
            #[cfg(url)]
            {
                info.os_info_url = row.get(11)?;
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

        Ok(())
    }

    fn detect_device_class<T>(&self, ua: &T, data: &mut UdgerData, info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        let word_ids = self
            .device_class_words_detector
            .get_word_ids(&ua.as_ref(), &mut data.device_word_scratch)?;

        let (row_id, _) = match self.device_class_regexes.get_row_id_and_capture(
            &ua.as_ref(),
            &mut data.device_class_regex_scratch,
            &word_ids.iter(),
        )? {
            None => {
                match info.class_id {
                    None => {}
                    Some(class_id) => {
                        let stmt = &mut data.conn.prepare(&sql::SQL_CLIENT_CLASS)?;
                        match stmt.query_row(params![class_id], |row| {
                            info.device_class = row.get(0)?;
                            info.device_class_code = row.get(1)?;
                            #[cfg(icon)]
                            {
                                info.device_class_icon = row.get(2)?;
                                info.device_class_icon_big = row.get(3)?;
                            }
                            #[cfg(url)]
                            {
                                info.device_class_info_url = row.get(4)?;
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
                    }
                };
                return Ok(());
            }
            Some(rid) => rid,
        };

        let stmt = &mut data.conn.prepare(&sql::SQL_DEVICE)?;
        match stmt.query_row(params![row_id], |row| {
            info.device_class = row.get(1)?;
            info.device_class_code = row.get(2)?;
            #[cfg(icon)]
            {
                info.device_class_icon = row.get(3)?;
                info.device_class_icon_big = row.get(4)?;
            }
            #[cfg(url)]
            {
                info.device_class_info_url = row.get(5)?;
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

        Ok(())
    }

    fn detect_device_brand<T>(&self, ua: &T, data: &mut UdgerData, info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        if info.os_family_code.is_empty() || info.os_code.is_empty() {
            return Ok(());
        }

        let mut word_ids = Vec::new();
        match self.os_codes.get(&info.os_family_code) {
            None => (),
            Some(code) => word_ids.push(*code as u16),
        };
        match self.os_codes.get(&info.os_code) {
            None => (),
            Some(code) => word_ids.push(*code as u16),
        };

        let (row_id, capture) = match self.device_name_regexes.get_row_id_and_capture(
            &ua.as_ref(),
            &mut data.device_name_regex_scratch,
            &word_ids.iter(),
        )? {
            None => return Ok(()),
            Some(rid) => rid,
        };

        let id = match self.device_name_regexes.get_id(row_id) {
            Some(id) => id,
            None => return Ok(()),
        };
        let capture = match capture {
            None => return Ok(()),
            Some(cap) => cap,
        };

        let stmt = &mut data.conn.prepare(sql::SQL_DEVICE_NAME_LIST)?;
        match stmt.query_row(params![id, &ua.as_ref()[capture]], |row| {
            info.device_marketname = row.get(0).unwrap_or_default();
            info.device_brand_code = row.get(1).unwrap_or_default();
            info.device_brand = row.get(2).unwrap_or_default();
            #[cfg(url)]
            {
                info.device_brand_url = row.get(3).unwrap_or_default();
            }
            #[cfg(icon)]
            {
                info.device_brand_icon = row.get(4).unwrap_or_default();
                info.device_brand_icon_big = row.get(5).unwrap_or_default();
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
        Ok(())
    }

    #[cfg(application)]
    fn detect_application<T>(&self, ua: &T, data: &mut UdgerData, _info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<str>,
    {
        self.application_words_detector
            .get_word_ids(&ua.as_ref(), &mut data.app_word_scratch)?;
        Ok(())
    }

    pub fn parse_ua<T>(&self, ua: &T, data: &mut UdgerData) -> Result<Rc<UaInfo>>
    where
        T: AsRef<str>,
    {
        // info.ua_string = ua.as_ref().to_string();
        // try to get cached ua info
        let ua = ua.as_ref().to_string();
        match data.get(&ua) {
            Some(cached) => return Ok(cached),
            None => {}
        };

        let mut info = Rc::new(UaInfo::default());
        Rc::get_mut(&mut info).unwrap().ua_string = ua.clone();

        self.detect_client(&ua, data, Rc::get_mut(&mut info).unwrap())?;
        self.detect_os(&ua, data, Rc::get_mut(&mut info).unwrap())?;
        #[cfg(application)]
        {
            self.detect_application(&ua, data, Rc::get_mut(&mut info).unwrap())?;
        }
        self.detect_device_class(&ua, data, Rc::get_mut(&mut info).unwrap())?;
        self.detect_device_brand(&ua, data, Rc::get_mut(&mut info).unwrap())?;

        data.set(&ua, info.clone());

        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        println!("{}", serde_json::to_string_pretty(&info).unwrap());
        assert_eq!(info.client_id.unwrap(), 3);
        assert_eq!(info.class_id.unwrap(), 0);
        assert_eq!(info.ua, "Firefox 40.0");
        assert_eq!(info.ua_class, "Browser");
        assert_eq!(info.ua_class_code, "browser");
        assert_eq!(info.ua_engine, "Gecko");
        assert_eq!(info.ua_uptodate_current_version, "50");
        assert_eq!(info.ua_family, "Firefox");
        assert_eq!(info.ua_family_code, "firefox");
        assert_eq!(info.ua_version, "40.0");
        assert_eq!(info.ua_version_major, "40");
        #[cfg(homepage)]
        {
            assert_eq!(info.ua_family_homepage, "http://www.firefox.com/");
            assert_eq!(info.ua_family_vendor_homepage, "http://www.mozilla.org/");
        }
        #[cfg(icon)]
        {
            assert_eq!(info.ua_family_icon, "firefox.png");
            assert_eq!(info.ua_family_icon_big, "firefox_big.png");
        }
        #[cfg(url)]
        {
            assert_eq!(
                info.ua_family_info_url,
                "https://udger.com/resources/ua-list/browser-detail?browser=Firefox"
            );
        }
        assert_eq!(info.ua_family_vendor, "Mozilla Foundation");
        assert_eq!(info.ua_family_vendor_code, "mozilla_foundation");

        let ua = String::from("Googlebot/2.1 (+http://www.google.com/bot.html)");
        udger.detect_client(&ua, &mut data, &mut info).unwrap();
        assert_eq!(info.crawler_category, "Search engine bot");
        assert_eq!(info.crawler_category_code, "search_engine_bot");
        assert_eq!(info.crawler_last_seen, "2017-01-06 08:57:43");
        assert_eq!(info.crawler_respect_robotstxt, "yes");
        assert_eq!(info.ua, "Googlebot/2.1");
        assert_eq!(info.ua_class, "Crawler");
        assert_eq!(info.ua_class_code, "crawler");
        assert_eq!(info.ua_family, "Googlebot");
        assert_eq!(info.ua_family_code, "googlebot");
        assert_eq!(info.ua_family_vendor, "Google Inc.");
        assert_eq!(info.ua_family_vendor_code, "google_inc");
        assert_eq!(info.ua_version, "2.1");
        assert_eq!(info.ua_version_major, "2");
        #[cfg(homepage)]
        {
            assert_eq!(info.ua_family_homepage, "http://www.google.com/bot.html");
            assert_eq!(
                info.ua_family_vendor_homepage,
                "https://www.google.com/about/company/"
            );
        }
        #[cfg(icon)]
        {
            assert_eq!(info.ua_family_icon, "bot_googlebot.png");
            assert_eq!(info.ua_family_icon_big, "");
        }
        #[cfg(icon)]
        {
            assert_eq!(
                info.ua_family_url,
                "https://udger.com/resources/ua-list/bot-detail?bot=Googlebot#id4966"
            );
        }
    }

    #[test]
    fn test_detect_os() {
        let mut udger = Udger::new();
        udger
            .init(PathBuf::from("./data/udgerdb_v3_test.dat"), 10000)
            .unwrap();

        let mut data = udger.alloc_udger_data().unwrap();
        let mut info = UaInfo::default();
        let ua = String::from(
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        );
        udger.detect_os(&ua, &mut data, &mut info).unwrap();

        assert_eq!(info.os, "Windows 10");
        assert_eq!(info.os_code, "windows_10");
        assert_eq!(info.os_family, "Windows");
        assert_eq!(info.os_family_code, "windows");
        assert_eq!(info.os_family_vendor, "Microsoft Corporation.");
        assert_eq!(info.os_family_vendor_code, "microsoft_corporation");
        #[cfg(homepage)]
        {
            assert_eq!(
                info.os_family_vendor_homepage,
                "https://www.microsoft.com/about/"
            );
            assert_eq!(info.os_homepage, "https://en.wikipedia.org/wiki/Windows_10");
        }
        #[cfg(icon)]
        {
            assert_eq!(info.os_icon, "windows10.png");
            assert_eq!(info.os_icon_big, "windows10_big.png");
        }
        #[cfg(icon)]
        {
            assert_eq!(
                info.os_info_url,
                "https://udger.com/resources/ua-list/os-detail?os=Windows%2010"
            );
        }
    }

    #[test]
    fn test_detect_device_class() {
        // some regular expressions in udgerdb_v3_test.data's udger_deviceclass_regex_words table
        // could cause lots of incorrect matching,
        // so use the real udger database to test this function
        let mut udger = Udger::new();
        udger
            .init(PathBuf::from("./data/udgerdb_v3_full.dat"), 10000)
            .unwrap();

        let mut data = udger.alloc_udger_data().unwrap();
        let mut info = UaInfo::default();
        let ua = String::from(
            "Mozilla/5.0 (iPad; CPU OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53",
        );
        udger.detect_client(&ua, &mut data, &mut info).unwrap();
        udger
            .detect_device_class(&ua, &mut data, &mut info)
            .unwrap();

        assert_eq!(info.device_class, "Tablet");
        assert_eq!(info.device_class_code, "tablet");
        #[cfg(icon)]
        {
            assert_eq!(info.device_class_icon, "tablet.png");
            assert_eq!(info.device_class_icon_big, "tablet_big.png");
        }
        #[cfg(url)]
        {
            assert_eq!(
                info.device_class_info_url,
                "https://udger.com/resources/ua-list/device-detail?device=Tablet"
            );
        }

        let mut info = UaInfo::default();
        let ua =
            String::from("Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) chrome/79.0.3945.117 Safari/537.36");
        udger.detect_client(&ua, &mut data, &mut info).unwrap();
        udger
            .detect_device_class(&ua, &mut data, &mut info)
            .unwrap();

        assert_eq!(info.device_class, "Desktop");
        assert_eq!(info.device_class_code, "desktop");
    }

    #[test]
    fn test_detect_device_brand() {
        // some regular expressions in udgerdb_v3_test.data's udger_deviceclass_regex_words table
        // could cause lots of incorrect matching,
        // so use the real udger database to test this function
        let mut udger = Udger::new();
        udger
            .init(PathBuf::from("./data/udgerdb_v3_full.dat"), 10000)
            .unwrap();

        let mut data = udger.alloc_udger_data().unwrap();
        let mut info = UaInfo::default();
        let ua = String::from(
            "Mozilla/5.0 (iPad; CPU OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53",
        );
        udger.detect_client(&ua, &mut data, &mut info).unwrap();
        udger.detect_os(&ua, &mut data, &mut info).unwrap();
        assert_eq!(info.os_family_code, "ios");
        udger
            .detect_device_class(&ua, &mut data, &mut info)
            .unwrap();
        udger
            .detect_device_brand(&ua, &mut data, &mut info)
            .unwrap();

        assert_eq!(info.device_brand, "Apple");
        assert_eq!(info.device_brand_code, "apple");
        #[cfg(homepage)]
        {
            assert_eq!(info.device_brand_homepage, "http://www.apple.com/");
        }
        #[cfg(icon)]
        {
            assert_eq!(info.device_brand_icon, "apple.png");
            assert_eq!(info.device_brand_icon_big, "apple_big.png");
        }
        #[cfg(url)]
        {
            assert_eq!(
                info.device_brand_info_url,
                "https://udger.com/resources/ua-list/devices-brand-detail?brand=apple"
            );
        }
    }

    #[test]
    fn test_unrecognized() {
        let mut udger = Udger::new();
        udger
            .init(PathBuf::from("./data/udgerdb_v3_full.dat"), 10000)
            .unwrap();

        let mut data = udger.alloc_udger_data().unwrap();
        let ua = String::from("this is not an user-agent");

        let info = udger.parse_ua(&ua, &mut data).unwrap();
        assert_eq!(info.ua_class, "unrecognized");
        assert_eq!(info.ua_class_code, "unrecognized");
        #[cfg(application)]
        {
            assert_eq!(info.application_name, "");
            assert_eq!(info.application_version, "");
        }
        assert_eq!(info.crawler_category, "");
        assert_eq!(info.crawler_category_code, "");
        assert_eq!(info.crawler_last_seen, "");
        assert_eq!(info.crawler_respect_robotstxt, "");
        assert_eq!(info.device_brand, "");
        assert_eq!(info.device_brand_code, "");
        assert_eq!(info.device_class, "");
        assert_eq!(info.device_class_code, "");
        assert_eq!(info.device_marketname, "");
        assert_eq!(info.os, "");
        assert_eq!(info.os_code, "");
        assert_eq!(info.os_family, "");
        assert_eq!(info.os_family_code, "");
        assert_eq!(info.os_family_vendor, "");
        assert_eq!(info.os_family_vendor_code, "");
        assert_eq!(info.ua, "");
        assert_eq!(info.ua_engine, "");
        assert_eq!(info.ua_family, "");
        assert_eq!(info.ua_family_code, "");
        assert_eq!(info.ua_family_vendor, "");
        assert_eq!(info.ua_family_vendor_code, "");
        assert_eq!(info.ua_string, ua);
        assert_eq!(info.ua_uptodate_current_version, "");
        assert_eq!(info.ua_version, "");
        assert_eq!(info.ua_version_major, "");
        assert_eq!(info.ua_version_minor, "");
    }
}
