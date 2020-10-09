use std::path::PathBuf;

use anyhow::Result;
use hyperscan::prelude::{Pattern, Patterns};
use hyperscan::{ExprExt, PatternFlags};
use rusqlite::{params, Connection};

use crate::ffi::UaInfo;

mod regex_sequence;
mod sql;
mod word_detector;

use self::regex_sequence::{RegexSequence, RegexSequenceScratch};
use self::word_detector::{WordDetector, WordDetectorScratch};

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
            &conn,
        )?;

        Udger::init_regex_sequence(
            &mut self.client_regexes,
            &String::from("udger_client_regex"),
            &String::from("client_id"),
            &conn,
        )?;

        Udger::init_regex_sequence(
            &mut self.device_class_regexes,
            &String::from("udger_deviceclass_regex"),
            &String::from("deviceclass_id"),
            &conn,
        )?;

        Udger::init_regex_sequence(
            &mut self.device_name_regexes,
            &String::from("udger_devicename_regex"),
            &String::from("id"),
            &conn,
        )?;

        Udger::init_regex_sequence(
            &mut self.os_regexes,
            &String::from("udger_os_regex"),
            &String::from("os_id"),
            &conn,
        )?;

        self.conn = Some(conn);

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
        conn: &Connection,
    ) -> Result<()> {
        let mut stmt = conn.prepare(
            format!(
                "SELECT rowid, {}, regstring, sequence, word_id, word2_id FROM {} ORDER BY sequence;",
                id_column_name,
                table
            )
            .as_str(),
        )?;
        let rows = stmt.query_map(params![], |row| {
            let rowid: i32 = row.get(0)?;
            let id: i32 = row.get(1)?;
            let expression: String = row.get(2)?;
            let expression: &str = expression.strip_prefix("/").unwrap();
            let expression: &str = expression.strip_suffix("/si").unwrap();
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
        rows.for_each(|row| {
            rowids.push(((&row).as_ref().unwrap().0) as u16);
            ids.push(((&row).as_ref().unwrap().1) as u16);
            regexes.push((&row).as_ref().unwrap().2.clone());
            sequences.push((&row).as_ref().unwrap().3 as u16);
            word1s.push((&row).as_ref().unwrap().4 as u16);
            word2s.push((&row).as_ref().unwrap().5 as u16);
        });

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

    fn detect_client<T>(&self, ua: T, data: &mut UdgerData, info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.client_words_detector
            .get_word_ids(ua, &mut data.client_word_scratch)?;
        Ok(())
    }

    fn detect_os<T>(&self, ua: T, data: &mut UdgerData, _info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.os_words_detector
            .get_word_ids(ua, &mut data.os_word_scratch)?;
        Ok(())
    }

    fn detect_device<T>(&self, ua: T, data: &mut UdgerData, _info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.device_class_words_detector
            .get_word_ids(ua, &mut data.device_word_scratch)?;
        Ok(())
    }

    fn detect_application<T>(&self, ua: T, data: &mut UdgerData, _info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.application_words_detector
            .get_word_ids(ua, &mut data.app_word_scratch)?;
        Ok(())
    }

    pub fn parse_ua<T>(&self, ua: T, data: &mut UdgerData, info: &mut UaInfo) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        unsafe {
            // We need to find a better way/strategy to handle un-utf8 input
            let buf = ua.as_ref();
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
