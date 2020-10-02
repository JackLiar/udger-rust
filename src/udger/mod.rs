use std::path::PathBuf;

use anyhow::Result;
use hyperscan::prelude::{Pattern, Patterns};
use hyperscan::{ExprExt, PatternFlags};
use rusqlite::{params, Connection};

use crate::ffi::UaInfo;

mod word_detector;
use self::word_detector::{WordDetector, WordDetectorScratch};

pub struct UdgerData {
    pub app_word_scratch: WordDetectorScratch,
    pub client_word_scratch: WordDetectorScratch,
    pub device_word_scratch: WordDetectorScratch,
    pub os_word_scratch: WordDetectorScratch,
}

#[derive(Default)]
pub struct Udger {
    capacity: u16,
    conn: Option<Connection>,

    application_words_detector: WordDetector,
    client_words_detector: WordDetector,
    device_class_words_detector: WordDetector,
    os_words_detector: WordDetector,
}

impl Udger {
    pub fn new() -> Udger {
        let mut udger = Udger::default();
        udger.capacity = 10000;
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

    pub fn alloc_udger_data(&self) -> Result<UdgerData> {
        Ok(UdgerData {
            app_word_scratch: self.application_words_detector.alloc_scratch()?,
            client_word_scratch: self.client_words_detector.alloc_scratch()?,
            device_word_scratch: self.device_class_words_detector.alloc_scratch()?,
            os_word_scratch: self.os_words_detector.alloc_scratch()?,
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
            // String::from_raw
        }
        self.detect_client(&ua, data, info)?;
        self.detect_os(&ua, data, info)?;
        self.detect_application(&ua, data, info)?;
        self.detect_device(&ua, data, info)?;

        Ok(())
    }
}
