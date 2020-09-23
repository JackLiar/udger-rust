use std::ffi::CString;

use anyhow::Result;

use crate::ffi::ua_info;

mod word_detector;
use self::word_detector::{WordDetector, WordDetectorScratch};

pub struct UdgerData {
    pub app_word_scratch: WordDetectorScratch,
    pub client_word_scratch: WordDetectorScratch,
    pub device_word_scratch: WordDetectorScratch,
    pub os_word_scratch: WordDetectorScratch,
}

pub struct Udger {
    application_words_detector: WordDetector,
    client_words_detector: WordDetector,
    device_class_words_detector: WordDetector,
    os_words_detector: WordDetector,
}

impl Udger {
    pub fn new() -> Udger {
        Udger {
            application_words_detector: WordDetector::new(),
            client_words_detector: WordDetector::new(),
            device_class_words_detector: WordDetector::new(),
            os_words_detector: WordDetector::new(),
        }
    }

    pub fn init() {}

    pub fn alloc_udger_data(&self) -> Result<UdgerData> {
        Ok(UdgerData {
            app_word_scratch: self.application_words_detector.alloc_scratch()?,
            client_word_scratch: self.client_words_detector.alloc_scratch()?,
            device_word_scratch: self.device_class_words_detector.alloc_scratch()?,
            os_word_scratch: self.os_words_detector.alloc_scratch()?,
        })
    }

    fn detect_client<T>(&self, ua: T, data: &mut UdgerData, _info: &mut ua_info) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.client_words_detector
            .get_word_ids(ua, &mut data.client_word_scratch)?;
        Ok(())
    }

    fn detect_os<T>(&self, ua: T, data: &mut UdgerData, _info: &mut ua_info) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.os_words_detector
            .get_word_ids(ua, &mut data.os_word_scratch)?;
        Ok(())
    }

    fn detect_device<T>(&self, ua: T, data: &mut UdgerData, _info: &mut ua_info) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.device_class_words_detector
            .get_word_ids(ua, &mut data.device_word_scratch)?;
        Ok(())
    }

    fn detect_application<T>(&self, ua: T, data: &mut UdgerData, _info: &mut ua_info) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.application_words_detector
            .get_word_ids(ua, &mut data.app_word_scratch)?;
        Ok(())
    }

    pub fn parse_ua<T>(&self, ua: T, data: &mut UdgerData, info: &mut ua_info) -> Result<()>
    where
        T: AsRef<[u8]>,
    {
        unsafe {
            info.ua = CString::from_raw(ua.as_ref().as_ptr() as *mut i8);
        }
        self.detect_client(&ua, data, info)?;
        self.detect_os(&ua, data, info)?;
        self.detect_application(&ua, data, info)?;
        self.detect_device(&ua, data, info)?;

        Ok(())
    }
}
