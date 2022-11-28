#[macro_use]
extern crate lazy_static;

use serde::{Deserialize, Serialize};

pub mod ffi;
mod udger;
pub use crate::udger::{Udger, UdgerData};

#[repr(C)]
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct UaInfo {
    #[serde(skip_serializing)]
    pub class_id: Option<u32>,
    #[serde(skip_serializing)]
    pub client_id: Option<u32>,
    pub ua_class: String,
    pub ua_class_code: String,
    pub ua: String,
    pub ua_engine: String,
    pub ua_version: String,
    pub ua_version_major: String,
    pub ua_version_minor: String,
    pub crawler_last_seen: String,
    pub crawler_respect_robotstxt: String,
    pub crawler_category: String,
    pub crawler_category_code: String,
    pub ua_uptodate_current_version: String,
    pub ua_family: String,
    pub ua_family_code: String,
    pub ua_family_vendor: String,
    pub ua_family_vendor_code: String,
    pub ua_string: String,

    pub os_family: String,
    pub os_family_code: String,
    pub os: String,
    pub os_code: String,
    pub os_family_vendor: String,
    pub os_family_vendor_code: String,

    pub device_class: String,
    pub device_class_code: String,
    pub device_marketname: String,
    pub device_brand: String,
    pub device_brand_code: String,

    #[cfg(feature = "application")]
    pub application_name: String,
    #[cfg(feature = "application")]
    pub application_version: String,

    #[cfg(feature = "icon")]
    pub ua_family_icon: String,
    #[cfg(feature = "icon")]
    pub ua_family_icon_big: String,
    #[cfg(feature = "icon")]
    pub os_icon: String,
    #[cfg(feature = "icon")]
    pub os_icon_big: String,
    #[cfg(feature = "icon")]
    pub device_class_icon: String,
    #[cfg(feature = "icon")]
    pub device_class_icon_big: String,
    #[cfg(feature = "icon")]
    pub device_brand_icon: String,
    #[cfg(feature = "icon")]
    pub device_brand_icon_big: String,

    #[cfg(feature = "homepage")]
    pub ua_family_homepage: String,
    #[cfg(feature = "homepage")]
    pub ua_family_vendor_homepage: String,
    #[cfg(feature = "homepage")]
    pub os_homepage: String,
    #[cfg(feature = "homepage")]
    pub os_family_vendor_homepage: String,
    #[cfg(feature = "homepage")]
    pub device_brand_homepage: String,

    #[cfg(feature = "url")]
    pub ua_family_info_url: String,
    #[cfg(feature = "url")]
    pub os_info_url: String,
    #[cfg(feature = "url")]
    pub device_class_info_url: String,
    #[cfg(feature = "url")]
    pub device_brand_info_url: String,
}
