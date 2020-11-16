use std::ffi::{CStr, OsStr};
use std::os::raw::{c_char, c_int, c_void};
#[cfg(target_family = "unix")]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use libc::size_t;
use serde::{Deserialize, Serialize};

use super::udger::{Udger, UdgerData};

#[no_mangle]
unsafe extern "C" fn udger_new(
    mut _udger: *mut *const Udger,
    db_path: *const c_char,
    capacity: std::os::raw::c_uint,
) -> c_int {
    let mut rc = 0;
    let mut u = Box::new(Udger::new());

    #[cfg(target_family = "unix")]
    let cstr = CStr::from_ptr(db_path as *mut i8);
    #[cfg(target_family = "unix")]
    let osstr = OsStr::from_bytes(cstr.to_bytes());
    #[cfg(target_family = "unix")]
    let path_buf = PathBuf::from(osstr);

    match u.init(path_buf, capacity as usize) {
        Ok(_) => {}
        Err(_) => rc = -1,
    }
    *_udger = Box::into_raw(u);
    return rc;
}

#[no_mangle]
unsafe extern "C" fn udger_drop(udger: *mut Udger) {
    if udger != std::ptr::null_mut() {
        drop(Box::from_raw(udger))
    }
}

type UdgerCallBack = unsafe extern "C" fn(info: *const UaInfo, data: *mut c_void) -> c_int;

#[no_mangle]
unsafe extern "C" fn udger_parse_ua(
    udger: *const Udger,
    udger_data: *mut UdgerData,
    ua: *const c_char,
    cb: UdgerCallBack,
    data: *mut c_void,
) -> c_int {
    let ua = CStr::from_ptr(ua).to_string_lossy();
    match (*udger).parse_ua(&ua, &mut *udger_data) {
        Ok(info) => match cb(info.as_ref() as *const UaInfo, data) {
            rc if rc >= 0 => 0,
            _ => -2,
        },
        Err(_) => -1,
    }
}

#[no_mangle]
unsafe extern "C" fn udger_data_alloc(
    udger: *const Udger,
    mut _data: *mut *const UdgerData,
) -> c_int {
    match (*udger).alloc_udger_data() {
        Err(_) => return -1,
        Ok(udata) => {
            let data_box = Box::new(udata);
            *_data = Box::into_raw(data_box);
        }
    }
    0
}

#[no_mangle]
unsafe extern "C" fn udger_data_drop(data: *mut UdgerData) {
    if data != std::ptr::null_mut() {
        drop(Box::from_raw(data))
    }
}

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

    #[cfg(application)]
    pub application_name: String,
    #[cfg(application)]
    pub application_version: String,

    #[cfg(icon)]
    pub ua_family_icon: String,
    #[cfg(icon)]
    pub ua_family_icon_big: String,
    #[cfg(icon)]
    pub os_icon: String,
    #[cfg(icon)]
    pub os_icon_big: String,
    #[cfg(icon)]
    pub device_class_icon: String,
    #[cfg(icon)]
    pub device_class_icon_big: String,
    #[cfg(icon)]
    pub device_brand_icon: String,
    #[cfg(icon)]
    pub device_brand_icon_big: String,

    #[cfg(homepage)]
    pub ua_family_homepage: String,
    #[cfg(homepage)]
    pub ua_family_vendor_homepage: String,
    #[cfg(homepage)]
    pub os_homepage: String,
    #[cfg(homepage)]
    pub os_family_vendor_homepage: String,
    #[cfg(homepage)]
    pub device_brand_homepage: String,

    #[cfg(url)]
    pub ua_family_info_url: String,
    #[cfg(url)]
    pub os_info_url: String,
    #[cfg(url)]
    pub device_class_info_url: String,
    #[cfg(url)]
    pub device_brand_info_url: String,
}

macro_rules! get_function {
    ($func_name:ident, $field_name:ident) => {
        #[no_mangle]
        unsafe extern "C" fn $func_name(
            info: *const UaInfo,
            mut _buf: *mut *const c_char,
            len: *mut size_t,
        ) {
            *_buf = (*info).$field_name.as_ptr() as *const c_char;
            *len = (*info).$field_name.len();
        }
    };
}

get_function!(ua_info_get_ua_class, ua_class);
get_function!(ua_info_get_ua_class_code, ua_class_code);
get_function!(ua_info_get_ua, ua);
get_function!(ua_info_get_ua_engine, ua_engine);
get_function!(ua_info_get_ua_version, ua_version);
get_function!(ua_info_get_ua_version_major, ua_version_major);
get_function!(ua_info_get_ua_version_minor, ua_version_minor);

get_function!(ua_info_get_crawler_last_seen, crawler_last_seen);
get_function!(
    ua_info_get_crawler_respect_robotstxt,
    crawler_respect_robotstxt
);
get_function!(ua_info_get_crawler_category, crawler_category);
get_function!(ua_info_get_crawler_category_code, crawler_category_code);

get_function!(
    ua_info_get_ua_uptodate_current_version,
    ua_uptodate_current_version
);
get_function!(ua_info_get_ua_family, ua_family);
get_function!(ua_info_get_ua_family_code, ua_family_code);
get_function!(ua_info_get_ua_family_vendor, ua_family_vendor);
get_function!(ua_info_get_ua_family_vendor_code, ua_family_vendor_code);
get_function!(ua_info_get_ua_string, ua_string);

get_function!(ua_info_get_os_family, os_family);
get_function!(ua_info_get_os_family_code, os_family_code);
get_function!(ua_info_get_os, os);
get_function!(ua_info_get_os_code, os_code);
get_function!(ua_info_get_os_family_vendor, os_family_vendor);
get_function!(ua_info_get_os_family_vendor_code, os_family_vendor_code);

get_function!(ua_info_get_device_class, device_class);
get_function!(ua_info_get_device_class_code, device_class_code);
get_function!(ua_info_get_device_marketname, device_marketname);
get_function!(ua_info_get_device_brand, device_brand);
get_function!(ua_info_get_device_brand_code, device_brand_code);

#[cfg(application)]
get_function!(ua_info_get_application_name, application_name);

#[cfg(application)]
get_function!(ua_info_get_application_version, application_version);

#[cfg(icon)]
get_function!(ua_info_get_os_family_icon, os_family_icon);

#[cfg(icon)]
get_function!(ua_info_get_os_family_icon_big, os_family_icon_big);

#[cfg(icon)]
get_function!(ua_info_get_os_icon, os_icon);

#[cfg(icon)]
get_function!(ua_info_get_os_icon_big, os_icon_big);

#[cfg(icon)]
get_function!(ua_info_get_device_class_icon, device_class_icon);

#[cfg(icon)]
get_function!(ua_info_get_device_class_icon_big, device_class_icon_big);

#[cfg(icon)]
get_function!(ua_info_get_device_brand_icon, device_brand_icon);

#[cfg(icon)]
get_function!(ua_info_get_device_brand_icon_big, device_brand_icon_big);

#[cfg(homepage)]
get_function!(ua_info_get_os_family_homepage, os_family_homepage);

#[cfg(homepage)]
get_function!(ua_info_get_os_homepage, os_homepage);

#[cfg(homepage)]
get_function!(
    ua_info_get_os_familiy_vendor_homepage,
    os_familiy_vendor_homepage
);

#[cfg(homepage)]
get_function!(ua_info_get_device_brand_homepage, device_brand_homepage);

#[cfg(url)]
get_function!(ua_info_get_ua_family_info_url, ua_family_info_url);

#[cfg(url)]
get_function!(ua_info_get_os_info_url, os_info_url);

#[cfg(url)]
get_function!(ua_info_get_device_class_info_url, device_class_info_url);

#[cfg(url)]
get_function!(ua_info_get_device_brand_info_url, device_brand_info_url);

#[no_mangle]
unsafe extern "C" fn ua_info_to_string(
    info: *const UaInfo,
    output: *mut *mut c_char,
    len: *mut size_t,
    pretty: bool,
) -> c_int {
    match pretty {
        true => {
            match serde_json::to_string_pretty(&(*info)) {
                Err(_) => todo!("Properly handle to_string error"),
                Ok(s) => {
                    *len = s.len() + 1;
                    *output = libc::malloc(*len) as *mut c_char;
                    libc::memset(*output as *mut std::os::raw::c_void, 0, *len);
                    libc::memcpy(
                        *output as *mut std::os::raw::c_void,
                        s.as_ptr() as *mut std::os::raw::c_void,
                        s.len(),
                    );
                }
            };
        }
        false => {
            match serde_json::to_string(&(*info)) {
                Err(_) => todo!("Properly handle to_string error"),
                Ok(s) => {
                    *len = s.len() + 1;
                    *output = libc::malloc(*len) as *mut c_char;
                    libc::memset(*output as *mut std::os::raw::c_void, 0, *len);
                    libc::memcpy(
                        *output as *mut std::os::raw::c_void,
                        s.as_ptr() as *mut std::os::raw::c_void,
                        s.len(),
                    );
                }
            };
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get() {
        let info = UaInfo::default();
        let mut buf: *const c_char = std::ptr::null_mut();
        let mut len: size_t = 0;

        macro_rules! test_get_function {
            ($func_name:ident, $field_name:ident) => {
                $func_name(&info as *const UaInfo, &mut buf, &mut len);
                assert_eq!(buf, info.$field_name.as_ptr() as *mut c_char);
                assert_eq!(len, info.$field_name.len());
            };
        }

        unsafe {
            #[cfg(application)]
            assert_eq!(
                ua_info_get_application_name(&info as *const UaInfo),
                info.application_name.as_ptr() as *const c_char
            );

            #[cfg(application)]
            assert_eq!(
                ua_info_get_application_version(&info as *const UaInfo),
                info.application_version.as_ptr() as *const c_char
            );

            test_get_function!(ua_info_get_crawler_category, crawler_category);
            test_get_function!(ua_info_get_crawler_category_code, crawler_category_code);
            test_get_function!(ua_info_get_crawler_last_seen, crawler_last_seen);
            test_get_function!(
                ua_info_get_crawler_respect_robotstxt,
                crawler_respect_robotstxt
            );

            test_get_function!(ua_info_get_device_brand, device_brand);
            test_get_function!(ua_info_get_device_brand_code, device_brand_code);
            test_get_function!(ua_info_get_device_class, device_class);
            test_get_function!(ua_info_get_device_class_code, device_class_code);
            test_get_function!(ua_info_get_device_marketname, device_marketname);

            test_get_function!(ua_info_get_os, os);
            test_get_function!(ua_info_get_os_code, os_code);
            test_get_function!(ua_info_get_os_family, os_family);
            test_get_function!(ua_info_get_os_family_code, os_family_code);
            test_get_function!(ua_info_get_os_family_vendor, os_family_vendor);
            test_get_function!(ua_info_get_os_family_vendor_code, os_family_vendor_code);

            test_get_function!(ua_info_get_ua, ua);
            test_get_function!(ua_info_get_ua, ua_string);

            test_get_function!(ua_info_get_ua_class, ua_class);
            test_get_function!(ua_info_get_ua_class_code, ua_class_code);
            test_get_function!(ua_info_get_ua_engine, ua_engine);
            test_get_function!(ua_info_get_ua_family, ua_family);
            test_get_function!(ua_info_get_ua_family_code, ua_family_code);
            test_get_function!(ua_info_get_ua_family_vendor, ua_family_vendor);
            test_get_function!(ua_info_get_ua_family_vendor_code, ua_family_vendor_code);
            test_get_function!(ua_info_get_ua_string, ua_string);
            test_get_function!(
                ua_info_get_ua_uptodate_current_version,
                ua_uptodate_current_version
            );
            test_get_function!(ua_info_get_ua_version, ua_version);
            test_get_function!(ua_info_get_ua_version_major, ua_version_major);
            test_get_function!(ua_info_get_ua_version_minor, ua_version_minor);

            #[cfg(icon)]
            {
                test_get_function!(ua_info_get_device_brand_icon, ua_device_brand_icon);
                test_get_function!(ua_info_get_device_brand_icon_big, ua_device_brand_icon_big);
                test_get_function!(ua_info_get_device_class_icon, ua_device_class_icon);
                test_get_function!(ua_info_get_device_class_icon_big, ua_device_class_icon_big);
                test_get_function!(ua_info_get_os_icon, ua_os_icon);
                test_get_function!(ua_info_get_os_icon_big, ua_os_icon_big);
                test_get_function!(ua_info_get_ua_family_icon, ua_family_icon);
                test_get_function!(ua_info_get_ua_family_icon_big, ua_family_icon_big);
            }

            #[cfg(homepage)]
            {
                test_get_function!(ua_info_get_device_brand_homepage, ua_device_brand_homepage);
                test_get_function!(ua_info_get_os_homepage, ua_os_homepage);
                test_get_function!(
                    ua_info_get_os_family_vendor_homepage,
                    ua_os_family_vendor_homepage
                );
                test_get_function!(ua_info_get_ua_family_homepage, ua_family_homepage);
                test_get_function!(
                    ua_info_get_ua_family_vendor_homepage,
                    ua_family_vendor_homepage
                );
            }

            #[cfg(url)]
            {
                test_get_function!(ua_info_get_device_brand_info_url, ua_device_brand_info_url);
                test_get_function!(ua_info_get_device_class_info_url, ua_device_class_info_url);
                test_get_function!(ua_info_get_os_info_url, ua_os_info_url);
                test_get_function!(ua_info_get_ua_family_info_url, ua_family_info_url);
            }
        }
    }

    #[test]
    fn test_to_string() {
        let mut info = UaInfo::default();
        info.ua = String::from("wget/1.20.3");
        let mut output: *mut c_char = std::ptr::null_mut();
        let mut len: usize = 0;
        let output_string: String;
        unsafe {
            ua_info_to_string(&info, &mut output, &mut len, false);
            output_string = String::from_raw_parts(output as *mut u8, len - 1, len - 1);
        }

        assert_eq!(output_string, "{\"ua_class\":\"\",\"ua_class_code\":\"\",\"ua\":\"wget/1.20.3\",\"ua_engine\":\"\",\"ua_version\":\"\",\"ua_version_major\":\"\",\"ua_version_minor\":\"\",\"crawler_last_seen\":\"\",\"crawler_respect_robotstxt\":\"\",\"crawler_category\":\"\",\"crawler_category_code\":\"\",\"ua_uptodate_current_version\":\"\",\"ua_family\":\"\",\"ua_family_code\":\"\",\"ua_family_vendor\":\"\",\"ua_family_vendor_code\":\"\",\"ua_string\":\"\",\"os_family\":\"\",\"os_family_code\":\"\",\"os\":\"\",\"os_code\":\"\",\"os_family_vendor\":\"\",\"os_family_vendor_code\":\"\",\"device_class\":\"\",\"device_class_code\":\"\",\"device_marketname\":\"\",\"device_brand\":\"\",\"device_brand_code\":\"\"}");
    }
}
