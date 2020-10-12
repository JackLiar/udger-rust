use std::os::raw::{c_char, c_int};

use libc::size_t;
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct UaInfo {
    #[serde(skip_serializing)]
    pub class_id: u8,
    #[serde(skip_serializing)]
    pub client_id: i16,

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

    pub application_name: String,
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

#[no_mangle]
unsafe extern "C" fn ua_info_get_class_id(info: *const UaInfo) -> u8 {
    (*info).class_id
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_client_id(info: *const UaInfo) -> i16 {
    (*info).client_id
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_class(info: *const UaInfo) -> *const c_char {
    (*info).ua_class.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_class_code(info: *const UaInfo) -> *const c_char {
    (*info).ua_class_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua(info: *const UaInfo) -> *const c_char {
    (*info).ua.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_engine(info: *const UaInfo) -> *const c_char {
    (*info).ua_engine.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_version(info: *const UaInfo) -> *const c_char {
    (*info).ua_version.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_version_major(info: *const UaInfo) -> *const c_char {
    (*info).ua_version_major.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_version_minor(info: *const UaInfo) -> *const c_char {
    (*info).ua_version_minor.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_crawler_last_seen(info: *const UaInfo) -> *const c_char {
    (*info).crawler_last_seen.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_crawler_respect_robotstxt(info: *const UaInfo) -> *const c_char {
    (*info).crawler_respect_robotstxt.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_crawler_category(info: *const UaInfo) -> *const c_char {
    (*info).crawler_category.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_crawler_category_code(info: *const UaInfo) -> *const c_char {
    (*info).crawler_category_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_uptodate_current_version(info: *const UaInfo) -> *const c_char {
    (*info).ua_uptodate_current_version.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family(info: *const UaInfo) -> *const c_char {
    (*info).ua_family.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_code(info: *const UaInfo) -> *const c_char {
    (*info).ua_family_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_vendor(info: *const UaInfo) -> *const c_char {
    (*info).ua_family_vendor.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_vendor_code(info: *const UaInfo) -> *const c_char {
    (*info).ua_family_vendor_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_string(info: *const UaInfo) -> *const c_char {
    (*info).ua_string.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family(info: *const UaInfo) -> *const c_char {
    (*info).os_family.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_code(info: *const UaInfo) -> *const c_char {
    (*info).os_family_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os(info: *const UaInfo) -> *const c_char {
    (*info).os.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_code(info: *const UaInfo) -> *const c_char {
    (*info).os_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_vendor(info: *const UaInfo) -> *const c_char {
    (*info).os_family_vendor.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_vendor_code(info: *const UaInfo) -> *const c_char {
    (*info).os_family_vendor_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class(info: *const UaInfo) -> *const c_char {
    (*info).device_class.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class_code(info: *const UaInfo) -> *const c_char {
    (*info).device_class_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_marketname(info: *const UaInfo) -> *const c_char {
    (*info).device_marketname.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand(info: *const UaInfo) -> *const c_char {
    (*info).device_brand.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_code(info: *const UaInfo) -> *const c_char {
    (*info).device_brand_code.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_application_name(info: *const UaInfo) -> *const c_char {
    (*info).application_name.as_ptr() as *const c_char
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_application_version(info: *const UaInfo) -> *const c_char {
    (*info).application_version.as_ptr() as *const c_char
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_icon(info: *const UaInfo) -> *const c_char {
    (*info).ua_family_icon.as_ptr() as *const c_char
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_icon_big(info: *const UaInfo) -> *const c_char {
    (*info).ua_family_icon_big.as_ptr() as *const c_char
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_icon(info: *const UaInfo) -> *const c_char {
    (*info).os_icon.as_ptr() as *const c_char
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_icon_big(info: *const UaInfo) -> *const c_char {
    (*info).os_icon_big.as_ptr() as *const c_char
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class_icon(info: *const UaInfo) -> *const c_char {
    (*info).device_class_icon.as_ptr() as *const c_char
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class_icon_big(info: *const UaInfo) -> *const c_char {
    (*info).device_class_icon_big.as_ptr() as *const c_char
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_icon(info: *const UaInfo) -> *const c_char {
    (*info).device_brand_icon.as_ptr() as *const c_char
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_icon_big(info: *const UaInfo) -> *const c_char {
    (*info).device_brand_icon_big.as_ptr() as *const c_char
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_homepage(info: *const UaInfo) -> *const c_char {
    (*info).ua_family_homepage.as_ptr() as *const c_char
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_vendor_homepage(info: *const UaInfo) -> *const c_char {
    (*info).ua_family_vendor_homepage.as_ptr() as *const c_char
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_homepage(info: *const UaInfo) -> *const c_char {
    (*info).os_homepage.as_ptr() as *const c_char
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_vendor_homepage(info: *const UaInfo) -> *const c_char {
    (*info).os_family_vendor_homepage.as_ptr() as *const c_char
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_vendor_homepage(info: *const UaInfo) -> *const c_char {
    (*info).os_family_vendor_homepage.as_ptr() as *const c_char
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_homepage(info: *const UaInfo) -> *const c_char {
    (*info).device_brand_homepage.as_ptr() as *const c_char
}

#[cfg(url)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_info_url(info: *const UaInfo) -> *const c_char {
    (*info).ua_family_info_url.as_ptr() as *const c_char
}

#[cfg(url)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_info_url(info: *const UaInfo) -> *const c_char {
    (*info).os_info_url.as_ptr() as *const c_char
}

#[cfg(url)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class_info_url(info: *const UaInfo) -> *const c_char {
    (*info).device_class_info_url.as_ptr() as *const c_char
}

#[cfg(url)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_info_url(info: *const UaInfo) -> *const c_char {
    (*info).device_brand_info_url.as_ptr() as *const c_char
}

unsafe extern "C" fn ua_info_to_string(
    info: *const UaInfo,
    output: *mut *mut c_char,
    len: *mut size_t,
) -> c_int {
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

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get() {
        let info = UaInfo::default();
        unsafe {
            assert_eq!(
                ua_info_get_application_name(&info as *const UaInfo),
                info.application_name.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_application_version(&info as *const UaInfo),
                info.application_version.as_ptr() as *const c_char
            );

            assert_eq!(ua_info_get_class_id(&info as *const UaInfo), info.class_id);

            assert_eq!(
                ua_info_get_client_id(&info as *const UaInfo),
                info.client_id
            );

            assert_eq!(
                ua_info_get_crawler_category(&info as *const UaInfo),
                info.crawler_category.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_crawler_category_code(&info as *const UaInfo),
                info.crawler_category_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_crawler_last_seen(&info as *const UaInfo),
                info.crawler_last_seen.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_crawler_respect_robotstxt(&info as *const UaInfo),
                info.crawler_respect_robotstxt.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_device_brand(&info as *const UaInfo),
                info.device_brand.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_device_brand_code(&info as *const UaInfo),
                info.device_brand_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_device_class(&info as *const UaInfo),
                info.device_class.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_device_class_code(&info as *const UaInfo),
                info.device_class_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_device_marketname(&info as *const UaInfo),
                info.device_marketname.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_os(&info as *const UaInfo),
                info.os.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_os_code(&info as *const UaInfo),
                info.os_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_os_family(&info as *const UaInfo),
                info.os_family.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_os_family_code(&info as *const UaInfo),
                info.os_family_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_os_family_vendor(&info as *const UaInfo),
                info.os_family_vendor.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_os_family_vendor_code(&info as *const UaInfo),
                info.os_family_vendor_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua(&info as *const UaInfo),
                info.ua.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_class(&info as *const UaInfo),
                info.ua_class.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_class_code(&info as *const UaInfo),
                info.ua_class_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_engine(&info as *const UaInfo),
                info.ua_engine.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_family(&info as *const UaInfo),
                info.ua_family.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_family_code(&info as *const UaInfo),
                info.ua_family_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_family_vendor(&info as *const UaInfo),
                info.ua_family_vendor.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_family_vendor_code(&info as *const UaInfo),
                info.ua_family_vendor_code.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_string(&info as *const UaInfo),
                info.ua_string.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_uptodate_current_version(&info as *const UaInfo),
                info.ua_uptodate_current_version.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_version(&info as *const UaInfo),
                info.ua_version.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_version_major(&info as *const UaInfo),
                info.ua_version_major.as_ptr() as *const c_char
            );

            assert_eq!(
                ua_info_get_ua_version_minor(&info as *const UaInfo),
                info.ua_version_minor.as_ptr() as *const c_char
            );

            #[cfg(icon)]
            {
                assert_eq!(
                    ua_info_get_device_brand_icon(&info as *const UaInfo),
                    info.device_brand_icon.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_device_brand_icon_big(&info as *const UaInfo),
                    info.device_brand_icon_big.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_device_class_icon(&info as *const UaInfo),
                    info.device_class_icon.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_device_class_icon_big(&info as *const UaInfo),
                    info.device_class_icon_big.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_os_icon(&info as *const UaInfo),
                    info.os_icon.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_os_icon_big(&info as *const UaInfo),
                    info.os_icon_big.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_ua_family_icon(&info as *const UaInfo),
                    info.ua_family_icon.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_ua_family_icon_big(&info as *const UaInfo),
                    info.ua_family_icon_big.as_ptr() as *const c_char
                );
            }

            #[cfg(homepage)]
            {
                assert_eq!(
                    ua_info_get_device_brand_homepage(&info as *const UaInfo),
                    info.device_brand_homepage.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_os_homepage(&info as *const UaInfo),
                    info.os_homepage.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_os_family_vendor_homepage(&info as *const UaInfo),
                    info.os_family_vendor_homepage.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_ua_family_homepage(&info as *const UaInfo),
                    info.ua_family_homepage.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_ua_family_vendor_homepage(&info as *const UaInfo),
                    info.ua_family_vendor_homepage.as_ptr() as *const c_char
                );
            }

            #[cfg(url)]
            {
                assert_eq!(
                    ua_info_get_device_brand_info_url(&info as *const UaInfo),
                    info.device_brand_info_url.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_device_class_info_url(&info as *const UaInfo),
                    info.device_class_info_url.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_os_info_url(&info as *const UaInfo),
                    info.os_info_url.as_ptr() as *const c_char
                );

                assert_eq!(
                    ua_info_get_ua_family_info_url(&info as *const UaInfo),
                    info.ua_family_info_url.as_ptr() as *const c_char
                );
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
            ua_info_to_string(&info, &mut output, &mut len);
            output_string = String::from_raw_parts(output as *mut u8, len - 1, len - 1);
            // println!("output string: {}", output_string);
        }

        assert_eq!(output_string, "{\"ua_class\":\"\",\"ua_class_code\":\"\",\"ua\":\"wget/1.20.3\",\"ua_engine\":\"\",\"ua_version\":\"\",\"ua_version_major\":\"\",\"ua_version_minor\":\"\",\"crawler_last_seen\":\"\",\"crawler_respect_robotstxt\":\"\",\"crawler_category\":\"\",\"crawler_category_code\":\"\",\"ua_uptodate_current_version\":\"\",\"ua_family\":\"\",\"ua_family_code\":\"\",\"ua_family_vendor\":\"\",\"ua_family_vendor_code\":\"\",\"ua_string\":\"\",\"os_family\":\"\",\"os_family_code\":\"\",\"os\":\"\",\"os_code\":\"\",\"os_family_vendor\":\"\",\"os_family_vendor_code\":\"\",\"device_class\":\"\",\"device_class_code\":\"\",\"device_marketname\":\"\",\"device_brand\":\"\",\"device_brand_code\":\"\",\"application_name\":\"\",\"application_version\":\"\"}");
    }
}
