use std::ffi::CString;
use std::os::raw::c_char;

#[repr(C)]
#[no_mangle]
#[derive(Default)]
pub struct ua_info {
    pub class_id: u8,
    pub client_id: u16,

    pub ua_class: CString,
    pub ua_class_code: CString,
    pub ua: CString,
    pub ua_engine: CString,
    pub ua_version: CString,
    pub ua_version_major: CString,
    pub ua_version_minor: CString,
    pub crawler_last_seen: CString,
    pub crawler_respect_robotstxt: CString,
    pub crawler_category: CString,
    pub crawler_category_code: CString,
    pub ua_uptodate_current_version: CString,
    pub ua_family: CString,
    pub ua_family_code: CString,
    pub ua_family_vendor: CString,
    pub ua_family_vendor_code: CString,
    pub ua_string: CString,

    pub os_family: CString,
    pub os_family_code: CString,
    pub os: CString,
    pub os_code: CString,
    pub os_family_vendor: CString,
    pub os_family_vendor_code: CString,

    pub device_class: CString,
    pub device_class_code: CString,
    pub device_marketname: CString,
    pub device_brand: CString,
    pub device_brand_code: CString,

    pub application_name: CString,
    pub application_version: CString,

    #[cfg(icon)]
    pub ua_family_icon: CString,
    #[cfg(icon)]
    pub ua_family_icon_big: CString,
    #[cfg(icon)]
    pub os_icon: CString,
    #[cfg(icon)]
    pub os_icon_big: CString,
    #[cfg(icon)]
    pub device_class_icon: CString,
    #[cfg(icon)]
    pub device_class_icon_big: CString,
    #[cfg(icon)]
    pub device_brand_icon: CString,
    #[cfg(icon)]
    pub device_brand_icon_big: CString,

    #[cfg(homepage)]
    pub ua_family_homepage: CString,
    #[cfg(homepage)]
    pub ua_family_vendor_homepage: CString,
    #[cfg(homepage)]
    pub os_homepage: CString,
    #[cfg(homepage)]
    pub os_family_vendor_homepage: CString,
    #[cfg(homepage)]
    pub device_brand_homepage: CString,

    #[cfg(url)]
    pub ua_family_info_url: CString,
    #[cfg(url)]
    pub os_info_url: CString,
    #[cfg(url)]
    pub device_class_info_url: CString,
    #[cfg(url)]
    pub device_brand_info_url: CString,
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_class_id(info: *const ua_info) -> u8 {
    (*info).class_id
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_client_id(info: *const ua_info) -> u16 {
    (*info).client_id
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_class(info: *const ua_info) -> *const c_char {
    (*info).ua_class.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_class_code(info: *const ua_info) -> *const c_char {
    (*info).ua_class_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua(info: *const ua_info) -> *const c_char {
    (*info).ua.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_engine(info: *const ua_info) -> *const c_char {
    (*info).ua_engine.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_version(info: *const ua_info) -> *const c_char {
    (*info).ua_version.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_version_major(info: *const ua_info) -> *const c_char {
    (*info).ua_version_major.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_version_minor(info: *const ua_info) -> *const c_char {
    (*info).ua_version_minor.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_crawler_last_seen(info: *const ua_info) -> *const c_char {
    (*info).crawler_last_seen.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_crawler_respect_robotstxt(info: *const ua_info) -> *const c_char {
    (*info).crawler_respect_robotstxt.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_crawler_category(info: *const ua_info) -> *const c_char {
    (*info).crawler_category.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_crawler_category_code(info: *const ua_info) -> *const c_char {
    (*info).crawler_category_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_uptodate_current_version(
    info: *const ua_info,
) -> *const c_char {
    (*info).ua_uptodate_current_version.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family(info: *const ua_info) -> *const c_char {
    (*info).ua_family.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_code(info: *const ua_info) -> *const c_char {
    (*info).ua_family_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_vendor(info: *const ua_info) -> *const c_char {
    (*info).ua_family_vendor.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_vendor_code(info: *const ua_info) -> *const c_char {
    (*info).ua_family_vendor_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_string(info: *const ua_info) -> *const c_char {
    (*info).ua_string.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family(info: *const ua_info) -> *const c_char {
    (*info).os_family.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_code(info: *const ua_info) -> *const c_char {
    (*info).os_family_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os(info: *const ua_info) -> *const c_char {
    (*info).os.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_code(info: *const ua_info) -> *const c_char {
    (*info).os_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_vendor(info: *const ua_info) -> *const c_char {
    (*info).os_family_vendor.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_vendor_code(info: *const ua_info) -> *const c_char {
    (*info).os_family_vendor_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class(info: *const ua_info) -> *const c_char {
    (*info).device_class.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class_code(info: *const ua_info) -> *const c_char {
    (*info).device_class_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_marketname(info: *const ua_info) -> *const c_char {
    (*info).device_marketname.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand(info: *const ua_info) -> *const c_char {
    (*info).device_brand.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_code(info: *const ua_info) -> *const c_char {
    (*info).device_brand_code.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_application_name(info: *const ua_info) -> *const c_char {
    (*info).application_name.as_ptr()
}

#[no_mangle]
unsafe extern "C" fn ua_info_get_application_version(info: *const ua_info) -> *const c_char {
    (*info).application_version.as_ptr()
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_icon(info: *const ua_info) -> *const c_char {
    (*info).ua_family_icon.as_ptr()
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_icon_big(info: *const ua_info) -> *const c_char {
    (*info).ua_family_icon_big.as_ptr()
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_icon(info: *const ua_info) -> *const c_char {
    (*info).os_icon.as_ptr()
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_icon_big(info: *const ua_info) -> *const c_char {
    (*info).os_icon_big.as_ptr()
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class_icon(info: *const ua_info) -> *const c_char {
    (*info).device_class_icon.as_ptr()
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class_icon_big(info: *const ua_info) -> *const c_char {
    (*info).device_class_icon_big.as_ptr()
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_icon(info: *const ua_info) -> *const c_char {
    (*info).device_brand_icon.as_ptr()
}

#[cfg(icon)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_icon_big(info: *const ua_info) -> *const c_char {
    (*info).device_brand_icon_big.as_ptr()
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_homepage(info: *const ua_info) -> *const c_char {
    (*info).ua_family_homepage.as_ptr()
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_vendor_homepage(info: *const ua_info) -> *const c_char {
    (*info).ua_family_vendor_homepage.as_ptr()
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_homepage(info: *const ua_info) -> *const c_char {
    (*info).os_homepage.as_ptr()
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_vendor_homepage(info: *const ua_info) -> *const c_char {
    (*info).os_family_vendor_homepage.as_ptr()
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_family_vendor_homepage(info: *const ua_info) -> *const c_char {
    (*info).os_family_vendor_homepage.as_ptr()
}

#[cfg(homepage)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_homepage(info: *const ua_info) -> *const c_char {
    (*info).device_brand_homepage.as_ptr()
}

#[cfg(url)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_ua_family_info_url(info: *const ua_info) -> *const c_char {
    (*info).ua_family_info_url.as_ptr()
}

#[cfg(url)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_os_info_url(info: *const ua_info) -> *const c_char {
    (*info).os_info_url.as_ptr()
}

#[cfg(url)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_class_info_url(info: *const ua_info) -> *const c_char {
    (*info).device_class_info_url.as_ptr()
}

#[cfg(url)]
#[no_mangle]
unsafe extern "C" fn ua_info_get_device_brand_info_url(info: *const ua_info) -> *const c_char {
    (*info).device_brand_info_url.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get() {
        let info = ua_info::default();
        unsafe {
            assert_eq!(
                ua_info_get_application_name(&info as *const ua_info),
                info.application_name.as_ptr()
            );

            assert_eq!(
                ua_info_get_application_version(&info as *const ua_info),
                info.application_version.as_ptr()
            );

            assert_eq!(ua_info_get_class_id(&info as *const ua_info), info.class_id);

            assert_eq!(
                ua_info_get_client_id(&info as *const ua_info),
                info.client_id
            );

            assert_eq!(
                ua_info_get_crawler_category(&info as *const ua_info),
                info.crawler_category.as_ptr()
            );

            assert_eq!(
                ua_info_get_crawler_category_code(&info as *const ua_info),
                info.crawler_category_code.as_ptr()
            );

            assert_eq!(
                ua_info_get_crawler_last_seen(&info as *const ua_info),
                info.crawler_last_seen.as_ptr()
            );

            assert_eq!(
                ua_info_get_crawler_respect_robotstxt(&info as *const ua_info),
                info.crawler_respect_robotstxt.as_ptr()
            );

            assert_eq!(
                ua_info_get_device_brand(&info as *const ua_info),
                info.device_brand.as_ptr()
            );

            assert_eq!(
                ua_info_get_device_brand_code(&info as *const ua_info),
                info.device_brand_code.as_ptr()
            );

            assert_eq!(
                ua_info_get_device_class(&info as *const ua_info),
                info.device_class.as_ptr()
            );

            assert_eq!(
                ua_info_get_device_class_code(&info as *const ua_info),
                info.device_class_code.as_ptr()
            );

            assert_eq!(
                ua_info_get_device_marketname(&info as *const ua_info),
                info.device_marketname.as_ptr()
            );

            assert_eq!(ua_info_get_os(&info as *const ua_info), info.os.as_ptr());

            assert_eq!(
                ua_info_get_os_code(&info as *const ua_info),
                info.os_code.as_ptr()
            );

            assert_eq!(
                ua_info_get_os_family(&info as *const ua_info),
                info.os_family.as_ptr()
            );

            assert_eq!(
                ua_info_get_os_family_code(&info as *const ua_info),
                info.os_family_code.as_ptr()
            );

            assert_eq!(
                ua_info_get_os_family_vendor(&info as *const ua_info),
                info.os_family_vendor.as_ptr()
            );

            assert_eq!(
                ua_info_get_os_family_vendor_code(&info as *const ua_info),
                info.os_family_vendor_code.as_ptr()
            );

            assert_eq!(ua_info_get_ua(&info as *const ua_info), info.ua.as_ptr());

            assert_eq!(
                ua_info_get_ua_class(&info as *const ua_info),
                info.ua_class.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_class_code(&info as *const ua_info),
                info.ua_class_code.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_engine(&info as *const ua_info),
                info.ua_engine.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_family(&info as *const ua_info),
                info.ua_family.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_family_code(&info as *const ua_info),
                info.ua_family_code.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_family_vendor(&info as *const ua_info),
                info.ua_family_vendor.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_family_vendor_code(&info as *const ua_info),
                info.ua_family_vendor_code.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_string(&info as *const ua_info),
                info.ua_string.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_uptodate_current_version(&info as *const ua_info),
                info.ua_uptodate_current_version.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_version(&info as *const ua_info),
                info.ua_version.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_version_major(&info as *const ua_info),
                info.ua_version_major.as_ptr()
            );

            assert_eq!(
                ua_info_get_ua_version_minor(&info as *const ua_info),
                info.ua_version_minor.as_ptr()
            );

            #[cfg(icon)]
            {
                assert_eq!(
                    ua_info_get_device_brand_icon(&info as *const ua_info),
                    info.device_brand_icon.as_ptr()
                );

                assert_eq!(
                    ua_info_get_device_brand_icon_big(&info as *const ua_info),
                    info.device_brand_icon_big.as_ptr()
                );

                assert_eq!(
                    ua_info_get_device_class_icon(&info as *const ua_info),
                    info.device_class_icon.as_ptr()
                );

                assert_eq!(
                    ua_info_get_device_class_icon_big(&info as *const ua_info),
                    info.device_class_icon_big.as_ptr()
                );

                assert_eq!(
                    ua_info_get_os_icon(&info as *const ua_info),
                    info.os_icon.as_ptr()
                );

                assert_eq!(
                    ua_info_get_os_icon_big(&info as *const ua_info),
                    info.os_icon_big.as_ptr()
                );

                assert_eq!(
                    ua_info_get_ua_family_icon(&info as *const ua_info),
                    info.ua_family_icon.as_ptr()
                );

                assert_eq!(
                    ua_info_get_ua_family_icon_big(&info as *const ua_info),
                    info.ua_family_icon_big.as_ptr()
                );
            }

            #[cfg(homepage)]
            {
                assert_eq!(
                    ua_info_get_device_brand_homepage(&info as *const ua_info),
                    info.device_brand_homepage.as_ptr()
                );

                assert_eq!(
                    ua_info_get_os_homepage(&info as *const ua_info),
                    info.os_homepage.as_ptr()
                );

                assert_eq!(
                    ua_info_get_os_family_vendor_homepage(&info as *const ua_info),
                    info.os_family_vendor_homepage.as_ptr()
                );

                assert_eq!(
                    ua_info_get_ua_family_homepage(&info as *const ua_info),
                    info.ua_family_homepage.as_ptr()
                );

                assert_eq!(
                    ua_info_get_ua_family_vendor_homepage(&info as *const ua_info),
                    info.ua_family_vendor_homepage.as_ptr()
                );
            }

            #[cfg(url)]
            {
                assert_eq!(
                    ua_info_get_device_brand_info_url(&info as *const ua_info),
                    info.device_brand_info_url.as_ptr()
                );

                assert_eq!(
                    ua_info_get_device_class_info_url(&info as *const ua_info),
                    info.device_class_info_url.as_ptr()
                );

                assert_eq!(
                    ua_info_get_os_info_url(&info as *const ua_info),
                    info.os_info_url.as_ptr()
                );

                assert_eq!(
                    ua_info_get_ua_family_info_url(&info as *const ua_info),
                    info.ua_family_info_url.as_ptr()
                );
            }
        }
    }
}
