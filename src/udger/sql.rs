pub const SQL_CRAWLER: &str = "SELECT \
    NULL AS client_id, \
    NULL AS class_id, \
    'Crawler' AS ua_class, \
    'crawler' AS ua_class_code, \
    name AS ua, \
    NULL AS ua_engine, \
    ver AS ua_version, \
    ver_major AS ua_version_major, \
    last_seen AS crawler_last_seen, \
    respect_robotstxt AS crawler_respect_robotstxt, \
    crawler_classification AS crawler_category, \
    crawler_classification_code AS crawler_category_code, \
    NULL AS ua_uptodate_current_version, \
    family AS ua_family, \
    family_code AS ua_family_code, \
    family_homepage AS ua_family_homepage, \
    family_icon AS ua_family_icon, \
    NULL AS ua_family_icon_big, \
    vendor AS ua_family_vendor, \
    vendor_code AS ua_family_vendor_code, \
    vendor_homepage AS ua_family_vendor_homepage, \
    'https://udger.com/resources/ua-list/bot-detail?bot=' || REPLACE(family, ' ', '%20') || \
    '#id' || udger_crawler_list.id AS ua_family_info_url \
    FROM \
    udger_crawler_list \
    LEFT JOIN \
    udger_crawler_class ON udger_crawler_class.id = udger_crawler_list.class_id \
    WHERE \
    ua_string = ?";

pub const SQL_CLIENT: &str = "SELECT \
    ur.rowid, \
    client_id AS client_id, \
    class_id AS class_id, \
    client_classification AS ua_class, \
    client_classification_code AS ua_class_code, \
    name AS ua, \
    engine AS ua_engine, \
    NULL AS ua_version, \
    NULL AS ua_version_major, \
    NULL AS crawler_last_seen, \
    NULL AS crawler_respect_robotstxt, \
    NULL AS crawler_category, \
    NULL AS crawler_category_code, \
    uptodate_current_version AS ua_uptodate_current_version, \
    name AS ua_family, \
    name_code AS ua_family_code, \
    homepage AS ua_family_homepage, \
    icon AS ua_family_icon, \
    icon_big AS ua_family_icon_big, \
    vendor AS ua_family_vendor, \
    vendor_code AS ua_family_vendor_code, \
    vendor_homepage AS ua_family_vendor_homepage, \
    'https://udger.com/resources/ua-list/browser-detail?browser=' || REPLACE(name, ' ', \
    '%20') \
    AS ua_family_info_url \
    FROM \
    udger_client_regex ur \
    JOIN \
    udger_client_list ON udger_client_list.id = ur.client_id \
    JOIN \
    udger_client_class ON udger_client_class.id = udger_client_list.class_id \
    WHERE \
    ur.rowid = ?";

const OS_COLUMNS: &str = "family AS os_family, \
    family_code AS os_family_code, \
    name AS os, \
    name_code AS os_code, \
    homepage AS os_home_page, \
    icon AS os_icon, \
    icon_big AS os_icon_big, \
    vendor AS os_family_vendor, \
    vendor_code AS os_family_vendor_code, \
    vendor_homepage AS os_family_vendor_homepage, \
    'https://udger.com/resources/ua-list/os-detail?os=' || REPLACE(name, ' ', '%20') AS os_info_url ";

const DEVICE_COLUMNS: &str = 
    "name AS device_class, \
    name_code AS device_class_code, \
    icon AS device_class_icon, \
    icon_big AS device_class_icon_big, \
    'https://udger.com/resources/ua-list/device-detail?device=' || REPLACE(name, ' ', '%20') AS device_class_info_url ";

pub const SQL_DEVICE_NAME_LIST: &str = "SELECT \
    marketname, \
    brand_code,\
    brand, \
    brand_url, \
    icon, \
    icon_big \
    FROM \
    udger_devicename_list \
    JOIN \
    udger_devicename_brand ON udger_devicename_brand.id=udger_devicename_list.brand_id \
    WHERE \
    regex_id = ? AND code = ?";

lazy_static! {
    pub static ref SQL_OS: String = format!(
        "{}{}{}{}{}{}{}{}{}",
        "SELECT ",
        "ur.rowid, ",
        OS_COLUMNS,
        "FROM ",
        "udger_os_regex ur ",
        "JOIN ",
        "udger_os_list ON udger_os_list.id = ur.os_id ",
        "WHERE ",
        "ur.rowid=?"
    );
    pub static ref SQL_CLIENT_OS: String = format!(
        "{}{}{}{}{}{}{}{}",
        "SELECT ",
        OS_COLUMNS,
        "FROM ",
        "udger_client_os_relation ",
        "JOIN ",
        "udger_os_list ON udger_os_list.id = udger_client_os_relation.os_id ",
        "WHERE ",
        "client_id = ?"
    );
    pub static ref SQL_DEVICE: String = format!(
        "{}{}{}{}{}{}{}{}{}",
        "SELECT ",
        "ur.rowid, ",
        DEVICE_COLUMNS,
        "FROM ",
        "udger_deviceclass_regex ur ",
        "JOIN ",
        "udger_deviceclass_list ON udger_deviceclass_list.id = ur.deviceclass_id ",
        "WHERE ",
        "ur.rowid=?"
    );
    #[derive(Debug)]
    pub static ref SQL_CLIENT_CLASS: String = format!(
        "{}{}{}{}{}{}{}{}",
        "SELECT ",
        DEVICE_COLUMNS,
        "FROM ",
        "udger_deviceclass_list ",
        "JOIN ",
        "udger_client_class ON udger_client_class.deviceclass_id = udger_deviceclass_list.id ",
        "WHERE ",
        "udger_client_class.id = ?"
    );
}
