#include <stdbool.h>

struct ua_info;
struct udger;
struct udger_data;

typedef struct ua_info ua_info_t;
typedef struct udger udger_t;
typedef struct udger_data udger_data_t;

typedef int (*udger_callback)(const ua_info_t *, void *);

#ifdef __cplusplus
extern "C" {
#endif
int udger_new(udger_t **udger, const char *db_path, unsigned int capacity);

void udger_drop(udger_t *udger);

int udger_parse_ua(const udger_t *udger, const udger_data_t *udger_data, const char *ua,
                   udger_callback cb, void *data);

int udger_data_alloc(udger_t *udger, udger_data_t **data);

void udger_data_drop(udger_data_t *data);

int ua_info_to_string(const ua_info_t *info, char **buf, size_t *len, bool pretty);

void ua_info_get_ua_class(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_class_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_engine(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_version(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_version_major(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_version_minor(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_crawler_last_seen(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_crawler_respect_robotstxt(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_crawler_category(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_crawler_category_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_uptodate_current_version(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family_vendor(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family_vendor_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_string(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_family(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_family_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_family_vendor(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_family_vendor_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_class(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_class_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_marketname(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_brand(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_brand_code(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_application_name(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_application_version(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family_icon(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family_icon_big(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_icon(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_icon_big(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_class_icon(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_class_icon_big(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_brand_icon(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_brand_icon_big(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family_homepage(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family_vendor_homepage(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_homepage(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_family_vendor_homepage(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_family_vendor_homepage(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_brand_homepage(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_ua_family_info_url(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_os_info_url(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_class_info_url(const ua_info_t *info, char **buf, size_t *buf_len);

void ua_info_get_device_brand_info_url(const ua_info_t *info, char **buf, size_t *buf_len);

#ifdef __cplusplus
} // extern "C"
#endif
