if(OFFLINE_ENVIRONMENT)
    set(pcre_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pcre-8.44.tar.bz2)
else()
    set(pcre_url https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.bz2)
endif()

ExternalProject_Add(libpcre
    URL ${pcre_url}
    EXCLUDE_FROM_ALL ON
    PREFIX pcre
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CMAKE_ARGS  -D CMAKE_BUILD_TYPE=Release
                -D CMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                -D BUILD_SHARED_LIBS=ON
                -D PCRE_BUILD_PCREGREP=OFF
                -D PCRE_BUILD_TESTS=OFF
                -D PCRE_BUILD_PCRECPP=OFF
                -D PCRE_SUPPORT_UNICODE_PROPERTIES=ON
                -D CMAKE_POSITION_INDEPENDENT_CODE=ON
)