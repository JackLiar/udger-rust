if(OFFLINE_ENVIRONMENT)
    set(hyperscan_url ${CMAKE_CURRENT_SOURCE_DIR}/third_party/hyperscan-5.3.0.tar.gz)
else()
    set(hyperscan_url https://github.com/intel/hyperscan/archive/v5.3.0.tar.gz)
endif()

ExternalProject_Add(hyperscan
    URL ${hyperscan_url}
    EXCLUDE_FROM_ALL ON
    PREFIX hyperscan
    INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install
    CMAKE_ARGS  -D CMAKE_BUILD_TYPE=Release
                -D CMAKE_INSTALL_PREFIX=<INSTALL_DIR>
                -D BUILD_STATIC_AND_SHARED=ON
                -D BOOST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/boost/src/boost
                -D PCRE_SOURCE=${CMAKE_CURRENT_BINARY_DIR}/pcre/src/libpcre
                -D CMAKE_PREFIX_PATH=${CMAKE_CURRENT_BINARY_DIR}/install/bin
                -D CMAKE_POSITION_INDEPENDENT_CODE=ON
)