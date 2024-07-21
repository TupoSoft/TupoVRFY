#pragma once

#include <string>

namespace tuposoft::vrf {
    enum class vrf_result : std::uint8_t {
        success, invalid_email, failure, catch_all_detected, invalid_domain, mx_record_not_found
    };

    struct vrf_data {
        std::string email;
        std::string username;
        std::string domain;
        std::string mx_record;
        vrf_result result;
        bool catch_all;
    };

    auto operator<<(std::ostream &out, const vrf_data &data) -> decltype(out);
}
