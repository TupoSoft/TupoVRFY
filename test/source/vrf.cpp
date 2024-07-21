#include "vrf.hpp"
#include "vrf_data.hpp"

#include <fmt/format.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace tuposoft::vrf;

TEST(VRF_TEST, ThrowsInvalidArgumentErrorOnInvalidInput) {
    EXPECT_THROW(extract_email_parts("john.doe"), std::invalid_argument);
}

TEST(VRF_TEST, ThrowsInvalidArgumentErrorOnInvalidInput2) {
    EXPECT_THROW(extract_email_parts("test.email@@mail.com"), std::invalid_argument);
}

TEST(VRF_TEST, ExtractUsernameAndDomainSuccess) {
    const std::string expectedUsername{"john.doe"};
    const auto expectedDomain{"example.com"};
    const auto email{expectedUsername + '@' + expectedDomain};

    const auto [actualUsername, actualDomain] = extract_email_parts(email);

    EXPECT_EQ(actualUsername, expectedUsername);
    EXPECT_EQ(actualDomain, expectedDomain);
}

TEST(VRF_TEST, EmailVerificationDataOutputSuccess) {
    const auto data = vrf_data{
        "john.doe@tuposoft.com", "john.doe", "tuposoft.com", "mail.tuposoft.com", vrf_result::success, false,
    };

    const auto expected = fmt::format("\nVerification summary:\n"
                                      "email: {}\n"
                                      "username: {}\n"
                                      "domain: {}\n"
                                      "mx_record: {}\n"
                                      "result: {}\n"
                                      "catch_all: {}\n\n",
                                      data.email, data.username, data.domain, data.mx_record, "true", "false");

    std::ostringstream os{};
    os << data;
    const auto actual = os.str();

    EXPECT_EQ(expected, actual);
}
