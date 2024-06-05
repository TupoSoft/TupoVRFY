#include "EmailVerification.hpp"

#include <gtest/gtest.h>

#include "fmt/format.h"

using namespace TupoSoft::VRF;

TEST(EmailVerificationTest, ThrowsInvalidArgumentErrorOnInvalidInput) {
    EXPECT_THROW(extractLocalPartAndDomain("john.doe"), std::invalid_argument);
}

TEST(EmailVerificationTest, ExtractUsernameAndDomainSuccess) {
    const std::string expectedUsername{"john.doe"};
    const auto expectedDomain{"example.com"};
    const auto email{expectedUsername + '@' + expectedDomain};

    const auto [actualUsername, actualDomain] = extractLocalPartAndDomain(email);

    EXPECT_EQ(actualUsername, expectedUsername);
    EXPECT_EQ(actualDomain, expectedDomain);
}

TEST(EmailVerificationTest, GetMXRecordsSuccess) {
    const auto domain{"tuposoft.com"};
    const std::vector result = {std::string{"mail."} + domain};
    EXPECT_EQ(result, getMXRecords(domain));
}

TEST(EmailVerificationTest, EmailVerificationDataOutputSuccess) {
    const auto data = EmailVerificationData{
        "john.doe@tuposoft.com",
        "john.doe",
        "tuposoft.com",
        "mail.tuposoft.com",
        EmailVerificationResult::Success,
        false,
    };

    const auto expected = fmt::format("\nVerification summary:\n"
                                      "email: {}\n"
                                      "username: {}\n"
                                      "domain: {}\n"
                                      "mx_record: {}\n"
                                      "result: {}\n"
                                      "catch_all: {}\n\n",
                                      data.email,
                                      data.username,
                                      data.domain,
                                      data.mxRecord,
                                      "true",
                                      "false");

    std::ostringstream os{};
    os << data;
    const auto actual = os.str();

    EXPECT_EQ(expected, actual);
}
