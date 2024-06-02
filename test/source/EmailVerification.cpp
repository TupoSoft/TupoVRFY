#include "EmailVerification.hpp"

#include <gtest/gtest.h>

using namespace TupoSoft::VRF;

TEST(EmailVerificationTest, ThrowsInvalidArgumentErrorOnInvalidInput) {
    const auto invalidEmail{"john.doe"};
    EXPECT_THROW(extractLocalPartAndDomain(invalidEmail), std::invalid_argument);
}

TEST(EmailVerificationTest, ExtractLocalPartAndDomainSuccess) {
    const std::string expectedUsername{"john.doe"};
    const auto expectedDomain{"example.com"};
    const auto email{expectedUsername + '@' + expectedDomain};

    const auto [actualUsername, actualDomain] = extractLocalPartAndDomain(email);

    EXPECT_EQ(actualUsername, expectedUsername);
    EXPECT_EQ(actualDomain, expectedDomain);
}
