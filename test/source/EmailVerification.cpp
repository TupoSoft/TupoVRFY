#include "EmailVerification.hpp"

#include <gtest/gtest.h>

using namespace TupoSoft::VRF;

TEST(EmailVerificationTest, ExtractLocalPartAndDomain) {
    const std::string expectedUsername{"john.doe"};
    const std::string expectedDomain{"example.com"};
    const std::string email{expectedUsername + '@' + expectedDomain};

    const auto [actualUsername, actualDomain] = extractLocalPartAndDomain(email);

    EXPECT_EQ(actualUsername, expectedUsername);
    EXPECT_EQ(actualDomain, expectedDomain);
}
