#include "vrf.hpp"

#include "gmock/gmock.h"
#include "mocks/mock_socket.hpp"

#include <fmt/format.h>
#include <gmock/gmock.h>
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

TEST(VRF_TEST, GetMXRecordsSuccess) {
    const auto domain{"tuposoft.com"};
    const std::vector result = {std::string{"mail."} + domain};

    EXPECT_EQ(result, get_mx_records(domain));
}

TEST(VRF_TEST, EmailVerificationDataOutputSuccess) {
    const auto data = verifier::data{"john.doe@tuposoft.com", "john.doe", "tuposoft.com", "mail.tuposoft.com",
                                     verifier::status::success};

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

TEST(VRF_TEST, CHECK_MX_1) {
    // auto socket = std::make_unique<mock_socket>();
    // EXPECT_CALL(socket->close()).WillOnce();
    auto socket = std::make_unique<mock_socket>();
    auto buffer = std::vector<std::byte>(128);
    EXPECT_CALL(*socket, read(buffer)).WillOnce(testing::Return(1));
    auto verifier = tuposoft::vrf::verifier(nullptr);

    const auto result = verifier.check_mx("mail.tuposoft.com", "kk@tuposoft.com");
    EXPECT_EQ(250, result);
}
