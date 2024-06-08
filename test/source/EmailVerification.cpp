#include "EmailVerification.hpp"

#include <fmt/format.h>
#include <gtest/gtest.h>
#include <stdexcept>

using namespace tuposoft::vrf;

TEST(EmailVerificationTest, ThrowsInvalidArgumentErrorOnInvalidInput) {
  EXPECT_THROW(extract_email_parts("john.doe"), std::invalid_argument);
}

TEST(EmailVerificationTest, ExtractUsernameAndDomainSuccess) {
  const std::string expectedUsername{"john.doe"};
  const auto expectedDomain{"example.com"};
  const auto email{expectedUsername + '@' + expectedDomain};

  const auto [actualUsername, actualDomain] = extract_email_parts(email);

  EXPECT_EQ(actualUsername, expectedUsername);
  EXPECT_EQ(actualDomain, expectedDomain);
}

TEST(EmailVerificationTest, ThrowsInvalidArgumentErrorOnInvalidInput2) {
  EXPECT_THROW(extract_email_parts("test.email@@mail.com"),
               std::invalid_argument);
}

TEST(EmailVerificationTest, GetMXRecordsSuccess) {
  const auto domain{"tuposoft.com"};
  const std::vector result = {std::string{"mail."} + domain};
  EXPECT_EQ(result, get_mx_records(domain));
}

TEST(EmailVerificationTest, EmailVerificationDataOutputSuccess) {
  const auto data = vrf_data{
      "john.doe@tuposoft.com", "john.doe",          "tuposoft.com",
      "mail.tuposoft.com",     vrf_result::success, false,
  };

  const auto expected = fmt::format("\nVerification summary:\n"
                                    "email: {}\n"
                                    "username: {}\n"
                                    "domain: {}\n"
                                    "mx_record: {}\n"
                                    "result: {}\n"
                                    "catch_all: {}\n\n",
                                    data.email, data.username, data.domain,
                                    data.mx_record, "true", "false");

  std::ostringstream os{};
  os << data;
  const auto actual = os.str();

  EXPECT_EQ(expected, actual);
}
