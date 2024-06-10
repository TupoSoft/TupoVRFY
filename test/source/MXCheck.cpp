#include <asio.hpp>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "EmailVerification.hpp"

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

// Custom action to simulate reading into a streambuf
void ReadIntoStreambuf(asio::streambuf &streambuf, const std::string &data) {
    std::ostream os(&streambuf);
    os << data;
}

// Mock class for Asio services
class MockAsioServices {
public:
    MOCK_METHOD0(get_io_service, asio::io_service &());
    MOCK_METHOD0(get_tcp_resolver, asio::ip::tcp::resolver &());
    MOCK_METHOD0(get_socket, asio::ip::tcp::socket &());
};

// Mock class for the TCP resolver
class MockTcpResolver {
public:
    MOCK_METHOD1(resolve, asio::ip::tcp::resolver::iterator(const asio::ip::tcp::resolver::query &));
};

// Mock class for the TCP socket
class MockTcpSocket {
public:
    MOCK_METHOD1(connect, void(const asio::ip::tcp::endpoint &));
    MOCK_METHOD0(close, void());
    MOCK_METHOD2(read_until, std::size_t(asio::streambuf &, const std::string &));
};

// Test fixture
class CheckMxTest : public ::testing::Test {
protected:
    MockAsioServices mock_asio_services;
    MockTcpResolver mock_tcp_resolver;
    MockTcpSocket mock_tcp_socket;
    asio::io_service ios;
    asio::ip::tcp::resolver tcp_resolver{ios};
    asio::ip::tcp::socket socket{ios};
    asio::ip::tcp::resolver::iterator endpoint_iterator;

    void SetUp() override {
        // Set up the mock behavior for Asio services
        ON_CALL(mock_asio_services, get_io_service()).WillByDefault(testing::ReturnRef(ios));
        ON_CALL(mock_asio_services, get_tcp_resolver()).WillByDefault(testing::ReturnRef(tcp_resolver));
        ON_CALL(mock_asio_services, get_socket()).WillByDefault(testing::ReturnRef(socket));

        // Set up the mock behavior for the TCP resolver
        ON_CALL(mock_tcp_resolver, resolve(_)).WillByDefault(Return(endpoint_iterator));

        // Set up the mock behavior for the TCP socket
        ON_CALL(mock_tcp_socket, connect(_)).WillByDefault(Return());
        ON_CALL(mock_tcp_socket, close()).WillByDefault(Return());
        ON_CALL(mock_tcp_socket, read_until(_, _)).WillByDefault(Invoke([] {
            return std::string("dummy response").size();
        }));
    }

    // Helper function to simulate server responses
    void SimulateServerResponse(const std::string &response) {
        ON_CALL(mock_tcp_socket, read_until(_, _)).WillByDefault(Invoke([] {
            return std::string("dummy response").size();
        }));
    }
};

TEST_F(CheckMxTest, ValidRecipient) {
    SimulateServerResponse("250 2.1.5 Recipient OK\r\n");

    int result = tuposoft::vrf::check_mx("valid@example.com", "mail.example.com");
    EXPECT_EQ(result, 250);
}

TEST_F(CheckMxTest, InvalidRecipient) {
    SimulateServerResponse("550 5.1.1 User unknown\r\n");

    int result = tuposoft::vrf::check_mx("invalid@example.com", "mail.example.com");
    EXPECT_EQ(result, 550);
}
