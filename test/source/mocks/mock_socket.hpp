#include <gmock/gmock.h>

#include <socket_wrapper.hpp>

class mock_socket : public tuposoft::vrf::basic_socket_wrapper {
public:
    MOCK_METHOD(void, connect, (const std::string &, const std::string &), (override));
    MOCK_METHOD(std::size_t, read, (std::vector<std::byte> &), (override));
    MOCK_METHOD(std::size_t, write, (const std::string &), (override));
    MOCK_METHOD(void, close, (), (override));
};
