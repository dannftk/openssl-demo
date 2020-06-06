#pragma once

#include <string>
#include <string_view>

namespace test
{

enum class color_e
{
    red      = 31,
    green    = 32,
    yellow   = 33,
    blue     = 34,
    mangenta = 35,
    cyan     = 36,
    lgreen   = 92,
};

inline std::string_view color_escape_reset() noexcept { return "\e[0m"; }

inline std::string color_escape(color_e color)
{
    return "\e[" + std::to_string(static_cast<int>(color)) + 'm';
}

inline std::string colored(std::string_view input, color_e color)
{
    return color_escape(color) + input.data() + color_escape_reset().data();
}

inline auto cred(std::string_view input) { return colored(input, color_e::red); }
inline auto cgreen(std::string_view input) { return colored(input, color_e::green); }
inline auto clgreen(std::string_view input) { return colored(input, color_e::lgreen); }
inline auto cyellow(std::string_view input) { return colored(input, color_e::yellow); }
inline auto cblue(std::string_view input) { return colored(input, color_e::blue); }
inline auto cmangenta(std::string_view input) { return colored(input, color_e::mangenta); }
inline auto ccyan(std::string_view input) { return colored(input, color_e::cyan); }

} // namespace test
