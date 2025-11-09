// Copyright (c) 2015-2019 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#ifndef PARAMS_H
#define PARAMS_H

#include <vector>
#include <deque>
#include <string>
#include <string_view>
#include <optional>
#include <type_traits>
#include <vector>
#include <utility>

namespace pg
{

class params
{
public:
    params& add(std::string &&param);
    params& add(const std::string &param);
    params& add(const char *param, int size = -1);
    template <std::size_t N>
    params& add(const char(&param)[N]) { return add(param, static_cast<int>(N ? N - 1 : 0)); }
    params& add(std::string_view sv) { return add(std::string(sv)); }
    params& add(std::nullptr_t) { return addref(nullptr, 0); }

    // Binary convenience overloads (copied into internal storage)
    params& add(const std::vector<char> &bytes) { return add(std::string(bytes.data(), bytes.size())); }

    template <typename T>
    std::enable_if_t<std::is_arithmetic_v<T> && !std::is_same_v<T, bool>, params&>
    add(T v)
    {
        return add(std::to_string(v));
    }

    params& add(bool v) { return add(v ? std::string("true") : std::string("false")); }

    template <typename T>
    params& add(const std::optional<T> &opt)
    {
        if (opt.has_value())
            return add(*opt);
        return addref(nullptr, 0);
    }

    template <typename T>
    params& operator<<(T&& v) { return add(std::forward<T>(v)); }

    params& addref(const std::string &param);
    params& addref(const char *param, int size = -1);
    template <std::size_t N>
    params& addref(const char(&param)[N]) { return addref(param, static_cast<int>(N ? N - 1 : 0)); }

    const char* const* values() const { return _param_pointers.data(); }
    const int* lengths() const { return _param_lengths.data(); }
    size_t count() const { return _param_lengths.size(); }
    params& clear();

private:
    std::vector<const char*> _param_pointers;
    std::vector<int> _param_lengths;
    std::deque<std::string> _temps;
};

} // namespace pg

#endif // PARAMS_H
