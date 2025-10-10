// Copyright (c) 2015-2019 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#ifndef PG_RESULT_H
#define PG_RESULT_H

#include <optional>
#include <charconv>
#include <string>
#include <system_error>
#include <vector>
#include <memory>
#if __has_include(<postgresql/libpq-fe.h>)
#	include <postgresql/libpq-fe.h>
#else
#	include <libpq-fe.h>
#endif

namespace pg
{

std::string_view severity_eng(const PGresult *res);
std::string_view severity(const PGresult *res);
std::string_view state(const PGresult *res);
std::string_view primary_message(const PGresult *res);
std::string_view detail(const PGresult *res);
std::string_view hint(const PGresult *res);
std::string_view full_message(const PGresult *res);

class result
{
public:
    explicit result(PGresult *res) noexcept;
    ~result();

    PGresult* result_ptr() const noexcept { return _res; }
    void clear_data();

    int row_count() const noexcept;
    int column_count() const noexcept;

    const char* raw_value(int row, int col) const noexcept;
    const char* raw_value(int row, const char *col_name) const noexcept;
    std::vector<unsigned char> bytea_value(int row, int col);

    int value_size(int row, int col) const noexcept;
    int value_size(int row, const char *col_name) const noexcept;

    bool is_null(int row, int col) const noexcept;
    bool is_null(int row, const char *col_name) const noexcept;

    int column_index(const char* col_name) const noexcept;
    const char* column_name(int col_number) const noexcept;
    unsigned int column_type(int col_number) const noexcept;
    int scale(int col_number) const noexcept;

    template <typename T>
    std::optional<T> value(int row, int col) const
    {
        if (is_null(row, col))
            return {};
        auto val = std::string_view(raw_value(row, col), value_size(row, col));
        if constexpr (std::is_integral_v<T>  || std::is_floating_point_v<T>)
        {
            T num;
            auto ec = std::from_chars(val.data(), val.data() + val.size(), num).ec;
            if (ec == std::errc{})
                return {num};
            throw std::runtime_error(std::make_error_code(ec).message());
        }
        if constexpr (std::is_same_v<T, std::string_view>)
        {
            return {val};
        }
        if constexpr (std::is_same_v<T, std::string>)
        {
            return {std::string{val}};
        }
    }

    template <typename T>
    std::optional<T> value(int row, const char* col_name) const
    {
        int cind = column_index(col_name);
        if (cind < 0)
            throw std::runtime_error("column `" + std::string(col_name) + "` not found");
        return value<T>(row, cind);
    }

    template <typename T>
    std::optional<T> value(int row, std::string_view col_name) const
    {
        return value<T>(row, col_name.data());
    }

    operator bool() const;
    bool copy_in_ready() const;
    bool copy_out_ready() const;

    std::string_view severity_eng() const;
    std::string_view severity() const;
    std::string_view state() const;
    std::string_view primary_message() const;
    std::string_view detail() const;
    std::string_view hint() const;
    std::string_view full_message() const;

    // contains rows already fetched before error occured (async query only)
    std::shared_ptr<result> partial_result;

private:
    PGresult *_res;
};

}
#endif // PG_RESULT_H
