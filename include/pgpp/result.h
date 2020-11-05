// Copyright (c) 2015-2019 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#ifndef PG_RESULT_H
#define PG_RESULT_H

#include <string>
#include <vector>
#include <memory>
#include <postgresql/libpq-fe.h>

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
