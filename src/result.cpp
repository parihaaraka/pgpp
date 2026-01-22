// Copyright (c) 2015-2019 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#include "pgpp/result.h"
#include "pgpp/connection.h"
#include "pgpp/types.h"

namespace pg
{

using namespace std;

const char* err_field(const PGresult *res, int code) noexcept
{
    const char *value = PQresultErrorField(res, code);
    return value ? value : "";
}

std::string_view severity_eng(const PGresult *res) { return err_field(res, PG_DIAG_SEVERITY_NONLOCALIZED); }
std::string_view severity(const PGresult *res) { return err_field(res, PG_DIAG_SEVERITY); }
std::string_view state(const PGresult *res) { return err_field(res, PG_DIAG_SQLSTATE); }
std::string_view primary_message(const PGresult *res) { return err_field(res, PG_DIAG_MESSAGE_PRIMARY); }
std::string_view detail(const PGresult *res) { return err_field(res, PG_DIAG_MESSAGE_DETAIL); }
std::string_view hint(const PGresult *res) { return err_field(res, PG_DIAG_MESSAGE_HINT); }
std::string_view full_message(const PGresult *res) { return PQresultErrorMessage(res); }

result::result(PGresult *res) noexcept
    : _res(res)
{
}

result::~result()
{
    partial_result.reset();
    PQclear(_res);
}

void result::clear_data()
{
    PGresult *tmp = PQcopyResult(_res, PG_COPYRES_ATTRS);
    PQclear(_res);
    _res = tmp;
}

int result::row_count() const noexcept
{
    return (_res ? PQntuples(_res) : 0);
}

int result::column_count() const noexcept
{
    return (_res ? PQnfields(_res) : 0);
}

const char* result::raw_value(int row, int col) const noexcept
{
    return PQgetvalue(_res, row, col);
}

const char* result::raw_value(int row, const char* col_name) const noexcept
{
    int cnum = PQfnumber(_res, col_name);
    return cnum < 0 ? nullptr : PQgetvalue(_res, row, cnum);
}

std::vector<unsigned char> result::bytea_value(int row, int col)
{
    return pg::unescape_bytea(raw_value(row, col));
}

int result::value_size(int row, int col) const noexcept
{
    return PQgetlength(_res, row, col);
}

int result::value_size(int row, const char* col_name) const noexcept
{
    int cnum = PQfnumber(_res, col_name);
    return cnum < 0 ? 0 : PQgetlength(_res, row, cnum);
}

bool result::is_null(int row, int col) const noexcept
{
    return PQgetisnull(_res, row, col);
}

bool result::is_null(int row, const char* col_name) const noexcept
{
    int cnum = PQfnumber(_res, col_name);
    return cnum < 0 ? true : PQgetisnull(_res, row, cnum);
}

int result::column_index(const char* col_name) const noexcept
{
    return (_res ? PQfnumber(_res, col_name) : -1);
}

int result::column_index(std::string_view col_name) const noexcept
{
    if (!_res)
        return -1;
    auto *buf = static_cast<char*>(alloca(col_name.size() + 1));
    std::memcpy(buf, col_name.data(), col_name.size());
    buf[col_name.size()] = '\0';
    return PQfnumber(_res, buf);
}

const char* result::column_name(int col_number) const noexcept
{
    return (_res ? PQfname(_res, col_number) : nullptr);
}

unsigned int result::column_type(int col_number) const noexcept
{
    return (_res ? PQftype(_res, col_number) : InvalidOid);
}

int result::scale(int col_number) const noexcept
{
    int pgfmod = PQfmod(_res, col_number);
    if (column_type(col_number) != NUMERICOID || pgfmod == -1)
        return -1;
    return ((pgfmod - VARHDRSZ) & 0xffff);
}

bool result::copy_in_ready() const
{
    ExecStatusType status = PQresultStatus(_res);
    return (status == PGRES_COPY_IN);
}

bool result::copy_out_ready() const
{
    ExecStatusType status = PQresultStatus(_res);
    return (status == PGRES_COPY_OUT);
}

pg::result::operator bool() const
{
    ExecStatusType status = PQresultStatus(_res);
    return (status < PGRES_BAD_RESPONSE); // PGRES_EMPTY_QUERY, PGRES_COMMAND_OK, PGRES_TUPLES_OK, PGRES_COPY_OUT, PGRES_COPY_IN
}

string_view result::severity_eng() const
{
    return pg::severity_eng(_res);
}

std::string_view result::severity() const
{
    return pg::severity(_res);
}

std::string_view result::state() const
{
    return pg::state(_res);
}

std::string_view result::primary_message() const
{
    return pg::primary_message(_res);
}

std::string_view result::detail() const
{
    return pg::detail(_res);
}

std::string_view result::hint() const
{
    return pg::hint(_res);
}

std::string_view result::full_message() const
{
    return pg::full_message(_res);
}

} // namespace pg
