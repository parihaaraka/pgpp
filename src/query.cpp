// Copyright (c) 2015-2019 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#include "pgpp/query.h"

namespace pg
{

query::query(const std::string &q) : query_string(q)
{

}

std::string query::operator =(const std::string &q)
{
    query_string = q;
    return query_string;
}

// TODO: safe api, indirect members access

} // namespace pg
