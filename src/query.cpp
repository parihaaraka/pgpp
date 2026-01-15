// Copyright (c) 2015-2026 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#include "pgpp/query.h"

namespace pg
{

query::query(std::string_view q) : query_string(q)
{
}

query& query::operator =(std::string_view q)
{
    query_string = q;
    return *this;
}

// TODO: safe api, indirect members access

} // namespace pg
