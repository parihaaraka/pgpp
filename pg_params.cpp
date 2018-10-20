// Copyright (c) 2015-2018 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#include "pg_params.h"
#include <string.h>

namespace pg
{

params &params::add(std::string &&param)
{
    _temps.push_back(param);
    return addref(_temps.back().data(), static_cast<int>(_temps.back().size()));
}

params &params::add(const std::string &param)
{
    return add(std::string(param));
}

params &params::add(const char *param, int size)
{
    if (!param)
        return addref(nullptr, 0);

    if (size == -1)
        return add(std::string(param));

    return add(std::string(param, static_cast<size_t>(size)));
}

params &params::operator<<(std::string &&param)
{
    return add(param);
}

params &params::operator<<(const std::string &param)
{
    return add(param);
}

params &params::operator<<(const char *param)
{
    return add(param);
}

params &params::addref(std::string &&param)
{
    return add(param);
}

params &params::addref(const std::string &param)
{
    return addref(param.data(), param.size());
}

params &params::addref(const char *param, int size)
{
    _param_pointers.push_back(param);
    _param_lengths.push_back(size);
    return *this;
}

params &params::clear()
{
    _param_pointers.clear();
    _param_lengths.clear();
    _temps.clear();
    return *this;
}

} // namespace pg
