// Copyright (c) 2015-2019 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#ifndef PARAMS_H
#define PARAMS_H

#include <vector>
#include <deque>
#include <string>

namespace pg
{

class params
{
public:
    params& add(std::string &&param);
    params& add(const std::string &param);
    params& add(const char *param, int size = -1);

    params& operator<<(std::string &&param);
    params& operator<<(const std::string &param);
    params& operator<<(const char *param);

    params& addref(std::string &&param);
    params& addref(const std::string &param);
    params& addref(const char *param, int size = -1);

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
