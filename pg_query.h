// Copyright (c) 2015-2018 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#ifndef PG_QUERY_H
#define PG_QUERY_H

#include <functional>
#include "pg_params.h"
#include "pg_result.h"
#include "pg_connection.h"

namespace pg
{

class query
{
public:
    query(const std::string &q = "");
    std::string operator = (const std::string &q);
    std::string query_string;
    pg::params params;
    bool throw_on_error = false;
    std::deque<std::shared_ptr<result>> results;

    /**
     * @brief On query finished callback.
     * It is always called when query processing finished (in any case: success, execution error or connection error).
     */
    std::function<void(connection &cn, std::shared_ptr<query> q, const std::string &error)> query_finished_async_cb;

    /**
     * @brief The function is called when fetching of new resultset is started.
     * If a command string contains multiple sql commands, the results
     * of those commands can be obtained individually.
     */
    std::function<void(const connection &cn, result &res)> resultset_started_async_cb;

    /**
     * @brief The function is called when fetching of new resultset is finished successfully.
     * In case of error during fetching this function is not called, last item within results array
     * will contain empty result with error, but the result may contain nonempty partial_result.
     */
    std::function<void(const connection &cn, result &res)> resultset_fetched_async_cb;

    /**
     * @brief Called on susscessful fetch of every single row (the last one in last result).
     */
    std::function<void(const connection &cn, result &res)> row_fetched_async_cb;

    std::function<void(const connection &cn, const std::string &severity, const std::string &message, const std::string &hint)> notice_cb;

    void clear()
    {
        query_string.clear();
        results.clear();
        params.clear();
        throw_on_error = false;
        query_finished_async_cb = nullptr;
        resultset_started_async_cb = nullptr;
        resultset_fetched_async_cb = nullptr;
        row_fetched_async_cb = nullptr;
        notice_cb = nullptr;
    }
};

} // namespace pg

#endif // PG_QUERY_H
