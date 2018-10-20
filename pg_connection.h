// Copyright (c) 2015-2018 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#ifndef PG_CONNECTION_H
#define PG_CONNECTION_H

/** @file */

#include <libpq-fe.h>
#include <atomic>
#include <string>
#include <functional>
#include <memory>
#include <deque>
#include <vector>
#include <mutex>
#include <chrono>
#include "dbpool.h"
#include "pg_result.h"

#define CONNECT_TIMEOUT_SEC 40

namespace pg
{

class params;
class query;

/** PostgreSQL error containig native PGresult */
class query_error : public std::runtime_error
{
public:
    explicit query_error(std::shared_ptr<pg::result> res): std::runtime_error(PQresultErrorMessage(res->result_ptr())), _res(res) {}
    virtual std::shared_ptr<pg::result> result() const;
private:
    std::shared_ptr<pg::result> _res;
};

/** Socket state enum. */
enum socket_watch_mode {
    none = 0, /**< used to disable watching */
    read,     /**< ready read state */
    write     /**< ready write state */
};

// deprecated!
// "It might give the wrong results if used in programs that use multiple database connections."
std::string escape_bytea(const unsigned char *value, size_t size);
std::vector<unsigned char> unescape_bytea(const char *value);
std::string encrypt_password(const std::string &password, const std::string &user = "");

// TODO async api:
//  check all external calls within async api (noexcept / try-catch and so on)
//  timeouts

/** PostgreSQL connection */
class connection
{
    friend std::shared_ptr<connection> dbpool<connection>::get_connection(bool, bool);
public:
    connection(const std::string &connection_string = std::string());
    ~connection();

    /** Executes 'select 1' query to verify connectivity. */
    bool ping() noexcept;
    /**
     * Listen on specified notification channels, unlisten previous channels.
     * Subscription will be repaired in case of reconnection.
     * It's ok to call this function before connection being established.
     */
    void listen(const std::vector<std::string> &channels);
    void disconnect(bool call_disconnect_handler = true) noexcept;
    bool cancel() noexcept;
    bool is_connected() const noexcept { return _conn && PQstatus(_conn) == CONNECTION_OK; }
    bool is_idle() const noexcept;
    std::chrono::seconds idle_duration();
    void set_connection_string(const std::string &cs) { _current_cs = cs; } // TODO: reconnect or something else
    const std::string& last_error() const { return _last_error; }
    std::string escape_bytea(const unsigned char *value, size_t size);

    /*!
     * @brief Establishes connection to postgresql server.
     * @param connect_timeout_sec Minimum duration of *retries* in case of problems. Single try timeout may be defined in connection string (connection_timeout)
     * @return true on success
     */
    bool connect(unsigned int connect_timeout_sec = CONNECT_TIMEOUT_SEC);
    bool exec(query &q, bool throw_on_error = true, unsigned int connect_timeout_sec = CONNECT_TIMEOUT_SEC);
    std::shared_ptr<pg::result> exec(const std::string &query_string, const params *p = nullptr, bool throw_on_error = true, unsigned int connect_timeout_sec = CONNECT_TIMEOUT_SEC);

    /*!
     * @brief Sends data to the server during COPY_IN state.
     *
     * man: The application can divide the COPY data stream into buffer loads of any convenient size.
     *  Buffer-load boundaries have no semantic significance when sending.
     *  The contents of the data stream must match the data format expected by the COPY command.
     */
    bool put_copy_data(const char *buffer, int nbytes, bool throw_on_error = true);

    /*!
     * @brief Sends end-of-data indication to the server during COPY_IN state.
     * @param stop_reason the COPY is forced to fail with the string pointed to by stop_reason used as the error message
     * @return result containing the final status of COPY operation
     */
    std::unique_ptr<pg::result> stop_copy_in(const char *stop_reason = nullptr);

    /*!
     * @brief Receives data from the server during COPY_OUT state.
     * @param fetch_cb callback to process fetched data row by row. Return false to emit cancel() and prevent next calls.
     * @return result containing the final status of COPY operation
     */
    std::unique_ptr<pg::result> get_copy_data(std::function<bool(const char *buffer, int nbytes)> fetch_cb) noexcept;

    // TODO implement async COPY

    // ASYNC API
    int socket() const noexcept { return _conn ? PQsocket(_conn) : -1; }
    void connect_async() noexcept;
    void exec_async(std::shared_ptr<pg::query> q) noexcept;

private:
    enum class async_stage { none, connecting, sending_query, flush, wait_ready_read };
    connection(const std::string &connection_string, std::function<void(connection*, std::string&, dbmode)> db_state_detected_cb);

    PGconn *_conn = nullptr;
    async_stage _async_stage = async_stage::none;
    std::shared_ptr<pg::result> _temp_result; ///< temporary resultset for asynchronous processing
    std::function<void(dbmode)> _db_state_detected_cb; ///< pooler's callback

    std::string _current_cs;
    std::string _last_error;
    std::vector<std::string> _channels;
    std::chrono::time_point<std::chrono::system_clock> _last_action_moment;
    static void notice_receiver(void *arg ,const PGresult *res);
    void fetch_notifications();

    std::function<void(const connection &cn)> _connected_cb;
    std::function<void(const connection &cn)> _before_disconnect_cb;
    static std::function<void(const connection &cn, const std::string &severity, const std::string &message, const std::string &hint)> _notice_cb_global;
    std::function<void(const void *sender, const std::string &error, const pg::result *res)> _error_cb;
    std::function<void(int, const std::string&, const std::string&)> _notify_cb;

    // ASYNC API
    std::function<void(const connection &cn, int mode)> _socket_watcher_request_cb; // should be noexcept
    std::function<void(const connection &cn, int delay_ms)> _timer_request_cb;
    void raise_error(const std::shared_ptr<pg::result> &res = nullptr) noexcept;
    void raise_error(const std::string& error, const std::shared_ptr<pg::result> &res = nullptr) noexcept;
    void fetch();
    void async_connection_proceed();
    void async_validate_rw_mode();
    void async_restore_listen_channels();

    std::shared_ptr<pg::query> _q; // currently executing query
    std::shared_ptr<pg::query> _suspended_query;

    std::string _context;
    time_t _connection_start_moment, _last_try;  // TODO:  use these vars to enable timeouts

public:
    void on_connected(decltype(_connected_cb) handler) { _connected_cb = handler; }
    void on_before_disconnect(decltype(_before_disconnect_cb) handler) { _before_disconnect_cb = handler; }
    static void on_notice_global(decltype(_notice_cb_global) handler) { _notice_cb_global = handler; }
    void on_notify(decltype(_notify_cb) handler) { _notify_cb = handler; }
    void on_error(decltype(_error_cb) handler) { _error_cb = handler; }

    // ASYNC API
    /**
     * Callback for asking external watcher to wait for specified socket state.
     * Mandatory for async api (including notifications receiving).
     * @param handler functor to be called
     */
    void on_socket_watcher_request(decltype(_socket_watcher_request_cb) handler) { _socket_watcher_request_cb = handler; }

    /** External socket watcher must call this function on ready read state detected. */
    void ready_read_socket();

    /** External socket watcher must call this function on ready write state detected. */
    void ready_write_socket();

    /** External timer must call this function when elapsed. */
    void timer_elapsed();

    /** Callback for asking external timer to countdown the requested msecs. */
    void on_timer_request(decltype(_timer_request_cb) handler) { _timer_request_cb = handler; }

    // async libpq api usage example:
    // https://github.com/markokr/libpq-rowproc-demos/blob/master/demo-onerow-async.c
};

} // namespace pg

#endif // PG_CONNECTION_H
