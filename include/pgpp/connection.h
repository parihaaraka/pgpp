// Copyright (c) 2015-2019 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#ifndef PG_CONNECTION_H
#define PG_CONNECTION_H

/** @file */

#if __has_include(<postgresql/libpq-fe.h>)
#	include <postgresql/libpq-fe.h>
#else
#	include <libpq-fe.h>
#endif
#include <atomic>
#include <string>
#include <functional>
#include <memory>
#include <deque>
#include <vector>
#include <mutex>
#include <chrono>
#include "dbpool.h"
#include "pgpp/result.h"
#include "fu2/function2.hpp"

#define CONNECT_TIMEOUT_SEC 40

#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__ ((dllexport))
    #else
      #define DLL_PUBLIC __declspec(dllexport)
    #endif
  #else
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__ ((dllimport))
    #else
      #define DLL_PUBLIC __declspec(dllimport)
    #endif
  #endif
  #define DLL_LOCAL
#else
  #if __GNUC__ >= 4
    #define DLL_PUBLIC __attribute__ ((visibility ("default")))
    #define DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else
    #define DLL_PUBLIC
    #define DLL_LOCAL
  #endif
#endif

namespace pg
{

class params;
class query;

/** PostgreSQL error containig native PGresult */
class DLL_PUBLIC query_error : public std::runtime_error
{
public:
    explicit query_error(std::shared_ptr<pg::result> res);
    virtual std::shared_ptr<pg::result> result() const;
private:
    std::shared_ptr<pg::result> _res;
};

#undef DLL_PUBLIC
#undef DLL_LOCAL

/** Socket state enum. */
enum socket_watch_mode {
    none = 0,  /**< used to disable watching */
    read,      /**< ready read state */
    write,     /**< ready write state */
    read_write
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
    //friend std::shared_ptr<connection> dbpool<connection>::get_connection(bool, bool);
    friend class dbpool<connection>;
    //WA for Clang compilation error. See https://bugs.llvm.org/show_bug.cgi?id=30859
public:
    connection(const std::string &connection_string = std::string());
    ~connection();

    /** Executes 'select 1' query to verify connectivity. */
    bool ping() noexcept;
    /**
     * Listen on specified notification channels, unlisten previous channels.
     * Subscription will be repaired in case of reconnection.
     * It's ok to call this function before connection being established.
     * If the connection is already established, this method executes
     * subscription query synchronously!
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
    std::string escape_identifier(std::string_view ident);

    /*!
     * @brief Establishes connection to postgresql server.
     * @param connect_timeout_sec Minimum duration of *retries* in case of problems. Single try timeout may be defined in connection string (connection_timeout)
     * @return true on success
     */
    bool connect(unsigned int connect_timeout_sec = CONNECT_TIMEOUT_SEC);
    bool exec(
            query &q,
            bool throw_on_error = true,
            unsigned int connect_timeout_sec = CONNECT_TIMEOUT_SEC);

    std::shared_ptr<pg::result> exec(
            const std::string &query_string,
            const params *p = nullptr,
            bool throw_on_error = true,
            unsigned int connect_timeout_sec = CONNECT_TIMEOUT_SEC);

    /*!
     * @brief Sends data to the server during COPY_IN state (blocking mode only).
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
    std::unique_ptr<pg::result> on_get_copy_data(std::function<bool(const char *buffer, int nbytes)> fetch_cb) noexcept;

    // TODO implement async COPY

    // ASYNC API
    int socket() const noexcept;
    void connect_async() noexcept;
    void exec_async(std::shared_ptr<pg::query> q) noexcept;

private:
    enum class async_stage {
        none,
        connecting,
        sending_query,
        flush,
        wait_ready_read,
        put_copy_end
    };
    std::string _copy_end_error;

    connection(const std::string &connection_string,
               std::function<void(connection*, std::string&, dbmode)> db_state_detected_cb);

    PGconn *_conn = nullptr;
    async_stage _async_stage = async_stage::none;
    std::shared_ptr<pg::result> _temp_result; ///< temporary resultset for asynchronous processing
    std::function<void(dbmode)> _db_state_detected_cb; ///< pooler's callback

    static std::function<void(connection*)> _on_construct_global_cb;
    static std::function<void(connection*)> _on_destruct_global_cb;
    fu2::unique_function<void()> _on_destruct_cb;

    std::string _current_cs;
    std::string _last_error;
    std::vector<std::string> _channels;
    std::chrono::time_point<std::chrono::system_clock> _last_action_moment;
    static void notice_receiver(void *arg ,const PGresult *res);
    void fetch_notifications();

    std::function<void(const connection &cn)> _connected_cb;
    std::function<void(const connection &cn)> _before_disconnect_cb;

    static std::function<void(
            const connection *cn,
            std::string_view severity,
            std::string_view message,
            std::string_view hint
            )> _notice_cb_global;

    /** preferred error handler */
    std::function<void(
            const void *sender,
            std::string_view error,
            const pg::result *res
            )> _error_cb;

    static std::function<void(
            const void *sender,
            std::string_view error,
            const pg::result *res
            )> _error_cb_global;

    std::function<void(int, const std::string&, const std::string&)> _notify_cb;

    void handle_error(const pg::result *res = nullptr) noexcept;

    // ASYNC API

    // need to capture watcher
    fu2::unique_function<void(int mode) noexcept> _socket_watcher_request_cb;
    std::function<void(const connection &cn, int delay_ms)> _timer_request_cb;
    void raise_error(const std::shared_ptr<pg::result> &res = nullptr) noexcept;
    void raise_error(const std::string& error, const std::shared_ptr<pg::result> &res = nullptr) noexcept;
    void fetch();
    void on_async_connected();
    void async_connection_proceed();
    void async_validate_rw_mode();
    void async_restore_listen_channels();

    std::shared_ptr<pg::query> _q; // currently executing query
    std::shared_ptr<pg::query> _suspended_query;

    std::string _context;
    time_t _connection_start_moment, _last_try;  // TODO:  use these vars to enable timeouts

    std::string _copy_in_buf;
    bool _copy_in_done = false;
    bool send_copy_data();

public:
    void on_connected(decltype(_connected_cb) handler) { _connected_cb = handler; }
    void on_before_disconnect(decltype(_before_disconnect_cb) handler) { _before_disconnect_cb = handler; }
    static void on_notice_global(decltype(_notice_cb_global) handler) { _notice_cb_global = handler; }
    void on_notify(decltype(_notify_cb) handler) { _notify_cb = handler; }
    void on_error(decltype(_error_cb) handler) { _error_cb = handler; }
    static void on_error_global(decltype(_error_cb_global) handler) { _error_cb_global = handler; }

    /** Callback to be called on connection instantiation. */
    static void on_construct_global(const std::function<void(connection*)> &handler);
    /** Callback to be called on connection destruction. */
    static void on_destruct_global(const std::function<void(connection*)> &handler);
    /** Single instance-wide callback to be called on connection destruction. */
    void on_destruct(fu2::unique_function<void()> &&handler);

    // ASYNC API
    /**
     * Callback for asking external watcher to wait for specified socket state.
     * Mandatory for async api (including notifications receiving).
     * @param handler functor to be called
     */
    void on_socket_watcher_request(fu2::unique_function<void(int) noexcept> &&handler);

    /** External socket watcher must call this function on ready read state detected. */
    void ready_read_socket();

    /** External socket watcher must call this function on ready write state detected. */
    void ready_write_socket();

    /*  not implemented yet - prefer `tcp_user_timeout` and `keepalives*` connection string options
        https://www.postgresql.org/docs/12/libpq-connect.html#LIBPQ-KEEPALIVES

    /// External timer must call this function when elapsed.
    void timer_elapsed();

    /// Callback for asking external timer to countdown the requested msecs.
    void on_timer_request(decltype(_timer_request_cb) handler) { _timer_request_cb = handler; }
    */

    // async libpq api usage example:
    // https://github.com/markokr/libpq-rowproc-demos/blob/master/demo-onerow-async.c
};

} // namespace pg

#endif // PG_CONNECTION_H
