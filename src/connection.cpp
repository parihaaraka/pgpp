// Copyright (c) 2015-2026 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#include "pgpp/connection.h"
#include "pgpp/query.h"
#include "pgpp/result.h"
#include <exception>
#include <memory>
#include <thread>
#include <cstring>

namespace pg
{

std::unordered_set<connection*> connection::existence_witness{};
std::mutex connection::witness_guard{};

std::function<void(connection*)> connection::_on_construct_global_cb;
std::function<void(connection*)> connection::_on_destruct_global_cb;

std::function<void(
        const connection *cn,
        std::string_view severity,
        std::string_view message,
        std::string_view hint
        )> connection::_notice_cb_global = nullptr;

std::function<void(
        const void *sender,
        std::string_view error,
        const pg::result *res
        )> connection::_error_cb_global = nullptr;

query_error::query_error(std::shared_ptr<pg::result> &res)
    : std::runtime_error(PQresultErrorMessage(res->result_ptr())), _res(res)
{
}

std::shared_ptr<pg::result> query_error::result() const
{
    return _res;
}

connection::connection(std::string_view connection_string) : _current_cs(connection_string)
{
    if (_on_construct_global_cb)
        _on_construct_global_cb(this);
    auto lk = std::lock_guard(witness_guard);
    existence_witness.insert(this);
}

connection::connection(std::string_view connection_string,
                       std::function<void(connection *, std::string &, dbmode)> db_state_detected_cb)
    : connection(connection_string)
{
    if (db_state_detected_cb)
        _db_state_detected_cb = [cb = std::move(db_state_detected_cb), this](auto &&mode)
        { cb(this, _current_cs, std::forward<decltype(mode)>(mode)); };
}

connection::~connection()
{
    disconnect();
    try
    {
        if (_on_destruct_cb)
            _on_destruct_cb();
        else if (_on_destruct_global_cb)
            _on_destruct_global_cb(this);
    }
    catch (const std::exception &e)
    {
        _last_error = e.what();
        handle_error();
    }
    catch (...) {}
    auto lk = std::lock_guard(witness_guard);
    existence_witness.erase(this);
}

void connection::notice_receiver(void *arg, const PGresult *res)
{
    connection *cn = static_cast<connection*>(arg);
    auto severity = pg::severity_eng(res);
    auto msg = pg::primary_message(res);
    auto hint = pg::hint(res);

    // notice handler may be called from another thread, so we shouldn't allow
    // to alter the connections set during its execution

    auto lk = std::lock_guard(witness_guard);
    if (existence_witness.find(cn) == existence_witness.end())
        cn = nullptr;

    if (_notice_cb_global)
        _notice_cb_global(cn, severity, msg, hint);
    if (cn && cn->_q && cn->_q->notice_cb)
        cn->_q->notice_cb(cn, severity, msg, hint);
}

void connection::fetch_notifications()
{
    PGnotify *notify{};
    while ((notify = PQnotifies(_conn)) != nullptr)
    {
        std::unique_ptr<PGnotify, void(*)(void*)> n_guard(notify, PQfreemem);
        if (_notify_cb)
            _notify_cb(n_guard->be_pid, std::string(n_guard->relname), std::string(n_guard->extra));
    }
}

void connection::handle_error(const result *res) noexcept
{
    if (_error_cb)
    {
        try
        {
            _error_cb(this, _last_error, res);
        } catch (...) {}
    }
    else if (_error_cb_global)
    {
        try
        {
            _error_cb_global(this, _last_error, res);
        } catch (...) {}
    }
}

void connection::fetch()
{
    bool is_notification = is_idle();
    do
    {
        _last_action_moment = std::chrono::system_clock::now();
        if (!PQconsumeInput(_conn))
        {
            // dead connection detected (too late to call on_before_disconnect())

            _socket_watcher_request_cb(socket_watch_mode::none);

            // save error message and finalize connection to make closed state available within error handler
            const char *msg = PQerrorMessage(_conn);
            std::string err(msg ? msg : "");
            _temp_result = nullptr;
            PQfinish(_conn);
            _conn = nullptr;
            raise_error(err);

            // we can't reconnect here because a user may try to use the connection
            // while it is in process
            break;
        }

        fetch_notifications();
        if (PQisBusy(_conn) || is_notification)
            break;

        PGresult *tmp_res = PQgetResult(_conn);

        // TODO
        // Implement errors handling (25006, 40001, 40P01) if possible (?)
        // Async query may contain multiple statements, and there is no way to count them
        // or retry only erroneous one.
        // * In case of additional argument to force retry we must handle PQTRANS_INERROR state (?).

        if (!tmp_res)   // query processing finished
        {
            _async_stage = async_stage::none;

            // backup query pointer for callback
            auto q_tmp = _q;

            // clear query object to avoid execution on reconnect
            // and to allow sequental execution via query_finished_async_cb
            if (!_suspended_query && _async_stage == async_stage::none)
            {
                _q = nullptr;
                _socket_watcher_request_cb(_channels.empty() ?
                                               socket_watch_mode::none : socket_watch_mode::read);
            }

            if (q_tmp && q_tmp->query_finished_async_cb)
            {
                try
                {
                    q_tmp->query_finished_async_cb(*this, q_tmp, _last_error);
                } catch (...) {}
            }
            break;
        }

        ExecStatusType status = PQresultStatus(tmp_res);
        if (status == PGRES_COMMAND_OK || status == PGRES_EMPTY_QUERY)
        {
            PQclear(tmp_res);
            _temp_result = nullptr;
            continue;
        }

        if (status == PGRES_COPY_IN)
        {
            _last_error.clear();
            _temp_result = std::make_shared<pg::result>(tmp_res);
            if (send_copy_data())
                return;
            continue;  // error (need to fetch empty resultset)
        }

        // in case of error the result contains error's details,
        // so we want to save it too
        if (!_temp_result)
        {
            // initialize new resultset
            _temp_result = std::make_shared<pg::result>(tmp_res);

            if (status != PGRES_FATAL_ERROR && _q->resultset_started_async_cb)
            {
                try
                {
                    _q->resultset_started_async_cb(*this, *_temp_result);
                } catch (...) {}
            }
        }
        else if (status != PGRES_FATAL_ERROR && PQnfields(tmp_res))
        {
            // append row to resultset
            int current_part_rows = PQntuples(tmp_res);
            int columns_count = PQnfields(tmp_res);
            int last_row_num = _temp_result->row_count();
            for (int r = 0; r < current_part_rows; ++r)
            {
                for (int i = 0; i < columns_count; ++i)
                {
                    if (!PQsetvalue(_temp_result->result_ptr(),
                                    last_row_num,
                                    i,
                                    PQgetvalue(tmp_res, 0, i),
                                    PQgetisnull(tmp_res, 0, i) ? -1 : PQgetlength(tmp_res, 0, i)))
                    { // ?
                        _last_error = PQerrorMessage(_conn);
                        handle_error();
                    }
                }
                ++last_row_num;
            }
            PQclear(tmp_res);
            tmp_res = nullptr;
        }
        else // error while fetching rows
        {
            // main result is the empty one with error,
            // partial_result contains partial result already fetched
            auto _new_temp_result = std::make_shared<pg::result>(tmp_res);
            _new_temp_result->partial_result = _temp_result;
            _temp_result = std::move(_new_temp_result);
        }

        // resultset completely fetched
        if (status == PGRES_FATAL_ERROR || status == PGRES_TUPLES_OK)
        {
            _q->results.push_back(_temp_result);
            if (status == PGRES_FATAL_ERROR) // erroneous resultset
            {
                _last_error = full_message(_temp_result->result_ptr());
                handle_error(_temp_result.get());
            }

            // invalidate intermediate resultset pointer
            _temp_result = nullptr;

            if (_q->resultset_fetched_async_cb && _q->results.back()->column_count())
            {
                try
                {
                    _q->resultset_fetched_async_cb(*this, *_q->results.back());
                } catch (...) {}
            }
            continue;
        }

        if (_q->row_fetched_async_cb)
        {
            try
            {
                _q->row_fetched_async_cb(*this, *_temp_result);
            } catch (...) {}
        }
    }
    while (true);
}

bool connection::ping() noexcept
{
    _last_error.clear();
    bool is_ok = false;

    if (_conn)
    {
        PGresult *res = PQexec(_conn, "select 1");
        is_ok = (res && PQresultStatus(res) == PGRES_TUPLES_OK);
        if (!is_ok)
            _last_error += PQresultErrorMessage(res);
        PQclear(res);
        if (!is_ok)
            disconnect();
    }
    return is_ok;
}

void connection::disconnect(bool call_disconnect_handler) noexcept
{
    if (!_conn)
        return;

    // stop socket watcher
    if (_socket_watcher_request_cb)
        _socket_watcher_request_cb(socket_watch_mode::none);

    if (_before_disconnect_cb && call_disconnect_handler)
    {
        try // go further in any case
        {
            _before_disconnect_cb(*this);
        }
        catch (...) {}
    }
    PQfinish(_conn);
    _conn = nullptr;
}

bool connection::cancel() noexcept
{
    if (!_conn)
        return true;
    char errbuf[256];
    PGcancel *cancel = PQgetCancel(_conn);
    if (!PQcancel(cancel, errbuf, sizeof(errbuf)))
        _last_error = errbuf;
    PQfreeCancel(cancel);
    return _last_error.empty();
}

bool connection::is_idle() const noexcept
{
    // nullptr _conn is ok here
    int status = PQtransactionStatus(_conn);
    return !_conn || status == PQTRANS_IDLE || status == PQTRANS_UNKNOWN;
}

std::chrono::seconds connection::idle_duration()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - _last_action_moment);
}

std::string connection::escape_bytea(const unsigned char *value, size_t size)
{
    if (!_conn)
        return {};
    size_t len{};
    char *data = reinterpret_cast<char*>(PQescapeByteaConn(_conn, value, size, &len)); //NOLINT
    std::string res(data, data + len);
    PQfreemem(data);
    return res;
}

// pay attention the connection must be alive
std::string connection::escape_identifier(std::string_view ident) const
{
    if (!_conn || ident.empty())
        return {};
    char *escaped_identifier = reinterpret_cast<char*>(PQescapeIdentifier(_conn, ident.data(), ident.size())); //NOLINT
    std::string res;
    if (escaped_identifier)
    {
        res = escaped_identifier;
        PQfreemem(escaped_identifier);
    }
    return res;
}

std::string escape_identifier_1b(std::string_view ident)
{
    if (ident.size() > 512)
        throw std::invalid_argument("don't do it");
    char *pos = static_cast<char*>(alloca(ident.size() * 2 + 2));
    char *begin = pos;
    *pos++ = '"';
    for (auto c: ident)
    {
        *pos++ = c;
        if (c == '"')
            *pos++ = c;
        else if (static_cast<unsigned char>(c) & 0x80)
            throw std::runtime_error("unsupported character, use `pg::connection::escape_identifier()` instead");
    }
    *pos++ = '"';
    return {begin, static_cast<size_t>(pos - begin)};
}

std::string escape_bytea(const unsigned char *value, size_t size)
{
    size_t len{};
    char *data = reinterpret_cast<char*>(PQescapeBytea(value, size, &len)); //NOLINT
    std::string res(data, data + len);
    PQfreemem(data);
    return res;
}

std::vector<unsigned char> unescape_bytea(const char *value)
{
    size_t len{};
    unsigned char *data = PQunescapeBytea(reinterpret_cast<const unsigned char*>(value), &len); //NOLINT
    std::vector<unsigned char> res(data, data + len);
    PQfreemem(data);
    return res;
}

std::string encrypt_password(const std::string &password, const std::string &user)
{
    char *raw_enc_pwd = PQencryptPassword(password.c_str(), user.c_str());
    std::string enc_pwd;
    if (raw_enc_pwd)
    {
        enc_pwd = raw_enc_pwd;
        PQfreemem(raw_enc_pwd);
    }
    return enc_pwd;
}

void connection::raise_error(const std::shared_ptr<pg::result> &res) noexcept
{
    _async_stage = async_stage::none;
    if (_socket_watcher_request_cb)
    {
        _socket_watcher_request_cb(is_connected() && !_channels.empty() ?
                                       socket_watch_mode::read :
                                       socket_watch_mode::none);
    }
    handle_error(res.get());

    // clear query object to avoid execution on reconnect
    // and to allow sequental execution via query_finished_async_cb
    auto q_tmp = std::move(_q);
    if (q_tmp && q_tmp->query_finished_async_cb)
    {
        try
        {
            q_tmp->query_finished_async_cb(*this, q_tmp, _last_error);
        } catch (...) {}
    }
}

void connection::raise_error(const std::string &error, const std::shared_ptr<pg::result> &res) noexcept
{
    _last_error = error;
    raise_error(res);
}

void connection::on_async_connected()
{
    // set notice and warning messages handler
    PQsetNoticeReceiver(_conn, notice_receiver, this);
    // prevent PQsendQuery to block execution
    PQsetnonblocking(_conn, 1);

    _socket_watcher_request_cb(socket_watch_mode::none);
    if (!_channels.empty())
    {
        // _connected_cb() inside
        async_restore_listen_channels();
        return;
    }

    auto prev_q = _q;
    // callback on successful connection
    if (_connected_cb)
        _connected_cb(*this);

    // if the callback has not changed current query, then
    // restore previous state as usual
    if (prev_q == _q && _q)
        exec_async(_q);
}

void connection::async_connection_proceed()
{
    PostgresPollingStatusType state = PQconnectPoll(_conn);
    switch (state)
    {
    case PGRES_POLLING_READING:
        _socket_watcher_request_cb(socket_watch_mode::read);
        break;
    case PGRES_POLLING_WRITING:
        _socket_watcher_request_cb(socket_watch_mode::write);
        break;
    case PGRES_POLLING_FAILED: // connection failed
    {
        _socket_watcher_request_cb(socket_watch_mode::none);
        std::string error = PQerrorMessage(_conn);

        // prev comment here (why?!): "do not release _conn here to avoid error 'connection pointer is NULL'"
        PQfinish(_conn);
        _conn = nullptr;

        _async_stage = async_stage::none;
        if (_db_state_detected_cb)
        {
            //string prev_cs = _current_cs;
            _db_state_detected_cb(dbmode::na);
            if (!_current_cs.empty())// && prev_cs != _current_cs)
            {
                _async_stage = async_stage::none;
                connect_async();
                break;
            }
        }
        raise_error(error);
        break;
    }
    default:    // PGRES_POLLING_OK
        // successful connection
        _async_stage = async_stage::none;
        if (_db_state_detected_cb)
            async_validate_rw_mode();
        else
            on_async_connected();
    }
}

void connection::async_validate_rw_mode()
{
    if (_q)
        _suspended_query = std::move(_q);
    _q = std::make_shared<query>();
    *_q = "select pg_is_in_recovery()::int::text";
    _q->query_finished_async_cb = [](connection &cn, std::shared_ptr<query> &q, const std::string &error)
    {
        std::string prev_cs = cn._current_cs;
        if (cn._db_state_detected_cb)
        {
            if (!q || !error.empty()) // connection has been broken just before PQexec?!
            {
                cn._db_state_detected_cb(dbmode::na);
            }
            else
            {
                bool is_writable = (q->results.back()->raw_value(0, 0)[0] == '0');
                cn._db_state_detected_cb(is_writable ? dbmode::rw : dbmode::ro);
            }
        }

        // restore suspended (initial) query
        cn._q = std::move(cn._suspended_query);
        if (prev_cs == cn._current_cs) // ok
        {
            cn.on_async_connected();
            return;
        }

        cn.disconnect(false);
        cn._async_stage = async_stage::none;
        if (cn._current_cs.empty())
            cn.raise_error("pgdb: incompatible access mode\n", nullptr);
        else // reconnect
            cn.connect_async();
    };
    exec_async(_q);
}

void connection::async_restore_listen_channels()
{
    if (_q)
        _suspended_query = std::move(_q);
    _q = std::make_shared<query>();
    for (std::string &ch : _channels)
        _q->query_string += "LISTEN " + ch + ';';
    _q->query_finished_async_cb = [](connection &cn, std::shared_ptr<query>&, const std::string &err)
    {
        auto prev_q = cn._q;
        if (err.empty())
        {
            // callback on successful connection
            if (cn._connected_cb)
                cn._connected_cb(cn);

            // it looks like a caller initiated a new request
            if (prev_q != cn._q)
            {
                cn._suspended_query.reset();
                return;
            }
        }

        // restore suspended (initial) query
        cn._q = std::move(cn._suspended_query);
        if (cn._q) // run initial query
            cn.exec_async(cn._q); // entire cycle will start (reconnect and so on) in case of error
        else
            cn._socket_watcher_request_cb(socket_watch_mode::read);
    };
    exec_async(_q);
}

bool connection::send_copy_data()
{
    if (!_q || !_q->copy_in_cb)
    {
        _copy_in_done = true;
    }
    else
    {
        auto get_more_data = [this]() -> bool
        {
            try
            {
                _copy_in_done = _q->copy_in_cb(_copy_in_buf);
            }
            catch (const std::exception &e)
            {
                _copy_in_buf.clear();
                _temp_result.reset();
                _copy_in_done = false;
                // init server-side error
                _copy_end_error = std::string("client-side error:\n") + e.what();
                _async_stage = async_stage::put_copy_end;
                ready_write_socket();
                return false;
            }
            return true;
        };

        if (!_copy_in_done && _copy_in_buf.empty() && !get_more_data())
            return true; // copy_in_cb error -> do not fetch right now (sending end of data marker)

        while (!_copy_in_buf.empty())
        {
            auto res = PQputCopyData(_conn, _copy_in_buf.data(), static_cast<int>(_copy_in_buf.size()));
            if (res < 0)
            {
                _copy_in_buf.clear();
                _temp_result.reset();
                _copy_in_done = false;
                _last_error = PQerrorMessage(_conn);
                handle_error();
                return false;
            }

            if (res == 0)
            {
                _socket_watcher_request_cb(socket_watch_mode::write);
                return true;
            }

            _copy_in_buf.clear();
            if (!get_more_data())
                return true;
        }
    }

    if (_copy_in_done)
    {
        _copy_end_error.clear();
        _async_stage = async_stage::put_copy_end;
        ready_write_socket();
    }
    return true;
}

void connection::on_construct_global(const std::function<void(connection*)> &handler)
{
    _on_construct_global_cb = handler;
}

void connection::on_destruct_global(const std::function<void(connection*)> &handler)
{
    _on_destruct_global_cb = handler;
}

void connection::on_destruct(fu2::unique_function<void()> &&handler)
{
    _on_destruct_cb = std::move(handler);
}

void connection::on_socket_watcher_request(fu2::unique_function<void(int) noexcept> &&handler)
{
    _socket_watcher_request_cb = std::move(handler);
}

void connection::connect_async() noexcept
{
    // NB: on_connected callback will not be called if the connection is already established

    if (_async_stage != async_stage::none || !is_idle())
    {
        int status = PQtransactionStatus(_conn);
        raise_error("pgdb: connection busy - unable to execute connect_async()\n"
                    "status: " + std::to_string(status) + "\n");
        return;
    }

    if (!_q) // standalone connect (not because of query execution)
    {
        _last_error.clear();
        _last_action_moment = std::chrono::system_clock::now();
    }

    // if current connection is actually broken, the further query will detect it and will try to reconnect
    // (but it may looks like ok here)
    if (_conn)
    {
        if (PQstatus(_conn) == CONNECTION_OK) // already connected -
            return;                           // silent exit !!!
        disconnect(PQtransactionStatus(_conn) != PQTRANS_UNKNOWN);
    }

    // could be initial state
    if (_current_cs.empty())
    {
        if (_db_state_detected_cb)
        {
            try
            {
                _db_state_detected_cb(dbmode::na);
            }
            catch (...)
            {
                _current_cs.clear();
            }
        }
        if (_current_cs.empty())
        {
            raise_error("pgdb: connection string unavailable\n");
            return;
        }
    }

    time(&_connection_start_moment);
    _last_try = _connection_start_moment;

    _conn = PQconnectStart(_current_cs.c_str());
    if (PQstatus(_conn) == CONNECTION_BAD)
    {
        // connection failed
        raise_error(PQerrorMessage(_conn));
        if (_conn)
        {
            PQfinish(_conn);
            _conn = nullptr;
        }
        return;
    }
    _async_stage = async_stage::connecting;

    _socket_watcher_request_cb(socket_watch_mode::write);
}

void connection::exec_async(std::shared_ptr<query> q) noexcept
{
    // do not change current query state
    auto safe_raise = [this, &q](const std::string& error)
    {
        _last_error = error;
        handle_error();
        if (q && q->query_finished_async_cb)
        {
            try
            {
                q->query_finished_async_cb(*this, q, error);
            } catch (...) {}
        }
    };


    // save transaction status to avoid reconnects within transaction
    PGTransactionStatusType initial_state = PQtransactionStatus(_conn);
    if (initial_state == PQTRANS_ACTIVE)
    {
        safe_raise("pgdb: another command is already in progress\n");
        return;
    }

    if (!_socket_watcher_request_cb)
    {
        safe_raise("pgdb: socket watcher request callback must be set to operate asynchronously\n");
        return;
    }

    bool was_in_transaction = (initial_state == PQTRANS_INTRANS);
    _async_stage = async_stage::sending_query;
    q->results.clear();
    _q = q;

    _last_error.clear();
    int async_sent_ok = 0;
    if (_conn)
    {
        if (_q->params.count())
        {
            async_sent_ok = PQsendQueryParams(_conn,
                                              _q->query_string.c_str(),
                                              static_cast<int>(_q->params.count()),
                                              nullptr,
                                              _q->params.values(),
                                              _q->params.lengths(),
                                              nullptr,
                                              0);
            if (async_sent_ok)
                PQsetSingleRowMode(_conn);
        }
        else
        {
            async_sent_ok = PQsendQuery(_conn, _q->query_string.c_str());
            if (async_sent_ok)
                PQsetSingleRowMode(_conn);
        }
        _last_action_moment = std::chrono::system_clock::now();
    }

    // disconnected or connection broken => reconnect and try again
    if (PQstatus(_conn) == CONNECTION_BAD)
    {
        _last_error = PQerrorMessage(_conn);
        disconnect();
        _async_stage = async_stage::none;
        if (was_in_transaction)
        {
            raise_error("pgdb: connection broken, transaction terminated\n");
            return;
        }

        connect_async();
        return;
    }

    if (async_sent_ok)
    {
        _async_stage = async_stage::flush;
        int res = PQflush(_conn);
        if (res < 0)    // error
        {
            _async_stage = async_stage::none;
            _socket_watcher_request_cb(socket_watch_mode::read);
        }
        else
        {
            if (!res)
            {
                _async_stage = async_stage::wait_ready_read;
                _socket_watcher_request_cb(socket_watch_mode::read);
            }
            else
            {
                _socket_watcher_request_cb(socket_watch_mode::read_write);
            }
            return;
        }
    }
    raise_error(PQerrorMessage(_conn));
}

bool connection::connect(unsigned int connect_timeout_sec)
{
    _last_error.clear();
    _last_action_moment = std::chrono::system_clock::now();

    // if current connection is actually broken, the further query will detect it and will try to reconnect
    // (but it may looks like ok here)
    if (_conn)
    {
        if (PQstatus(_conn) == CONNECTION_OK)
            return true;
        disconnect();
    }

    // could be initial state
    if (_current_cs.empty())
    {
        if (_db_state_detected_cb)
            _db_state_detected_cb(dbmode::na);
        if (_current_cs.empty())
        {
            _last_error = "connection string unavailable\n";
            return false;
        }
    }

    auto current_time = []() ->std::string
    {
        std::chrono::high_resolution_clock::time_point p = std::chrono::high_resolution_clock::now();
        std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(p.time_since_epoch());
        std::chrono::seconds sec = std::chrono::duration_cast<std::chrono::seconds>(ms);
        time_t t = sec.count();
        auto fractional_seconds = ms.count() % 1000;
        tm timeinfo{};
#ifdef WIN32
        localtime_s(&timeinfo, &t);
#else
        localtime_r(&t, &timeinfo);
#endif
        char buffer[32];
        size_t len = strftime(buffer, 32, "%H:%M:%S", &timeinfo); //%Y-%m-%d
        len += sprintf(buffer + len, ".%03ld", fractional_seconds);
        return {buffer, len};
    };

    std::vector<std::pair<std::string, std::string>> errors;
    auto push_error = [this, &errors, &current_time](std::string_view err)
    {
        if (err.empty())
            return;
        char *host = PQhost(_conn);
        char *port = PQport(_conn);

        std::stringstream ss;
        ss << "error connecting to ";
        if (host)
            ss << host << (*host == '/' ? "/<unix socket>." : ":") << (port ? port : "unknown");
        else
            ss << "database";
        ss << ":" << std::endl << err;
        if (!errors.empty() && errors.back().second == ss.str())
        {
            errors.back().first = current_time();
            return;
        }
        errors.push_back({current_time(), ss.str()});
    };

    time_t start_moment{};
    time(&start_moment);
    time_t last_try = start_moment;
    std::string prev_cs = "foo";
    do
    {
        if (time(nullptr) - last_try < 1 && (prev_cs == _current_cs || _current_cs.empty()))
            std::this_thread::sleep_for(std::chrono::seconds(1));
        time(&last_try);

        if (_current_cs.empty())
        {
            _db_state_detected_cb(dbmode::na);
            if (_current_cs.empty())
            {
                push_error("suitable db node not found");
                continue;
            }
        }

        _conn = PQconnectdb(_current_cs.c_str());
        prev_cs = _current_cs;
        if (PQstatus(_conn) == CONNECTION_OK)
        {
            if (_db_state_detected_cb)
            {
                // check db access mode
                PGresult *res = PQexec(_conn, "select pg_is_in_recovery()::int::text");
                if (res && PQresultStatus(res) == PGRES_TUPLES_OK)
                {
                    bool is_writable = (*PQgetvalue(res, 0, 0) == '0');
                    PQclear(res);

                    _db_state_detected_cb(is_writable ? dbmode::rw : dbmode::ro);
                    if (prev_cs == _current_cs) // ok
                        break;

                    push_error("incompatible access mode\n");
                    disconnect();
                }
                else // connection has been broken just before PQexec?!
                {
                    if (res)
                        push_error(pg::primary_message(res));
                    else
                    {
                        auto *err = PQerrorMessage(_conn);
                        push_error(err ? std::string_view{err} : std::string_view{});
                    }
                    PQclear(res);
                    disconnect();
                    _db_state_detected_cb(dbmode::na);
                }
            }
        }
        else
        {
            // man: "...a nonempty PQerrorMessage result can consist of multiple lines, and will include a trailing newline.
            // The caller should not free the result directly."
            push_error(PQerrorMessage(_conn));
            PQfinish(_conn);
            _conn = nullptr;
            if (_db_state_detected_cb)
                _db_state_detected_cb(dbmode::na);
        }
    }
    while (PQstatus(_conn) != CONNECTION_OK &&
        time(nullptr) - start_moment < connect_timeout_sec); // retry during <connect_timeout_sec> seconds (e.g. wait for restart to finish)

    // update after possibly slow connection
    _last_action_moment = std::chrono::system_clock::now();

    // connection failed
    if (!_conn)
    {
        if (!errors.empty())
        {
            for(auto const &e: errors)
                _last_error += e.first + ": " + e.second;
            handle_error();
        }
        return false;
    }

    // set notice and warning messages handler
    PQsetNoticeReceiver(_conn, notice_receiver, this);
    PQsetnonblocking(_conn, 1);

    // subscribe to notifications
    if (!_channels.empty())
        listen(_channels);

    // callback on successful connection
    if (_connected_cb)
        _connected_cb(*this);

    return true;
}

bool connection::exec(query &q, bool throw_on_error, unsigned int connect_timeout_sec)
{
    auto raise_error = [this, throw_on_error](std::string_view error, std::shared_ptr<pg::result> res = {})
    {
        _last_error = error;
        handle_error(res.get());
        if (throw_on_error)
        {
            if (res)
                throw query_error(res);
            throw std::runtime_error(_last_error);
        }
    };

    // save transaction status to avoid reconnects within transaction
    PGTransactionStatusType initial_state = PQtransactionStatus(_conn);
    if (initial_state == PQTRANS_ACTIVE)
    {
        raise_error("pgdb: another command is already in progress\n");
        return false;
    }

    bool was_in_transaction = (initial_state == PQTRANS_INTRANS);
    q.results.clear();
    // suspend external socket watcher
    if (_socket_watcher_request_cb)
        _socket_watcher_request_cb(socket_watch_mode::none);

    // ***** DIRTY HACK to grant existence of _q to call it's notice handler
    _q = std::shared_ptr<query>(&q, [](query*) { /* do nothing */ });
    // finally we will fix it *****
    std::unique_ptr<query, std::function<void(query*)>> cur_query_guard(&q, [this](query*) { _q.reset(); });

    do
    {
        _last_error.clear();
        PGresult *tmp_res = nullptr;
        if (_conn)
        {
            if (q.params.count())
            {
                tmp_res = PQexecParams(_conn,
                                       q.query_string.c_str(),
                                       static_cast<int>(q.params.count()),
                                       nullptr,
                                       q.params.values(),
                                       q.params.lengths(),
                                       nullptr,
                                       0);
            }
            else
            {
                tmp_res = PQexec(_conn, q.query_string.c_str());
            }
            _last_action_moment = std::chrono::system_clock::now();
        }

        // disconnected or connection broken => reconnect and try again
        if (PQstatus(_conn) == CONNECTION_BAD)
        {
            _last_error = PQerrorMessage(_conn);
            disconnect();
            if (was_in_transaction || !connect(connect_timeout_sec))
            {
                if (throw_on_error)
                    throw std::runtime_error(_last_error);
                return false;
            }
            continue;
        }

        auto result = std::make_shared<pg::result>(tmp_res);
        fetch_notifications();

        ExecStatusType status = PQresultStatus(tmp_res);
        if (status > PGRES_COPY_IN) // errors
        {
            if (!was_in_transaction && tmp_res)
            {
                _last_error = result->full_message();
                std::string_view state = result->state();
                // read_only_sql_transaction
                if (state == "25006" && _db_state_detected_cb)
                {
                    // try to get another connection string
                    // (this error means requested rw mode, so pooler must rethink the connection string)
                    _db_state_detected_cb(dbmode::ro);
                    if (!_current_cs.empty())
                    {
                        handle_error(result.get());
                        disconnect();
                        // reconnect and try again
                        continue;
                    }
                }
                // deadlock_detected | serialization_failure
                else if (state == "40P01" || state == "40001")
                {
                    handle_error(result.get());
                    continue;
                }
            }

            // restore watching socket to receive notifications
            if (_socket_watcher_request_cb && !_channels.empty())
                _socket_watcher_request_cb(socket_watch_mode::read);
            if (tmp_res)
            {
                q.results.push_back(result); // error details
                raise_error(pg::full_message(tmp_res), result);
            }
            else
                raise_error(PQerrorMessage(_conn));
            return false;
        }

        if (status != PGRES_EMPTY_QUERY)
            q.results.push_back(result);

        // restore watching socket to receive notifications
        if (_socket_watcher_request_cb && !_channels.empty())
            _socket_watcher_request_cb(socket_watch_mode::read);
        break;
    }
    while (true);

    return true;
}

std::shared_ptr<pg::result> connection::exec(const std::string &query_string, const params *p,
                                             bool throw_on_error, unsigned int connect_timeout_sec)
{
    query q;
    q = query_string;
    if (p)
        q.params = *p;
    exec(q, throw_on_error, connect_timeout_sec);
    if (q.results.empty())
        return nullptr;
    return q.results.back();
}

bool connection::put_copy_data(const char *buffer, int nbytes, bool throw_on_error)
{
    _last_error.clear();
    // PQputCopyData returns 0 (could not queue the termination message because of full buffers)
    // only in nonblocking mode
    if (PQputCopyData(_conn, buffer, nbytes) < 0)
    {
        _last_error = PQerrorMessage(_conn);
        handle_error();

        if (throw_on_error)
            throw std::runtime_error(_last_error);
        return false;
    }
    return true;
}

std::unique_ptr<pg::result> connection::stop_copy_in(const char *stop_reason)
{
    _last_error.clear();
    // PQputCopyEnd returns 0 (could not queue the termination message because of full buffers)
    // only in nonblocking mode
    if (PQputCopyEnd(_conn, stop_reason) < 0)
    {
        _last_error = PQerrorMessage(_conn);
        handle_error();
        return nullptr;
    }

    // Acquire PGresult. We must call PQgetResult until nullptr returned.
    // All hope that we will get a single PGresult because we can do nothing with other PGresults.
    auto res = std::unique_ptr<pg::result>(new pg::result(PQgetResult(_conn)));
    while (PGresult *tmp_res = PQgetResult(_conn))
        PQclear(tmp_res);
    return res;
}

std::unique_ptr<pg::result> connection::on_get_copy_data(std::function<bool(const char *, int)> &fetch_cb) noexcept
{
    _last_error.clear();
    char *buf{};
    int len{};
    int stop_stage{};
    while (true)
    {
        len = PQgetCopyData(_conn, &buf, false);
        if (buf && len >= 0)
        {
            std::unique_ptr<char, void(*)(void*)> buf_guard(buf, PQfreemem);
            if (stop_stage == 1)
            {
                // try to cancel fetching (result will be in PGRES_FATAL_ERROR state)
                cancel();
                ++stop_stage;
            }

            if (len > 0 && !stop_stage)
            {
                try
                {
                    if (!fetch_cb(buf, len))
                        ++stop_stage;
                }
                catch (const std::runtime_error &e)
                {
                    _last_error = e.what();
                    ++stop_stage;
                }
                catch (...)
                {
                    ++stop_stage;
                }
            }
        }

        if (len < 0)
            break;
    }

    if (len == -2)
    {
        _last_error = PQerrorMessage(_conn);
        handle_error();
        return nullptr;
    }

    // Acquire PGresult. We must call PQgetResult until nullptr returned.
    // All hope that we will get a single PGresult because we can do nothing with other PGresults.
    std::unique_ptr<pg::result> res;
    try
    {
        res = std::make_unique<pg::result>(PQgetResult(_conn));
    }
    catch (const std::exception &e)
    {
        _last_error = e.what();
        handle_error();
        return nullptr;
    }
    while (PGresult *tmp_res = PQgetResult(_conn))
        PQclear(tmp_res);
    return res;
}

int connection::socket() const noexcept
{
    return _conn ? PQsocket(_conn) : -1;
}

void connection::listen(const std::vector<std::string> &channels)
{
    _channels = channels;
    if (_conn)
    {
        std::string q = "UNLISTEN *;";
        for (std::string &ch : _channels) q += "LISTEN " + ch + ';';
        if (_socket_watcher_request_cb)
            _socket_watcher_request_cb(socket_watch_mode::none);
        exec(q, nullptr, false);
        if (_socket_watcher_request_cb)
            _socket_watcher_request_cb(_channels.empty() ?
                                           socket_watch_mode::none : socket_watch_mode::read);
    }
}

void connection::ready_read_socket()
{
    if (_async_stage == async_stage::connecting)
    {
        async_connection_proceed();
        return;
    }

    if (_async_stage == async_stage::flush) // sending query to a server
    {
        if (PQconsumeInput(_conn))
        {
            ready_write_socket();
            return;
        }
        _last_error = PQerrorMessage(_conn);
        handle_error();
        _async_stage = async_stage::none;
        _socket_watcher_request_cb(socket_watch_mode::read);
    }
    // async query is fetching result or notification received
    else if (_async_stage == async_stage::wait_ready_read || is_idle())
    {
        fetch();
    }
}

void connection::ready_write_socket()
{
    if (_async_stage == async_stage::connecting)
    {
        async_connection_proceed();
        return;
    }

    if (_async_stage == async_stage::put_copy_end)
    {
        _last_error.clear();
        auto res = PQputCopyEnd(_conn, _copy_end_error.empty() ? nullptr : _copy_end_error.c_str());
        if (res < 0)
        {
            _copy_in_done = false;
            _temp_result.reset();

            _last_error = PQerrorMessage(_conn);
            handle_error();
            _async_stage = async_stage::none;
            fetch();
            return;
        }

        if (res > 0)
            _async_stage = async_stage::flush;
        // man:
        // If the value is zero, wait for write-ready and try again.
        _socket_watcher_request_cb(socket_watch_mode::write);
        return;
    }

    if (_async_stage == async_stage::flush)
    {
        int res = PQflush(_conn);
        if (res < 0)    // error
            _async_stage = async_stage::none;
        else
        {
            if (!res)
            {
                if (_copy_in_done)
                {
                    _copy_in_done = false;
                    _temp_result.reset();
                }
                _async_stage = async_stage::wait_ready_read;
                _socket_watcher_request_cb(socket_watch_mode::read);
                return;
            }
            // current mode is rw
            return;
        }
        _last_error = PQerrorMessage(_conn);
        handle_error();
        _async_stage = async_stage::none;
    }
    else if (_temp_result && _temp_result->copy_in_ready())
    {
        send_copy_data();
    }

    _socket_watcher_request_cb(socket_watch_mode::read);
}

} // namespace pg
