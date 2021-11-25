#include <ev.h>
#include "pgpp/dbpool.h"
#include "pgpp/connection.h"
#include "pgpp/query.h"
#include "pgpp/result.h"
#include <iostream>
#include <string.h>
#include <fstream>

using namespace std;

static shared_ptr<pg::connection> _cn;
static ev_io _db_connection_watcher;
static ev_async _reinit_db_guard_watcher;
static ev_signal _term_signal_watcher;
static struct ev_loop *_loop;

//static ev::io _db_connection_watcher;
//static ev::async _reinit_db_guard_watcher;
//static ev::sig _term_signal_watcher;

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

#define CLEAR "\033[2J"  // clear screen escape code

string currentTime()
{
    chrono::high_resolution_clock::time_point p = chrono::high_resolution_clock::now();
    chrono::milliseconds ms = chrono::duration_cast<chrono::milliseconds>(p.time_since_epoch());
    chrono::seconds sec = chrono::duration_cast<chrono::seconds>(ms);
    time_t t = sec.count();
    int fractional_seconds = ms.count() % 1000;

    char buffer[32];
    strftime(buffer, 32, "%H:%M:%S", localtime(&t)); //%Y-%m-%d
    sprintf(buffer + strlen(buffer), ".%03d: ", fractional_seconds);
    return string(buffer);
}

static void socket_event_cb(struct ev_loop *, ev_io *w, int revents)
{
    pg::connection *cn = static_cast<pg::connection*>(w->data);
    if (revents & EV_WRITE)
        cn->ready_write_socket();
    if (revents & EV_READ)
        cn->ready_read_socket();
}

void reinit_db_cb(struct ev_loop *loop, ev_async *, int)
{
    cout << BOLDWHITE << "### DB REINIT..." << RESET << endl;
    if (_cn)
    {
        if (!_cn->is_idle())
            throw runtime_error("wtf? current connection is active!");
        // old connection will get back to the pool so make it clean
        _cn->disconnect();
        _cn->on_socket_watcher_request({});
        _cn->on_connected(nullptr);
        _cn->on_before_disconnect(nullptr);
        _cn->on_notify(nullptr);
        _cn->listen({});
    }
    // replace connection with new one
    _cn = dbpool<pg::connection>::get()->get_connection(true);
    _db_connection_watcher.data = _cn.get();
    _cn->disconnect(); // to fire on_connected
    _cn->listen({"job_ready", "telegram"});

    _cn->on_notify([](int, const std::string &channel, const std::string &payload)
    {
        cout << currentTime() << "! notification received: " <<
                BOLDGREEN << channel << " (" << payload << ")" << RESET << endl;
    });

    _cn->on_notice_global([](const pg::connection &, std::string_view severity, std::string_view message, std::string_view hint)
    {
        cout << currentTime() << "! notice received: " << BOLDGREEN << severity << ": " << message;
        if (!hint.empty())
             cout << "(HINT: " << hint << ")";
        cout << RESET << endl;
    });

    _cn->on_before_disconnect([](const pg::connection &)
    {
        cout << currentTime() << "on_before_disconnect" << endl;
    });

    _cn->on_error([](const void *, std::string_view error, const pg::result *res)
    {
        cout << currentTime() << RED << error << MAGENTA;
        if (res && res->partial_result)
        {
            cout << "partial result contains " << res->partial_result->row_count() << " rows" << endl << endl;
        }
        cout << RESET;
    });

    _cn->on_socket_watcher_request([](int mode) noexcept
    {
        int events =
                (mode & pg::socket_watch_mode::read  ? EV_READ  : 0) |
                (mode & pg::socket_watch_mode::write ? EV_WRITE : 0);
        cout << "# socket watch mode: " <<
                (mode & pg::socket_watch_mode::read ? "R" : "") <<
                (mode & pg::socket_watch_mode::write ? "W" : "") <<
                (mode ? "" : "none") << endl;
        if (ev_is_active(&_db_connection_watcher))
        {
             if ((_db_connection_watcher.events & (EV_READ | EV_WRITE)) == events)
                 return;
             ev_ref(_loop);
             ev_io_stop(_loop, &_db_connection_watcher);
        }
        if (!events)
            return;

        ev_io_set(&_db_connection_watcher, _cn->socket(), events);
        ev_io_start(_loop, &_db_connection_watcher);
        ev_unref(_loop);
    });

    _cn->on_connected([](const pg::connection &)
    {
        cout << currentTime() << "on_connected" << endl;
    });

    //cout << currentTime() << "connecting..." << endl;
    //cn->connect();
}

shared_ptr<pg::query> create_query()
{
    auto qobj = make_shared<pg::query>();

    qobj->resultset_started_async_cb = [](const pg::connection &, pg::result &res)
    {
        cout << currentTime() << BOLDYELLOW << ">>> resultset started: ";
        for (int i = 0; i < res.column_count(); ++i)
            cout << res.column_name(i) << "; ";
        cout << RESET << endl;
    };

    qobj->row_fetched_async_cb = [](const pg::connection &, pg::result &res)
    {
        cout << BLUE << "> ";
        int rownum = res.row_count() - 1;

        for (int j = 0; j < res.column_count(); ++j)
            cout << res.raw_value(rownum, j) << "; ";
        cout << RESET << endl;
    };

    qobj->resultset_fetched_async_cb = [](const pg::connection &, pg::result &res)
    {
        cout << currentTime() << GREEN << "resultset fetched, rows: " << res.row_count() << RESET << endl << endl;
    };

    qobj->query_finished_async_cb = [](pg::connection &, std::shared_ptr<pg::query> , const std::string &)
    {
        cout << currentTime() << BOLDCYAN << "query finished" << RESET << endl;
        ev_signal_stop(_loop, &_term_signal_watcher);
        cout << currentTime() << "SIGTERM watcher stopped" << endl;
    };

    return qobj;
}

static void timer_cb(struct ev_loop *loop, ev_timer *w, int)
{
    if (!_cn->is_idle())
    {
        cout << currentTime() << "db connection is busy -> delay for 500 msec" << endl;
        w->repeat = 0.5;
    }
    else
    {
        auto qobj = create_query();
        qobj->query_string = *static_cast<const string*>(w->data);

        qobj->query_finished_async_cb = [loop](pg::connection &, std::shared_ptr<pg::query> , const std::string &)
        {
            cout << currentTime() << BOLDCYAN << "query finished" << RESET << endl;

            static int count = 0;
            if (++count == 1)   // reinit test
                ev_async_send(loop, &_reinit_db_guard_watcher);

            // stop after specified retries without SIGTERM
            // (event loop terminates on last watcher stop)
            if (count == 2)
            {
                ev_signal_stop(loop, &_term_signal_watcher);
                cout << currentTime() << "SIGTERM watcher stopped" << endl;
            }

        };

        cout << currentTime() <<
                BOLDCYAN <<
                "starting async query (" << qobj->query_string.size() << " bytes long)..." <<
                RESET << endl;
        _cn->exec_async(qobj);
        w->repeat = 2;
    }

    ev_timer_again(loop, w); // restart timer with new settings
    //ev_ref(loop); ev_timer_stop(loop, w);
}

int main(int argc, char *argv[])
{
    const char *cs = (argc > 1 ? argv[1] : "user=postgres port=5432 connect_timeout=5");
    dbpool<pg::connection>::get()->set_connection_strings({cs});
    _loop = EV_DEFAULT;
    ev_init(&_db_connection_watcher, socket_event_cb);

    // copy to
    {
        string r1fetched;
        int i = 0;
        cout << currentTime() << "started" << endl;
        auto qobj = create_query();
        qobj->query_string = "copy (select * from pg_class) to stdout with (delimiter ',', format csv, header)";
        reinit_db_cb(nullptr, nullptr, 0);
        try
        {
            std::ofstream outfile("/tmp/query_res.csv", std::ofstream::binary|std::ofstream::trunc);
            if (!outfile)
            {
                cout << strerror(errno) << endl;
            }
            else if (_cn->exec(*qobj.get()) && qobj->results.back()->copy_out_ready())
            {
                auto res = _cn->on_get_copy_data([&](const char *buf, int nbytes) -> bool
                {
                    if (!i)
                        r1fetched = currentTime();
                    ++i;
                    cout << buf;
                    outfile.write(buf, nbytes);

                    // test COPY TO cancellation by exception
                    if (i > 50)
                        throw runtime_error("my exception");

                    // will get 100 rows max
                    return i < 100;
                });

                if (res && !*res)
                    cout << res->full_message() << endl
                         << "last error: " << _cn->last_error() << endl;
            }

        }
        catch (const std::exception &e)
        {
            cout << e.what() << endl;
        }
        cout << "first row fetched: " << r1fetched << endl
             << "total rows: " << i << endl;
    }


/*
    auto qobj = create_query();
    qobj->query_string.swap(q);
    _term_signal_watcher.start(SIGTERM);
    reinit_db_cb(nullptr, nullptr, 0);
    qobj->query_finished_async_cb = [](pg::connection &cn, std::shared_ptr<pg::query> q, const std::string &error)
    {
        cout << currentTime() << BOLDCYAN << "query finished" << RESET << endl;
        cn.disconnect();
        q->query_string = "select * from pg_stat_activity";
        q->query_finished_async_cb = [](pg::connection &cn, std::shared_ptr<pg::query> q, const std::string &error)
        {
            cout << currentTime() << BOLDCYAN << "query finished" << RESET << endl;
            _term_signal_watcher.stop();
            cout << currentTime() << "SIGTERM watcher stopped" << endl;
        };
        cn.exec_async(q);
    };

    cout << currentTime() << BOLDCYAN << "starting async query" << RESET << endl;
    _cn->exec_async(qobj);
    _loop.run();
    return 0;
*/


    // long asynchronous query

    string q = R"(
begin;
select table_name, table_type from information_schema.tables limit 5;
select pg_is_in_recovery()::int, 'test';
-- NOTIFY will not be sent to client without explicit transaction
-- (otherwize the whole batch executes within single transaction,
--  and final division by zero prevents notification from being sent)
notify telegram, 'notification from successful transaction';
do $$ begin raise notice 'notice from successful transaction'; end $$;
select pg_sleep(3), 'slept for 3 sec';
commit;
notify telegram, 'should not see this message';
do $$ begin raise notice 'notice from terminated transaction'; end $$;
select x, y, z, z/(z - 5)
from (values
               )";
    // large query to verify sending in parts
    for (int i = 0; i < 8192; i++)
        q += "('qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm', '01234567890123456789', " + std::to_string(i)+ "),"
             "('01234567890123456789', 'qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm', null),\n";
    q += R"(
('last', 'row', 0)) as long_query(x, y, z)
         )";

    ev_signal_init(&_term_signal_watcher, [](struct ev_loop *loop, ev_signal *w, int)
    {
        ev_signal_stop(loop, w);
        cout << currentTime() << "SIGTERM watcher stopped" << endl;
    }, SIGTERM);
    ev_signal_start(_loop, &_term_signal_watcher);

    ev_timer periodic_timer;
    ev_timer_init(&periodic_timer, timer_cb, 0, 0);
    periodic_timer.data = &q;
    ev_timer_start(_loop, &periodic_timer);
    ev_unref(_loop);

    ev_async_init(&_reinit_db_guard_watcher, reinit_db_cb);
    ev_async_start(_loop, &_reinit_db_guard_watcher);
    ev_unref(_loop);
    ev_async_send(_loop, &_reinit_db_guard_watcher);

    ev_run(_loop, 0);
    return 0;
}

