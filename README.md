# pgpp
libpq C++ wrapper

## Feature highlights
* Multiple named connection pools with multiple db nodes support (single master (rw), multiple slaves (ro)).
* Automatic reconnection.
* Automatic node's role detection and substitution with a suitable node on the fly.
* Automatic query retry on reconnects, deadlock or serialization failures.
* Asynchronous connection and queries (by means of any external socket watcher).
* NOTIFY support, channels survival during disconnects or manual reconnects.
* Notices support.
* Client side COPY IN/OUT.
* GUI bonus (Qt).

### Example
```c++
auto cn = dbpool<pg::connection>::get()->get_connection();
pg::params p;
p << "pg_%";
auto res = cn->exec(
            "select relname from pg_class "
            "where relname like $1 and relkind = 'r'",
            &p);
for (int i = 0; i < res->row_count(); ++i)
    cout << res->raw_value(i, 0) << endl;
```

## TODO
Resultset-level part of api just maps to libpq and should be reworked.
