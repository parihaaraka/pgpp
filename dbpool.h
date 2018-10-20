// Copyright (c) 2015-2018 Andrey Lukyanov <parihaaraka@gmail.com>
// MIT License

#ifndef DBPOOL_H
#define DBPOOL_H

/** @file */

#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <vector>
#include <mutex>
#include <deque>
#include <functional>
#include <sstream>

/*
  todo: several attempts to reconnect during timeout (cluster reconfiguration?)
*/

/** DB node access mode: */
enum class dbmode {
    na, /**< unknown */
    ro, /**< read-only */
    rw  /**< read/write */
};

/** @class dbpool
 *  Multi-node db connection pool.
 * @tparam T database class to be pooled
 */
template<typename T>
class dbpool
{
private:
    static std::function<void(
            const void *sender,
            const std::string &error,
            const void *user_ptr)> _error_cb;

public:
    dbpool(const dbpool&) = delete;
    dbpool& operator=(const dbpool&) = delete;

    /** Generate state information for every pool's node (debug purposes). */
    std::string state()
    {
        std::stringstream res;
        std::lock_guard<std::mutex> pooler_lock(_m);
        for (auto& npair :_nodes)
        {
            std::shared_ptr<dbnode> &n = npair.second;
            res << "node " << n->hash
                << ":  " << n->available
                << " of " << n->total
                << " available, "
                << (n->mode == dbmode::na ? "NA" : (n->mode == dbmode::ro ? "RO" : "RW"))
                << ", "
                << std::chrono::duration_cast<std::chrono::milliseconds>(
                       n->next_try - std::chrono::system_clock::now()
                       ).count()
                << " ms untill next_try" << std::endl;
        }
        return res.str();
    }

    /** Create new or retrieve existing connection. */
    std::shared_ptr<T> get_connection(bool is_writable = true, bool throw_on_error = true)
    {
        std::lock_guard<std::mutex> pooler_lock(_m);

        std::shared_ptr<dbnode> node(find_node(is_writable ? dbmode::rw : dbmode::ro));
        if (!node)
        {
            std::string error("pooler error: suitable database node not found");
            if (_error_cb)
                _error_cb(this, error, nullptr);
            if (throw_on_error)
                throw std::runtime_error(error);
            return std::shared_ptr<T>(nullptr);
        }

        // disable node for concurrent getters for a while
        //if (node->mode == dbmode::na)
        //    node->next_try = std::chrono::system_clock::now() + std::chrono::seconds(5);

        // delete old connections
        while (!_available_connections.empty() &&
               std::chrono::system_clock::now() - _available_connections.back()->got_back
                    > std::chrono::minutes(1))
        {
            dbnode *n = _available_connections.back()->node.get();
            --n->total;
            --n->available;
            _available_connections.pop_back();
        }

        T *db = nullptr;
        if (node->available)
        {
            // retrieve available connection
            for (auto it = _available_connections.begin();
                 it != _available_connections.end();
                 ++it)
            {
                if ((*it)->node == node)
                {
                    db = (*it)->db.get();
                    _connections_in_use.emplace(db, std::move(*it));
                    _available_connections.erase(it);
                    --node->available;
                    break;
                }
            }
        }
        else
        {
            // create new connection
            db = new T(node->connection_string,
                       bind(&dbpool<T>::db_state_detected,
                            this,
                            std::placeholders::_1,
                            std::placeholders::_2,
                            std::placeholders::_3,
                            is_writable ? dbmode::rw : dbmode::ro));
            _connections_in_use.emplace(db, new dbconnection{
                                            std::unique_ptr<T>(db),
                                            node,
                                            std::chrono::system_clock::now()});
            ++node->total;
        }
        db->on_error(_error_cb);

        std::shared_ptr<dbpool> pool(get(this));
        if (!pool)
        {
            std::string error("pooler error: the pool has been released");
            if (_error_cb)
                _error_cb(this, error, nullptr);
            if (throw_on_error)
                throw std::runtime_error(error);
            return std::shared_ptr<T>(nullptr);
        }

        // return another smart pointer with it's own control block with custom deleter
        // (pool captured inside lambda to keep it alive)
        return std::shared_ptr<T>(db, [pool](T *cn_raw)
        {
            std::lock_guard<std::mutex> pooler_lock(pool->_m);
            std::unique_ptr<dbconnection> &cn = pool->_connections_in_use.at(cn_raw);
            //auto node = cn->node;

            const auto it = pool->_nodes.find(cn->node->hash);
            // the pool claimed to delete, or node not available -> delete connection
            if (it == pool->_nodes.end() || cn->node->mode == dbmode::na)
            {
                --cn->node->total;
                pool->_connections_in_use.erase(cn_raw);
            }
            // get back connection if node is still in use
            else
            {
                cn->got_back = std::chrono::system_clock::now();
                pool->_available_connections.push_front(move(cn));
                pool->_connections_in_use.erase(cn_raw);
                ++(*it).second->available;
            }
        });
    }

    /** (Re)set connection strings for all dbms nodes. */
    void set_connection_strings(const std::vector<std::string>& css)
    {
        std::hash<std::string> hash_fn;
        std::unordered_set<size_t> new_hashes;
        std::lock_guard<std::mutex> pooler_lock(_m);

        // add new nodes
        for (const std::string &cs : css)
        {
            size_t hash = hash_fn(cs);
            new_hashes.insert(hash);
            if (_nodes.find(hash) == _nodes.end())
                _nodes.emplace(hash, std::make_shared<dbnode>(cs));
        }

        // remove nodes which are not in argument
        for (auto it = _nodes.begin(); it != _nodes.end();)
        {
            if (new_hashes.find(it->first) == new_hashes.end())
                it = _nodes.erase(it);
            else
                ++it;
        }
    }

    /** Create or retrieve existing shared pointer to a named connection pool. */
    static std::shared_ptr<dbpool> get(const std::string &name = "default")
    {
        std::lock_guard<std::mutex> lk(dbpool::_sm);
        auto pool_it = _pools.find(name);
        if (pool_it != _pools.end())
            return pool_it->second;

        // make_shared unable to use private constructor
        auto pool = std::shared_ptr<dbpool>(new dbpool);
        _pools.emplace(name, pool);
        return pool;
    }

    /** Release internal connection pool pointer. */
    static void release(const std::string &name = "default")
    {
        std::lock_guard<std::mutex> lk(_sm);
        _pools.erase(name);
    }

    /** Assign global error receiver function. */
    static void onError(decltype(_error_cb) handler)
    {
        std::lock_guard<std::mutex> pooler_lock(_sm);
        _error_cb = handler;
    }

private:
    mutable std::mutex _m;
    static std::mutex _sm;
    static std::unordered_map<std::string, std::shared_ptr<dbpool>> _pools;

    dbpool() = default;

    static std::shared_ptr<dbpool> get(const dbpool *pool)
    {
        std::lock_guard<std::mutex> lk(_sm);
        for (auto &p : _pools)
        {
            if (pool == p.second.get())
                return p.second;
        }
        return std::shared_ptr<dbpool>(nullptr);
    }

    // node metadata
    struct dbnode
    {
        dbnode(const std::string &cs) : connection_string(cs), mode(dbmode::na)
        {
            std::hash<std::string> hash_fn;
            hash = hash_fn(cs);
        }
        dbnode(const dbnode&) = delete;
        dbnode& operator=(const dbnode&) = delete;

        std::string connection_string;
        dbmode mode;
        size_t hash;
        size_t total = 0;
        size_t available = 0;

        // avoid usage of this node untill *next_try*
        std::chrono::time_point<std::chrono::system_clock> next_try;
    };

    // entire connection item
    struct dbconnection
    {
        std::unique_ptr<T> db;
        std::shared_ptr<dbnode> node;
        std::chrono::time_point<std::chrono::system_clock> got_back;
    };

    // available connections
    std::deque<std::unique_ptr<dbconnection>> _available_connections;

    // connections in use
    std::unordered_map<T*, std::unique_ptr<dbconnection>> _connections_in_use;

    // db nodes dictionary
    std::unordered_map<size_t, std::shared_ptr<dbnode>> _nodes;

    // callback to adjust caller connection string (clears connection string when suitable node not found)
    // * pool is captured by smart pointer deleter, so this function will alway stay valid within connection
    void db_state_detected(T *cn, std::string &cs, dbmode detected_mode, dbmode wanted_mode)
    {
        std::lock_guard<std::mutex> pooler_lock(_m);
        std::shared_ptr<dbnode> &cur_node = _connections_in_use.at(cn)->node;

        // initialize connection string
        if (cs.empty() && detected_mode == dbmode::na && !cur_node->connection_string.empty())
        {
            cs = cur_node->connection_string;
            return;
        }

        bool want_another_connection;
        // refresh current node state
        if (detected_mode == dbmode::na)
        {
            want_another_connection = true;

            // don't try this node for a while
            cur_node->next_try = std::chrono::system_clock::now() + std::chrono::seconds(5);

            // remove available connections
            for (auto it = _available_connections.begin(); it != _available_connections.end();)
            {
                if ((*it)->node == cur_node)
                {
                    it = _available_connections.erase(it);
                    --cur_node->total;
                    --cur_node->available;
                }
                else
                    ++it;
            }
        }
        else
        {
            want_another_connection = (detected_mode == dbmode::ro && wanted_mode == dbmode::rw);

            // RW -> RO: mark all other RO nodes as NA to use them for RW request
            if (cur_node->mode == dbmode::rw && detected_mode == dbmode::ro)
            {
                for (auto& db :_nodes)
                {
                    if (db.second->mode == dbmode::ro)
                        db.second->mode = dbmode::na;
                }
            }
        }
        cur_node->mode = detected_mode;

        if (want_another_connection)
        {
            // switch node for current connection
            std::shared_ptr<dbnode> new_node(find_node(wanted_mode));
            if (!new_node)
            {
                cs.clear();
                return;
            }

            // same pointers are possible if we have just a single db node
            if (new_node != cur_node)
            {
                ++new_node->total;
                --cur_node->total;
                cur_node = new_node;
            }

            cs = new_node->connection_string;
        }
    }

    // search for suitable node
    std::shared_ptr<dbnode> find_node(dbmode wanted_mode)
    {
        // do not strain if there is nothing to choose
        if (_nodes.size() == 1)
            return (*_nodes.begin()).second;

        std::shared_ptr<dbnode> new_node;
        for (auto& npair :_nodes)
        {
            std::shared_ptr<dbnode> &n = npair.second;
            if (n->next_try >= std::chrono::system_clock::now() && n->mode == dbmode::na)
                continue;

            if (n->mode != dbmode::ro || wanted_mode == dbmode::ro)
            {
                if (    !new_node ||
                        // single master politics
                        (wanted_mode == dbmode::rw && n->mode == dbmode::rw) ||
                        new_node->total > n->total)
                    new_node = n;
            }
        }
        return new_node;
    }
};

template <typename T>
std::function<void(
        const void *sender,
        const std::string &error,
        const void *user_ptr)> dbpool<T>::_error_cb;

template <typename T>
std::mutex dbpool<T>::_sm;

template <typename T>
std::unordered_map<std::string, std::shared_ptr<dbpool<T>>> dbpool<T>::_pools;

#endif // DBPOOL_H
