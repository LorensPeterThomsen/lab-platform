// livelinkd.cpp
// Build:
//   g++ -std=c++17 livelinkd.cpp -O2 -Wall -Wextra -lpq -lboost_system -lpthread -o livelinkd
//
// Run (env):
//   export LIVELINK_CONNINFO='host=127.0.0.1 port=5432 dbname=... user=... password=...'
//   export LIVELINK_PORT=9100
//   export LIVELINK_POLLMS=1000
//   ./livelinkd
//
// Protocol:
//   TCP server on 127.0.0.1:<port>
//   Emits newline-delimited JSON events (NDJSON), one per livelink row.
//   Example line:
//     {"type":"livelink","id":123,"table":"t","rowid":42,"op":"update","ts":"..."}\n

#include <boost/asio.hpp>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdlib>
#include <deque>
#include <iostream>
#include <limits>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>
#include <thread>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using json = nlohmann::json;

static std::string getenv_or(const char* k, const std::string& defv) {
  const char* v = std::getenv(k);
  if (!v || !*v) return defv;
  return std::string(v);
}




// -------------------- PostgreSQL helper (auto-reconnect) --------------------
class PgConn {
public:
  explicit PgConn(const std::string& conninfo)
    : conninfo_(conninfo)
  {
    connectOrThrow();
  }

  ~PgConn() {
    if (conn_) PQfinish(conn_);
  }

  PgConn(const PgConn&) = delete;
  PgConn& operator=(const PgConn&) = delete;

  // FIFO drain: oldest first. Deletes drained rows in same transaction.
  std::vector<std::string> fetchAndClearFIFO(int maxBatch = 2000, int maxLoops = 50) {
    std::vector<std::string> out;
    out.reserve(static_cast<size_t>(maxBatch));

    ensureConnected();

    for (int loop = 0; loop < maxLoops; ++loop) {
      try {
        execOrThrow("BEGIN");

        std::string sql =
          "SELECT id, table_name, rowid, operation, inserted "
          "FROM public.livelink "
          "ORDER BY id ASC "
          "LIMIT " + std::to_string(maxBatch);

        PGresult* res = PQexec(conn_, sql.c_str());
        checkResultOrThrow(res, "SELECT livelink fifo");

        int rows = PQntuples(res);
        if (rows == 0) {
          PQclear(res);
          execOrThrow("COMMIT");
          break;
        }

        long long minId = (std::numeric_limits<long long>::max)();
        long long maxId = 0;

        for (int i = 0; i < rows; ++i) {
          long long id = std::stoll(PQgetvalue(res, i, 0));
          const char* table = PQgetvalue(res, i, 1);
          long long rowid = std::stoll(PQgetvalue(res, i, 2));
          const char* op = PQgetvalue(res, i, 3);
          const char* ts = PQgetvalue(res, i, 4);

          if (id < minId) minId = id;
          if (id > maxId) maxId = id;

          json j;
          j["type"]  = "livelink";
          j["id"]    = id;
          j["table"] = table;
          j["rowid"] = rowid;
          j["op"]    = op;
          j["ts"]    = ts;

          out.push_back(j.dump() + "\n");
        }

        PQclear(res);

        std::string del =
          "DELETE FROM public.livelink "
          "WHERE id >= " + std::to_string(minId) +
          " AND id <= " + std::to_string(maxId);

        execOrThrow(del.c_str());
        execOrThrow("COMMIT");

        if (rows < maxBatch) break;
      }
      catch (const std::exception& e) {
        // DB fejl → reconnect og retry næste loop
        std::cerr << "[livelinkd] DB error: " << e.what() << std::endl;
        reconnectWithBackoff();
        break; // næste tick prøver igen
      }
    }

    return out;
  }

private:
  PGconn* conn_{nullptr};
  std::string conninfo_;

  // ---------- connection helpers ----------

  void connectOrThrow() {
    conn_ = PQconnectdb(conninfo_.c_str());
    if (!conn_ || PQstatus(conn_) != CONNECTION_OK) {
      std::string err = conn_ ? PQerrorMessage(conn_) : "null conn";
      throw std::runtime_error("PQconnectdb failed: " + err);
    }
    std::cout << "[livelinkd] DB connected" << std::endl;
  }

  void ensureConnected() {
    if (conn_ && PQstatus(conn_) == CONNECTION_OK)
      return;

    reconnectWithBackoff();
  }

  void reconnectWithBackoff() {
    if (conn_) {
      PQfinish(conn_);
      conn_ = nullptr;
    }

    const int maxAttempts = 5;
    for (int i = 1; i <= maxAttempts; ++i) {
      try {
        connectOrThrow();
        return;
      } catch (...) {
        std::cerr << "[livelinkd] reconnect attempt "
                  << i << "/" << maxAttempts << " failed\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }

    throw std::runtime_error("DB reconnect failed after retries");
  }

  // ---------- exec wrappers ----------

  void execOrThrow(const char* sql) {
    ensureConnected();

    PGresult* res = PQexec(conn_, sql);
    checkResultOrThrow(res, sql);
    PQclear(res);
  }

  void checkResultOrThrow(PGresult* res, const char* what) {
    if (!res)
      throw std::runtime_error(std::string("PQexec null result: ") + what);

    auto st = PQresultStatus(res);

    if (st == PGRES_FATAL_ERROR ||
        st == PGRES_BAD_RESPONSE ||
        st == PGRES_NONFATAL_ERROR) {
      std::string err = PQerrorMessage(conn_);
      PQclear(res);
      throw std::runtime_error(std::string("PG error at [") + what + "]: " + err);
    }
  }
};

// -------------------- TCP client session --------------------
class LiveLinkd;

class ClientSession : public std::enable_shared_from_this<ClientSession> {
public:
  ClientSession(tcp::socket socket, LiveLinkd& owner)
    : socket_(std::move(socket)), owner_(owner) {}

  void start();
  void sendLine(const std::string& line);
  bool isOpen() const { return socket_.is_open(); }
  void close();

private:
  tcp::socket socket_;
  LiveLinkd& owner_;
  std::deque<std::string> outq_;
  bool writing_ = false;

  // simple backpressure guard:
  static constexpr size_t kMaxQueuedBytes = 4 * 1024 * 1024; // 4MB per client
  size_t queuedBytes_ = 0;

  void doWrite();
};

// -------------------- LiveLink daemon --------------------
class LiveLinkd {
public:
  LiveLinkd(asio::io_context& io,
            const std::string& bindAddr,
            std::string conninfo,
            uint16_t port,
            int pollMs)
    : io_(io),
      acceptor_(io, tcp::endpoint(asio::ip::make_address(bindAddr), port)),
      timer_(io),
      pg_(std::move(conninfo)),
      pollMs_(pollMs) {}
      
      
  void start() {
    doAccept();
    scheduleTick();
  }

  void addClient(const std::shared_ptr<ClientSession>& c) { clients_.insert(c); }
  void removeClient(const std::shared_ptr<ClientSession>& c) { clients_.erase(c); }

  void broadcastLines(const std::vector<std::string>& lines) {
    if (lines.empty()) return;
    cleanupDead();
    for (auto& c : clients_) {
      if (!c->isOpen()) continue;
      for (auto& ln : lines) c->sendLine(ln);
    }
  }

private:
  asio::io_context& io_;
  tcp::acceptor acceptor_;
  asio::steady_timer timer_;
  PgConn pg_;
  int pollMs_;
  std::unordered_set<std::shared_ptr<ClientSession>> clients_;

  void doAccept() {
    acceptor_.async_accept([this](boost::system::error_code ec, tcp::socket sock) {
      if (!ec) {
        auto c = std::make_shared<ClientSession>(std::move(sock), *this);
        addClient(c);
        c->start();
      }
      doAccept();
    });
  }

  void scheduleTick() {
    timer_.expires_after(std::chrono::milliseconds(pollMs_));
    timer_.async_wait([this](boost::system::error_code ec) {
      if (!ec) tick();
      scheduleTick();
    });
  }

  void tick() {
    try {
#ifdef DEBUG
      static uint64_t t = 0; ++t;
      std::cout << "[tick " << t << "] enter\n";
#endif
      auto lines = pg_.fetchAndClearFIFO(2000, 50);
#ifdef DEBUG
      std::cout << "[tick " << t << "] drained=" << lines.size() << "\n";
#endif

			if (lines.empty()) {
			  // Heartbeat hvert tick når der er stille
			  json hb;
			  hb["type"] = "hb";
			  hb["ts"] = std::chrono::duration_cast<std::chrono::milliseconds>(
			               std::chrono::system_clock::now().time_since_epoch()
			            ).count();
			  // NDJSON
			  std::vector<std::string> one;
			  one.push_back(hb.dump() + "\n");
			  broadcastLines(one);
			} else {
			  broadcastLines(lines);
			}

    } catch (const std::exception& e) {
      std::cerr << "Tick error: " << e.what() << "\n";
    }
  }

  void cleanupDead() {
    for (auto it = clients_.begin(); it != clients_.end();) {
      if (!(*it)->isOpen()) it = clients_.erase(it);
      else ++it;
    }
  }
};

// -------------------- ClientSession impl --------------------
void ClientSession::start() {
  // Optional: send a hello line so DS can verify stream is live
  json j;
  j["type"] = "hello";
  j["proto"] = 1;
  j["stream"] = "livelink_ndjson";
  sendLine(j.dump() + "\n");

  // We don't need to read anything from the client.
  // If you want to detect peer close faster, you can async_read some bytes,
  // but simplest is: rely on write errors.
}

void ClientSession::sendLine(const std::string& line) {
  if (!socket_.is_open()) return;

  // backpressure: if client is too slow, drop it (or drop messages).
  if (queuedBytes_ + line.size() > kMaxQueuedBytes) {
    // drop client to protect server
    close();
    return;
  }

  outq_.push_back(line);
  queuedBytes_ += line.size();

  if (!writing_) doWrite();
}

void ClientSession::doWrite() {
  if (!socket_.is_open()) { outq_.clear(); queuedBytes_ = 0; writing_ = false; return; }
  if (outq_.empty()) { writing_ = false; return; }

  writing_ = true;
  auto self = shared_from_this();

  asio::async_write(socket_, asio::buffer(outq_.front()),
    [this, self](boost::system::error_code ec, std::size_t) {
      if (ec) { close(); return; }

      // remove sent
      if (!outq_.empty()) {
        queuedBytes_ -= outq_.front().size();
        outq_.pop_front();
      }

      if (!outq_.empty()) doWrite();
      else writing_ = false;
    }
  );
}

void ClientSession::close() {
  if (!socket_.is_open()) return;
  boost::system::error_code ignored;
  socket_.shutdown(tcp::socket::shutdown_both, ignored);
  socket_.close(ignored);
  owner_.removeClient(shared_from_this());
}

// -------------------- main --------------------
static std::string require_env(const char* name) {
  const char* v = std::getenv(name);
  if (!v || std::string(v).empty())
    throw std::runtime_error(std::string("Missing env var: ") + name);
  return std::string(v);
}

static uint16_t parse_u16(const std::string& s, const char* name) {
  try {
    int v = std::stoi(s);
    if (v < 1 || v > 65535) throw std::out_of_range("range");
    return static_cast<uint16_t>(v);
  } catch (...) {
    throw std::runtime_error(std::string("Invalid ") + name + ": '" + s + "'");
  }
}

static int parse_i32(const std::string& s, const char* name) {
  try {
    int v = std::stoi(s);
    if (v < 1 || v > 3600000) throw std::out_of_range("range");
    return v;
  } catch (...) {
    throw std::runtime_error(std::string("Invalid ") + name + ": '" + s + "'");
  }
}

int main(int argc, char** argv) {
  try {
    std::string conninfo;
    uint16_t port = 9100;
    int pollMs = 1000;

    if (argc >= 4) {
      // CLI mode: ./livelinkd "conninfo" <port> <pollMs>
      conninfo = argv[1];
      port = parse_u16(argv[2], "port");
      pollMs = parse_i32(argv[3], "pollMs");
    } else {
      // Env mode
      conninfo = require_env("DB_CONNINFO");
      if (const char* p = std::getenv("LIVELINK_PORT"); p && *p) port = parse_u16(p, "LIVELINK_PORT");
      if (const char* ms = std::getenv("LIVELINK_POLL_MS"); ms && *ms) pollMs = parse_i32(ms, "LIVELINK_POLL_MS");
    }

    asio::io_context io;
   	const std::string bindAddr = getenv_or("LIVELINK_BIND", "0.0.0.0");
		LiveLinkd srv(io, bindAddr, conninfo, port, pollMs);	
    srv.start();

    std::cout << "LiveLinkD NDJSON: tcp://127.0.0.1:" << port
              << "  poll=" << pollMs << "ms\n";

    io.run();
  } catch (const std::exception& e) {
    std::cerr << "Fatal: " << e.what() << "\n";
    return 1;
  }
  return 0;
}
