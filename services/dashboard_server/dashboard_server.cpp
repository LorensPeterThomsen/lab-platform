// dashboard_server.cpp  (DS-3 + DB source-of-truth for boxqueue)
//
// Build:
//   g++ -std=c++17 dashboard_server.cpp -O2 -Wall -Wextra -I/usr/include/postgresql -lboost_system -lpthread -lpq -o dashboard_server
//
//
// Local WS:
//   ws://127.0.0.1:9200/ws/plcbridge?token=...
//   ws://127.0.0.1:9200/ws/dashboard?token=...

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <libpq-fe.h>
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <thread>

namespace asio  = boost::asio;
namespace beast = boost::beast;
namespace http  = beast::http;
namespace ws    = beast::websocket;
using tcp  = asio::ip::tcp;
using json = nlohmann::json;

struct WhereEventPoint {
  long long ms = 0;

  bool where_at_is_null = true;
  std::string where_at;

  bool where_id_is_null = true;
  long long where_id = 0;

  bool where_name_is_null = true;
  std::string where_name;
};

// ---------------- utilities ----------------
static uint16_t parse_u16_or(const std::string& s, uint16_t defv) {
  try {
    int v = std::stoi(s);
    if (v < 1 || v > 65535) return defv;
    return static_cast<uint16_t>(v);
  } catch (...) { return defv; }
}

static std::string getenv_or(const char* k, const std::string& defv) {
  const char* v = std::getenv(k);
  if (!v || !*v) return defv;
  return std::string(v);
}

// query param helper: target "/ws/dashboard?token=abc&x=y"
static std::string_view getQueryParam(std::string_view target, std::string_view key) {
  auto qpos = target.find('?');
  if (qpos == std::string_view::npos) return {};
  std::string_view q = target.substr(qpos + 1);
  while (!q.empty()) {
    auto amp = q.find('&');
    std::string_view part = (amp == std::string_view::npos) ? q : q.substr(0, amp);

    auto eq = part.find('=');
    std::string_view k = (eq == std::string_view::npos) ? part : part.substr(0, eq);
    std::string_view v = (eq == std::string_view::npos) ? std::string_view{} : part.substr(eq + 1);

    if (k == key) return v;

    if (amp == std::string_view::npos) break;
    q.remove_prefix(amp + 1);
  }
  return {};
}



// ---------------- auth model ----------------
struct AuthInfo {
  std::string lab_id;
  std::string role; // "plcbridge" or "dashboard"
  bool enabled = true;
};

static std::unordered_map<std::string, AuthInfo> loadTokens(const std::string& path) {
  std::ifstream f(path);
  if (!f) throw std::runtime_error("Cannot open TOKENS_FILE: " + path);

  json j;
  f >> j;
  if (!j.is_array()) throw std::runtime_error("TOKENS_FILE must be JSON array");

  std::unordered_map<std::string, AuthInfo> out;
  for (auto& it : j) {
    if (!it.is_object()) continue;
    std::string token = it.value("token", "");
    if (token.empty()) continue;

    AuthInfo a;
    a.lab_id  = it.value("lab_id", "");
    a.role    = it.value("role", "");
    a.enabled = it.value("enabled", true);

    if (a.lab_id.empty() || a.role.empty()) continue;
    out[token] = std::move(a);
  }
  return out;
}

class DashboardServer;
class DashWsSession;

// Hash/eq for shared_ptr in unordered_set
template <class T>
struct PtrHash {
  size_t operator()(const std::shared_ptr<T>& p) const noexcept {
    return std::hash<const void*>()(p.get());
  }
};
template <class T>
struct PtrEq {
  bool operator()(const std::shared_ptr<T>& a, const std::shared_ptr<T>& b) const noexcept {
    return a.get() == b.get();
  }
};



struct BoxInfo {
  long long boxid = 0;
  bool exists = false;

  std::string qrcode;
  std::string temp_status; // enum -> text

  bool clinic_is_null = true;
  long long last_clinicid = 0;
  std::string clinic_name;
};

struct CurvePoint {
  long long ms = 0;     // epoch millis
  double value = 0.0;

  // colour enum as text: "red" / "green" (eller tom hvis NULL)
  bool colour_is_null = true;
  std::string colour;

  // where info from box_where_events
  bool where_at_is_null = true;
  std::string where_at;       // "new"/"lab"/"clinic"/"car"/"phone"

  bool where_id_is_null = true;
  long long where_id = 0;     // labid/clinicid/carid/phoneid

  bool where_name_is_null = true;
  std::string where_name;     // labs.name/code, clinics.clinic_name, cars.qrcode, phones.phone_number
};


struct BoxListItem {
  long long boxid = 0;
  std::string qrcode;
};

struct CsvExportData {
  std::string filename;
  std::string content;
};


struct TransportWindow {
  bool has_clinic = false;  // findes der en clinic-event overhovedet
  bool has_start  = false;  // er boksen blevet hentet (event efter clinic findes)
  bool has_end    = false;  // er boksen kommet til lab efter clinic
  std::string start_at;     // timestamptz text
  std::string end_at;       // timestamptz text
};


// ---------------- Postgres helper (auto-reconnect) ----------------
class PgConn {
public:
  explicit PgConn(std::string conninfo)
    : conninfo_(std::move(conninfo))
  {
    connectOrThrow();
  }

  ~PgConn() {
    if (conn_) PQfinish(conn_);
  }

  PgConn(const PgConn&) = delete;
  PgConn& operator=(const PgConn&) = delete;

  // ---------- types ----------
  struct Row { std::string lab_id; int boxpos; long long boxid; };

  // ---------- boxqueue ----------
  std::vector<Row> loadBoxQueueAll() {
    ensureConnected();

    const char* sql =
      "SELECT lab_id, boxpos, boxid "
      "FROM public.boxqueue "
      "ORDER BY lab_id, boxpos";

    PGresult* res = PQexec(conn_, sql);
    check(res, "SELECT boxqueue");

    int n = PQntuples(res);
    std::vector<Row> out;
    out.reserve((size_t)n);

    for (int i = 0; i < n; ++i) {
      Row r;
      r.lab_id = PQgetvalue(res, i, 0);
      r.boxpos = std::stoi(PQgetvalue(res, i, 1));
      if (PQgetisnull(res, i, 2))
        r.boxid = 0;
      else
        r.boxid = std::stoll(PQgetvalue(res, i, 2));

      out.push_back(std::move(r));
    }

    PQclear(res);
    return out;
  }

  // ---------- params exec ----------
  PGresult* execParamsOrThrow(const char* sql, int nParams, const char* const* values) {
    ensureConnected();

    PGresult* res = PQexecParams(conn_, sql, nParams, nullptr, values, nullptr, nullptr, 0);
    check(res, sql);
    return res;
  }

  // ---------- boxinfo ----------
  BoxInfo loadBoxInfo(long long boxid) {
    static const char* sql =
      "SELECT "
		  "  b.boxid, "
		  "  b.qrcode, "
		  "  b.temp_status::text, "
		  "  lc.clinicid, "
		  "  lc.clinic_name "
		  "FROM public.boxes b "
		  "LEFT JOIN LATERAL ( "
		  "  SELECT c.clinicid, c.clinic_name "
		  "  FROM public.box_where_events e "
		  "  JOIN public.clinics c ON c.clinicid = e.where_clinicid "
		  "  WHERE e.boxid = b.boxid "
		  "    AND e.where_at = 'clinic' "
		  "  ORDER BY e.started_at DESC "
		  "  LIMIT 1 "
		  ") lc ON true "
		  "WHERE b.boxid = $1";
    std::string id = std::to_string(boxid);
    const char* vals[1] = { id.c_str() };

    PGresult* res = execParamsOrThrow(sql, 1, vals);

    BoxInfo out;

    if (PQntuples(res) == 1) {
      out.exists = true;
      out.boxid = std::stoll(PQgetvalue(res, 0, 0));

      if (!PQgetisnull(res, 0, 1))
        out.qrcode = PQgetvalue(res, 0, 1);

      if (!PQgetisnull(res, 0, 2))
        out.temp_status = PQgetvalue(res, 0, 2);

      out.clinic_is_null = PQgetisnull(res, 0, 3);
      if (!out.clinic_is_null)
        out.last_clinicid = std::stoll(PQgetvalue(res, 0, 3));

      if (!PQgetisnull(res, 0, 4))
        out.clinic_name = PQgetvalue(res, 0, 4);
    }

    PQclear(res);
    return out;
  }

  // ---------- curve ----------
 
 
  std::vector<CurvePoint> loadCurve24h(long long boxid) {
	  static const char* sql =
	    "SELECT "
	    "  (EXTRACT(EPOCH FROM t.logged_at) * 1000)::bigint AS ms, "
	    "  t.value::float8, "
	    "  t.colour::text, "
	    "  e.where_at::text, "
	    "  COALESCE(e.where_labid, e.where_clinicid, e.where_carid, e.where_phoneid) AS where_id, "
	    "  CASE e.where_at "
	    "    WHEN 'clinic' THEN c.clinic_name "
	    "    WHEN 'lab'    THEN COALESCE(l.name, l.code) "
	    "    WHEN 'car'    THEN ca.qrcode "
	    "    WHEN 'phone'  THEN p.phone_number "
	    "    ELSE NULL "
	    "  END AS where_name "
	    "FROM public.temp_values t "
	    "LEFT JOIN public.box_where_events e ON e.id = t.where_event_id "
	    "LEFT JOIN public.clinics c ON c.clinicid = e.where_clinicid "
	    "LEFT JOIN public.labs    l ON l.labid     = e.where_labid "
	    "LEFT JOIN public.cars    ca ON ca.carid   = e.where_carid "
	    "LEFT JOIN public.phones  p  ON p.phoneid  = e.where_phoneid "
	    "WHERE t.boxid = $1 "
	    "  AND t.logged_at >= NOW() - INTERVAL '24 hours' "
	    "ORDER BY t.logged_at ASC";
	
	  std::string id = std::to_string(boxid);
	  const char* vals[1] = { id.c_str() };
	
	  PGresult* res = execParamsOrThrow(sql, 1, vals);
	
	  int n = PQntuples(res);
	  std::vector<CurvePoint> out;
	  out.reserve((size_t)n);
	
	  for (int i = 0; i < n; ++i) {
	    if (PQgetisnull(res, i, 0) || PQgetisnull(res, i, 1))
	      continue;
	
	    CurvePoint p;
	    p.ms = std::stoll(PQgetvalue(res, i, 0));
	    p.value = std::stod(PQgetvalue(res, i, 1));
	
	    // colour
	    p.colour_is_null = PQgetisnull(res, i, 2);
	    if (!p.colour_is_null) p.colour = PQgetvalue(res, i, 2);
	
	    // where_at
	    p.where_at_is_null = PQgetisnull(res, i, 3);
	    if (!p.where_at_is_null) p.where_at = PQgetvalue(res, i, 3);
	
	    // where_id
	    p.where_id_is_null = PQgetisnull(res, i, 4);
	    if (!p.where_id_is_null) p.where_id = std::stoll(PQgetvalue(res, i, 4));
	
	    // where_name
	    p.where_name_is_null = PQgetisnull(res, i, 5);
	    if (!p.where_name_is_null) p.where_name = PQgetvalue(res, i, 5);
	
	    out.push_back(std::move(p));
	  }
	
	  PQclear(res);
	  return out;
	}
		 
	TransportWindow loadTransportWindow(long long boxid) {
	  static const char* sql =
	    "WITH last_clinic AS ( "
	    "  SELECT id AS clinic_event_id, started_at AS clinic_at "
	    "  FROM public.box_where_events "
	    "  WHERE boxid = $1 AND where_at = 'clinic' "
	    "  ORDER BY started_at DESC "
	    "  LIMIT 1 "
	    "), "
	    "start_ev AS ( "
	    "  SELECT e.id, e.started_at "
	    "  FROM public.box_where_events e, last_clinic lc "
	    "  WHERE e.boxid = $1 AND e.started_at > lc.clinic_at "
	    "  ORDER BY e.started_at ASC "
	    "  LIMIT 1 "
	    "), "
	    "end_ev AS ( "
	    "  SELECT e.id, e.started_at "
	    "  FROM public.box_where_events e, last_clinic lc "
	    "  WHERE e.boxid = $1 AND e.where_at='lab' AND e.started_at > lc.clinic_at "
	    "  ORDER BY e.started_at ASC "
	    "  LIMIT 1 "
	    ") "
	    "SELECT "
	    "  (SELECT clinic_event_id FROM last_clinic) AS clinic_event_id, "
	    "  (SELECT started_at FROM start_ev) AS start_at, "
	    "  (SELECT started_at FROM end_ev) AS end_at;";
	
	  std::string id = std::to_string(boxid);
	  const char* vals[1] = { id.c_str() };
	  PGresult* res = execParamsOrThrow(sql, 1, vals);
	
	  TransportWindow tw;
	
	  if (PQntuples(res) == 1) {
	    tw.has_clinic = !PQgetisnull(res, 0, 0);
	    tw.has_start  = !PQgetisnull(res, 0, 1);
	    tw.has_end    = !PQgetisnull(res, 0, 2);
	
	    if (tw.has_start) tw.start_at = PQgetvalue(res, 0, 1);
	    if (tw.has_end)   tw.end_at   = PQgetvalue(res, 0, 2);
	  }
	
	  PQclear(res);
	  return tw;
	}	
	
	std::vector<WhereEventPoint> loadWhereEventsRange(long long boxid,
                                                  long long start_ms,
                                                  long long end_ms) {
	  static const char* sql =
	    "SELECT "
	    "  (EXTRACT(EPOCH FROM e.started_at) * 1000)::bigint AS ms, "
	    "  e.where_at::text, "
	    "  COALESCE(e.where_labid, e.where_clinicid, e.where_carid, e.where_phoneid) AS where_id, "
	    "  CASE e.where_at "
	    "    WHEN 'clinic' THEN c.clinic_name "
	    "    WHEN 'lab'    THEN COALESCE(l.name, l.code) "
	    "    WHEN 'car'    THEN ca.qrcode "
	    "    WHEN 'phone'  THEN p.phone_number "
	    "    ELSE NULL "
	    "  END AS where_name "
	    "FROM public.box_where_events e "
	    "LEFT JOIN public.clinics c ON c.clinicid = e.where_clinicid "
	    "LEFT JOIN public.labs    l ON l.labid     = e.where_labid "
	    "LEFT JOIN public.cars    ca ON ca.carid   = e.where_carid "
	    "LEFT JOIN public.phones  p  ON p.phoneid  = e.where_phoneid "
	    "WHERE e.boxid = $1 "
	    "  AND e.started_at >= to_timestamp(($2::bigint) / 1000.0) "
	    "  AND e.started_at <= to_timestamp(($3::bigint) / 1000.0) "
	    "ORDER BY e.started_at ASC";
	
	  std::string id  = std::to_string(boxid);
	  std::string sMs = std::to_string(start_ms);
	  std::string eMs = std::to_string(end_ms);
	  const char* vals[3] = { id.c_str(), sMs.c_str(), eMs.c_str() };
	
	  PGresult* res = execParamsOrThrow(sql, 3, vals);
	
	  int n = PQntuples(res);
	  std::vector<WhereEventPoint> out;
	  out.reserve((size_t)n);
	
	  for (int i = 0; i < n; ++i) {
	    if (PQgetisnull(res, i, 0)) continue;
	
	    WhereEventPoint p;
	    p.ms = std::stoll(PQgetvalue(res, i, 0));
	
	    p.where_at_is_null = PQgetisnull(res, i, 1);
	    if (!p.where_at_is_null) p.where_at = PQgetvalue(res, i, 1);
	
	    p.where_id_is_null = PQgetisnull(res, i, 2);
	    if (!p.where_id_is_null) p.where_id = std::stoll(PQgetvalue(res, i, 2));
	
	    p.where_name_is_null = PQgetisnull(res, i, 3);
	    if (!p.where_name_is_null) p.where_name = PQgetvalue(res, i, 3);
	
	    out.push_back(std::move(p));
	  }
	
	  PQclear(res);
	  return out;
	}
		
	std::vector<CurvePoint> loadCurveRange(long long boxid,
	                                       long long start_ms,
	                                       long long end_ms) {
	  static const char* sql =
	    "SELECT "
	    "  (EXTRACT(EPOCH FROM t.logged_at) * 1000)::bigint AS ms, "
	    "  t.value::float8, "
	    "  t.colour::text, "
	    "  e.where_at::text, "
	    "  COALESCE(e.where_labid, e.where_clinicid, e.where_carid, e.where_phoneid) AS where_id, "
	    "  CASE e.where_at "
	    "    WHEN 'clinic' THEN c.clinic_name "
	    "    WHEN 'lab'    THEN COALESCE(l.name, l.code) "
	    "    WHEN 'car'    THEN ca.qrcode "
	    "    WHEN 'phone'  THEN p.phone_number "
	    "    ELSE NULL "
	    "  END AS where_name "
	    "FROM public.temp_values t "
	    "LEFT JOIN public.box_where_events e ON e.id = t.where_event_id "
	    "LEFT JOIN public.clinics c ON c.clinicid = e.where_clinicid "
	    "LEFT JOIN public.labs    l ON l.labid     = e.where_labid "
	    "LEFT JOIN public.cars    ca ON ca.carid   = e.where_carid "
	    "LEFT JOIN public.phones  p  ON p.phoneid  = e.where_phoneid "
	    "WHERE t.boxid = $1 "
	    "  AND t.logged_at >= to_timestamp(($2::bigint) / 1000.0) "
	    "  AND t.logged_at <= to_timestamp(($3::bigint) / 1000.0) "
	    "ORDER BY t.logged_at ASC";
	
	  std::string id  = std::to_string(boxid);
	  std::string sMs = std::to_string(start_ms);
	  std::string eMs = std::to_string(end_ms);
	  const char* vals[3] = { id.c_str(), sMs.c_str(), eMs.c_str() };
	
	  PGresult* res = execParamsOrThrow(sql, 3, vals);
	
	  int n = PQntuples(res);
	  std::vector<CurvePoint> out;
	  out.reserve((size_t)n);
	
	  for (int i = 0; i < n; ++i) {
	    if (PQgetisnull(res, i, 0) || PQgetisnull(res, i, 1))
	      continue;
	
	    CurvePoint p;
	    p.ms = std::stoll(PQgetvalue(res, i, 0));
	    p.value = std::stod(PQgetvalue(res, i, 1));
	
	    p.colour_is_null = PQgetisnull(res, i, 2);
	    if (!p.colour_is_null) p.colour = PQgetvalue(res, i, 2);
	
	    p.where_at_is_null = PQgetisnull(res, i, 3);
	    if (!p.where_at_is_null) p.where_at = PQgetvalue(res, i, 3);
	
	    p.where_id_is_null = PQgetisnull(res, i, 4);
	    if (!p.where_id_is_null) p.where_id = std::stoll(PQgetvalue(res, i, 4));
	
	    p.where_name_is_null = PQgetisnull(res, i, 5);
	    if (!p.where_name_is_null) p.where_name = PQgetvalue(res, i, 5);
	
	    out.push_back(std::move(p));
	  }
	
	  PQclear(res);
	  return out;
	}	
	
	
	
	std::vector<BoxListItem> loadBoxListForLabCode(const std::string& lab_code) {
	  static const char* sql =
	    "SELECT b.boxid, b.qrcode "
	    "FROM public.boxes b "
	    "JOIN public.labs l ON l.labid = b.labid "
	    "WHERE l.code = $1 "
	    "ORDER BY b.qrcode ASC";
	
	  const char* vals[1] = { lab_code.c_str() };
	  PGresult* res = execParamsOrThrow(sql, 1, vals);
	
	  int n = PQntuples(res);
	  std::vector<BoxListItem> out;
	  out.reserve((size_t)n);
	
	  for (int i = 0; i < n; ++i) {
	    if (PQgetisnull(res, i, 0)) continue;
	
	    BoxListItem b;
	    b.boxid = std::stoll(PQgetvalue(res, i, 0));
	    if (!PQgetisnull(res, i, 1)) b.qrcode = PQgetvalue(res, i, 1);
	
	    out.push_back(std::move(b));
	  }
	
	  PQclear(res);
	  return out;
	}	
		
	bool boxBelongsToLabCode(long long boxid, const std::string& lab_code) {
	  static const char* sql =
	    "SELECT 1 "
	    "FROM public.boxes b "
	    "JOIN public.labs l ON l.labid = b.labid "
	    "WHERE b.boxid = $1 AND l.code = $2";
	
	  std::string id = std::to_string(boxid);
	  const char* vals[2] = { id.c_str(), lab_code.c_str() };
	
	  PGresult* res = execParamsOrThrow(sql, 2, vals);
	  bool ok = PQntuples(res) > 0;
	  PQclear(res);
	  return ok;
	}
	
	std::string loadBoxQrCode(long long boxid) {
	  static const char* sql =
	    "SELECT qrcode "
	    "FROM public.boxes "
	    "WHERE boxid = $1";
	
	  std::string id = std::to_string(boxid);
	  const char* vals[1] = { id.c_str() };
	
	  PGresult* res = execParamsOrThrow(sql, 1, vals);
	  std::string out;
	
	  if (PQntuples(res) == 1 && !PQgetisnull(res, 0, 0))
	    out = PQgetvalue(res, 0, 0);
	
	  PQclear(res);
	  return out;
	}
	
	
		 
	std::vector<CurvePoint> loadTransportSparkline(long long boxid, int maxPoints = 240) {
	  // find transport window
	  TransportWindow tw = loadTransportWindow(boxid);
	  if (!tw.has_clinic || !tw.has_start) {
	    // ingen transport (endnu)
	    return {};
	  }
	
	  // NOTE: når tw.has_end == false bruger vi NOW() direkte i SQL
	  // Vi bruger LIMIT maxPoints og tager seneste maxPoints i intervallet, men
	  // returnerer i ASC orden til graf.
	
	  static const char* sql_end_known =
	    "SELECT * FROM ( "
	    "  SELECT "
	    "    (EXTRACT(EPOCH FROM t.logged_at) * 1000)::bigint AS ms, "
	    "    t.value::float8, "
	    "    t.colour::text, "
	    "    e.where_at::text, "
	    "    COALESCE(e.where_labid, e.where_clinicid, e.where_carid, e.where_phoneid) AS where_id, "
	    "    CASE e.where_at "
	    "      WHEN 'clinic' THEN c.clinic_name "
	    "      WHEN 'lab'    THEN COALESCE(l.name, l.code) "
	    "      WHEN 'car'    THEN ca.qrcode "
	    "      WHEN 'phone'  THEN p.phone_number "
	    "      ELSE NULL "
	    "    END AS where_name "
	    "  FROM public.temp_values t "
	    "  LEFT JOIN public.box_where_events e ON e.id = t.where_event_id "
	    "  LEFT JOIN public.clinics c ON c.clinicid = e.where_clinicid "
	    "  LEFT JOIN public.labs    l ON l.labid     = e.where_labid "
	    "  LEFT JOIN public.cars    ca ON ca.carid   = e.where_carid "
	    "  LEFT JOIN public.phones  p  ON p.phoneid  = e.where_phoneid "
	    "  WHERE t.boxid = $1 "
	    "    AND t.logged_at >= $2::timestamptz "
	    "    AND t.logged_at <= $3::timestamptz "
	    "  ORDER BY t.logged_at DESC "
	    "  LIMIT $4::int "
	    ") q ORDER BY ms ASC;";
	
	  static const char* sql_end_now =
	    "SELECT * FROM ( "
	    "  SELECT "
	    "    (EXTRACT(EPOCH FROM t.logged_at) * 1000)::bigint AS ms, "
	    "    t.value::float8, "
	    "    t.colour::text, "
	    "    e.where_at::text, "
	    "    COALESCE(e.where_labid, e.where_clinicid, e.where_carid, e.where_phoneid) AS where_id, "
	    "    CASE e.where_at "
	    "      WHEN 'clinic' THEN c.clinic_name "
	    "      WHEN 'lab'    THEN COALESCE(l.name, l.code) "
	    "      WHEN 'car'    THEN ca.qrcode "
	    "      WHEN 'phone'  THEN p.phone_number "
	    "      ELSE NULL "
	    "    END AS where_name "
	    "  FROM public.temp_values t "
	    "  LEFT JOIN public.box_where_events e ON e.id = t.where_event_id "
	    "  LEFT JOIN public.clinics c ON c.clinicid = e.where_clinicid "
	    "  LEFT JOIN public.labs    l ON l.labid     = e.where_labid "
	    "  LEFT JOIN public.cars    ca ON ca.carid   = e.where_carid "
	    "  LEFT JOIN public.phones  p  ON p.phoneid  = e.where_phoneid "
	    "  WHERE t.boxid = $1 "
	    "    AND t.logged_at >= $2::timestamptz "
	    "    AND t.logged_at <= NOW() "
	    "  ORDER BY t.logged_at DESC "
	    "  LIMIT $3::int "
	    ") q ORDER BY ms ASC;";
	
	  std::string id  = std::to_string(boxid);
	  std::string lim = std::to_string(maxPoints);
	
	  PGresult* res = nullptr;
	  if (tw.has_end) {
	    const char* vals[4] = { id.c_str(), tw.start_at.c_str(), tw.end_at.c_str(), lim.c_str() };
	    res = execParamsOrThrow(sql_end_known, 4, vals);
	  } else {
	    const char* vals[3] = { id.c_str(), tw.start_at.c_str(), lim.c_str() };
	    res = execParamsOrThrow(sql_end_now, 3, vals);
	  }
	
	  int n = PQntuples(res);
	  std::vector<CurvePoint> out;
	  out.reserve((size_t)n);
	
	  for (int i = 0; i < n; ++i) {
	    if (PQgetisnull(res, i, 0) || PQgetisnull(res, i, 1)) continue;
	
	    CurvePoint p;
	    p.ms = std::stoll(PQgetvalue(res, i, 0));
	    p.value = std::stod(PQgetvalue(res, i, 1));
	
	    p.colour_is_null = PQgetisnull(res, i, 2);
	    if (!p.colour_is_null) p.colour = PQgetvalue(res, i, 2);
	
	    p.where_at_is_null = PQgetisnull(res, i, 3);
	    if (!p.where_at_is_null) p.where_at = PQgetvalue(res, i, 3);
	
	    p.where_id_is_null = PQgetisnull(res, i, 4);
	    if (!p.where_id_is_null) p.where_id = std::stoll(PQgetvalue(res, i, 4));
	
	    p.where_name_is_null = PQgetisnull(res, i, 5);
	    if (!p.where_name_is_null) p.where_name = PQgetvalue(res, i, 5);
	
	    out.push_back(std::move(p));
	  }
	
	  PQclear(res);
	  return out;
	}

	CsvExportData buildCurveExportCsv(long long boxid,
	                                  long long start_ms,
	                                  long long end_ms) {
	  auto pts = loadCurveRange(boxid, start_ms, end_ms);
	  auto evs = loadWhereEventsRange(boxid, start_ms, end_ms);
	  auto qr = loadBoxQrCode(boxid);
	
	  CsvExportData out;
	  out.filename = qr.empty() ? "curve_export.csv" : (qr + "_curve_export.csv");
	
	  std::ostringstream ss;
	
	  ss << "POINTS\n";
	  ss << "ms,logged_at,value,colour,where_at,where_id,where_name\n";
	
	  for (auto& p : pts) {
	    std::time_t tt = (std::time_t)(p.ms / 1000);
	    std::tm tm{};
	#if defined(_WIN32)
	    gmtime_s(&tm, &tt);
	#else
	    gmtime_r(&tt, &tm);
	#endif
	    char buf[64];
	    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
	
	    ss << p.ms << ","
	       << csvEscape(buf) << ","
	       << p.value << ","
	       << csvEscape(p.colour_is_null ? "" : p.colour) << ","
	       << csvEscape(p.where_at_is_null ? "" : p.where_at) << ","
	       << (p.where_id_is_null ? "" : std::to_string(p.where_id)) << ","
	       << csvEscape(p.where_name_is_null ? "" : p.where_name)
	       << "\n";
	  }
	
	  ss << "\n";
	  ss << "EVENTS\n";
	  ss << "event_ms,event_at,where_at,where_id,where_name\n";
	
	  for (auto& e : evs) {
	    std::time_t tt = (std::time_t)(e.ms / 1000);
	    std::tm tm{};
	#if defined(_WIN32)
	    gmtime_s(&tm, &tt);
	#else
	    gmtime_r(&tt, &tm);
	#endif
	    char buf[64];
	    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
	
	    ss << e.ms << ","
	       << csvEscape(buf) << ","
	       << csvEscape(e.where_at_is_null ? "" : e.where_at) << ","
	       << (e.where_id_is_null ? "" : std::to_string(e.where_id)) << ","
	       << csvEscape(e.where_name_is_null ? "" : e.where_name)
	       << "\n";
	  }
	
	  out.content = ss.str();
	  return out;
	}

private:
  PGconn* conn_{nullptr};
  std::string conninfo_;

  // ---------- connection ----------
  void connectOrThrow() {
    conn_ = PQconnectdb(conninfo_.c_str());
    if (!conn_ || PQstatus(conn_) != CONNECTION_OK) {
      std::string err = conn_ ? PQerrorMessage(conn_) : "null conn";
      throw std::runtime_error("PQconnectdb failed: " + err);
    }
    std::cout << "[ds] DB connected" << std::endl;
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
        std::cerr << "[ds] DB reconnect attempt "
                  << i << "/" << maxAttempts << " failed" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }

    throw std::runtime_error("DS DB reconnect failed after retries");
  }

  // ---------- result check ----------
  void check(PGresult* res, const char* what) {
    if (!res)
      throw std::runtime_error(std::string("PQexec null: ") + what);

    auto st = PQresultStatus(res);

    if (st == PGRES_FATAL_ERROR ||
        st == PGRES_BAD_RESPONSE ||
        st == PGRES_NONFATAL_ERROR) {
      std::string err = PQerrorMessage(conn_);
      PQclear(res);
      throw std::runtime_error(std::string("PG error at [") + what + "]: " + err);
    }
  }

	static std::string csvEscape(const std::string& s) {
	  bool needQuotes = false;
	  for (char c : s) {
	    if (c == '"' || c == ',' || c == '\n' || c == '\r') {
	      needQuotes = true;
	      break;
	    }
	  }
	  if (!needQuotes) return s;
	
	  std::string out = "\"";
	  for (char c : s) {
	    if (c == '"') out += "\"\"";
	    else out += c;
	  }
	  out += "\"";
	  return out;
	}
	
};
// ---------------- lab state ----------------
struct LabState {
  std::string lab_id;

  bool plc_online = false;
  std::chrono::system_clock::time_point plc_last_seen{};
  std::array<long long, 4> active_boxes{0,0,0,0};
  uint64_t rev = 0;

  std::unordered_set<std::shared_ptr<DashWsSession>, PtrHash<DashWsSession>, PtrEq<DashWsSession>> dashboards;
  std::unordered_map<long long, BoxInfo> boxinfo; // key=boxid
};

// ---------------- feed client ----------------
class FeedClient : public std::enable_shared_from_this<FeedClient> {
public:
  FeedClient(asio::io_context& io, std::string host, uint16_t port, DashboardServer& ds)
    : io_(io), host_(std::move(host)), port_(port), ds_(ds),
      socket_(io), resolver_(io), reconnect_timer_(io), idle_timer_(io){}

  void start() { connect(); }

private:
  asio::io_context& io_;
  std::string host_;
  uint16_t port_;
  DashboardServer& ds_;

  tcp::socket socket_;
  tcp::resolver resolver_;
  asio::steady_timer reconnect_timer_;
  asio::streambuf buf_;
  bool connecting_ = false;

	asio::steady_timer idle_timer_;
	std::chrono::steady_clock::time_point last_rx_{std::chrono::steady_clock::now()};

  void connect();
  void scheduleReconnect(const char* stage, const boost::system::error_code& ec);
  void doReadLine();
  void handleLine(const std::string& line);
	void scheduleIdleWatchdog();
};

// ---------------- WS sessions ----------------
class PlcWsSession : public std::enable_shared_from_this<PlcWsSession> {
public:
  PlcWsSession(tcp::socket sock, DashboardServer& server)
    : ws_(std::move(sock)), server_(server) {}

  void run(http::request<http::string_body>&& req, AuthInfo auth);

private:
  ws::stream<tcp::socket> ws_;
  DashboardServer& server_;
  beast::flat_buffer buffer_;
  bool ws_open_ = false;
  std::string lab_id_;

  std::deque<std::string> outbox_;
  bool writing_ = false;

  void doRead();
  void closeSelf();
  void onClientMsg(std::string_view txt);

  void sendText(const std::string& s);
  void doWrite();
};

class DashWsSession : public std::enable_shared_from_this<DashWsSession> {
public:
  DashWsSession(tcp::socket sock, DashboardServer& server)
    : ws_(std::move(sock)), server_(server) {}

  void run(http::request<http::string_body>&& req, AuthInfo auth);

  bool isOpen() const { return ws_open_ && ws_.is_open(); }
  const std::string& labId() const { return lab_id_; }

  void sendText(const std::string& s);

private:
  ws::stream<tcp::socket> ws_;
  DashboardServer& server_;
  beast::flat_buffer buffer_;
  bool ws_open_ = false;
  std::string lab_id_;

  std::deque<std::string> outbox_;
  bool writing_ = false;

  void doRead();
  void closeSelf();
  void onClientMsg(std::string_view txt);

  void doWrite();
};

// ---------------- DashboardServer ----------------
class DashboardServer {
public:
  DashboardServer(asio::io_context& io,
                  const std::string& bindAddr,
                  uint16_t listenPort,
                  std::unordered_map<std::string, AuthInfo> tokens,
                  std::string pgConnInfo)
    : io_(io),
      acceptor_(io, tcp::endpoint(asio::ip::make_address(bindAddr), listenPort)),
      tokens_(std::move(tokens)),
      pg_(std::move(pgConnInfo)) {}

  void start() {
    // Initial load of boxqueue
    reloadBoxQueueAll("startup");
    doAccept();
  }

  const AuthInfo* auth(std::string_view token) const {
    auto it = tokens_.find(std::string(token));
    if (it == tokens_.end()) return nullptr;
    if (!it->second.enabled) return nullptr;
    return &it->second;
  }

  LabState& lab(const std::string& lab_id) {
    auto it = labs_.find(lab_id);
    if (it != labs_.end()) return it->second;
    LabState s;
    s.lab_id = lab_id;
    auto [insIt, _] = labs_.emplace(lab_id, std::move(s));
    return insIt->second;
  }

  // PLC heartbeat only (DB is source for active_boxes)
  void onPlcHeartbeat(const std::string& lab_id) {
    auto& s = lab(lab_id);
    bool was = s.plc_online;
    s.plc_online = true;
    s.plc_last_seen = std::chrono::system_clock::now();
    if (!was) {
      s.rev++;
      std::cout << "[plc] online lab=" << lab_id << " rev=" << s.rev << std::endl;
      broadcastSnapshot(lab_id);
      broadcastTransportSparks(lab_id);
    }
  }

  // Called by feed client when it sees boxqueue changes
  void onBoxQueueChangedFromFeed() {
    reloadBoxQueueAll("livelink");
  }

  // dashboards
  void addDashboard(const std::shared_ptr<DashWsSession>& sess) {
    auto& s = lab(sess->labId());
    s.dashboards.insert(sess);
    std::cout << "[dash] connect lab=" << sess->labId()
              << " count=" << s.dashboards.size() << std::endl;

    sess->sendText(makeSnapshotJson(sess->labId()));
    sendTransportSparksTo(sess->labId(), sess);
  }

  void removeDashboard(const std::shared_ptr<DashWsSession>& sess) {
    auto it = labs_.find(sess->labId());
    if (it == labs_.end()) return;
    it->second.dashboards.erase(sess);
    std::cout << "[dash] disconnect lab=" << sess->labId()
              << " count=" << it->second.dashboards.size() << std::endl;
  }

	std::string makeSnapshotJson(const std::string& lab_id) {
	  auto& s = lab(lab_id);
	
	  json j;
	  j["type"] = "status_snapshot";
	  j["rev"] = s.rev;
	  j["plc_online"] = s.plc_online;
	  j["max_temp"] = 38.0;
	
	  // active_boxes: [id|null,...]
	  json ab = json::array();
	  for (auto id : s.active_boxes) {
	    if (id == 0) ab.push_back(nullptr);
	    else ab.push_back(id);
	  }
	  j["active_boxes"] = std::move(ab);
	
	  json boxes = json::array();
	
	  for (int pos = 1; pos <= 4; ++pos) {
	    long long box_id = s.active_boxes[(size_t)pos - 1];
	
	    json b;
	    b["boxpos"] = pos;
	
	    if (box_id == 0) {
	      b["box_id"] = nullptr;
	      b["empty"] = true;
	
	      // backward compatible fields
	      b["qrcode"] = nullptr;
	      b["temp_status"] = nullptr;
	      b["last_clinicid"] = nullptr;
	      b["clinic_name"] = nullptr;
	      b["clinic"] = { {"id", nullptr}, {"name", nullptr} };
	
	      boxes.push_back(std::move(b));
	      continue;
	    }
	
	    b["empty"] = false;
	    b["box_id"] = box_id;
	
	    // 1) Try cache first
	    BoxInfo bi;
	    bool have = false;
	
	    auto itInfo = s.boxinfo.find(box_id);
	    if (itInfo != s.boxinfo.end() && itInfo->second.exists) {
	      bi = itInfo->second;
	      have = true;
	    } else {
	      // 2) DB fallback (so UI shows immediately even if cache isn't warmed)
	      try {
	        bi = pg_.loadBoxInfo(box_id);   // <-- uses your PgConn in DashboardServer
	        if (bi.exists) {
	          s.boxinfo[box_id] = bi;       // warm cache
	          have = true;
	        }
	      } catch (...) {
	        // keep have=false
	      }
	    }
	
	    if (have) {
	      // new + old fields
	      b["qrcode"] = bi.qrcode.empty() ? json(nullptr) : json(bi.qrcode);
	      b["temp_status"] = bi.temp_status.empty() ? json(nullptr) : json(bi.temp_status);
	
	      // backward compatible (what your current frontend expects)
	      b["last_clinicid"] = bi.clinic_is_null ? json(nullptr) : json(bi.last_clinicid);
	      b["clinic_name"] = bi.clinic_name.empty() ? json(nullptr) : json(bi.clinic_name);
	
	      // nice nested object as well
	      json clinic;
	      clinic["id"] = bi.clinic_is_null ? json(nullptr) : json(bi.last_clinicid);
	      clinic["name"] = bi.clinic_name.empty() ? json(nullptr) : json(bi.clinic_name);
	      b["clinic"] = std::move(clinic);
	    } else {
	      b["qrcode"] = nullptr;
	      b["temp_status"] = nullptr;
	      b["last_clinicid"] = nullptr;
	      b["clinic_name"] = nullptr;
	      b["clinic"] = { {"id", nullptr}, {"name", nullptr} };
	    }
	
	    boxes.push_back(std::move(b));
	  }
	
	  j["boxes"] = std::move(boxes);
	  return j.dump();
	}

  void broadcastSnapshot(const std::string& lab_id) {
    auto it = labs_.find(lab_id);
    if (it == labs_.end()) return;

    auto msg = makeSnapshotJson(lab_id);
    auto sessions = it->second.dashboards; // copy
    for (auto& s : sessions) {
      if (s && s->isOpen()) s->sendText(msg);
    }
  }

private:
  asio::io_context& io_;
  tcp::acceptor acceptor_;
  std::unordered_map<std::string, AuthInfo> tokens_;
  PgConn pg_;

  std::unordered_map<std::string, LabState> labs_;

  void doAccept();

	void onBoxesOrClinicsChangedFromFeed(const std::string& table, long long rowid) {
	  // boxes.rowid = boxid (din trigger lægger NEW.id/OLD.id? her antager vi "rowid=boxid")
	  // clinics.rowid = clinicid
	
	  for (auto& [lab_id, s] : labs_) {
	    bool affected = false;
	
	    if (table == "boxes") {
	      for (auto id : s.active_boxes) {
	        if (id != 0 && id == rowid) { affected = true; break; }
	      }
	      if (affected) {
	        refreshBoxInfoForLab(lab_id);
	        s.rev++;
	        std::cout << "[db] boxes change affects lab=" << lab_id << " rev=" << s.rev << std::endl;
	        broadcastSnapshot(lab_id);
	        broadcastTransportSparks(lab_id);
	      }
	    } else { // clinics
	      // hvis en aktiv box peger på clinicid=rowid
	      for (auto& [boxid, bi] : s.boxinfo) {
	        if (!bi.clinic_is_null && bi.last_clinicid == rowid) { affected = true; break; }
	      }
	      if (affected) {
	        refreshBoxInfoForLab(lab_id);
	        s.rev++;
	        std::cout << "[db] clinics change affects lab=" << lab_id << " rev=" << s.rev << std::endl;
	        broadcastSnapshot(lab_id);
	        broadcastTransportSparks(lab_id);
	      }
	    }
	  }
	}
	
	
	void sendTransportSparksTo(const std::string& lab_id, const std::shared_ptr<DashWsSession>& one) {
	  auto& s = lab(lab_id);
	
	  for (auto box_id : s.active_boxes) {
	    if (box_id == 0) continue;
	
	    auto pts = pg_.loadTransportSparkline(box_id, 240);
	
	    json msg;
	    msg["type"] = "transport_spark";
	    msg["box_id"] = box_id;
	    msg["points"] = json::array();
	
	    for (auto& p : pts) {
	      json e;
	      e["ms"] = p.ms;
	      e["value"] = p.value;
	      e["colour"] = p.colour_is_null ? json(nullptr) : json(p.colour);
	
	      json w;
	      w["at"]   = p.where_at_is_null   ? json(nullptr) : json(p.where_at);
	      w["id"]   = p.where_id_is_null   ? json(nullptr) : json(p.where_id);
	      w["name"] = p.where_name_is_null ? json(nullptr) : json(p.where_name);
	      e["where"] = std::move(w);
	
	      msg["points"].push_back(std::move(e));
	    }
	
	    if (one && one->isOpen()) {
	    	std::cout << "[dash] transport_spark box=" << box_id << " points=" << pts.size() << std::endl;
	      one->sendText(msg.dump());
	    }
	  }
	}
	
	void broadcastTransportSparks(const std::string& lab_id) {
	  auto it = labs_.find(lab_id);
	  if (it == labs_.end()) return;
	
	  // send to all dashboards for this lab
	  auto sessions = it->second.dashboards; // copy
	  for (auto& sess : sessions) {
	    if (sess && sess->isOpen())
	      sendTransportSparksTo(lab_id, sess);
	  }
	}
	
 
 
  // DB source-of-truth: reload all rows and update labs_ state
	void reloadBoxQueueAll(const char* reason) {
	  auto rows = pg_.loadBoxQueueAll();
	  std::unordered_map<std::string, std::array<long long,4>> byLab;
		try {
		  for (auto& r : rows) {
		    auto& arr = byLab[r.lab_id];
		    if (r.boxpos >= 1 && r.boxpos <= 4)
		      arr[(size_t)r.boxpos - 1] = r.boxid;
		  }
		
		  int changed = 0;
	
	
			// update labs with rows
		  for (auto& [lab_id, arr] : byLab) {
		    auto& s = lab(lab_id);
		    if (s.active_boxes != arr) {
		      s.active_boxes = arr;
		      s.rev++;
		      std::cout << "[db] boxqueue reload(" << reason << ") lab=" << lab_id << " ..." << std::endl;
		      broadcastSnapshot(lab_id);
		      broadcastTransportSparks(lab_id);
		      ++changed;
		    }
		  }
		
		  // labs without rows -> clear
		  for (auto& [lab_id, s] : labs_) {
		    if (!byLab.count(lab_id)) {
		      if (s.active_boxes != std::array<long long,4>{0,0,0,0}) {
		        s.active_boxes = {0,0,0,0};
		        s.rev++;
		        std::cout << "[db] boxqueue cleared(" << reason << ") lab=" << lab_id << std::endl;
		        broadcastSnapshot(lab_id);
		        broadcastTransportSparks(lab_id);
		        ++changed;
		      }
		    }
		  }
		
		
	    std::cout << "[db] reloadBoxQueueAll(" << reason << ") done changed_labs=" << changed << std::endl;
    } catch (const std::exception& e) {
      std::cerr << "[db] reloadBoxQueueAll error: " << e.what() << std::endl;
    }
  }
  
  
  void refreshBoxInfoForLab(const std::string& lab_id) {
	  auto it = labs_.find(lab_id);
	  if (it == labs_.end()) return;
	  auto& s = it->second;
	
	  std::unordered_map<long long, BoxInfo> next;
	
	  for (auto boxid : s.active_boxes) {
	    if (boxid == 0) continue;
	    try {
	      next[boxid] = pg_.loadBoxInfo(boxid);
	    } catch (const std::exception& e) {
	      std::cerr << "[db] loadBoxInfo error boxid=" << boxid << " " << e.what() << std::endl;
	    }
	  }
	
	  s.boxinfo = std::move(next);
	}

  friend class PlcWsSession;
  friend class DashWsSession;
  friend class FeedClient;
};

// ---------------- Router session ----------------
class RouterSession : public std::enable_shared_from_this<RouterSession> {
public:
  RouterSession(tcp::socket sock, DashboardServer& server)
    : socket_(std::move(sock)), server_(server) {}

  void start() { readHttp(); }

private:
  tcp::socket socket_;
  DashboardServer& server_;
  beast::flat_buffer buffer_;

  void readHttp() {
    auto self = shared_from_this();
    auto req = std::make_shared<http::request<http::string_body>>();
    http::async_read(socket_, buffer_, *req,
      [this, self, req](beast::error_code ec, std::size_t /*n*/) {
        if (ec) return;
        handle(*req);
      }
    );
  }

  void writeAndClose(http::response<http::string_body>&& res) {
    auto self = shared_from_this();
    auto sp = std::make_shared<http::response<http::string_body>>(std::move(res));
    http::async_write(socket_, *sp,
      [this, self, sp](beast::error_code /*ec*/, std::size_t /*n*/) {
        beast::error_code ignored;
        socket_.shutdown(tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
      }
    );
  }

  void handle(const http::request<http::string_body>& req) {
    if (req.method() == http::verb::get && req.target() == "/health") {
      http::response<http::string_body> res{http::status::ok, req.version()};
      res.set(http::field::server, "ds");
      res.set(http::field::content_type, "text/plain");
      res.body() = "ok\n";
      res.prepare_payload();
      return writeAndClose(std::move(res));
    }

    auto target = std::string_view(req.target().data(), req.target().size());

    if (!ws::is_upgrade(req)) {
      http::response<http::string_body> res{http::status::bad_request, req.version()};
      res.set(http::field::server, "ds");
      res.set(http::field::content_type, "text/plain");
      res.body() = "Expected WebSocket upgrade\n";
      res.prepare_payload();
      return writeAndClose(std::move(res));
    }

    std::string_view tok = getQueryParam(target, "token");
    const AuthInfo* a = (!tok.empty()) ? server_.auth(tok) : nullptr;
    if (!a) {
      http::response<http::string_body> res{http::status::unauthorized, req.version()};
      res.set(http::field::server, "ds");
      res.set(http::field::content_type, "text/plain");
      res.body() = "Unauthorized\n";
      res.prepare_payload();
      return writeAndClose(std::move(res));
    }

    if (target == "/ws/plcbridge" || target.rfind("/ws/plcbridge?", 0) == 0) {
      if (a->role != "plcbridge") {
        http::response<http::string_body> res{http::status::unauthorized, req.version()};
        res.set(http::field::server, "ds");
        res.set(http::field::content_type, "text/plain");
        res.body() = "Unauthorized\n";
        res.prepare_payload();
        return writeAndClose(std::move(res));
      }
      auto sess = std::make_shared<PlcWsSession>(std::move(socket_), server_);
      sess->run(http::request<http::string_body>(req), *a);
      return;
    }

    if (target == "/ws/dashboard" || target.rfind("/ws/dashboard?", 0) == 0) {
      if (a->role != "dashboard") {
        http::response<http::string_body> res{http::status::unauthorized, req.version()};
        res.set(http::field::server, "ds");
        res.set(http::field::content_type, "text/plain");
        res.body() = "Unauthorized\n";
        res.prepare_payload();
        return writeAndClose(std::move(res));
      }
      auto sess = std::make_shared<DashWsSession>(std::move(socket_), server_);
      sess->run(http::request<http::string_body>(req), *a);
      return;
    }

    http::response<http::string_body> res{http::status::not_found, req.version()};
    res.set(http::field::server, "ds");
    res.set(http::field::content_type, "text/plain");
    res.body() = "Not found\n";
    res.prepare_payload();
    return writeAndClose(std::move(res));
  }
};

void DashboardServer::doAccept() {
  acceptor_.async_accept([this](beast::error_code ec, tcp::socket sock) {
    if (!ec) std::make_shared<RouterSession>(std::move(sock), *this)->start();
    doAccept();
  });
}

// ---------------- FeedClient impl ----------------


void FeedClient::scheduleIdleWatchdog() {
  auto self = shared_from_this();
  idle_timer_.expires_after(std::chrono::seconds(5));
  idle_timer_.async_wait([this, self](boost::system::error_code ec) {
    if (ec) return;

    auto now = std::chrono::steady_clock::now();
    auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - last_rx_).count();

    // hvis ingen feed-data i 60s: drop forbindelsen og reconnect
    if (idle > 60) {
      std::cerr << "[ds] feed idle " << idle << "s -> reconnect" << std::endl;
      boost::system::error_code ig;
      socket_.close(ig);
      connecting_ = false;
      boost::system::error_code ig2;
			reconnect_timer_.cancel(ig2);
      connect();
      return;
    }

    scheduleIdleWatchdog();
  });
}



void FeedClient::connect() {
  if (connecting_) return;
  connecting_ = true;

  boost::system::error_code ignored;
  socket_.close(ignored);

  auto self = shared_from_this();
  resolver_.async_resolve(host_, std::to_string(port_),
    [this, self](boost::system::error_code ec, tcp::resolver::results_type results) {
      if (ec) return scheduleReconnect("resolve", ec);

      asio::async_connect(socket_, results,
        [this, self](boost::system::error_code ec2, const tcp::endpoint&) {
          if (ec2) return scheduleReconnect("connect", ec2);
          connecting_ = false;
          boost::system::error_code igc;
					reconnect_timer_.cancel(igc);
          std::cout << "[ds] connected to livelink feed" << std::endl;
          boost::system::error_code ig;
					socket_.set_option(asio::socket_base::keep_alive(true), ig);
					socket_.set_option(tcp::no_delay(true), ig);					
					last_rx_ = std::chrono::steady_clock::now();
					scheduleIdleWatchdog();
          
          doReadLine();
        }
      );
    }
  );
}

void FeedClient::scheduleReconnect(const char* stage, const boost::system::error_code& ec) {
  connecting_ = false;
  std::cerr << "[ds] feed " << stage << " failed: " << ec.message()
            << " (reconnect in 1s)" << std::endl;
  boost::system::error_code ignored;
  boost::system::error_code ig2;
	idle_timer_.cancel(ig2);
  socket_.close(ignored);

  auto self = shared_from_this();
  reconnect_timer_.expires_after(std::chrono::seconds(1));
  reconnect_timer_.async_wait([this, self](boost::system::error_code ec3) {
    if (ec3) return;
    connect();
  });
}

void FeedClient::doReadLine() {
  auto self = shared_from_this();
  asio::async_read_until(socket_, buf_, '\n',
    [this, self](boost::system::error_code ec, std::size_t /*n*/) {
    	if (ec == asio::error::operation_aborted) {
			  // Vi har selv afbrudt (watchdog/reconnect). Ignorér.
			  return;
			}
      if (ec) return scheduleReconnect("read", ec);

      std::istream is(&buf_);
      std::string line;
      std::getline(is, line);
      	
      last_rx_ = std::chrono::steady_clock::now();
      if (!line.empty()) handleLine(line);

      doReadLine();
    }
  );
}

void FeedClient::handleLine(const std::string& line) {
  try {
    auto j = json::parse(line);
    const std::string type = j.value("type", "");
    if (type == "hello") {
      std::cout << "[feed] hello proto=" << j.value("proto", 0)
                << " stream=" << j.value("stream", "") << std::endl;
      return;
    }
    
    
    if (type == "hb") {
 		 	// stille heartbeat – vi skal bare holde last_rx_ frisk
  		return;
		}
    
    if (type == "livelink") {
		  const std::string table = j.value("table", "");
		  long long rowid = j.value("rowid", 0LL);
		
		  if (table == "boxqueue") {
		    ds_.onBoxQueueChangedFromFeed();
		    return;
		  }
		
		  if (table == "boxes" || table == "clinics") {
		    ds_.onBoxesOrClinicsChangedFromFeed(table, rowid);
		    return;
		  }
		  
		  return;
		}
		
    
  } catch (...) {
    // ignore
  }
}

// ---------------- PlcWsSession ----------------
void PlcWsSession::run(http::request<http::string_body>&& req, AuthInfo auth) {
  lab_id_ = std::move(auth.lab_id);

  ws_.set_option(ws::stream_base::timeout::suggested(beast::role_type::server));
  ws_.set_option(ws::stream_base::decorator(
    [](ws::response_type& res) { res.set(http::field::server, "ds"); }
  ));

  auto self = shared_from_this();
  ws_.async_accept(req, [this, self](beast::error_code ec) {
    if (ec) { closeSelf(); return; }
    ws_open_ = true;

    server_.onPlcHeartbeat(lab_id_);

    json j;
    j["type"] = "hello";
    j["proto"] = 1;
    j["role"] = "plcbridge";
    j["lab_id"] = lab_id_;
    sendText(j.dump());

    doRead();
  });
}

void PlcWsSession::doRead() {
  auto self = shared_from_this();
  ws_.async_read(buffer_, [this, self](beast::error_code ec, std::size_t /*n*/) {
    if (ec) { closeSelf(); return; }
    std::string_view sv(static_cast<const char*>(buffer_.data().data()), buffer_.size());
    onClientMsg(sv);
    buffer_.consume(buffer_.size());
    doRead();
  });
}

void PlcWsSession::onClientMsg(std::string_view txt) {
  if (txt == "ping") { sendText("pong"); return; }

  json j;
  try { j = json::parse(txt); }
  catch (...) {
    sendText(R"({"type":"error","code":"bad_request","message":"invalid json"})");
    return;
  }

  const std::string type = j.value("type", "");
  if (type == "hb") {
    server_.onPlcHeartbeat(lab_id_);
    sendText(R"({"type":"hb_ack"})");
    return;
  }

  // DB is source-of-truth for boxqueue
  if (type == "active_boxes") {
    sendText("{\"type\":\"error\",\"code\":\"bad_request\",\"message\":\"active_boxes disabled; write public.boxqueue instead (DB is source-of-truth)\"}");
    return;
  }

  sendText(R"({"type":"error","code":"bad_request","message":"unknown message type"})");
}

void PlcWsSession::sendText(const std::string& s) {
  if (!ws_open_ || !ws_.is_open()) return;
  bool was_empty = outbox_.empty();
  outbox_.push_back(s);
  if (was_empty && !writing_) doWrite();
}

void PlcWsSession::doWrite() {
  if (!ws_open_ || !ws_.is_open()) { outbox_.clear(); writing_ = false; return; }
  if (outbox_.empty()) { writing_ = false; return; }

  writing_ = true;
  auto self = shared_from_this();
  ws_.text(true);
  ws_.async_write(asio::buffer(outbox_.front()),
    [this, self](beast::error_code ec, std::size_t /*n*/) {
      if (ec) { closeSelf(); return; }
      outbox_.pop_front();
      if (!outbox_.empty()) doWrite();
      else writing_ = false;
    }
  );
}

void PlcWsSession::closeSelf() {
  if (!ws_open_) return;
  ws_open_ = false;
  outbox_.clear();
  writing_ = false;
  beast::error_code ignored;
  if (ws_.is_open()) ws_.close(ws::close_code::normal, ignored);
  ws_.next_layer().close(ignored);
}

// ---------------- DashWsSession ----------------
void DashWsSession::run(http::request<http::string_body>&& req, AuthInfo auth) {
  lab_id_ = std::move(auth.lab_id);

  ws_.set_option(ws::stream_base::timeout::suggested(beast::role_type::server));
  ws_.set_option(ws::stream_base::decorator(
    [](ws::response_type& res) { res.set(http::field::server, "ds"); }
  ));

  auto self = shared_from_this();
  ws_.async_accept(req, [this, self](beast::error_code ec) {
    if (ec) { closeSelf(); return; }
    ws_open_ = true;

    json j;
    j["type"] = "hello";
    j["proto"] = 1;
    j["role"] = "dashboard";
    j["lab_id"] = lab_id_;
    sendText(j.dump());

    server_.addDashboard(self);
    doRead();
  });
}

void DashWsSession::doRead() {
  auto self = shared_from_this();
  ws_.async_read(buffer_, [this, self](beast::error_code ec, std::size_t /*n*/) {
    if (ec) { closeSelf(); return; }
    std::string_view sv(static_cast<const char*>(buffer_.data().data()), buffer_.size());
    onClientMsg(sv);
    buffer_.consume(buffer_.size());
    doRead();
  });
}

void DashWsSession::onClientMsg(std::string_view txt) {
  if (txt == "ping") {
    sendText("pong");
    return;
  }

  json j;
  try {
    j = json::parse(txt);
  } catch (...) {
    sendText(R"({"type":"error","code":"bad_request","message":"invalid json"})");
    return;
  }

  const std::string type = j.value("type", "");

  // ------------------------------------------------------------
  // box_list_request
  // ------------------------------------------------------------
  if (type == "box_list_request") {
    try {
      auto boxes = server_.pg_.loadBoxListForLabCode(lab_id_);

      json resp;
      resp["type"] = "box_list";
      resp["boxes"] = json::array();

      for (auto& b : boxes) {
        json e;
        e["box_id"] = b.boxid;
        e["qrcode"] = b.qrcode;
        resp["boxes"].push_back(std::move(e));
      }

      sendText(resp.dump());
    } catch (const std::exception& e) {
      json err;
      err["type"] = "error";
      err["code"] = "db_error";
      err["message"] = e.what();
      sendText(err.dump());
    }
    return;
  }

  // ------------------------------------------------------------
  // curve_open
  // ------------------------------------------------------------
  if (type == "curve_open") {
    if (!j.contains("box_id") || !j["box_id"].is_number_integer()) {
      sendText(R"({"type":"error","code":"bad_request","message":"curve_open requires integer box_id"})");
      return;
    }

    long long box_id = j["box_id"].get<long long>();

    // Ny validering: box skal høre til samme lab, ikke nødvendigvis være aktiv
    try {
      if (!server_.pg_.boxBelongsToLabCode(box_id, lab_id_)) {
        sendText(R"({"type":"error","code":"unknown_box","message":"box_id not in this lab"})");
        return;
      }
    } catch (const std::exception& e) {
      json err;
      err["type"] = "error";
      err["code"] = "db_error";
      err["message"] = e.what();
      sendText(err.dump());
      return;
    }

    long long end_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
      ).count();

    long long start_ms = end_ms - 24LL * 3600LL * 1000LL;

    if (j.contains("start_ms") && j["start_ms"].is_number_integer())
      start_ms = j["start_ms"].get<long long>();

    if (j.contains("end_ms") && j["end_ms"].is_number_integer())
      end_ms = j["end_ms"].get<long long>();

    if (end_ms <= start_ms) {
      sendText(R"({"type":"error","code":"bad_request","message":"end_ms must be greater than start_ms"})");
      return;
    }

    try {
      auto pts = server_.pg_.loadCurveRange(box_id, start_ms, end_ms);
      auto evs = server_.pg_.loadWhereEventsRange(box_id, start_ms, end_ms);

      json resp;
      resp["type"] = "curve_data";
      resp["box_id"] = box_id;
      resp["start_ms"] = start_ms;
      resp["end_ms"] = end_ms;
      resp["points"] = json::array();
      resp["events"] = json::array();

      for (auto& p : pts) {
        json e;
        e["ms"] = p.ms;
        e["value"] = p.value;
        e["colour"] = p.colour_is_null ? json(nullptr) : json(p.colour);

        json w;
        w["at"]   = p.where_at_is_null   ? json(nullptr) : json(p.where_at);
        w["id"]   = p.where_id_is_null   ? json(nullptr) : json(p.where_id);
        w["name"] = p.where_name_is_null ? json(nullptr) : json(p.where_name);
        e["where"] = std::move(w);

        resp["points"].push_back(std::move(e));
      }

      for (auto& ev : evs) {
        json e;
        e["ms"] = ev.ms;
        e["at"] = ev.where_at_is_null ? json(nullptr) : json(ev.where_at);
        e["id"] = ev.where_id_is_null ? json(nullptr) : json(ev.where_id);
        e["name"] = ev.where_name_is_null ? json(nullptr) : json(ev.where_name);
        resp["events"].push_back(std::move(e));
      }

      sendText(resp.dump());
    } catch (const std::exception& e) {
      json err;
      err["type"] = "curve_data";
      err["box_id"] = box_id;
      err["error"] = "db_error";
      err["message"] = e.what();
      sendText(err.dump());
    }
    return;
  }

  // ------------------------------------------------------------
  // curve_export
  // ------------------------------------------------------------
  if (type == "curve_export") {
    if (!j.contains("box_id") || !j["box_id"].is_number_integer()) {
      sendText(R"({"type":"error","code":"bad_request","message":"curve_export requires integer box_id"})");
      return;
    }

    long long box_id = j["box_id"].get<long long>();

    try {
      if (!server_.pg_.boxBelongsToLabCode(box_id, lab_id_)) {
        sendText(R"({"type":"error","code":"unknown_box","message":"box_id not in this lab"})");
        return;
      }
    } catch (const std::exception& e) {
      json err;
      err["type"] = "error";
      err["code"] = "db_error";
      err["message"] = e.what();
      sendText(err.dump());
      return;
    }

    long long end_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
      ).count();

    long long start_ms = end_ms - 24LL * 3600LL * 1000LL;

    if (j.contains("start_ms") && j["start_ms"].is_number_integer())
      start_ms = j["start_ms"].get<long long>();

    if (j.contains("end_ms") && j["end_ms"].is_number_integer())
      end_ms = j["end_ms"].get<long long>();

    if (end_ms <= start_ms) {
      sendText(R"({"type":"error","code":"bad_request","message":"end_ms must be greater than start_ms"})");
      return;
    }

    try {
      auto exp = server_.pg_.buildCurveExportCsv(box_id, start_ms, end_ms);

      json resp;
      resp["type"] = "curve_export_data";
      resp["box_id"] = box_id;
      resp["filename"] = exp.filename;
      resp["mime"] = "text/csv";
      resp["start_ms"] = start_ms;
      resp["end_ms"] = end_ms;
      resp["content"] = exp.content;

      sendText(resp.dump());
    } catch (const std::exception& e) {
      json err;
      err["type"] = "error";
      err["code"] = "db_error";
      err["message"] = e.what();
      sendText(err.dump());
    }
    return;
  }

  sendText(R"({"type":"error","code":"bad_request","message":"unknown message type"})");
}


void DashWsSession::sendText(const std::string& s) {
  if (!ws_open_ || !ws_.is_open()) return;
  bool was_empty = outbox_.empty();
  outbox_.push_back(s);
  if (was_empty && !writing_) doWrite();
}

void DashWsSession::doWrite() {
  if (!ws_open_ || !ws_.is_open()) { outbox_.clear(); writing_ = false; return; }
  if (outbox_.empty()) { writing_ = false; return; }

  writing_ = true;
  auto self = shared_from_this();
  ws_.text(true);
  ws_.async_write(asio::buffer(outbox_.front()),
    [this, self](beast::error_code ec, std::size_t /*n*/) {
      if (ec) { closeSelf(); return; }
      outbox_.pop_front();
      if (!outbox_.empty()) doWrite();
      else writing_ = false;
    }
  );
}

void DashWsSession::closeSelf() {
  if (!ws_open_) return;
  ws_open_ = false;
  outbox_.clear();
  writing_ = false;

  server_.removeDashboard(shared_from_this());

  beast::error_code ignored;
  if (ws_.is_open()) ws_.close(ws::close_code::normal, ignored);
  ws_.next_layer().close(ignored);
}

// ---------------- main ----------------
int main() {
  try {
  	std::cout.setf(std::ios::unitbuf);
		std::cerr.setf(std::ios::unitbuf);
    const std::string feedHost = getenv_or("LIVELINK_HOST", "127.0.0.1");
    const uint16_t feedPort = parse_u16_or(getenv_or("LIVELINK_PORT", "9000"), 9000);
    const uint16_t listenPort = parse_u16_or(getenv_or("DASHBOARD_PORT", "9200"), 9200);
    const std::string tokensFile = getenv_or("TOKENS_FILE", "/etc/ds_tokens.json");
    const std::string pgConnInfo = getenv_or("DB_CONNINFO", "");

    if (pgConnInfo.empty()) throw std::runtime_error("Missing env var: DB_CONNINFO");

    auto tokens = loadTokens(tokensFile);

    asio::io_context io;

    const std::string bindAddr = getenv_or("DASHBOARD_BIND", "0.0.0.0");
		DashboardServer ds(io, bindAddr, listenPort, std::move(tokens), pgConnInfo);
    ds.start();

    auto feed = std::make_shared<FeedClient>(io, feedHost, feedPort, ds);
    feed->start();

    std::cout << "DS(DB source-of-truth): feed=" << feedHost << ":" << feedPort
              << " ws(local)=ws://127.0.0.1:" << listenPort << "/ws/{plcbridge|dashboard}"
              << std::endl;
    std::cout << "Tokens file: " << tokensFile << std::endl;

    io.run();
  } catch (const std::exception& e) {
    std::cerr << "Fatal: " << e.what() << std::endl;
    return 1;
  }
  return 0;
}