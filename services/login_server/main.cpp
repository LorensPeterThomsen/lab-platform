/*
	File main.cpp
	
	This code controls the login to the system over webpages
	
	Date 2026/01/22
	
	Author: Lorens Thomsen
	
*/


#include "crow_all.h"
#include <pqxx/pqxx>
#include <sodium.h>

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <cctype>
#include <memory>
#include <mutex>

#include <unordered_map>
#include <mutex>
#include <chrono>

static std::mutex g_touch_mx;
static std::unordered_map<std::string, std::chrono::steady_clock::time_point> g_last_touch;
static constexpr auto TOUCH_INTERVAL = std::chrono::seconds(60);

static bool should_touch(const std::string& sid) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(g_touch_mx);
    auto it = g_last_touch.find(sid);
    if (it == g_last_touch.end() || (now - it->second) > TOUCH_INTERVAL) {
        g_last_touch[sid] = now;
        return true;
    }
    return false;
}

static inline std::string trim_copy(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) b++;

    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) e--;

    return s.substr(b, e - b);
}

static inline void to_lower_ascii_inplace(std::string& s) {
    for (char& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
}



static std::array<unsigned char, 32> token_hash32(const std::string& token) {
    std::array<unsigned char, 32> out{};
    crypto_generichash(out.data(), out.size(),
                       reinterpret_cast<const unsigned char*>(token.data()), token.size(),
                       nullptr, 0);
    return out;
}

// -------------------- Sodium helpers (Argon2id) --------------------
static void sodium_init_or_throw() {
    static bool inited = false;
    if (!inited) {
        if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
        inited = true;
    }
}

static std::string to_hex(const unsigned char* p, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        unsigned char b = p[i];
        s[2*i]   = h[b >> 4];
        s[2*i+1] = h[b & 0x0F];
    }
    return s;
}


static std::optional<std::string> get_cookie_value(const crow::request& req, const std::string& name)
{
    auto cookie = req.get_header_value("Cookie");
    if (cookie.empty()) return std::nullopt;

    // Cookie header: "a=1; sid=XYZ; b=2"
    std::string needle = name + "=";
    size_t pos = 0;

    while (pos < cookie.size()) {
        // skip spaces and ';'
        while (pos < cookie.size() && (cookie[pos] == ' ' || cookie[pos] == ';')) pos++;

        // find end of this pair
        size_t end = cookie.find(';', pos);
        if (end == std::string::npos) end = cookie.size();

        // trim right spaces
        size_t pair_end = end;
        while (pair_end > pos && cookie[pair_end - 1] == ' ') pair_end--;

        // check if starts with "name="
        if (pair_end > pos && cookie.compare(pos, needle.size(), needle) == 0) {
            std::string val = cookie.substr(pos + needle.size(), pair_end - (pos + needle.size()));
            return val;
        }

        pos = end + 1;
    }
    return std::nullopt;
}

static std::string hash_password_argon2id(const std::string& password) {
    sodium_init_or_throw();
    char out[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(out,
                          password.c_str(),
                          password.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw std::runtime_error("crypto_pwhash_str failed");
    }
    return std::string(out);
}

static bool verify_password_argon2id(const std::string& stored_hash, const std::string& password) {
    sodium_init_or_throw();
    return crypto_pwhash_str_verify(stored_hash.c_str(),
                                    password.c_str(),
                                    password.size()) == 0;
}

static std::string random_token_b64url(size_t nbytes) {
    sodium_init_or_throw();
    std::vector<unsigned char> buf(nbytes);
    randombytes_buf(buf.data(), buf.size());

    size_t out_len = sodium_base64_encoded_len(buf.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    std::string out(out_len, '\0');
    sodium_bin2base64(out.data(), out.size(), buf.data(), buf.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(strlen(out.c_str()));
    return out;
}

// -------------------- Utility --------------------
static std::string header(const crow::request& req, const std::string& k) {
    auto v = req.get_header_value(k);
    return v.empty() ? "" : v;
}

static std::string client_ip(const crow::request& req) {
    // If behind Nginx, X-Forwarded-For is present. In production, trust only your proxy.
    auto xf = req.get_header_value("X-Forwarded-For");
    if (!xf.empty()) {
        // take first IP
        auto pos = xf.find(',');
        return pos == std::string::npos ? xf : xf.substr(0, pos);
    }
    return req.remote_ip_address;
}

static void set_cookie_sid(crow::response& res, const std::string& sid) {
    // Secure requires HTTPS (Nginx). SameSite=Lax is a sane default.
    res.add_header("Set-Cookie", "sid=" + sid + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000");
}

static void clear_cookie_sid(crow::response& res) {
    res.add_header("Set-Cookie", "sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax");
}

static crow::response json_error(int code, const std::string& msg) {
    crow::json::wvalue out;
    out["error"] = msg;
    return crow::response(code, out);
}

// -------------------- DB --------------------

struct Db {
    std::string connstr;
    std::unique_ptr<pqxx::connection> conn;
    std::mutex m;

    explicit Db(std::string cs) : connstr(std::move(cs)) {}

    void ensure_prepared(pqxx::connection& c) {
        // Læg ALLE dine c.prepare(...) her:
        c.prepare("user_by_email",
            "SELECT id, password_hash, is_active, failed_logins, lab_id, locked_until "
            "FROM users WHERE email=$1");

        c.prepare("insert_user",
            "INSERT INTO users(email, password_hash) VALUES($1,$2) RETURNING id");

        c.prepare("inc_failed",
            "UPDATE users SET failed_logins = failed_logins + 1 WHERE id=$1");

        c.prepare("lock_user",
            "UPDATE users SET locked_until = now() + interval '15 minutes' WHERE id=$1");

        c.prepare("reset_failed",
            "UPDATE users SET failed_logins=0, locked_until=NULL, last_login_at=now() WHERE id=$1");

        c.prepare("create_session",
        		"INSERT INTO sessions(id, user_id, lab_id, csrf_token, created_at, last_seen_at, expires_at, ip, user_agent) "
						"VALUES ($1::uuid, $2, $3, $4, now(), now(), now() + interval '30 days', $5::inet, $6)");
//            "INSERT INTO sessions(id, user_id, csrf_token, expires_at, ip, user_agent) "
//            "VALUES($1::uuid, $2, $3, now() + interval '30 days', $4::inet, $5)");

        c.prepare("session_by_id",
            "SELECT s.id::text, s.user_id, s.lab_id, s.csrf_token, (s.expires_at > now()) AS valid "
            "FROM sessions s WHERE s.id=$1::uuid");

        c.prepare("touch_session",
            "UPDATE sessions SET last_seen_at=now() WHERE id=$1::uuid");

        c.prepare("delete_session",
            "DELETE FROM sessions WHERE id=$1::uuid");

        c.prepare("rl_get",
            "SELECT window_start, count FROM rate_limits WHERE key=$1");

        c.prepare("rl_insert",
            "INSERT INTO rate_limits(key, window_start, count) VALUES($1, now(), 1)");

        c.prepare("rl_reset",
            "UPDATE rate_limits SET window_start=now(), count=1 WHERE key=$1");

        c.prepare("rl_inc",
            "UPDATE rate_limits SET count = count + 1 WHERE key=$1");
            
        c.prepare("user_hash_by_id",
					  "SELECT password_hash FROM users WHERE id = $1");
				
				c.prepare("update_user_hash",
					  "UPDATE users SET password_hash = $2 WHERE id = $1");
				
				c.prepare("delete_sessions_by_user",
				          "DELETE FROM sessions WHERE user_id=$1 AND lab_id=$2");
				
				c.prepare("delete_user_by_id",
				          "DELETE FROM users WHERE id=$1 AND lab_id=$2");
	  
				c.prepare("admin_list_users",
				  "SELECT id, email, is_admin, disabled, created_at FROM users ORDER BY id DESC LIMIT $1 OFFSET $2");
				
				c.prepare("admin_set_disabled",
				  "UPDATE users SET disabled=$2 WHERE id=$1");
				
				c.prepare("admin_delete_sessions_by_user",
				  "DELETE FROM sessions WHERE user_id=$1");
				
				c.prepare("admin_delete_user",
				  "DELETE FROM users WHERE id=$1");

				
				// Valgfrit: invalider alle andre sessions end den aktuelle
				c.prepare("drop_other_sessions",
					  "DELETE FROM sessions WHERE user_id = $1 AND id <> $2");

    }


    pqxx::connection& get() {
        std::lock_guard<std::mutex> lock(m);
        if (!conn || !conn->is_open()) {
            conn = std::make_unique<pqxx::connection>(connstr);
            ensure_prepared(*conn);
        }
        return *conn;
    }

    // optional: allow updating connstr if you reload config later
};

// -------------------- Rate limiting (DB-based) --------------------
static bool rate_limit_ok(Db& db,
                   const std::string& key,
                   int limit,
                   int window_seconds) {
    // window_seconds used for logic; stored as window_start timestamp + compare
    // In production, Redis is nicer, but this works.

    try {
    	pqxx::work tx(db.get());
    		
    	auto r = tx.exec_prepared("rl_get",key);

	    if (r.empty()) {
	        tx.exec_prepared("rl_insert",key);
	        tx.commit();
	        return true;
	    }
	
	    auto window_start = r[0]["window_start"].as<std::string>();
	    int count = r[0]["count"].as<int>();
	
	    // Compare in SQL to avoid timezone parsing in C++
	    // If now - window_start > window_seconds => reset
	    auto expired = tx.exec1(
	        "SELECT (extract(epoch from (now() - window_start)) > " + tx.quote(window_seconds) +
	        ") AS expired FROM rate_limits WHERE key=" + tx.quote(key)
	    )[0].as<bool>();
	
	    if (expired) {
	        tx.exec_prepared("rl_reset",key);
	        tx.commit();
	        return true;
	    }
	
	    if (count >= limit) {
	        tx.commit();
	        return false;
	    }
	
	    tx.exec_prepared("rl_inc",key);
	    tx.commit();
	    return true;
	  }
	  catch (const pqxx::broken_connection& e) {
	    // DB nede / forkert login / netværk
  	  json_error(503, std::string("Database unavailable"));
  	  return false;
		}
		catch (const pqxx::sql_error& e) {
	    // SQL fejl (syntax, constraint osv.)
	    json_error(500, std::string("Database error"));
  	  return false;
		}
		catch (const std::exception& e) {
	    json_error(500, std::string("Server error"));
  	  return false;
		}
	}


// -------------------- Session helpers --------------------
struct SessionInfo {
    std::string sid;
    int64_t user_id;
    int64_t lab_id;          // <-- NY
    std::string csrf_token;
};


enum class SessionCheck { Ok, NotLoggedIn, DbDown };

static SessionCheck require_session(Db& db, const crow::request& req, SessionInfo& out)
{
    auto sidOpt = get_cookie_value(req, "sid");
    if (!sidOpt || sidOpt->empty())
        return SessionCheck::NotLoggedIn;

    try {
        pqxx::work tx(db.get());

        auto r = tx.exec_prepared("session_by_id", *sidOpt);

        if (r.empty()) { tx.commit(); return SessionCheck::NotLoggedIn; }

        bool valid = r[0]["valid"].as<bool>();
        if (!valid) { tx.commit(); return SessionCheck::NotLoggedIn; }

        out.sid = r[0]["id"].as<std::string>();
        out.user_id = r[0]["user_id"].as<int64_t>();
        out.lab_id  = r[0]["lab_id"].as<int64_t>(); 
        out.csrf_token = r[0]["csrf_token"].as<std::string>();

				if (should_touch(out.sid)) {
				    tx.exec_prepared("touch_session", out.sid);
				}
        tx.commit();
        return SessionCheck::Ok;
    }
    catch (const pqxx::broken_connection&) {
        return SessionCheck::DbDown;
    }
    catch (const std::exception&) {
        return SessionCheck::DbDown;
    }
}


static bool is_admin(Db& db, int64_t user_id) {
    pqxx::work tx(db.get());
    auto r = tx.exec_params("SELECT is_admin FROM users WHERE id = $1",(long long)user_id);
    tx.commit();
    if (r.empty()) return false;
    return r[0][0].as<bool>();
}


static bool require_admin_session2(Db& db,
                                   const crow::request& req,
                                   SessionInfo& out,
                                   crow::response& err_out)
{
    auto sidOpt = get_cookie_value(req, "sid"); // du har allerede denne helper
    if (!sidOpt || sidOpt->empty()) {
        err_out = json_error(401, "Not logged in");
        return false;
    }
    std::string sid = *sidOpt;

    try {
        pqxx::work tx(db.get());

        // 1) session lookup (tilpas kolonnenavne hvis dine hedder noget andet)
				auto rs = tx.exec_params(
				    "SELECT id, user_id, lab_id, csrf_token, (expires_at > now()) AS valid "
				    "FROM sessions WHERE id = $1",
				    sid
				);
        if (rs.empty()) { tx.commit(); err_out = json_error(401, "Not logged in"); return false; }

        bool valid = false;
        try { valid = rs[0]["valid"].as<bool>(); } catch (...) { valid = true; } // hvis du ikke har expires_at
        if (!valid) { tx.commit(); err_out = json_error(401, "Not logged in"); return false; }

        out.sid = rs[0]["id"].as<std::string>();
        out.user_id = rs[0]["user_id"].as<int64_t>();
 				out.lab_id  = rs[0]["lab_id"].as<int64_t>(); 
        out.csrf_token = rs[0]["csrf_token"].as<std::string>();

        // optional touch (hvis du vil)
        // var der ikke før ændring med lab_id
        tx.exec_params("UPDATE sessions SET last_seen_at=now() WHERE user_id=$1 AND lab_id=$2;",
        	(long long)out.user_id, (long long)out.lab_id );

        // 2) admin check
        auto ra = tx.exec_params(
            "SELECT is_admin FROM users WHERE id = $1",
            (long long)out.user_id
        );

        tx.commit();

        if (ra.empty() || !ra[0][0].as<bool>()) {
            err_out = json_error(403, "Admin only");
            return false;
        }

        return true;

    } catch (const pqxx::broken_connection&) {
        err_out = json_error(503, "DB down");
        return false;

		} catch (const pqxx::sql_error& e) {
		    CROW_LOG_ERROR << "require_admin_session2 SQL error: " << e.what()
		                   << " query=" << e.query();
		    err_out = json_error(503, "DB error 120");
        return false;
		} catch (const std::exception& e) {
		    CROW_LOG_ERROR << "require_admin_session2: " << e.what();
		    err_out = json_error(503, "DB error 121");
        return false;
		} catch (...) {
		    CROW_LOG_ERROR << "require_admin_session2 unknown exception";
		    err_out = json_error(503, "DB error 122");
        return false;
		}


/*
        
    } catch (const pqxx::broken_connection&) {
        err_out = json_error(503, "DB down");
        return false;
    } catch (const std::exception&) {
        err_out = json_error(503, "DB error 104");
        return false;
    }*/
}




static bool require_admin_session(Db& db,
                                  const crow::request& req,
                                  SessionInfo& out,
                                  crow::response& err_out)
{
    // 1) require normal session
    auto rc = require_session(db, req, out);

    // Tilpas disse cases til din SessionCheck enum/navne
    if (rc == SessionCheck::NotLoggedIn) { //Ok, , DbDown
        err_out = json_error(401, "Not logged in");
        return false;
    }
    if (rc == SessionCheck::DbDown) {
        err_out = json_error(503, "DB down 3");
        return false;
    }
    if (rc != SessionCheck::Ok) {
        err_out = json_error(401, "Not logged in");
        return false;
    }

    // 2) admin check
    try {
        pqxx::work tx(db.get());
        auto r = tx.exec_params("SELECT is_admin FROM users WHERE id = $1",(long long)out.user_id);

        tx.commit();

        if (r.empty() || !r[0][0].as<bool>()) {
            err_out = json_error(403, "Admin only");
            return false;
        }
    } catch (const pqxx::broken_connection&) {
        err_out = json_error(503, "DB down 4");
        return false;
    } catch (...) {
        err_out = json_error(503, "DB error 5");
        return false;
    }

    return true;
}


static bool require_csrf(const crow::request& req, const SessionInfo& s) {
    // Header-based token
    auto token = req.get_header_value("X-CSRF-Token");
    return !token.empty() && token == s.csrf_token;
}

// -------------------- Main --------------------
int main() {
    // Set APP_DB env via systemd or export before running
    const char* cs = std::getenv("APP_DB");
    std::string connstr = cs ? cs : "dbname=lptdb user=lptsql password=3x/2Ccy^{c{!FE%mM}jX host=127.0.0.1 port=5432";

    Db db(connstr);

    crow::SimpleApp app;

    // Health
    CROW_ROUTE(app, "/health").methods("GET"_method) 
		([&db]{
		    crow::json::wvalue out;
		    out["ok"] = true;
		    try {
		        pqxx::work tx(db.get());
		        tx.exec("SELECT 1");
		        tx.commit();
		        out["db"] = "ok";
		        return crow::response(200, out);
		    } catch (const pqxx::broken_connection&) {
		        out["db"] = "down";
		        return crow::response(503, out);
		    } catch (...) {
		        out["db"] = "down";
		        return crow::response(503, out);
		    }
			}
		);

    // Register (no session required)
    
		// Register (ADMIN ONLY, same lab as current admin)
		CROW_ROUTE(app, "/auth/register").methods("POST"_method)
		([&db](const crow::request& req) {
		
		    // kræv admin session
		    SessionInfo s;
		    crow::response err;
		    if (!require_admin_session2(db, req, s, err)) return err;

		    // kræv CSRF (samme som dine andre POSTs)
				if (!require_csrf(req, s))
		        return json_error(403, "CSRF required");
		
		    auto body = crow::json::load(req.body);
		    if (!body) return json_error(400, "Invalid JSON");
		    	
		    if (!body.has("email") || !body.has("password")) return json_error(400, "Missing fields");
		    	
		    std::string email = trim_copy(body["email"].s());
				to_lower_ascii_inplace(email);
		    std::string password = body["password"].s();
		
		
		    if (email.size() < 3 || email.size() > 320) return json_error(400, "Invalid email");
		    if (password.size() < 12 || password.size() > 256) return json_error(400, "Weak password");
		
		    std::string hash;
		    try {
		        hash = hash_password_argon2id(password);
		    } catch (...) {
		        return json_error(500, "Hashing failed");
		    }
		
		    try {
		        pqxx::work tx(db.get());
		
		        // email unikhed er nu pr lab: (lab_id, email)
		        tx.exec_params(
		            "INSERT INTO users(lab_id, email, password_hash) VALUES ($1, $2, $3)",
		            (long long)s.lab_id, email, hash
		        );
		
		        tx.commit();
		        return crow::response(201, crow::json::wvalue{{"ok", true}});
			} catch (const pqxx::unique_violation&) {
					   return json_error(409, "Email already exists");
			} catch (...) {
					   return json_error(503, "Register - DB error");
			}
		});
    

		CROW_ROUTE(app, "/healthz").methods("GET"_method)
		([]{
		    crow::json::wvalue out;
		    out["ok"] = true;
		    return crow::response(200, out);
		});
		

    // Login (rate limited per IP)
    CROW_ROUTE(app, "/auth/login").methods("POST"_method)
    ([&db](const crow::request& req) {
    	
    	
	    	const std::string ip = client_ip(req);
				const std::string rip = req.remote_ip_address;  // crow
				const std::string ua = header(req, "User-Agent");
					
				bool bypass = (ip == "127.0.0.1" || rip == "127.0.0.1");
				if (!bypass) {
				    if (!rate_limit_ok(db, "login:" + ip, 10, 600)) return json_error(429, "Too many attempts");
				}

//    	
//        const std::string ip = client_ip(req);
//        const std::string ua = header(req, "User-Agent");
//
//				bool bypass = (ip == "127.0.0.1");
//				
//				if (!bypass) {
//				    if (!rate_limit_ok(db, "login:" + ip, /*limit*/10, /*window*/600)) {
//				        return json_error(429, "Too many attempts");
//				    }
//				}
//			
        auto body = crow::json::load(req.body);
        if (!body) return json_error(400, "Invalid JSON");

        const std::string email = body["email"].s();
        const std::string password = body["password"].s();

        try {
            pqxx::work tx(db.get());
            auto rows = tx.exec_prepared("user_by_email",email);

            // Avoid enumeration
            if (rows.empty()) { tx.commit(); return json_error(401, "Invalid credentials"); }

            auto row = rows[0];
            const int64_t user_id = row["id"].as<int64_t>();
            const int64_t lab_id  = row["lab_id"].as<int64_t>(); 
            const std::string stored_hash = row["password_hash"].as<std::string>();
            const bool is_active = row["is_active"].as<bool>();
            const int failed = row["failed_logins"].as<int>();

            // locked_until check in SQL to avoid parsing timestamp
            bool locked = tx.exec1(
                "SELECT (locked_until IS NOT NULL AND locked_until > now()) AS locked "
                "FROM users WHERE id=" + tx.quote(user_id)
            )[0].as<bool>();

            if (!is_active) { tx.commit(); return json_error(403, "Account disabled"); }
            if (locked) { tx.commit(); return json_error(403, "Account temporarily locked"); }

            if (!verify_password_argon2id(stored_hash, password)) {
                tx.exec_prepared("inc_failed",user_id);
                if (failed + 1 >= 10) tx.exec_prepared("lock_user",user_id);
                tx.commit();
                return json_error(401, "Invalid credentials");
            }

            // Success: reset failed counter
            tx.exec_prepared("reset_failed",user_id);

            // Generate session id in DB
            std::string sid = tx.exec1("SELECT gen_random_uuid()")[0].as<std::string>();

            // CSRF token bound to session
            std::string csrf = random_token_b64url(32);

						//tx.exec_prepared("create_session", sid, user_id, csrf, ip, ua);
						tx.exec_prepared("create_session", sid, user_id, lab_id, csrf, ip, ua);
						tx.commit();

            crow::json::wvalue out;
            out["ok"] = true;

            crow::response res(200, out);
            set_cookie_sid(res, sid);
            return res;
       } catch (const pqxx::sql_error& e) {
					CROW_LOG_ERROR << "SQL error: " << e.what()  << " query=" << e.query();
			    return json_error(500, "Server error");
			} catch (const std::exception& e) {
			    CROW_LOG_ERROR << "Exception: " << e.what();
			    return json_error(500, "Server error");
			} catch (...) {
			    CROW_LOG_ERROR << "Unknown exception in /auth/login";
			    return json_error(500, "Server error");
			}

    });


    // Logout (CSRF protected)


		CROW_ROUTE(app, "/auth/logout").methods("POST"_method)
		([&db](const crow::request& req) {
		    SessionInfo s;
		    crow::response err;
		    auto st = require_session(db, req, s);
		    if (st == SessionCheck::DbDown)
		        return json_error(503, "Database unavailable");
		    if (st == SessionCheck::NotLoggedIn)
		        return json_error(401, "Not logged in");
		
		    if (!require_csrf(req, s))
		        return json_error(403, "CSRF required");
		
		    try {
		        pqxx::work tx(db.get());
		        tx.exec_params("DELETE FROM sessions WHERE id=$1 AND lab_id=$2",
		                       s.sid, (long long)s.lab_id);
		        tx.commit();
		
		        crow::json::wvalue out;
		        out["ok"] = true;
		        crow::response res(200, out);
		
		        // Slet cookie i browseren:
		        // VIGTIGT: Path=/ skal matche den du satte ved login
		        clear_cookie_sid(res);
		        return res;
		    } catch (...) {
		        return json_error(503, "DB error");
		    }
		});



		CROW_ROUTE(app, "/auth/me").methods("GET"_method)
		([&db](const crow::request& req) {
				SessionInfo s;
	      auto st = require_session(db, req, s);
	      
	      if (st == SessionCheck::DbDown)
			    return json_error(503, "Database unavailable");
		    if (st == SessionCheck::NotLoggedIn)
		        return json_error(401, "Not logged in");
		
		    try {
		        pqxx::work tx(db.get());
		        auto r = tx.exec_params(
						    "SELECT email, is_admin FROM users WHERE id=$1 AND lab_id=$2",
						    (long long)s.user_id, (long long)s.lab_id
						);

		        tx.commit();
		
		        if (r.empty()) return json_error(500, "User missing");
		
		        crow::json::wvalue out;
		        out["id"] = (long long)s.user_id;
		        out["email"]   = r[0]["email"].as<std::string>();
		        out["is_admin"] = r[0]["is_admin"].as<bool>();
		        return crow::response(200, out);
		    } catch (...) {
		        return json_error(503, "DB error 105");
		    }
		});


    // CSRF token fetch (requires session)
    CROW_ROUTE(app, "/auth/csrf").methods("GET"_method)
    ([&db](const crow::request& req) {
    	SessionInfo s;
      auto st = require_session(db, req,s);
			if (st == SessionCheck::DbDown)
	        return json_error(503, "Database unavailable");
	    if (st == SessionCheck::NotLoggedIn)
	        return json_error(401, "Not logged in");
	  
      crow::json::wvalue out;
  		out["csrf_token"] = s.csrf_token;
    	return crow::response(200, out);
    		
    });
    

		CROW_ROUTE(app, "/auth/change_password").methods("POST"_method)
		([&db](const crow::request& req) {

	    	SessionInfo s;
		
		    auto st = require_session(db, req,s);
		    if (st == SessionCheck::NotLoggedIn) 
		    	return json_error(401, "Not logged in");
		
		    if (!require_csrf(req, s))
		        return json_error(403, "CSRF required");

		    auto body = crow::json::load(req.body);
		    if (!body) return json_error(400, "Bad JSON");
		


		    if (!body.has("old_password") || !body.has("new_password"))
		        return json_error(400, "Missing fields");
		
		    std::string old_pw = body["old_password"].s();
		    std::string new_pw = body["new_password"].s();
		
		    // Valider længde (du kan hæve til 12/14/16 som du ønsker)
		    if (new_pw.size() < 12) return json_error(400, "Password too short");
		
		    // (Optional) undgå alt for lange passwords (DoS via kæmpe body)
		    if (new_pw.size() > 200) return json_error(400, "Password too long");
		
		    try {
		        pqxx::work tx(db.get());
		
		        // Hent eksisterende hash
		        auto r = tx.exec_prepared("user_hash_by_id", (long long)s.user_id);
		        if (r.empty()) { tx.commit(); return json_error(404, "User not found"); }
		
		        std::string hash = r[0][0].as<std::string>();
		
		        // Verify old_password
		        if (crypto_pwhash_str_verify(hash.c_str(), old_pw.c_str(), old_pw.size()) != 0) {
		            tx.commit();
		            // samme besked som ved forkert login (ingen info leakage)
		            return json_error(401, "Invalid credentials");
		        }
		
		        // Hash new_password
		        char new_hash[crypto_pwhash_STRBYTES];
		        if (crypto_pwhash_str(new_hash,
		                              new_pw.c_str(),
		                              (unsigned long long)new_pw.size(),
		                              crypto_pwhash_OPSLIMIT_MODERATE,
		                              crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
		            tx.commit();
		            return json_error(500, "Hashing failed");
		        }
		
		        tx.exec_prepared("update_user_hash",
		                         (long long)s.user_id,
		                         std::string(new_hash));
		
		        // Valgfrit: invalider alle andre sessions end den aktuelle
		        tx.exec_prepared("drop_other_sessions",
		                         (long long)s.user_id,
		                         s.sid);
		
		        tx.commit();
		        return crow::response(200, crow::json::wvalue{{"ok", true}});
		    } catch (const pqxx::broken_connection&) {
		        return json_error(503, "DB down 6");
		    } catch (const std::exception&) {
		        return json_error(503, "DB error 7");
		    }
		});

		CROW_ROUTE(app, "/auth/delete_account").methods("POST"_method)
		([&db](const crow::request& req) {
    		SessionInfo s;

		    auto st = require_session(db, req,s);
		    if (st == SessionCheck::NotLoggedIn) 
		    	return json_error(401, "Not logged in");
		
		    if (!require_csrf(req, s))
		        return json_error(403, "CSRF required");

		    auto body = crow::json::load(req.body);
		    if (!body) return json_error(400, "Bad JSON");
		
		    if (!body.has("password"))
		        return json_error(400, "Missing password");
		
		    std::string pw = body["password"].s();
		
		    try {
		        pqxx::work tx(db.get());
		
		        // fetch hash
		        auto r = tx.exec_prepared("user_hash_by_id", (long long)s.user_id);
		        if (r.empty()) { tx.commit(); return json_error(404, "User not found"); }
		        std::string hash = r[0][0].as<std::string>();
		
		        // verify password
		        if (crypto_pwhash_str_verify(hash.c_str(), pw.c_str(), pw.size()) != 0) {
		            tx.commit();
		            return json_error(401, "Invalid credentials");
		        }
		
		        // If you don't have ON DELETE CASCADE for sessions, do:
		        // tx.exec_prepared("delete_sessions_by_user", (long long)s->user_id);
		
						tx.exec_prepared("delete_sessions_by_user", (long long)s.user_id, (long long)s.lab_id);
						auto rd = tx.exec_prepared("delete_user_by_id", (long long)s.user_id, (long long)s.lab_id);
						if (rd.affected_rows() == 0) { tx.commit(); return json_error(404, "Not found"); }
		
		        tx.commit();
		
		        // Clear cookie (sid) in response
		        crow::response resp(200, crow::json::wvalue{{"ok", true}});
						clear_cookie_sid(resp);
		        //resp.add_header("Set-Cookie", "sid=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");
		        return resp;
		    } catch (const pqxx::broken_connection&) {
		        return json_error(503, "DB down 8");
		    } catch (const std::exception&) {
		        return json_error(503, "DB error 9");
		    }
		});



		CROW_ROUTE(app, "/admin/users").methods("GET"_method)
		([&db](const crow::request& req) {
		    SessionInfo s;
		    crow::response err;
		    if (!require_admin_session2(db, req, s, err)) return err;
		
		    int limit = 50, offset = 0;
		    if (req.url_params.get("limit"))  limit  = std::min(200, std::max(1, atoi(req.url_params.get("limit"))));
		    if (req.url_params.get("offset")) offset = std::max(0, atoi(req.url_params.get("offset")));
		
		    std::string q;
		    if (req.url_params.get("q")) q = req.url_params.get("q");
		
		    try {
		        pqxx::work tx(db.get());
		
		        crow::json::wvalue out;
		        out["ok"] = true;
		        out["limit"] = limit;
		        out["offset"] = offset;
		        out["q"] = q;
		
		        crow::json::wvalue::list users;
		
		        if (!q.empty()) {
		            // count (LAB SCOPED)
		            auto rc = tx.exec_params(
		                "SELECT COUNT(*) AS cnt "
		                "FROM users "
		                "WHERE lab_id = $1 AND email ILIKE '%' || $2 || '%'",
		                (long long)s.lab_id, q
		            );
		            out["total"] = rc[0]["cnt"].as<long long>();
		
		            // page (LAB SCOPED + SEARCH)
		            auto r = tx.exec_params(
		                "SELECT id, email, is_admin, disabled, created_at "
		                "FROM users "
		                "WHERE lab_id = $1 AND email ILIKE '%' || $2 || '%'"
		                "ORDER BY id DESC "
		                "LIMIT $3 OFFSET $4",
		                (long long)s.lab_id, q, limit, offset
		            );
		
		            for (auto row : r) {
		                crow::json::wvalue u;
		                u["id"] = row["id"].as<long long>();
		                u["email"] = row["email"].as<std::string>();
		                u["is_admin"] = row["is_admin"].as<bool>();
		                u["disabled"] = row["disabled"].as<bool>();
		                try { u["created_at"] = row["created_at"].as<std::string>(); } catch (...) {}
		                users.push_back(std::move(u));
		            }
		        } else {
		            // count (LAB SCOPED)
		            auto rc = tx.exec_params(
		                "SELECT COUNT(*) AS cnt FROM users WHERE lab_id = $1",
		                (long long)s.lab_id
		            );
		            out["total"] = rc[0]["cnt"].as<long long>();
		
		            // page (LAB SCOPED)
		            auto r = tx.exec_params(
		                "SELECT id, email, is_admin, disabled, created_at "
		                "FROM users "
		                "WHERE lab_id = $1 "
		                "ORDER BY id DESC "
		                "LIMIT $2 OFFSET $3",
		                (long long)s.lab_id, limit, offset
		            );
		
		            for (auto row : r) {
		                crow::json::wvalue u;
		                u["id"] = row["id"].as<long long>();
		                u["email"] = row["email"].as<std::string>();
		                u["is_admin"] = row["is_admin"].as<bool>();
		                u["disabled"] = row["disabled"].as<bool>();
		                try { u["created_at"] = row["created_at"].as<std::string>(); } catch (...) {}
		                users.push_back(std::move(u));
		            }
		        }
		
		        out["users"] = std::move(users);
		
		        tx.commit();
		        return crow::response(200, out);

					} catch (const pqxx::sql_error& e) {
					    CROW_LOG_ERROR << "admin/users SQL error: " << e.what()
					                   << " query=" << e.query();
					    return json_error(503, "DB error");
					} catch (const std::exception& e) {
					    CROW_LOG_ERROR << "admin/users exception: " << e.what();
					    return json_error(503, "DB error");
					} catch (...) {
					    CROW_LOG_ERROR << "admin/users unknown exception";
					    return json_error(503, "DB error");
					}
//		    } catch (...) {
//		        return json_error(503, "DB error");
//		    }
		});



		CROW_ROUTE(app, "/admin/users/set_admin").methods("POST"_method)
		([&db](const crow::request& req) {
		    SessionInfo s;
		    crow::response err;
		    if (!require_admin_session2(db, req, s, err)) return err;
		
				if (!require_csrf(req, s))
		        return json_error(403, "CSRF required");
		
		    auto body = crow::json::load(req.body);
		    if (!body || !body.has("user_id") || !body.has("is_admin"))
		        return json_error(400, "Bad JSON");
		
		    int64_t uid = body["user_id"].i();
		    bool is_admin = body["is_admin"].b();
		
		    // Undgå at man fjerner admin fra sig selv (kan låse systemet)
		    if (uid == s.user_id && !is_admin) return json_error(400, "Cannot remove admin from self");
		
		    try {
		        pqxx::work tx(db.get());
		
		        auto r = tx.exec_params(
		            "UPDATE users SET is_admin=$3, updated_at=now() "
		            "WHERE id=$1 AND lab_id=$2 "
		            "RETURNING id",
		            (long long)uid, (long long)s.lab_id, is_admin
		        );
		
		        tx.commit();
		
		        if (r.empty()) return json_error(404, "Not found");
		        return crow::response(200, crow::json::wvalue{{"ok", true}});
		    } catch (...) {
		        return json_error(503, "DB error 101");
		    }
		});
		


		CROW_ROUTE(app, "/admin/users/disable").methods("POST"_method)
		([&db](const crow::request& req) {
				
		    SessionInfo s;
		    crow::response err;
		    if (!require_admin_session2(db, req, s, err)) return err;
		
				if (!require_csrf(req, s))
		        return json_error(403, "CSRF required");
		
		    auto body = crow::json::load(req.body);
		    if (!body || !body.has("user_id") || !body.has("disabled"))
		        return json_error(400, "Bad JSON");
		
		    int64_t uid = body["user_id"].i();
		    bool disabled = body["disabled"].b();
		
		    if (uid == s.user_id) return json_error(400, "Cannot disable self");
		
		    try {
		        pqxx::work tx(db.get());
		
		        auto r = tx.exec_params(
		            "UPDATE users SET disabled=$3, updated_at=now() "
		            "WHERE id=$1 AND lab_id=$2 "
		            "RETURNING id",
		            (long long)uid, (long long)s.lab_id, disabled
		        );
		
		        tx.commit();
		
		        if (r.empty()) return json_error(404, "Not found");
		        return crow::response(200, crow::json::wvalue{{"ok", true}});
		    } catch (...) {
		        return json_error(503, "DB error 102");
		    }
		});



		CROW_ROUTE(app, "/admin/users/delete").methods("POST"_method)
		([&db](const crow::request& req) {
		
		    SessionInfo s;
		    crow::response err;
		    if (!require_admin_session2(db, req, s, err)) return err;
		
				if (!require_csrf(req, s))
		        return json_error(403, "CSRF required");
		
		    auto body = crow::json::load(req.body);
		    if (!body || !body.has("user_id"))
		        return json_error(400, "Bad JSON");
		
		    int64_t uid = body["user_id"].i();
		    if (uid == s.user_id) return json_error(400, "Cannot delete self");
		
		    try {
		        pqxx::work tx(db.get());
		
		        // Slet sessions for user i samme lab (ingen cross-lab)
		        tx.exec_params(
		            "DELETE FROM sessions WHERE user_id=$1 AND lab_id=$2",
		            (long long)uid, (long long)s.lab_id
		        );
		
		        // Slet user i samme lab
		        auto r = tx.exec_params(
		            "DELETE FROM users WHERE id=$1 AND lab_id=$2 RETURNING id",
		            (long long)uid, (long long)s.lab_id
		        );
		
		        tx.commit();
		
		        if (r.empty()) return json_error(404, "Not found");
		        return crow::response(200, crow::json::wvalue{{"ok", true}});
		    } catch (...) {
		        return json_error(503, "DB error 103");
		    }
		});

		
		CROW_ROUTE(app, "/auth/bootstrap_admin").methods("POST"_method)
		([&db](const crow::request& req) {
		    auto body = crow::json::load(req.body);
		    if (!body) return json_error(400, "Invalid JSON");
		
		    if (!body.has("lab") || !body.has("token") || !body.has("email") || !body.has("password"))
		        return json_error(400, "Missing fields");
		
		    std::string lab   = body["lab"].s();
		    std::string token = body["token"].s();
		    std::string email = body["email"].s();
		    std::string password = body["password"].s();
		
		    if (lab.size() < 1 || lab.size() > 64) return json_error(400, "Invalid lab");
		    if (token.size() < 16 || token.size() > 256) return json_error(400, "Invalid token");
		    if (email.size() < 3 || email.size() > 320) return json_error(400, "Invalid email");
		    if (password.size() < 12 || password.size() > 256) return json_error(400, "Weak password");
		
		    std::string pw_hash;
		    try {
		        pw_hash = hash_password_argon2id(password);
		    } catch (...) {
		        return json_error(500, "Hashing failed");
		    }
		
		    auto th = token_hash32(token);
		    std::string th_hex = to_hex(th.data(), th.size());
		
		    try {
		        pqxx::work tx(db.get());
		
		        // 1) find lab_id
		        auto labr = tx.exec_params("SELECT id FROM labs WHERE code=$1", lab);
		        if (labr.empty()) { tx.commit(); return json_error(404, "Unknown lab"); }
		        int64_t lab_id = labr[0]["id"].as<long long>();
		
		        // 2) refuse if an admin already exists for this lab
		        auto ar = tx.exec_params(
		            "SELECT 1 FROM users WHERE lab_id=$1 AND is_admin=true LIMIT 1",
		            (long long)lab_id
		        );
		        if (!ar.empty()) { tx.commit(); return json_error(409, "Admin already exists"); }
		
		        // 3) lock active token row
						auto tr = tx.exec_params(
						    "SELECT id, encode(token_hash,'hex') AS token_hash_hex "
						    "FROM lab_bootstrap_tokens "
						    "WHERE lab_id=$1 AND used_at IS NULL AND expires_at > now() "
						    "FOR UPDATE",
						    (long long)lab_id
						);
						
						if (tr.empty()) { tx.commit(); return json_error(403, "Invalid token"); }
						
						auto token_row_id = tr[0]["id"].as<long long>();
						std::string db_hex = tr[0]["token_hash_hex"].as<std::string>();
						
						if (db_hex != th_hex) {
						    tx.commit();
						    return json_error(403, "Invalid token");
						}

								        		        
		        // 4) create admin user
		        auto ur = tx.exec_params(
		            "INSERT INTO users(lab_id, email, password_hash, is_admin, is_active, disabled) "
		            "VALUES ($1, $2, $3, true, true, false) "
		            "RETURNING id",
		            (long long)lab_id, email, pw_hash
		        );
		        int64_t new_user_id = ur[0]["id"].as<long long>();
		
		        // 5) mark token as used
		        tx.exec_params(
		            "UPDATE lab_bootstrap_tokens SET used_at=now(), used_by_user_id=$2 WHERE id=$1",
		            (long long)token_row_id, (long long)new_user_id
		        );
		
		        tx.commit();
		
		        crow::json::wvalue out;
		        out["ok"] = true;
		        out["user_id"] = (long long)new_user_id;
		        out["lab_id"] = (long long)lab_id;
		        return crow::response(201, out);
		
		    } catch (const pqxx::unique_violation&) {
		        return json_error(409, "Email already exists");
		    } catch (const pqxx::sql_error& e) {
		        CROW_LOG_ERROR << "bootstrap_admin SQL error: " << e.what() << " query=" << e.query();
		        return json_error(503, "DB error");
		    } catch (const std::exception& e) {
		        CROW_LOG_ERROR << "bootstrap_admin exception: " << e.what();
		        return json_error(503, "DB error");
		    } catch (...) {
		        CROW_LOG_ERROR << "bootstrap_admin unknown exception";
		        return json_error(503, "DB error");
		    }
		});



    // Example protected write endpoint
    CROW_ROUTE(app, "/profile/update").methods("POST"_method)
    ([&db](const crow::request& req) {
  		 SessionInfo s;

      auto st = require_session(db, req,s);
			if (st == SessionCheck::DbDown)
	        return json_error(503, "Database unavailable 16");
	    if (st == SessionCheck::NotLoggedIn)
	        return json_error(401, "Not logged in");

	    if (!require_csrf(req, s))
		        return json_error(403, "CSRF required");

      // ... update something in DB using prepared statements ...
      return crow::response(200);

    });

    // Run on localhost only; Nginx proxies to it
    const char* bind = std::getenv("LOGIN_BIND");
		std::string bindAddr = (bind && *bind) ? bind : "0.0.0.0";
		const char* p = std::getenv("LOGIN_PORT");
		uint16_t port = p ? static_cast<uint16_t>(std::stoi(p)) : 8080;
		
		app.bindaddr(bindAddr).port(port).multithreaded().run();
}
