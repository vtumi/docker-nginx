
// Nginx authentication via TOTP. Subrequest authentication
// using a local FastCGI server.

// The auth endpoint is at /auth
// The server will produce a 401 error whenever the request
// lacks the right authentication Cookie. This error must be
// caught by nginx and handled as a redirection to /login
// which will serve the login page configured.
// Once login is completed correctly, the cookie will be set
// and visiting the endpoint will produce a redirect to the
// original website.

#include <thread>
#include <mutex>
#include <regex>
#include <memory>
#include <cmath>
#include <unordered_map>
#include <fstream>
#include <fcgio.h>
#include <unistd.h>
#include <signal.h>
#include <libconfig.h>
#include <list>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "templates.h"
#include "queue.h"
#include "util.h"
#include "ratelimit.h"
#include "logger.h"

#define TOTP_DEF_DIGITS         6
#define TOTP_DEF_PERIOD        30
#define TOTP_DEF_GENS           1      // Allows a window of 90s by default
#define TOTP_DEF_ALGO      "sha1"

enum htAlgo {
	hAlgoSha1    = 0,
	hAlgoSha256  = 1,
	hAlgoSha512  = 2
};

const std::unordered_map<std::string, htAlgo> algnames = {
	{"sha1",    hAlgoSha1},
	{"sha-256", hAlgoSha256},
	{"sha-512", hAlgoSha512},
};

// Use some reasonable default.
int nthreads = 4;

#define MAX_REQ_SIZE    (4*1024)
#define RET_ERR(x) { std::cerr << x << std::endl; return 1; }

typedef std::unordered_map<std::string, std::string> StrMap;

struct cred_t {
	std::string username;  // Username
	std::string password;  // Password
	std::string totp;      // TOTP (binary)
	unsigned sduration;    // Duration of a valid session (seconds)
	unsigned digits;       // Digits of TOTP
	unsigned period;       // Period of TOTP
	htAlgo algorithm;      // TOTP hashing algorithm
	std::string path;      // Path
};

struct web_t {
	std::string webtemplate;      // Template to use
	unsigned totp_generations;    // 0 means only current code is valid,
	                              // 1 means previous and next code is also valid
	                              // 2 means the 2 previous and next codes are also valid, etc
	std::unordered_map<std::string, std::vector<cred_t>> users;  // User to credential
};

std::unordered_map<std::string, web_t> webcfg;   // Hostname -> Config

struct web_req {
	std::string method, host, uri;
	StrMap getvars, postvars, cookies;
	uint64_t ip64;
};

struct auth_result {
	bool valid = false;
	std::string user;
	std::string path;
	unsigned duration = 0;
	unsigned remaining = 0;   // Seconds until expiry
};

class AuthenticationServer {
private:
	// Secret 'random' string that is used to authenticate cookies
	std::string cookie_secret;

	// Thread to spawn
	std::thread cthread;

	// Shared queue
	ConcurrentQueue<std::unique_ptr<FCGX_Request>> *rq;

	// Rate limiter for auth attempts
	RateLimiter* const rl;

	// Event logging
	Logger *logger;

	// Website configuration
	const std::unordered_map<std::string, web_t>& webcfg;

	// Signal end of workers
	bool end;

	std::string create_cookie(std::string user, std::string path = "/") {
		std::string payload = std::to_string(time(0)) + ":" + hexencode(path + ":" + user);
		std::string token = payload + ":" + hexencode(hmac_sha256(this->cookie_secret, payload));
		return "authentication-token=" + token +
		       "; Path=" + path + "; HttpOnly; SameSite=Strict";
	}

	// Validates the cookie and returns auth result with user info.
	auth_result check_cookie(std::string cookie, const web_t *wcfg, const std::string& path) {
		auth_result res;
		// The cookie format is something like:
		// etime:hex(path:user):hex(hmac)
		auto p1 = cookie.find(':');
		if (p1 == std::string::npos)
			return res;
		auto p2 = cookie.find(':', p1 + 1);
		if (p2 == std::string::npos)
			return res;
		std::string c1 = cookie.substr(0, p1);
		std::string path_user = hexdecode(cookie.substr(p1+1, p2-p1-1));
		std::string hmac = hexdecode(cookie.substr(p2+1));
		uint64_t ets = atol(c1.c_str());

		std::string user = path_user;
		std::string user_path = "/";

		size_t colon_pos = path_user.find(':');
		if (colon_pos != std::string::npos) {
			user_path = path_user.substr(0, colon_pos);
			user = path_user.substr(colon_pos + 1);
		}

		if (path.substr(0, user_path.length()) != user_path) {
			return res;
		}

		const std::vector<cred_t> *users = nullptr;

		// First check the path from cookie (the path where user logged in)
		if (wcfg->users.count(user_path)) {
			users = &wcfg->users.at(user_path);
		}

		if (!users) return res;

		bool user_found = false;
		unsigned duration = 0;
		for (const auto& user_cred : *users) {
			if (user == user_cred.username) {
				duration = user_cred.sduration;
				if ((unsigned)time(0) > ets + duration)
					return res;
				user_found = true;
				break;
			}
		}

		if (!user_found) return res;

		// Finally check the HMAC with the secret to ensure the cookie is valid
		std::string hmac_calc = hmac_sha256(this->cookie_secret, cookie.substr(0, p2));
		if (hmac.size() == hmac_calc.size() &&
		    CRYPTO_memcmp(hmac.c_str(), hmac_calc.c_str(), hmac_calc.size()) == 0) {
			res.valid = true;
			res.user = user;
			res.path = user_path;
			res.duration = duration;
			res.remaining = (unsigned)(ets + duration - time(0));
		}
		return res;
	}

	std::string process_req(web_req *req, const web_t *wcfg) {
		std::string rpage = req->getvars["follow_page"];
		if (rpage.empty())
			rpage = req->postvars["follow_page"];

		if (ends_with(req->uri, "/auth")) {
			// Read cookie and validate the authorization
			auto ar = check_cookie(req->cookies["authentication-token"], wcfg, req->uri);
			logger->log("Requested auth with result: " + std::to_string(ar.valid));
			if (ar.valid) {
				std::string resp = "Status: 200\r\n";
				// Sliding renewal: refresh cookie when remaining < half duration
				if (ar.remaining < ar.duration / 2)
					resp += "Set-Cookie: " + create_cookie(ar.user, ar.path) + "\r\n";
				resp += "Content-Type: text/plain\r\n"
				        "Content-Length: 24\r\n\r\nAuthentication Succeeded";
				return resp;
			}
			else
				return "Status: 401\r\nContent-Type: text/plain\r\n"
				       "Content-Length: 21\r\n\r\nAuthentication Denied";
		}
		else if (ends_with(req->uri, "/login")) {
			if (rpage.empty())
				rpage = req->uri.substr(0, req->uri.length() - 5);

			// Die hard if someone's bruteforcing this
			if (rl->check(req->ip64)) {
				logger->log("Rate limit hit for ip id " + std::to_string(req->ip64));
				return "Status: 429\r\nContent-Type: text/plain\r\n"
				       "Content-Length: 34\r\n\r\nToo many requests, request blocked";
			}
			rl->consume(req->ip64);

			bool lerror = false;
			if (req->method == "POST") {
				std::string user = req->postvars["username"];
				std::string pass = req->postvars["password"];
				unsigned    totp = atoi(req->postvars["totp"].c_str());
				
				const std::vector<cred_t> *users = nullptr;

				if (wcfg->users.count(req->uri)) {
					users = &wcfg->users.at(req->uri);
				}
				else {
					for (const auto& path_users : wcfg->users) {
						if (req->uri.substr(0, path_users.first.length()) == path_users.first) {
							users = &path_users.second;
							break;
						}
					}
				}

				if (!users && wcfg->users.count("/")) {
					users = &wcfg->users.at("/");
				}

				if (users) {
					bool user_found = false;
					for (const auto& user_cred : *users) {
						if (user != user_cred.username)
							continue;

						user_found = true;
						if (!verify_password(pass, user_cred.password)) {
							logger->log("Failed login for user " + user + " on path " + req->uri + ": invalid password");
							break;
						}
						if (!totp_valid(user_cred, totp, wcfg->totp_generations)) {
							logger->log("Failed login for user " + user + " on path " + req->uri + ": invalid TOTP");
							break;
						}

						logger->log("Login successful for user " + user + " on path " + req->uri);

						// Render a redirect page to the redirect address (+cookie)
						std::string cookie = create_cookie(user, user_cred.path);
						return "Status: 302\r\nSet-Cookie: " + cookie +
							   "\r\nLocation: " + stripnl(rpage) + "\r\n\r\n";
					}

					if (!user_found)
						logger->log("Failed login for user " + user + " on path " + req->uri + ": user not found");
				}
				else {
					logger->log("Failed login for user " + user + " on path " + req->uri + ": no users configured");
				}

				lerror = true;   // Render login page with err message
			}

			// Just renders the login page
			if (!templates.count(wcfg->webtemplate))
				return "Status: 500\r\nContent-Type: text/plain\r\n"
					   "Content-Length: 23\r\n\r\nCould not find template";
			else {
				std::string page = templates.at(wcfg->webtemplate)(req->host, rpage, lerror);
				return "Status: 200\r\nContent-Type: text/html\r\n"
					   "Content-Length: " + std::to_string(page.size()) + "\r\n\r\n" + page;
			}
		}
		else if (ends_with(req->uri, "/logout")) {
			std::string logout_path = req->uri.substr(0, req->uri.length() - 6);
			if (logout_path.empty()) logout_path = "/";
			if (rpage.empty())
				rpage = logout_path + "login";

			logger->log("Logout requested");
			// Just redirect to the page (if present, otherwise login) deleting cookie
			return "Status: 302\r\nSet-Cookie: authentication-token=null"
				   "; Path=" + logout_path + "; HttpOnly; SameSite=Strict; Max-Age=0\r\n"
				   "Location: " + stripnl(rpage) + "\r\n\r\n";
		}
		logger->log("Unknown request for URL: " + req->uri);
		return "Status: 404\r\nContent-Type: text/plain\r\n"
			   "Content-Length: 48\r\nNot found, valid endpoints: /auth /login /logout\r\n\r\n";
	}

public:
	AuthenticationServer(ConcurrentQueue<std::unique_ptr<FCGX_Request>> *rq,
		std::string csecret, RateLimiter* const rl, Logger *logger,
		const std::unordered_map<std::string, web_t>& webcfg)
	: rq(rq), rl(rl), logger(logger), webcfg(webcfg), end(false)
	{
		// Use work() as thread entry point
		cthread = std::thread(&AuthenticationServer::work, this);
		if (csecret.empty())
			this->cookie_secret = randstr();
		else
			this->cookie_secret = csecret;
	}

	~AuthenticationServer() {
		// Now join the thread
		cthread.join();
	}

	bool totp_valid(cred_t user, unsigned input, unsigned generations) {
		uint32_t ct = time(0) / user.period;
		for (int i = -(signed)generations; i <= (signed)generations; i++)
			if (totp_calc(user.totp, user.algorithm, user.digits, ct + i) == input)
				return true;
		return false;
	}

	static unsigned totp_calc(std::string key, htAlgo algo, uint8_t digits, uint32_t epoch) {
		const uint32_t po10[] = {
			1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000 };
		std::string(* const algtbl[])(std::string, std::string) = {
			hmac_sha1, hmac_sha256, hmac_sha512
		};
		// Key comes in binary format already!
		// Concatenate the epoc in big endian fashion
		uint8_t msg [8] = {
			0, 0, 0, 0,
			(uint8_t)(epoch >> 24),
			(uint8_t)((epoch >> 16) & 255),
			(uint8_t)((epoch >>  8) & 255),
			(uint8_t)(epoch & 255)
		};

		std::string hashs = algtbl[(unsigned)algo](key, std::string((char*)msg, sizeof(msg)));
		uint8_t *hash = (uint8_t*)hashs.c_str();

		// The last nibble of the hash is an offset:
		unsigned off = hash[hashs.size() - 1] & 15;
		// The result is a substr in hash at that offset (pick 32 bits)
		uint32_t value = (hash[off] << 24) | (hash[off+1] << 16) | (hash[off+2] << 8) | hash[off+3];
		value &= 0x7fffffff;
		return value % po10[digits];
	}

	// Receives requests and processes them by replying via a side http call.
	void work() {
		std::unique_ptr<FCGX_Request> req;
		while (rq->pop(&req)) {
			// Read request body and validate it
			int bsize = atoi(FCGX_GetParam("CONTENT_LENGTH", req->envp) ?: "0");
			bsize = std::max(0, std::min(bsize, MAX_REQ_SIZE));

			// Get streams to write
			fcgi_streambuf reqout(req->out);
			fcgi_streambuf reqin(req->in);
			std::iostream obuf(&reqout);
			std::iostream ibuf(&reqin);

			char body[MAX_REQ_SIZE+1];
			ibuf.read(body, bsize);
			body[bsize] = 0;

			// Find out basic info
			web_req wreq;
			wreq.method   = FCGX_GetParam("REQUEST_METHOD", req->envp) ?: "";
			wreq.uri      = FCGX_GetParam("DOCUMENT_URI", req->envp) ?: "";
			wreq.getvars  = parse_vars(FCGX_GetParam("QUERY_STRING", req->envp) ?: "");
			wreq.postvars = parse_vars(body);
			wreq.host     = FCGX_GetParam("HTTP_HOST", req->envp) ?: "";
			wreq.cookies  = parse_cookies(FCGX_GetParam("HTTP_COOKIE", req->envp) ?: "");

			// Extract source IP
			const char *sip = FCGX_GetParam("REMOTE_ADDR", req->envp) ?: "0.0.0.0";
			struct in6_addr res6; struct in_addr res4;
			if (inet_pton(AF_INET6, sip, &res6) == 1)
				wreq.ip64 = ((uint64_t)res6.s6_addr[0] << 40) | ((uint64_t)res6.s6_addr[1] << 32) |
				            ((uint64_t)res6.s6_addr[2] << 24) | ((uint64_t)res6.s6_addr[3] << 16) |
				            ((uint64_t)res6.s6_addr[4] <<  8) | ((uint64_t)res6.s6_addr[5]);
			else if (inet_pton(AF_INET, sip, &res4) == 1)
				wreq.ip64 = res4.s_addr;
			else
				wreq.ip64 = 0;

			// Lookup hostname for this request
			if (!webcfg.count(wreq.host)) {
				logger->log("Failed to find host '" + wreq.host + "'");
				obuf << "Status: 500\r\nContent-Type: text/plain\r\n"
					 << "Content-Length: " << (wreq.host.size() + 18) << "\r\n\r\n"
					 << "Unknown hostname: " << wreq.host;
			}
			else {
				const web_t* wptr = &webcfg.at(wreq.host);
				std::string resp = process_req(&wreq, wptr);

				// Respond with an immediate update JSON encoded too
				obuf << resp;
			}

			FCGX_Finish_r(req.get());
			req.reset();
		}
	}
};

volatile sig_atomic_t serving = 1;
void sighandler(int) {
	std::cerr << "Signal caught" << std::endl;
	// Just tweak a couple of vars really
	serving = 0;
	// Ask for CGI lib shutdown
	FCGX_ShutdownPending();
	// Close stdin so we stop accepting
	close(0);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " file.conf" << std::endl;
		return 1;
	}

	config_t cfg;
	config_init(&cfg);
	if (!config_read_file(&cfg, argv[1]))
		RET_ERR("Error reading config file");

	// Read config vars
	config_lookup_int(&cfg, "nthreads", (int*)&nthreads);
	nthreads = std::max(nthreads, 1);
	// Number of auth attempts (per ~IP?) per second
	unsigned auths_per_second = 2;
	config_lookup_int(&cfg, "auth_per_second", (int*)&auths_per_second);
	// Secret holds the server secret used to create cookies
	const char *secret;
	if (!config_lookup_string(&cfg, "secret", &secret))
		RET_ERR("'secret' missing, this field is required");
	// Secret holds the server secret used to create cookies
	const char *logpath = "";
	if (!config_lookup_string(&cfg, "log-path", &logpath))
		std::cerr << "'log-path' not specified" << std::endl;

	config_setting_t *webs_cfg = config_lookup(&cfg, "webs");
	if (!webs_cfg)
		RET_ERR("Missing 'webs' config array definition");
	int webscnt = config_setting_length(webs_cfg);
	if (!webscnt)
		RET_ERR("webscnt must be an array of 1 or more elements");

	for (int i = 0; i < webscnt; i++) {
		config_setting_t *webentry  = config_setting_get_elem(webs_cfg, i);
		config_setting_t *hostname  = config_setting_get_member(webentry, "hostname");
		config_setting_t *wtemplate = config_setting_get_member(webentry, "template");
		config_setting_t *totp_gens = config_setting_get_member(webentry, "totp_generations");
		config_setting_t *users_cfg = config_setting_lookup(webentry, "users");

		if (!webentry || !hostname || !wtemplate || !users_cfg)
			RET_ERR("hostname, template and users must be present in the web group");

		web_t wentry = {
			.webtemplate = config_setting_get_string(wtemplate),
			.totp_generations = !totp_gens ? TOTP_DEF_GENS : (unsigned)config_setting_get_int(totp_gens) };

		for (int j = 0; j < config_setting_length(users_cfg); j++) {
			config_setting_t *userentry = config_setting_get_elem(users_cfg, j);
			config_setting_t *path = config_setting_get_member(userentry, "path");
			config_setting_t *user = config_setting_get_member(userentry, "username");
			config_setting_t *pass = config_setting_get_member(userentry, "password");
			config_setting_t *totp = config_setting_get_member(userentry, "totp");
			config_setting_t *algo = config_setting_get_member(userentry, "algorithm");
			config_setting_t *digi = config_setting_get_member(userentry, "digits");
			config_setting_t *peri = config_setting_get_member(userentry, "period");
			config_setting_t *durt = config_setting_get_member(userentry, "duration");

			std::string algorithm = !algo ? TOTP_DEF_ALGO : config_setting_get_string(algo);
			int digits = !digi ? TOTP_DEF_DIGITS : config_setting_get_int(digi);
			int period = !peri ? TOTP_DEF_PERIOD : config_setting_get_int(peri);

			if (!user || !pass || !totp || !durt)
				RET_ERR("username, password, totp and duration must be present in the user group");
			if (digits < 6 || digits > 9)
				RET_ERR("digits must be between 6 and 9 (included)");
			if (period <= 0)
				RET_ERR("period must be bigger than zero");
			if (!algnames.count(algorithm))
				RET_ERR("invalid algorithm specified");

			std::string user_path = "/";
			if (path) {
				user_path = config_setting_get_string(path);
				if (user_path.empty()) user_path = "/";
			}
			
			cred_t cred = {
				.username = config_setting_get_string(user),
				.password = config_setting_get_string(pass),
				.totp = b32dec(b32pad(config_setting_get_string(totp))),
				.sduration = (unsigned)config_setting_get_int(durt),
				.digits = (unsigned)digits,
				.period = (unsigned)period,
				.algorithm = algnames.at(algorithm),
				.path = user_path
			};

			wentry.users[user_path].push_back(cred);
		}

		webcfg[config_setting_get_string(hostname)] = wentry;
	}

	// Start FastCGI interface
	FCGX_Init();

	// Signal handling
	struct sigaction sa = {};
	sa.sa_handler = sighandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, nullptr);
	sigaction(SIGTERM, &sa, nullptr);

	struct sigaction sa_ign = {};
	sa_ign.sa_handler = SIG_IGN;
	sigemptyset(&sa_ign.sa_mask);
	sigaction(SIGPIPE, &sa_ign, nullptr);

	// Start worker threads for this
	auto logger = std::make_unique<Logger>(logpath);
	RateLimiter globalrl(auths_per_second);
	ConcurrentQueue<std::unique_ptr<FCGX_Request>> reqqueue;
	std::vector<std::unique_ptr<AuthenticationServer>> workers;
	for (int i = 0; i < nthreads; i++)
		workers.emplace_back(new AuthenticationServer(
			&reqqueue, secret, &globalrl, logger.get(), webcfg));

	std::cerr << "All workers up, serving until SIGINT/SIGTERM" << std::endl;

	// Now keep ingesting incoming requests, we do this in the main
	// thread since threads are much slower, unlikely to be a bottleneck.
	while (serving) {
		std::unique_ptr<FCGX_Request> request(new FCGX_Request());
		FCGX_InitRequest(request.get(), 0, 0);

		if (FCGX_Accept_r(request.get()) >= 0)
			// Get a worker that's free and queue it there
			reqqueue.push(std::move(request));
	}

	std::cerr << "Signal caught! Starting shutdown" << std::endl;
	reqqueue.close();
	workers.clear();
	logger.reset();

	std::cerr << "All clear, service is down" << std::endl;
}

