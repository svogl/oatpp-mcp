#include "SseAccessTest.hpp"

#include "TestChecks.hpp"

#include "oatpp-mcp/event/Server.hpp"
#include "oatpp-mcp/sse/Controller.hpp"
#include "oatpp-mcp/utils/AccessGuard.hpp"

#include "oatpp/json/ObjectMapper.hpp"
#include "oatpp/web/client/HttpRequestExecutor.hpp"
#include "oatpp/web/mime/ContentMappers.hpp"
#include "oatpp/web/protocol/http/outgoing/BufferBody.hpp"
#include "oatpp/web/server/HttpConnectionHandler.hpp"
#include "oatpp/web/server/HttpRouter.hpp"
#include "oatpp/network/Server.hpp"
#include "oatpp/network/tcp/client/ConnectionProvider.hpp"
#include "oatpp/network/tcp/server/ConnectionProvider.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using oatpp::mcp::test::Checks;
using oatpp::mcp::test::str;

namespace {

using Response = oatpp::web::protocol::http::incoming::Response;
using HeaderList = std::vector<std::pair<std::string, std::string>>;

/**
 * Records what a session was handed.
 *
 * Not the real <code>Listener</code>, and not a read of the session's own in-stream: a session that
 * is registered is being listened to by its own thread, which consumes the stream before a test can.
 * Delivery is therefore asserted on the listener, which is where it matters anyway - and which is
 * the only way to assert that something did <i>not</i> arrive.
 */
class RecordingListener : public oatpp::mcp::event::Session::EventListener {
private:
  std::mutex m_mutex;
  std::string m_last;
  v_int32 m_count = 0;
public:

  void onEvent(oatpp::mcp::event::Session&, const oatpp::mcp::event::Event& event) override {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_last = str(event.data);
    m_count ++;
  }

  v_int32 count() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_count;
  }

  std::string last() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_last;
  }

};

/**
 * One HTTP request, and the response that came back with it.
 *
 * The response object is what holds the connection open: an SSE response never completes, so a test
 * that wants its session to stay alive has to keep the returned pointer alive, and a test that wants
 * it to die has to let go of it.
 */
static std::shared_ptr<Response> send(v_uint16 port,
                                      const char* method,
                                      const char* path,
                                      const HeaderList& headers = HeaderList(),
                                      const std::string& body = std::string())
{
  auto provider = std::make_shared<oatpp::network::tcp::client::ConnectionProvider>(
    oatpp::network::Address("127.0.0.1", port, oatpp::network::Address::IP_4));
  oatpp::web::client::HttpRequestExecutor executor(provider);

  oatpp::web::protocol::http::Headers h;
  for(const auto& header : headers) {
    h.put(oatpp::String(header.first), oatpp::String(header.second));
  }

  std::shared_ptr<oatpp::web::protocol::http::outgoing::Body> outBody;
  if(!body.empty()) {
    outBody = std::make_shared<oatpp::web::protocol::http::outgoing::BufferBody>(
      oatpp::String(body), "application/json");
  }

  return executor.execute(oatpp::String(method), oatpp::String(path), h, outBody, nullptr);
}

/**
 * An MCP-over-SSE server on 127.0.0.1, configured per test.
 *
 * A real socket rather than a unit-level call into the controller, because the finding is about what
 * an unauthenticated remote client can do - and because "the endpoint never asked the guard" is
 * invisible to a test that does not send a request.
 */
class Fixture {
public:
  std::shared_ptr<oatpp::mcp::event::Server> eventServer;
  std::shared_ptr<RecordingListener> recorder;
  v_uint16 port = 0;
private:
  std::shared_ptr<oatpp::network::Server> server;
  std::thread thread;
public:

  Fixture(const oatpp::mcp::utils::AccessGuard::Config& access,
          const oatpp::mcp::event::Server::Config& sessions = oatpp::mcp::event::Server::Config())
  {
    recorder = std::make_shared<RecordingListener>();
    eventServer = std::make_shared<oatpp::mcp::event::Server>(nullptr, sessions);

    auto json = std::make_shared<oatpp::json::ObjectMapper>();
    auto mappers = std::make_shared<oatpp::web::mime::ContentMappers>();
    mappers->putMapper(json);

    auto controller = std::make_shared<oatpp::mcp::sse::Controller>(
      eventServer, recorder, mappers, "mcp/", access);

    auto router = oatpp::web::server::HttpRouter::createShared();
    router->addController(controller);

    std::shared_ptr<oatpp::network::tcp::server::ConnectionProvider> provider;
    std::string failures;
    for(v_uint32 candidate = 3131; candidate < 3161 && provider == nullptr; candidate++) {
      try {
        provider = oatpp::network::tcp::server::ConnectionProvider::createShared(
          {"127.0.0.1", static_cast<v_uint16>(candidate), oatpp::network::Address::IP_4});
        port = static_cast<v_uint16>(candidate);
      } catch (const std::exception& e) {
        failures += e.what();
        failures += "; ";
      }
    }
    if(provider == nullptr) {
      throw std::runtime_error("could not bind a port for the test server: " + failures);
    }

    auto handler = oatpp::web::server::HttpConnectionHandler::createShared(router);
    server = std::make_shared<oatpp::network::Server>(provider, handler);
    thread = std::thread([this] { server->run(); });

    std::this_thread::sleep_for(std::chrono::milliseconds(150)); // let it start accepting
  }

  ~Fixture() {
    /*
     * Every SSE connection holds a session thread and a connection thread, both parked - the writer
     * on the outbound stream, the session on the inbound one. Closing the sessions is what releases
     * the writer; without it this destructor waits for threads that are waiting for a client that has
     * already gone. (That is finding F5, and it is why it is worth fixing.)
     */
    eventServer->closeSessions();
    server->stop();
    if(thread.joinable()) {
      thread.join();
    }
  }

  /** Wait until the registry is empty, or give up. */
  bool waitUntilEmpty(v_int32 timeoutMillis) {
    for(v_int32 waited = 0; waited < timeoutMillis; waited += 20) {
      if(eventServer->sessionCount() == 0) {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return eventServer->sessionCount() == 0;
  }

};

/** A server that only accepts the address it is bound to - the recommended local configuration. */
static oatpp::mcp::utils::AccessGuard::Config localOnly() {
  oatpp::mcp::utils::AccessGuard::Config config;
  config.allowedHosts.push_back("127.0.0.1");
  return config;
}

/** Wait for a condition that is true on a thread other than this one. */
template<class Predicate>
static bool waitFor(Predicate predicate, v_int32 timeoutMillis) {
  for(v_int32 waited = 0; waited < timeoutMillis; waited += 20) {
    if(predicate()) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  return predicate();
}

}

void oatpp::mcp::test::SseAccessTest::onRun() {

  Checks checks("TEST[mcp::SseAccess]");

  /*--- control: a native client opens a session ----------------------------------------*/
  {
    Fixture fixture(localOnly());

    auto response = send(fixture.port, "GET", "/mcp/sse");
    checks.check(response != nullptr, "GET /mcp/sse is answered");
    checks.check(response && response->getStatusCode() == 200,
                 "control: a client that sends no Origin opens a session",
                 "status=" + std::to_string(response ? response->getStatusCode() : 0));
    checks.check(fixture.eventServer->sessionCount() == 1,
                 "control: exactly one session was created",
                 "sessions=" + std::to_string(fixture.eventServer->sessionCount()));
  }

  /*--- Origin --------------------------------------------------------------------------*/
  {
    Fixture fixture(localOnly());

    auto crossOrigin = send(fixture.port, "GET", "/mcp/sse",
                            {{"Origin", "http://evil.example"}});
    checks.check(crossOrigin && crossOrigin->getStatusCode() == 403,
                 "a cross-origin GET /sse is refused with 403",
                 "status=" + std::to_string(crossOrigin ? crossOrigin->getStatusCode() : 0));
    checks.check(fixture.eventServer->sessionCount() == 0,
                 "a refused GET /sse opens no session",
                 "sessions=" + std::to_string(fixture.eventServer->sessionCount()));

    /*
     * The order matters: a POST that is refused must not have been delivered first, which is what
     * checking the in-stream after the refusal tests.
     */
    auto session = fixture.eventServer->startNewSession(fixture.recorder);
    checks.check(session != nullptr, "a session could be opened for the POST control");

    auto path = std::string("/mcp/sessions/") + str(session->getId());
    auto refused = send(fixture.port, "POST", path.c_str(),
                        {{"Origin", "http://evil.example"}}, "{\"jsonrpc\":\"2.0\"}");
    checks.check(refused && refused->getStatusCode() == 403,
                 "a cross-origin POST to a live session is refused with 403",
                 "status=" + std::to_string(refused ? refused->getStatusCode() : 0));

    /*
     * Given a moment to be delivered if it were going to be: the check is that nothing arrived, and
     * "not yet" looks exactly like that without a wait.
     */
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    checks.check(fixture.recorder->count() == 0, "a refused POST delivers nothing to the session",
                 "delivered: '" + fixture.recorder->last() + "'");

    session->close();
  }

  /*--- Host: DNS rebinding -------------------------------------------------------------*/
  {
    Fixture fixture(localOnly());

    /*
     * The attacker's domain resolved to 127.0.0.1, so the browser sends its own name in Host and an
     * Origin that agrees with it. The pair is self-consistent; only the allow-list notices.
     */
    auto rebound = send(fixture.port, "GET", "/mcp/sse",
                        {{"Host", "rebound.attacker.example"},
                         {"Origin", "http://rebound.attacker.example"}});
    checks.check(rebound && rebound->getStatusCode() == 403,
                 "a Host the server is not configured for is refused with 403",
                 "status=" + std::to_string(rebound ? rebound->getStatusCode() : 0));
    checks.check(fixture.eventServer->sessionCount() == 0,
                 "a refused Host opens no session");
  }

  /*--- an unknown session is a 404 -----------------------------------------------------*/
  {
    Fixture fixture(localOnly());

    auto missing = send(fixture.port, "POST", "/mcp/sessions/0f6f0b4a-3f0a-4a1a-9d1c-000000000000",
                        HeaderList(), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
    checks.check(missing && missing->getStatusCode() == 404,
                 "POST to an unknown session answers 404, not 200",
                 "status=" + std::to_string(missing ? missing->getStatusCode() : 0));

    /* The control: the same POST to a session that exists is accepted and delivered. */
    auto session = fixture.eventServer->startNewSession(fixture.recorder);
    auto path = std::string("/mcp/sessions/") + str(session->getId());
    auto ok = send(fixture.port, "POST", path.c_str(), HeaderList(), "{\"jsonrpc\":\"2.0\"}");
    checks.check(ok && ok->getStatusCode() == 200,
                 "POST to a live session is still accepted",
                 "status=" + std::to_string(ok ? ok->getStatusCode() : 0));

    checks.check(waitFor([&] { return fixture.recorder->count() == 1; }, 1000),
                 "the delivered message reaches the session's listener",
                 "count=" + std::to_string(fixture.recorder->count())
                   + ", last='" + fixture.recorder->last() + "'");
    checks.check(fixture.recorder->last() == "{\"jsonrpc\":\"2.0\"}",
                 "and it is the message that was posted, unchanged",
                 "last='" + fixture.recorder->last() + "'");

    session->close();
  }

  /*--- the session cap -----------------------------------------------------------------*/
  {
    oatpp::mcp::event::Server::Config sessions;
    sessions.maxSessions = 1;
    Fixture fixture(localOnly(), sessions);

    auto first = send(fixture.port, "GET", "/mcp/sse");
    checks.check(first && first->getStatusCode() == 200,
                 "cap: the first session is accepted",
                 "status=" + std::to_string(first ? first->getStatusCode() : 0));

    auto second = send(fixture.port, "GET", "/mcp/sse");
    checks.check(second && second->getStatusCode() == 503,
                 "cap: a server at its limit answers 503 rather than opening another session",
                 "status=" + std::to_string(second ? second->getStatusCode() : 0));
    checks.check(fixture.eventServer->sessionCount() == 1,
                 "cap: the refused request created nothing",
                 "sessions=" + std::to_string(fixture.eventServer->sessionCount()));

    /*
     * A 503 that never clears is a different bug, so the limit has to be shown to be about the live
     * sessions and not about the number of requests made.
     */
    fixture.eventServer->closeSessions();
    checks.check(fixture.waitUntilEmpty(3000), "cap: closing the sessions empties the registry");

    auto third = send(fixture.port, "GET", "/mcp/sse");
    checks.check(third && third->getStatusCode() == 200,
                 "cap: a freed slot is usable again",
                 "status=" + std::to_string(third ? third->getStatusCode() : 0));
  }

  /*--- the idle timeout ----------------------------------------------------------------*/
  {
    oatpp::mcp::event::Server::Config sessions;
    sessions.sessionIdleTimeoutMillis = 250;
    Fixture fixture(localOnly(), sessions);

    auto response = send(fixture.port, "GET", "/mcp/sse");
    checks.check(response && response->getStatusCode() == 200,
                 "ttl: a session is opened as usual");
    checks.check(fixture.eventServer->sessionCount() == 1, "ttl: the session is registered");

    /*
     * The client stays connected and silent - which is the case the timeout exists for. Nothing
     * else reclaims a session whose client has stopped talking but has not hung up.
     */
    checks.check(waitFor([&] { return fixture.eventServer->sessionCount() == 0; }, 3000),
                 "ttl: a silent session is closed by the idle timeout",
                 "sessions=" + std::to_string(fixture.eventServer->sessionCount()));
  }

  /*--- the default configuration is not a denial of service to honest clients -----------*/
  {
    oatpp::mcp::event::Server::Config sessions;
    sessions.sessionIdleTimeoutMillis = 0;   // the default: never expire
    Fixture fixture(oatpp::mcp::utils::AccessGuard::Config(), sessions);

    auto response = send(fixture.port, "GET", "/mcp/sse");
    checks.check(response && response->getStatusCode() == 200,
                 "default: any Host is accepted when no allow-list is configured",
                 "status=" + std::to_string(response ? response->getStatusCode() : 0));

    bool expired = waitFor([&] { return fixture.eventServer->sessionCount() == 0; }, 1200);
    checks.check(!expired,
                 "default: a session with no idle timeout is not expired out from under its client");
  }

  checks.assertNoFailures();
}
