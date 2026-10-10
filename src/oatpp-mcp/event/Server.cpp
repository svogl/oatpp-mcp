//
// Created by Leonid S on 12/8/24.
//

#include "Server.hpp"

#include "oatpp/base/Log.hpp"

#include <thread>

namespace oatpp { namespace mcp { namespace event {

Server::Server(const std::shared_ptr<Session::Pinger>& pinger)
  : m_pinger(pinger)
{}

std::shared_ptr<Session> Server::startNewSession(const std::shared_ptr<Session::EventListener>& listener) {

  auto session = std::make_shared<Session>(m_pinger);
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    if(m_sessions.find(session->getId()) != m_sessions.end()) {
      /* Identifiers are random 122-bit values, so this is not a race to be handled - it is the
       * identifier generator having stopped being random, which is finding F2 and must not be
       * papered over by quietly overwriting the session that got there first. */
      OATPP_LOGe("[oatpp::mcp::Server::startNewSession()]",
                 "Error - session identifier collision, identifiers are not unique: {}",
                 session->getId())
    }
    m_sessions[session->getId()] = session;
  }

  OATPP_LOGd("[oatpp::mcp::Server::startNewSession()]", "New session started {}", session->getId())

  std::thread t([this, session, listener]{
    session->listen(listener);
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      auto it = m_sessions.find(session->getId());
      /* Only remove our own entry: if an identifier were ever shared, the first session to finish
       * must not retire the session that replaced it. */
      if(it != m_sessions.end() && it->second == session) {
        m_sessions.erase(it);
      }
      OATPP_LOGd("Server", "sessions count={}", m_sessions.size())
    }
  });

  t.detach();

  return session;
}

std::shared_ptr<Session> Server::getSession(const oatpp::String& sessionId) const {
  std::lock_guard<std::mutex> lock(m_mutex);
  auto it = m_sessions.find(sessionId);
  if(it != m_sessions.end()) {
    return it->second;
  }
  return nullptr;
}

}}}