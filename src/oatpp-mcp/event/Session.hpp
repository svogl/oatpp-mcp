//
// Created by Leonid S on 12/8/24.
//

#ifndef OATPP_MCP_EVENT_SESSION_HPP
#define OATPP_MCP_EVENT_SESSION_HPP

#include "EventStream.hpp"

#include <memory>

namespace oatpp { namespace mcp { namespace event {

class Session {
public:

  class Pinger {
  public:
    virtual ~Pinger() = default;
    virtual void onPing(Session& session) = 0;
  };

public:

  class EventListener {
  public:
    virtual ~EventListener() = default;
    virtual void onEvent(Session& session, const Event& event) = 0;
  };

public:

  class AssociatedData {
  public:
    virtual ~AssociatedData() = default;
  };

private:
  void closeNonBlocking();
private:
  /**
   * Random identifier, generated once per session. Never derived from the object, its address, a
   * counter or a timestamp - see oatpp::mcp::utils::Uuid and SECURITY-FINDINGS.md (F2).
   */
  oatpp::String m_id;
private:
  std::shared_ptr<Pinger> m_pinger;
  std::shared_ptr<EventStream> m_inStream;
  std::shared_ptr<EventStream> m_outStream;
private:
  bool m_open;
  std::mutex m_mutex;
private:
  std::shared_ptr<AssociatedData> m_data;
public:

  Session(const std::shared_ptr<Pinger>& pinger = nullptr);

  ~Session();

  std::shared_ptr<EventStream> getInStream();
  std::shared_ptr<EventStream> getOutStream();

  /**
   * Associate any arbitrary data with session
   * @param data
   */
  void setAssociatedData(const std::shared_ptr<AssociatedData>& data);

  /**
   * Get session associated data
   * @return
   */
  std::shared_ptr<AssociatedData> getAssociatedData() const;

  /**
   * process session
   */
  void listen(std::shared_ptr<EventListener> listener);

  bool isOpen();

  void close();

  /**
   * The session identifier - a random version-4 UUID, stable for the lifetime of the session.
   *
   * This value is what clients address in <code>POST /sessions/{sessionId}</code>, and the SSE
   * endpoints authenticate nothing (SECURITY-FINDINGS.md, F4), so it is the only thing standing
   * between one client and another client's message stream. It must be unguessable, and it must
   * not be derivable from anything the server otherwise reveals.
   * @return 36 characters, canonical UUID form.
   */
  oatpp::String getId() const;

};

}}}

#endif //OATPP_MCP_EVENT_SESSION_HPP
