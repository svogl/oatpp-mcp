//
// Created by Leonid S on 12/10/24.
//

#include "Server.hpp"
#include "oatpp/json/ObjectMapper.hpp"
#include "oatpp/web/mime/ContentMappers.hpp"

#include <iostream>
#include <thread>

namespace oatpp { namespace mcp {

Server::Server(const Config& config)
  : m_config(config)
  , m_pinger(std::make_shared<oatpp::mcp::Pinger>())
  , m_eventListener(std::make_shared<oatpp::mcp::Listener>())
  , m_eventServer(std::make_shared<oatpp::mcp::event::Server>(m_pinger, config.sessions))
{

  if(m_config.access.allowedHosts.empty()) {
    /*
     * The Origin check catches a page on another site driving this server, but it cannot see DNS
     * rebinding, where the attacker's own domain is both the Origin and the Host. Only a list of
     * the names this server is willing to be called by can - and only an operator knows them.
     */
    OATPP_LOGw("[oatpp::mcp::Server::Server()]",
               "Warning - no Host allow-list configured (Config::access::allowedHosts); "
               "DNS rebinding is not mitigated. A local server should set it to, e.g., "
               "{\"localhost\", \"127.0.0.1\"}")
  }

  m_schemaMapper = std::make_shared<oatpp::mcp::utils::ObjectSchemaMapper>();

  auto json = std::make_shared<oatpp::json::ObjectMapper>();
  json->serializerConfig().json.useBeautifier = true;

  m_mappers = std::make_shared<oatpp::web::mime::ContentMappers>();
  m_mappers->putMapper(json);

  m_apiBridge = std::make_shared<utils::ApiBridge>();
  std::thread t([this]{
    m_apiBridge->run();
  });
  t.detach();
}

void Server::addPrompt(const std::shared_ptr<capabilities::Prompt>& prompt) {
  m_eventListener->addPrompt(prompt);
}

void Server::addTool(const std::shared_ptr<capabilities::Tool>& tool) {
  m_eventListener->addTool(tool);
}

void Server::addResource(const std::shared_ptr<capabilities::Resource> &resource) {
  m_eventListener->addResource(resource);
}

void Server::addEndpoints(const oatpp::web::server::api::Endpoints& endpoints) {

  capabilities::EndpointTool::Components components;
  components.schemaMapper = m_schemaMapper;
  components.mappers = m_mappers;
  components.apiBridge = m_apiBridge;

  for(auto& endpoint : endpoints.list) {
    auto tool = std::make_shared<capabilities::EndpointTool>(endpoint, components);
    addTool(tool);
    m_apiBridge->addEndpoint(endpoint);
  }

}

std::shared_ptr<web::server::api::ApiController> Server::getSseController() {
  if(!m_sseController) {
    m_sseController = std::make_shared<oatpp::mcp::sse::Controller>(
      m_eventServer, m_eventListener, m_mappers, m_config.ssePrefix, m_config.access);
  }
  return m_sseController;
}

void Server::stdioListen() {

  auto session = m_eventServer->startNewSession(m_eventListener);
  if(!session) {
    /* Only the SSE endpoint can be refused for being full, and it answers 503; stdio has no such
     * conversation to have, so a full registry here is a misconfiguration to be reported. */
    OATPP_LOGe("[oatpp::mcp::Server::stdioListen()]",
               "Error - no session available (limit of {} sessions)",
               m_config.sessions.maxSessions)
    return;
  }

  std::thread tin([session]{
    std::string line;
    while (std::getline(std::cin, line) && session->isOpen()) {
      event::Event e;
      e.name = "stdio";
      e.data = line;
      session->getInStream()->post(e);
    }
  });

  std::thread tout([session]{
    while (session->isOpen()) {
      auto e = session->getOutStream()->read(std::chrono::milliseconds(0) /* wait until event */ );
      std::cout << *e.data << std::endl;
    }
  });

  tin.join();
  tout.join();

}

}}
