#pragma once

#include <ixwebsocket/IXWebSocketServer.h>
#include <nlohmann/json.hpp>
#include <unordered_map>

#include "logger.hpp"

class websocket {
    using OnClientMessageCallback =
        std::function<void(const std::shared_ptr<ix::ConnectionState> &connectionState, ix::WebSocket &webSocket,
                           const ix::WebSocketMessagePtr &message)>;

  public:
    websocket(short port, const OnClientMessageCallback &callback = nullptr) : _server(port) {
        if (callback != nullptr) {
            setOnClientMessageCallback(callback);
        }
    }

    bool start() { return _server.listenAndStart(); }
    void stop() { _server.stop(); }
    void broadcast(const std::string &message) {
        for (const auto &client : _clients) {
            client.second->send(message, false, [](int current, int total) -> bool {
                Log::info("Sending message: {} of {}", current, total);
                return true;
            });
        }
    }
    void setOnClientMessageCallback(const OnClientMessageCallback &callback) {
        _server.setOnClientMessageCallback([this, callback](const std::shared_ptr<ix::ConnectionState> &connectionState,
                                                            ix::WebSocket &webSocket,
                                                            const ix::WebSocketMessagePtr &message) {
            _client_handler(connectionState, webSocket, message);
            callback(connectionState, webSocket, message);
        });
    }

  private:
    ix::WebSocketServer _server;
    std::unordered_map<std::string, std::shared_ptr<ix::WebSocket>> _clients;
    const OnClientMessageCallback _client_handler = [this](const std::shared_ptr<ix::ConnectionState> &connectionState,
                                                           ix::WebSocket &webSocket,
                                                           const ix::WebSocketMessagePtr &message) {
        if (message->type == ix::WebSocketMessageType::Open) {
            Log::info("New connection from {}:{}", connectionState->getRemoteIp(), connectionState->getRemotePort());
            _clients[connectionState->getId()] =
                std::shared_ptr<ix::WebSocket>(&webSocket, [](ix::WebSocket *) { /* no-op deleter */ });
        } else if (message->type == ix::WebSocketMessageType::Close) {
            Log::info("Connection closed from {}:{}", connectionState->getRemoteIp(), connectionState->getRemotePort());
            _clients.erase(connectionState->getId());
        }
    };
};