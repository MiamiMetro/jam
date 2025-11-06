#pragma once

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include <ixwebsocket/IXConnectionState.h>
#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXWebSocketMessage.h>
#include <ixwebsocket/IXWebSocketMessageType.h>
#include <ixwebsocket/IXWebSocketServer.h>
#include <nlohmann/json.hpp>

#include "logger.h"

using OnClientMessageCallback =
    std::function<void(const std::shared_ptr<ix::ConnectionState>& connection_state,
                       ix::WebSocket& web_socket, const ix::WebSocketMessagePtr& message)>;

class WebSocket {
public:
    WebSocket(short port, const OnClientMessageCallback& callback = nullptr) : server_(port) {
        if (callback != nullptr) {
            set_on_client_message_callback(callback);
        }
    }

    bool start() {
        return server_.listenAndStart();
    }
    void stop() {
        server_.stop();
    }
    void broadcast(const std::string& message) {
        for (const auto& client: clients_) {
            client.second->send(message, false, [](int current, int total) -> bool {
                Log::info("Sending message: {} of {}", current, total);
                return true;
            });
        }
    }
    void set_on_client_message_callback(const OnClientMessageCallback& callback) {
        server_.setOnClientMessageCallback(
            [this, callback](const std::shared_ptr<ix::ConnectionState>& connection_state,
                             ix::WebSocket& web_socket, const ix::WebSocketMessagePtr& message) {
                client_handler_(connection_state, web_socket, message);
                callback(connection_state, web_socket, message);
            });
    }

private:
    ix::WebSocketServer                                             server_;
    std::unordered_map<std::string, std::shared_ptr<ix::WebSocket>> clients_;
    const OnClientMessageCallback                                   client_handler_ =
        [this](const std::shared_ptr<ix::ConnectionState>& connection_state,
               ix::WebSocket& web_socket, const ix::WebSocketMessagePtr& message) {
            if (message->type == ix::WebSocketMessageType::Open) {
                Log::info("New connection from {}:{}", connection_state->getRemoteIp(),
                          connection_state->getRemotePort());
                clients_[connection_state->getId()] = std::shared_ptr<ix::WebSocket>(
                    &web_socket, [](ix::WebSocket*) { /* no-op deleter */ });
            } else if (message->type == ix::WebSocketMessageType::Close) {
                Log::info("Connection closed from {}:{}", connection_state->getRemoteIp(),
                          connection_state->getRemotePort());
                clients_.erase(connection_state->getId());
            }
        };
};