#pragma once

#include <asio.hpp>
#include <functional>
#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

class tcp_control_server {
  public:
    static constexpr int HTTP_OK = 200;
    static constexpr int HTTP_NOT_FOUND = 404;
    static constexpr int HTTP_INTERNAL_ERROR = 500;

    struct http_response {
        int status_code;
        std::string status_text;
        std::string body;
        std::string content_type;

        http_response(int code, std::string text, std::string body, std::string content_type = "text/plain")
            : status_code(code), status_text(std::move(text)), body(std::move(body)), content_type(std::move(content_type)) {}
    };

    using endpoint_handler =
        std::function<http_response(const std::string &method, const std::string &path, const std::string &body)>;

    tcp_control_server(asio::io_context &io_context, short port)
        : acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)) {
        std::cout << "TCP Server listening on port " << port << "\n";

        // Add default endpoints
        add_endpoint("GET", "/", [](const std::string &, const std::string &, const std::string &) {
            return http_response(HTTP_OK, "OK", "Available endpoints: /status");
        });

        add_endpoint("GET", "/status", [](const std::string &, const std::string &, const std::string &) {
            return http_response(HTTP_OK, "OK", "Server is running and ready.");
        });

        start_accept();
    }

    void add_endpoint(const std::string &method, const std::string &path, endpoint_handler handler) {
        std::string key = method + " " + path;
        endpoints_[key] = std::move(handler);
        std::cout << "Added endpoint: " << key << "\n";
    }

  private:
    static constexpr size_t BUFFER_SIZE = 1024;
    std::unordered_map<std::string, endpoint_handler> endpoints_;

    void start_accept() {
        auto new_connection = std::make_shared<asio::ip::tcp::socket>(acceptor_.get_executor());

        acceptor_.async_accept(*new_connection, [this, new_connection](std::error_code error_code) {
            if (!error_code) {
                std::cout << "TCP Client connected from: " << new_connection->remote_endpoint().address().to_string()
                          << ":" << new_connection->remote_endpoint().port() << "\n";

                // Handle the connection
                handle_connection(new_connection);
            } else {
                std::cerr << "TCP Accept error: " << error_code.message() << "\n";
            }

            // Continue accepting new connections
            start_accept();
        });
    }

    void handle_connection(const std::shared_ptr<asio::ip::tcp::socket> &socket) {
        auto streambuf = std::make_shared<asio::streambuf>();

        // Read until double newline (HTTP headers end)
        asio::async_read_until(
            *socket, *streambuf, "\r\n\r\n", [this, socket, streambuf](std::error_code error_code, std::size_t length) {
                if (!error_code) {
                    // Extract the HTTP request from streambuf
                    std::istream stream(streambuf.get());
                    std::string request;
                    std::string line;
                    std::string content_length_str;
                    size_t content_length = 0;

                    // Read the request line by line
                    while (std::getline(stream, line) && line != "\r") {
                        request += line + "\n";

                        // Look for Content-Length header
                        if (line.substr(0, 15) == "Content-Length:") {
                            content_length_str = line.substr(15);
                            // Remove whitespace
                            content_length_str.erase(0, content_length_str.find_first_not_of(" \t"));
                            content_length_str.erase(content_length_str.find_last_not_of(" \t") + 1);
                            try {
                                content_length = std::stoul(content_length_str);
                                std::cout << "Found Content-Length header: " << content_length << "\n";
                            } catch (const std::exception &e) {
                                std::cout << "Error parsing Content-Length: " << e.what() << "\n";
                                content_length = 0;
                            }
                        }
                    }

                    std::cout << "HTTP Request received:\n" << request << "\n";
                    std::cout << "Content-Length: " << content_length << "\n";

                    // If there's a body, read it
                    if (content_length > 0) {
                        std::cout << "Reading POST body with length: " << content_length << "\n";

                        // Check if body is already in streambuf
                        size_t available = streambuf->size();
                        std::cout << "Available data in streambuf: " << available << " bytes\n";

                        if (available >= content_length) {
                            // Body is already in streambuf, read it directly
                            std::istream body_stream(streambuf.get());
                            std::string body(content_length, '\0');
                            body_stream.read(body.data(), content_length);

                            std::cout << "Body received from streambuf: '" << body << "' (length: " << body.length()
                                      << ")\n";

                            // Process the HTTP request with body
                            std::string response = process_http_request(request, body);
                            std::cout << "Response generated: " << response.substr(0, 50) << "...\n";

                            // Send HTTP response and close connection
                            asio::async_write(
                                *socket, asio::buffer(response), [socket](std::error_code write_error, std::size_t) {
                                    if (write_error) {
                                        std::cerr << "HTTP Write error: " << write_error.message() << "\n";
                                    } else {
                                        std::cout << "Response sent successfully\n";
                                    }
                                    socket->close();
                                    std::cout << "HTTP connection closed\n";
                                });
                        } else {
                            // Need to read more data from socket
                            std::cout << "Need to read more data from socket\n";
                            auto body_buffer = std::make_shared<std::vector<char>>(content_length);

                            // Read the body data directly into the buffer
                            asio::async_read(
                                *socket, asio::buffer(*body_buffer),
                                [this, socket, request, body_buffer, content_length](std::error_code body_error,
                                                                                     std::size_t body_length) {
                                    if (!body_error) {
                                        // Convert buffer to string
                                        std::string body(body_buffer->data(), content_length);

                                        std::cout << "Body received from socket: '" << body
                                                  << "' (length: " << body.length() << ")\n";

                                        // Process the HTTP request with body
                                        std::string response = process_http_request(request, body);
                                        std::cout << "Response generated: " << response.substr(0, 50) << "...\n";

                                        // Send HTTP response and close connection
                                        asio::async_write(*socket, asio::buffer(response),
                                                          [socket](std::error_code write_error, std::size_t) {
                                                              if (write_error) {
                                                                  std::cerr
                                                                      << "HTTP Write error: " << write_error.message()
                                                                      << "\n";
                                                              } else {
                                                                  std::cout << "Response sent successfully\n";
                                                              }
                                                              socket->close();
                                                              std::cout << "HTTP connection closed\n";
                                                          });
                                    } else {
                                        std::cout << "Error reading body: " << body_error.message() << "\n";
                                        socket->close();
                                    }
                                });
                        }
                    } else {
                        // No body, process request without body
                        std::cout << "No body to read, processing request without body\n";
                        std::string response = process_http_request(request, "");
                        std::cout << "Response generated: " << response.substr(0, 50) << "...\n";

                        // Send HTTP response and close connection
                        asio::async_write(*socket, asio::buffer(response),
                                          [socket](std::error_code write_error, std::size_t) {
                                              if (write_error) {
                                                  std::cerr << "HTTP Write error: " << write_error.message() << "\n";
                                              } else {
                                                  std::cout << "Response sent successfully\n";
                                              }
                                              socket->close();
                                              std::cout << "HTTP connection closed\n";
                                          });
                    }
                } else {
                    std::cout << "HTTP Client disconnected\n";
                }
            });
    }

    std::string process_http_request(const std::string &request, const std::string &body) {
        std::istringstream iss(request);
        std::string line;

        // Parse the request line (first line)
        std::getline(iss, line);
        std::istringstream request_line(line);
        std::string method, path, version;
        request_line >> method >> path >> version;

        // Convert method to uppercase
        std::transform(method.begin(), method.end(), method.begin(), ::toupper);

        std::cout << "Processing HTTP request: " << method << " " << path << "\n";

        // Look for matching endpoint
        std::string key = method + " " + path;
        auto it = endpoints_.find(key);

        if (it != endpoints_.end()) {
            // Found endpoint, call the handler
            http_response response = it->second(method, path, body);
            return create_http_response(response.status_code, response.status_text, response.body, response.content_type);
        } else {
            // Endpoint not found
            std::string response_body = "Endpoint not found: " + method + " " + path;
            return create_http_response(404, "Not Found", response_body);
        }
    }

    std::string create_http_response(int status_code, const std::string &status_text, const std::string &body, const std::string &content_type = "text/plain") {
        std::string status_line = "HTTP/1.1 " + std::to_string(status_code) + " " + status_text;
        return status_line + "\r\nContent-Type: " + content_type + "\r\nContent-Length: " + std::to_string(body.length()) +
               "\r\nConnection: close\r\n\r\n" + body;
    }

    asio::ip::tcp::acceptor acceptor_;
};