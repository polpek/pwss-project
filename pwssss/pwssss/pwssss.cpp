#include <iostream>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#include <stdio.h>
#include <sys/types.h>
#include <iostream>
#include <string>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sys/types.h>
#include <iterator>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <lua.hpp>

#define MAX_CONNECTIONS 10
#define MAX_BUFFER_SIZE 1024


const int MAX_CLIENTS = 10;
const int BUFFER_SIZE = 4096;



// tworzenie gniazda
int create_socket(int port)
{
    int sockfd;
    sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        std::cerr << "Blad tworzenia gniazda" << std::endl;
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        std::cerr << "Blad w setsockopt" << std::endl;
        exit(EXIT_FAILURE);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    if (bind(sockfd, (sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        std::cerr << "Blad w bind" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, MAX_CLIENTS) < 0)
    {
        std::cerr << "Blad w listen" << std::endl;
        exit(EXIT_FAILURE);
    }

    return sockfd;
}
// wczytaj plik i zwróć go w formie odpowiedzi http
std::string get_file(const std::string& file_path)
{

    std::ifstream file_stream(file_path, std::ios::binary | std::ios::ate);
    if (!file_stream)
    {
        return "Blad ifstream";
    }

    int file_size = file_stream.tellg();
    std::string response;
    response += "HTTP/1.1 200 OK\r\n";
    response += "Content-Type: ";
    response += "text/html\r\n";
    response += "Content-Length: " + std::to_string(file_size) + "\r\n";
    response += "\r\n";

    file_stream.seekg(0, std::ios::beg);
    response.append(std::istreambuf_iterator<char>(file_stream), std::istreambuf_iterator<char>());

    return response;
}

// wyłuskaj nazwę pliku z requestu http
std::string extract_file_name(std::string request)
{
    std::istringstream iss(request);
    std::vector<std::string> components((std::istream_iterator<std::string>(iss)),
        std::istream_iterator<std::string>());

    std::string resource = components[1];
    std::size_t pos = resource.find('?');
    std::string file_name = resource.substr(1, pos);

    return file_name;
}

int server(int port)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    //przygotowanie OpenSSL
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr)
    {
        std::cerr << "Blad w SSL_CTX_new" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Blad SSL_CTX_use_certificate_file" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Blad SSL_CTX_use_PrivateKey_file" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        std::cerr << "Blad SSL_CTX_check_private_key" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //glowny socket
    int sockfd = create_socket(port);

    //inicjalizacja LUA
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);

    std::unordered_map<int, SSL*> ssl_map;
    std::vector<int> client_fds;

    //petla nasluchiwania
    while (true)
    {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        for (const auto& fd : client_fds)
        {
            FD_SET(fd, &read_fds);
        }

        int max_fd = sockfd;
        for (const auto& fd : client_fds)
        {
            if (fd > max_fd)
            {
                max_fd = fd;
            }
        }
        //sprawdzamy czy pojawilo sie nowe połaczenie
        if (select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr) < 0)
        {
            std::cerr << "Blad select" << std::endl;
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(sockfd, &read_fds))
        {
            sockaddr_in cli_addr;
            socklen_t cli_len = sizeof(cli_addr);
            int client_fd = accept(sockfd, (sockaddr*)&cli_addr, &cli_len);
            if (client_fd < 0)
            {
                std::cerr << "Blad accept" << std::endl;
                exit(EXIT_FAILURE);
            }

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) < 0)
            {
                std::cerr << "Blad SSL_accept" << std::endl;
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_fd);
                continue;
            }

            ssl_map[client_fd] = ssl;
            client_fds.push_back(client_fd);
        }
        //odczytujemy dane z socketow jesli są dostepne
        for (const auto& fd : client_fds)
        {
            if (FD_ISSET(fd, &read_fds))
            {
                char buffer[BUFFER_SIZE];
                int bytes_received = SSL_read(ssl_map[fd], buffer, BUFFER_SIZE);
                if (bytes_received < 0)
                {
                    std::cerr << "Blad SSL_read" << std::endl;
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl_map[fd]);
                    close(fd);
                    continue;
                }
                else if (bytes_received == 0)
                {
                    SSL_free(ssl_map[fd]);
                    close(fd);
                    continue;
                }

                std::string request(buffer, bytes_received);
                std::cout << "Otrzymano request: " << request << std::endl;

                std::string response = "";

                //sprawdzamy czy w requescie jest nazwa skryptu lua
                if (request.find(".lua") != std::string::npos)
                {

                    std::string script_name = "script.lua";
                    size_t pos = request.find("/");
                    if (pos != std::string::npos) {

                        size_t end_pos = request.find(" ", pos);
                        if (end_pos != std::string::npos) {

                            script_name = request.substr(pos + 1, end_pos - pos - 1);

                        }
                    }


int main()
{
    server(8080);

    return 0;
}
