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

int main()
{
    server(8080);

    return 0;
}


