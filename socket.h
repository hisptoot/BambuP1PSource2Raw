/*
* Simple lightweight c/c++ socket implementation
* Supports: ssl, ftp, and udp 
* 
* By Gavin D 2022
* 
* Contents are under the MIT licence
*
* This is a `botching` tool, not meant to be perfect or super efficent, only easy
*/

#ifndef INCLUDED_SOCKET_H
#define INCLUDED_SOCKET_H

#define WINDOWS defined(_WIN32)

#define GNUcompiler defined(__GNUC__) || defined(__GNUG__)
#define MSCcompiler defined(_MSC_VER)

#ifdef __cplusplus
    extern "C" {
#endif

#if WINDOWS
    #include <winsock2.h>
#else
    #include <sys/socket.h>
    #include <netdb.h>
    #include <arpa/inet.h>
#endif

#define __USE_SSL__ (!defined(__NO_SSL__))

#if __USE_SSL__
    #include <openssl/err.h>
    #include <openssl/ssl.h>
#endif

#if MSCcompiler
    #pragma comment(lib,"ws2_32")
    #if __USE_SSL__
    #pragma comment(lib, "crypto");
    #pragma comment(lib, "ssl");
    #endif
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if __USE_SSL__
    #warning bind doesnt support ssl (yet) 
    #warning listen doesnt support ssl (yet) 
#endif // __USE_SSL__

// internal function
// throws the error from the socket implementation
void throwSocketError(){
    fprintf(stderr, "Thrown error: ");
    fflush(stderr);

    #if __USE_SSL__
        ERR_print_errors_fp(stderr);
    #elif WINDOWS
        fprintf(stderr, "%d (WSA ERROR CODE)",WSAGetLastError());
    #endif

    exit(-1);
}

typedef enum errCode{
    no_err = 0,
    /* types */
    err_locs = (1 << 5) - 1, // locs = locations (bits)
    err_ftp = 1,
    err_ssl = 2,
    err_udp = 3,
    /* codes */
    cant_create_sock = 1 << 5,
    cant_connect_sock = 1 << 6,
    cant_bind_sock = 1 << 7,
    cant_listen_sock = 1 << 8,
    cant_recive_host_info = 1 << 9,
    cant_init_winsock = 1 << 10,
} errCode;

const char* getErrMsg(errCode e){
    int type = e & err_locs;
    switch (e & (~err_locs)){
        case no_err: return "no error";
        case cant_create_sock: {
            switch (type){
                case err_ftp : return "cant create socket (ftp)";
                case err_ssl : return "cant create socket (ssl)";
                case err_udp : return "cant create socket (udp)";
            }
            return "cant create socket";
        }
        case cant_connect_sock: {
            switch (type){
                case err_ftp : return "cant connect socket (ftp) [check if server is http and check port]";
                case err_ssl : return "cant connect socket (ssl) [check if server is https and check port]";
                // udp doesnt have a connect handshake
            }
            return "cant connect socket";
        };
        case cant_bind_sock: return "cant bind sock";
        case cant_listen_sock: return "sock failed to execute listen";
        case cant_recive_host_info: return "cant recive host info";
        case cant_init_winsock: return "cant initialize winsock";
    }
    return "err op";
}

void throwError(errCode e){
    fprintf(stderr, "Thrown error: %s", getErrMsg(e));
    exit(-1);
}

typedef struct SOCKET_t{
    #if __USE_SSL__
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL* ssl;
    #endif
    int socketfd;
    bool sslViable;
} *SOCKET_t;

void closeSock(SOCKET_t sock);

/* sock contructor */
SOCKET_t createSock(){
    SOCKET_t sock = malloc(sizeof(struct SOCKET_t));
    return sock;
}

/* sock initiator (ftp/ssl) */
errCode initSock(SOCKET_t sock){
    #if WINDOWS
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
            return cant_init_winsock;
    #endif

    sock->socketfd = socket(PF_INET, SOCK_STREAM, 0);
    if(sock->socketfd == 0)
        return cant_create_sock | err_ftp;

    
    #if __USE_SSL__
        sock->sslViable = 1;
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        SSL_library_init();
        sock->method = TLS_client_method();
        if((sock->ctx = SSL_CTX_new(sock->method) ) == NULL)
            return cant_create_sock | err_ssl;
    #else
        sock->sslViable = 0;
    #endif

    return no_err;
}

/* sock initiator (udp) */
errCode initSockUDP(SOCKET_t sock){
    #if WINDOWS
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
            return cant_init_winsock;
    #endif

    sock->socketfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock->socketfd == 0)
        return cant_create_sock | err_udp;

    sock->sslViable = 0;

    /* bind */
    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = inet_addr(INADDR_ANY);
    local.sin_port = 0;

    bind(sock->socketfd, (struct sockaddr *)&local, sizeof(local));

    return no_err;
}

/* connects to server */
errCode connectSock(const char* hostname, int port, bool attemptSSL, SOCKET_t sock){
    errCode e;
    if((e = initSock(sock)) != no_err) return e;
    // get host info
    struct hostent *host;
    struct sockaddr_in addr;
    if((host = gethostbyname(hostname)) == NULL)
        return cant_recive_host_info;

    // connect sock
    
    memset(&addr, 0, sizeof(addr)); // clear address
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sock->socketfd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
        return cant_connect_sock | err_ftp;

    if(attemptSSL){
        #if __USE_SSL__
            // create SSL and connect to socket
            sock->ssl = SSL_new(sock->ctx);
            SSL_set_fd(sock->ssl, sock->socketfd);
            SSL_set_tlsext_host_name(sock->ssl, hostname);
            if(SSL_connect(sock->ssl) == -1){
                sock->sslViable = 0;
            }
        #else
            sock->sslViable = 0;
        #endif
    }else
        sock->sslViable = 0;

    return no_err;
}

/* send */

void sendBytes(const char* bytes, int len, SOCKET_t sock) {
    #if __USE_SSL__
        if(sock->sslViable) SSL_write(sock->ssl, bytes, len);
        else send(sock->socketfd, bytes, len, 0);
    #else
        send(sock->socketfd, (char*)bytes, len, 0);
    #endif
}

// sends bytes to a specific hostname and port
errCode sendBytesTo(const char* bytes, int len, const char* hostname, int port, SOCKET_t sock){
    /* server addr */
    struct hostent *host;
    struct sockaddr_in server;
    if((host = gethostbyname(hostname)) == NULL)
        return cant_recive_host_info;
    
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
	server.sin_addr.s_addr = *(long*)(host->h_addr);
	server.sin_port = htons(port);

    /* send */
    sendto(sock->socketfd, (char*)bytes, len, 0, (struct sockaddr *)&server, sizeof(server));
    
    return no_err;
}

/* bind */
errCode bindSock(const char* hostname, int port, SOCKET_t sock){
    struct hostent *host;
    struct sockaddr_in server;
    if((host = gethostbyname(hostname)) == NULL)
        return cant_recive_host_info;

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
	server.sin_addr.s_addr = *(long*)(host->h_addr);
	server.sin_port = htons(port);
    if(bind(sock->socketfd, (struct sockaddr *)&server , sizeof(server)) < 0)
        return cant_bind_sock | err_ftp;
    
    return no_err;
}

/* listen
* onConn: a function that is ran on each connection to the binded sock
* maxConn: maximum ammount of connections
* arg: a argument that is passed to the `onConn` func when a connection is made
*/
errCode listenSock(void (*onConn)(SOCKET_t conn, void* arg), int maxConn, SOCKET_t sock, void* arg){
    while(1){
        if(listen(sock->socketfd, maxConn) < 0)
            return cant_listen_sock;
        
        SOCKET_t c = createSock();
        initSock(c);
        c->sslViable = 0;

        int conn = accept(sock->socketfd, NULL, NULL);

        c->socketfd = conn;

        onConn(c, arg);

        closeSock(c);
    }
    return no_err; // never reached
}

/* recv
* buf: preinitialized array 
* bufSize: length of the `buf` array
* delay: how long in milliseconds to wait for a message (0 is infinite)
*/
int recvBytes(char buf[], int bufSize, int delay, SOCKET_t sock){
    #if WINDOWS
    setsockopt(sock->socketfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&delay, sizeof(delay));
    #else
    struct timeval tv = {(long)(delay / 1000), (long)((delay % 1000) * 1000)};
    setsockopt(sock->socketfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
    #endif

    if(sock->sslViable){
        #if __USE_SSL__
        return SSL_read(sock->ssl, buf, bufSize);
        #endif
    }else
        return recv(sock->socketfd, buf, bufSize, 0);

    return 0; // never reached
}

/* clean & close */
void closeSock(SOCKET_t sock){
    #if WINDOWS
    closesocket(sock->socketfd);
    #else
    close(sock->socketfd);
    #endif

    free(sock);
}

#ifdef __cplusplus
    }
#endif

#endif // INCLUDED_SOCKET_H
