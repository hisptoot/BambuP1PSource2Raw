#include <stdio.h>
#include <stdint.h>
#include "socket.h"
#include <string.h>

#pragma pack (push , 1)
struct p1p_login {
    uint8_t  v1[8];
    uint64_t v2;
    char username[32];
    char access_code[32];
};

struct p1p_jpeg_pkt_header {
    uint8_t jpeg_size[4];
    uint32_t v1; 
    uint8_t v2[8]; 
};

#pragma pack (pop)

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "%s [ip] [access_code]\n", argv[0]);
        exit(0);
    }

    char *ip = argv[1];
    char *access_code = argv[2];

    SOCKET_t sock = createSock();
    errCode e;

    if((e=initSock(sock)) != no_err) throwError(e);

    if((e=connectSock(ip, 6000, true, sock)) != no_err) throwError(e);
    fprintf(stderr, "connect ok\n");

    struct p1p_login login = {0};
    login.v1[0] = 0x40;
    login.v1[5] = 0x30;

    strcpy(&login.username[0], "bblp");
    strcpy(&login.access_code[0], access_code);
    sendBytes((char *)&login, sizeof(login), sock);
    fprintf(stderr, "send auth\n");

    char *data = NULL;
    size_t data_size = 2 * 1024 * 1024; 
    data = malloc(data_size);
    if (data == NULL)
    {
        fprintf(stderr, "malloc recv buffer failed\n");
        exit(-1);
    }

    while(true)
    {
        int is_error = 0;
        int ret = 0;
        struct p1p_jpeg_pkt_header p1p_jpg_ph = {0};
        char *ptr = (char *)&p1p_jpg_ph;
        size_t remain_size = sizeof(p1p_jpg_ph);
        while(remain_size > 0)
        {
            ret = recvBytes(ptr, remain_size, 0, sock);
            if (ret < 0)
            {
                is_error = 1;
                fprintf(stderr, "recvBytes error %d\n", ret);
                break;
            }

            remain_size -= ret;
            ptr += ret;
        }

        if (is_error)
        {
            break;
        }

        size_t jpeg_data_size = ((uint32_t)p1p_jpg_ph.jpeg_size[0]) | ((uint32_t)p1p_jpg_ph.jpeg_size[1] << 8) | ((uint32_t)p1p_jpg_ph.jpeg_size[2] << 16) | ((uint32_t)p1p_jpg_ph.jpeg_size[3] << 24);
        fprintf(stderr, "jpeg_frame size: %d\n", jpeg_data_size);

        size_t read_size = 0;
        remain_size = jpeg_data_size;
        size_t read_once_size = remain_size > data_size ? data_size : remain_size;
        for(;remain_size > 0; read_once_size = remain_size > data_size ? data_size : remain_size)
        {
            ret = recvBytes(data, read_once_size, 0, sock);
            if (ret < 0)
            {
                is_error = 1;
                fprintf(stderr, "recvBytes error %d\n", ret);
                break;
            }
            fwrite(data, 1, ret, stdout);
            fflush(stdout);

            remain_size -= ret;
        }

        if (is_error)
        {
            break;
        }
    }

    if (data != NULL)
    {
        free(data);
        data = NULL;
    }

    return 0;
}
