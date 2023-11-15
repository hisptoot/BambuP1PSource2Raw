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

#pragma pack (pop)

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
      printf("%s [ip] [access_code]\n", argv[0]);
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

    int is_fst = 1;
    while(true)
    {
        int ret = 0;
        char data[1400];
        ret = recvBytes(data, sizeof(data), 0, sock);
        if (ret < 0)
        {
            fprintf(stderr, "recvBytes error %d\n", ret);
            break;
        }

        if (is_fst)
        {
            const uint8_t sign[] = { 0xff, 0xd8, 0xff, 0xe0 };
            int i = 0;
            for(i = 0; sizeof(sign) < ret && i < ret - sizeof(sign); i++)
            {
                if (0 == memcmp(sign, &data[i], sizeof(sign)))
                {
                    fprintf(stderr, "start ok\n");
                    fwrite(&data[i], 1, ret - i, stdout);
                    fflush(stdout);
                    is_fst = 0;
                    break;
                }
            }
        }
        else
        {
            fwrite(data, 1, ret, stdout);
            fflush(stdout);
        }
    }
}
