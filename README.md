client -> p1p
````
struct p1p_login {
    uint8_t  v1[8];       /* 40 00 00 00 00 30 00 00 */
    uint64_t v2;          /* 00 00 00 00 00 00 00 00 */ 
    char username[32];    /* bblp */
    char access_code[32]; /* xxxxxx */
};
````

p1p -> client
````
struct p1p_jpeg_pkt {
    uint8_t jpeg_size[4];   /* jpeg data length in little endian */
    uint32_t v1;            /* 00 00 00 00 */
    uint8_t v2[8];          /* 01 00 00 00 00 00 00 00 */
    uint8_t jpeg_data[jpeg_size];  /* start with FF D8 FF E0, end with FF D9 */
};
````
