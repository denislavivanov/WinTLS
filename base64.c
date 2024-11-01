#include <stdint.h>
#include <string.h>

static const char* map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char* padding[] = {
    NULL, NULL, "=", NULL, "=="
};
static const uint8_t decode_map[] = {
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62,  0,  0,  0, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,
     0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,  0,  0,  0,  0,
     0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

void base64_encode(const uint8_t* data, 
                    char* dst, size_t len)
{
    uint8_t  byte, curr;
    uint8_t  saved = 0;
    uint32_t left  = 6;
    size_t   i = 0;

    while (i < len)
    {
        byte = data[i];
        curr = byte >> (8 - left);

        *dst++ = map[saved | curr];
        
        if (left == 0)
        {
            left  = 6;
            saved = 0;
            continue;
        }

        saved   = byte << left;
        saved >>= 2;
        left   -= 2;
        ++i;
    }

    *dst++ = map[saved];
    strcpy(dst, padding[left]);
}

void base64_decode(const char* data, uint8_t* dst)
{
    uint8_t saved  = 0;
    uint8_t byte;

    int32_t m;
    int32_t n = -1;
    int32_t i = 0;

    // T -> result = ?,              saved = c << 2
    // W -> result = saved | c >> 4, saved = c << 4 -> PRINT
    // F -> result = saved | c >> 2, saved = c << 6 -> PRINT
    // u -> result = saved | c,      saved = c << 8 -> PRINT

    while (data[i] != '\0' && data[i] != '=')
    {
        byte = decode_map[data[i]];

        if (n < 0)
        {
            saved = byte << 2;
            n = m = 4;
        }
        else
        {
            *dst++ = saved | (byte >> n);
            saved  = byte << m;

            n -= 2;
            m += 2;
        }

        ++i;
    }
}
