#include <stdint.h>
#include <string.h>



void base64_encode(const uint8_t* data, 
                    char* dst, size_t len)
{
    uint8_t  byte;
    uint8_t  curr;
    uint8_t  saved = 0;
    uint32_t left = 6;
    size_t i = 0;

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
    uint8_t result = 0;
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
            result = saved | (byte >> n);
            saved  = byte << m;
            
            *dst++ = result;
            
            n -= 2;
            m += 2;
        }

        ++i;
    }
}
