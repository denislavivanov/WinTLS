#pragma once


void base64_encode(const uint8_t* data, char* dst, size_t len);
void base64_decode(const char* data, uint8_t* dst);
