#pragma once
#include <Windows.h>

typedef struct TLS TLS;

/* Initialize Library */
BOOL TLS_Init(TLS* pTLS);
BOOL TLS_Handshake(TLS* pTLS, SOCKET s, LPSTR szDomain);
/* Send & Recv */
int TLS_Send(TLS* pTLS, SOCKET s, PBYTE pBuff, int len);
int TLS_Recv(TLS* pTLS, SOCKET s, PBYTE pBuff, int len);
/* Cleanup */
void TLS_Cleanup(TLS* pTLS);
