#pragma once
#define SECURITY_WIN32

#include <WinSock2.h>
#include <Windows.h>
#include <sspi.h>
#include <schannel.h>

typedef struct DecryptBuffer
{
    SECURITY_STATUS iCode;
    SecBuffer       Data[4];
} DecryptBuffer;

typedef struct TLS
{
    PBYTE  Buff;
    UINT   BuffLen;
    SOCKET Sock;

    CtxtHandle hCtx;
    CredHandle hCred;

    DecryptBuffer DecryptBuff;
    SecPkgContext_StreamSizes Sizes;
} TLS;

/* Initialize Library */
BOOL TLS_Init(TLS* pTLS);
/* Initiate handshake */
BOOL TLS_Handshake(TLS* pTLS, SOCKET s, LPSTR szDomain);
/* Send & Recv */
int TLS_Send(TLS* pTLS, PBYTE pBuff, int len);
int TLS_Recv(TLS* pTLS, PBYTE pBuff, int len);
/* Cleanup */
void TLS_Cleanup(TLS* pTLS);
