#define TLS_PACKET_LEN 16896

#include <stdio.h>
#include "TLS.h"

static int Recv(SOCKET s, PBYTE pBuff, int len)
{
    int readBytes;

    while (len > 0)
    {
        readBytes = recv(s, pBuff, len, 0);

        if (readBytes <= 0)
            return -1;

        pBuff += readBytes;
        len   -= readBytes;
    }

    return 0;
}

static int Send(SOCKET s, PBYTE pBuff, int len)
{
    int sentBytes;
    
    while (len > 0)
    {
        sentBytes = send(s, pBuff, len, 0);

        if (sentBytes == SOCKET_ERROR)
            return -1;
        
        pBuff += sentBytes;
        len   -= sentBytes;
    }

    return 0;
}

static void ErrCode(SECURITY_STATUS iCode)
{
    const char* szErrMsg = NULL;

    switch (iCode)
    {
        case SEC_E_INSUFFICIENT_MEMORY:           szErrMsg = "Insufficient Memory!"; break;
        case SEC_E_INTERNAL_ERROR:                szErrMsg = "Internal Error!"; break;
        case SEC_E_INVALID_HANDLE:                szErrMsg = "Invalid Handle!"; break;
        case SEC_E_INVALID_TOKEN:                 szErrMsg = "Invalid token!"; break;
        case SEC_E_LOGON_DENIED:                  szErrMsg = "Logon denied!"; break;
        case SEC_E_NO_AUTHENTICATING_AUTHORITY:   szErrMsg = "No auth authority"; break;
        case SEC_E_NO_CREDENTIALS:                szErrMsg = "No creds!"; break;
        case SEC_E_TARGET_UNKNOWN:                szErrMsg = "Target unknown!"; break;
        case SEC_E_UNSUPPORTED_FUNCTION:          szErrMsg = "Unsupported function!"; break;
        case SEC_E_WRONG_PRINCIPAL:               szErrMsg = "Certificate Name!"; break;
        case SEC_E_APPLICATION_PROTOCOL_MISMATCH: szErrMsg = "Protocol mismatch!"; break;
        case SEC_E_INCOMPLETE_MESSAGE:            szErrMsg = "Incomplete Message"; break;
        case SEC_I_COMPLETE_AND_CONTINUE:         szErrMsg = "Complete and Continue"; break;
        case SEC_I_COMPLETE_NEEDED:               szErrMsg = "Complete needed"; break;
        case SEC_I_CONTINUE_NEEDED:               szErrMsg = "Continue needed"; break;
        case SEC_I_INCOMPLETE_CREDENTIALS:        szErrMsg = "Incomplete credentials"; break;
        case SEC_E_ILLEGAL_MESSAGE:               szErrMsg = "Illegal Message"; break;
        case SEC_E_ALGORITHM_MISMATCH:            szErrMsg = "Algo mismatch"; break;
        case SEC_E_OK:                            szErrMsg = "OK";
    }

    fprintf(stderr, "(WinTLS): Handshake failed: %s\n", szErrMsg);
}

BOOL TLS_Init(TLS* pTLS)
{
    SECURITY_STATUS iCode;
    SCHANNEL_CRED   credData;

    pTLS->Buff    = HeapAlloc(GetProcessHeap(), 0, TLS_PACKET_LEN);
    pTLS->BuffLen = 0;

    ZeroMemory(&credData, sizeof credData);
    credData.dwVersion             = SCHANNEL_CRED_VERSION;
    credData.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    credData.dwFlags               = SCH_USE_STRONG_CRYPTO;

    ZeroMemory(pTLS->DecryptBuff.Data, sizeof pTLS->DecryptBuff.Data);
    pTLS->DecryptBuff.iCode            = SEC_E_INCOMPLETE_MESSAGE;
    pTLS->DecryptBuff.Data[0].pvBuffer = pTLS->Buff;

    iCode = AcquireCredentialsHandleA(
        NULL,
        UNISP_NAME,
        SECPKG_CRED_OUTBOUND,
        NULL,
        &credData,
        NULL,
        NULL,
        &pTLS->hCred,
        NULL
    );

    return iCode == SEC_E_OK &&
           pTLS->Buff != NULL;
}

BOOL TLS_Handshake(TLS* pTLS, SOCKET s, LPSTR szDomain)
{
    SECURITY_STATUS iCode;
    ULONG           ulFlags;
    SecBuffer       outBuff;
    SecBuffer       inBuff[2];
    SecBufferDesc   inBuffDesc;
    SecBufferDesc   outBuffDesc;

    outBuffDesc.cBuffers  = 1;
    outBuffDesc.pBuffers  = &outBuff;
    outBuffDesc.ulVersion = SECBUFFER_VERSION;

    outBuff.BufferType = SECBUFFER_TOKEN;
    outBuff.cbBuffer   = 0;

    inBuffDesc.cBuffers  = 2;
    inBuffDesc.pBuffers  = inBuff;
    inBuffDesc.ulVersion = SECBUFFER_VERSION;

    ZeroMemory(inBuff, sizeof inBuff);
    inBuff[0].BufferType = SECBUFFER_TOKEN;
    inBuff[0].cbBuffer   = TLS_PACKET_LEN;
    inBuff[0].pvBuffer   = pTLS->Buff;

    pTLS->Sock = s;

    iCode = InitializeSecurityContextA(
        &pTLS->hCred,
        NULL,
        szDomain,
        ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT  |
        ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
        0,
        0,
        NULL,
        0,
        &pTLS->hCtx,
        &outBuffDesc,
        &ulFlags,
        NULL
    );

    while (iCode != SEC_E_OK)
    {
        if (iCode == SEC_I_CONTINUE_NEEDED)
        {
            Send(s, outBuff.pvBuffer, outBuff.cbBuffer);
            Recv(s, inBuff[0].pvBuffer, 5);
            FreeContextBuffer(outBuff.pvBuffer);

            inBuff[0].cbBuffer = 5;
        }
        else if (iCode == SEC_E_INCOMPLETE_MESSAGE)
        {
            Recv(s, (PBYTE)inBuff[0].pvBuffer + 5, inBuff[1].cbBuffer);
            
            inBuff[0].cbBuffer   = inBuff[1].cbBuffer + 5;
            inBuff[1].cbBuffer   = 0;
            inBuff[1].pvBuffer   = NULL;
            inBuff[1].BufferType = SECBUFFER_EMPTY;
        }
        else
        {
            ErrCode(iCode);
            return FALSE;
        }

        iCode = InitializeSecurityContextA(
            &pTLS->hCred,
            &pTLS->hCtx,
            NULL,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT  |
            ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
            0,
            0,
            &inBuffDesc,
            0,
            &pTLS->hCtx,
            &outBuffDesc,
            &ulFlags,
            NULL
        );
    }

    Send(s, outBuff.pvBuffer, outBuff.cbBuffer);

    QueryContextAttributesA(&pTLS->hCtx, SECPKG_ATTR_STREAM_SIZES, &pTLS->Sizes);
    FreeCredentialsHandle(&pTLS->hCred);
    return TRUE;
}

int TLS_Send(TLS* pTLS, PBYTE pBuff, int len)
{
    int           iCode;
    int           copyBytes;
    SecBufferDesc buffDesc;
    SecBuffer     encryptBuff[3];

    buffDesc.cBuffers  = 3;
    buffDesc.pBuffers  = encryptBuff;
    buffDesc.ulVersion = SECBUFFER_VERSION;

    encryptBuff[0].BufferType = SECBUFFER_STREAM_HEADER;
    encryptBuff[0].pvBuffer   = pTLS->Buff;
    encryptBuff[0].cbBuffer   = pTLS->Sizes.cbHeader;

    encryptBuff[1].BufferType = SECBUFFER_DATA;
    encryptBuff[1].pvBuffer   = pTLS->Buff + pTLS->Sizes.cbHeader;
    
    encryptBuff[2].BufferType = SECBUFFER_STREAM_TRAILER;
    encryptBuff[2].cbBuffer   = pTLS->Sizes.cbTrailer;

    while (len > 0)
    {
        copyBytes = min(len, pTLS->Sizes.cbMaximumMessage);
        CopyMemory(encryptBuff[1].pvBuffer, pBuff, copyBytes);

        encryptBuff[1].cbBuffer = copyBytes;
        encryptBuff[2].pvBuffer = pTLS->Buff + pTLS->Sizes.cbHeader + copyBytes;

        EncryptMessage(&pTLS->hCtx, 0, &buffDesc, 0);
        iCode = Send(pTLS->Sock, encryptBuff[0].pvBuffer, encryptBuff[0].cbBuffer +
                                                          encryptBuff[1].cbBuffer +
                                                          encryptBuff[2].cbBuffer);
        if (iCode == SOCKET_ERROR)
            return -1;

        pBuff += copyBytes;
        len   -= copyBytes;
    }

    return 0;
}

int TLS_Recv(TLS* pTLS, PBYTE pBuff, int len)
{
    int originLen;
    int readBytes;
    int copyBytes;
    SecBufferDesc buffDesc;
    SecBuffer*    decryptBuff;

    originLen   = len;
    decryptBuff = pTLS->DecryptBuff.Data;

    buffDesc.cBuffers  = 4;
    buffDesc.pBuffers  = decryptBuff;
    buffDesc.ulVersion = SECBUFFER_VERSION;

    while (len > 0)
    {
        if (pTLS->DecryptBuff.iCode == SEC_E_INCOMPLETE_MESSAGE)
        {
            if (pTLS->BuffLen == TLS_PACKET_LEN)
            {
                CopyMemory(pTLS->Buff, decryptBuff[3].pvBuffer,
                                       decryptBuff[3].cbBuffer);

                pTLS->BuffLen = decryptBuff[3].cbBuffer;
                decryptBuff[0].pvBuffer = pTLS->Buff;
            }

            readBytes = recv(pTLS->Sock, pTLS->Buff + pTLS->BuffLen,
                             TLS_PACKET_LEN - pTLS->BuffLen, 0);

            if (readBytes <= 0)
                return readBytes;

            pTLS->BuffLen += readBytes;
            decryptBuff[0].cbBuffer = readBytes + decryptBuff[3].cbBuffer;
        }
        else
        {
            copyBytes = min(len, decryptBuff[1].cbBuffer);
            CopyMemory(pBuff, decryptBuff[1].pvBuffer, copyBytes);

            pBuff += copyBytes;
            len   -= copyBytes;

            if (decryptBuff[3].BufferType == SECBUFFER_EMPTY) 
            {
                pTLS->BuffLen             = 0;
                decryptBuff[3].cbBuffer   = 0;
                decryptBuff[0].pvBuffer   = pTLS->Buff;
                pTLS->DecryptBuff.iCode   = SEC_E_INCOMPLETE_MESSAGE;

                break;
            }

            decryptBuff[0].pvBuffer = decryptBuff[3].pvBuffer;
            decryptBuff[0].cbBuffer = decryptBuff[3].cbBuffer;
        }

        decryptBuff[0].BufferType = SECBUFFER_DATA;
        decryptBuff[1].BufferType = SECBUFFER_EMPTY;
        decryptBuff[2].BufferType = SECBUFFER_EMPTY;
        decryptBuff[3].BufferType = SECBUFFER_EMPTY;

        pTLS->DecryptBuff.iCode = DecryptMessage(&pTLS->hCtx, &buffDesc, 0, 0);
    }

    return originLen - len;
}

void TLS_Cleanup(TLS* pTLS)
{
    HeapFree(GetProcessHeap(), 0, pTLS->Buff);
    DeleteSecurityContext(&pTLS->hCtx);
}
