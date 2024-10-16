#define SECURITY_WIN32
#define TLS_PACKET_LEN 16896

#include <WinSock2.h>
#include <windows.h>
#include <sspi.h>
#include <schannel.h>

#include <stdio.h>


typedef struct TLS
{
    PBYTE pDecrypted;
    PBYTE pBuffer;
    UINT  uBuffLen;
    UINT  uDecryptedLen;

    CredHandle hCred;

} TLS;

static int Recv(SOCKET s, void* pBuffer, )
{

}

static int Send(SOCKET s, void* pBuffer, )
{
    
}

int TLS_Init(TLS* pTLS)
{
    pTLS->pBuffer  = malloc(TLS_PACKET_LEN);
    pTLS->uBuffLen = TLS_PACKET_LEN;



    return 0;
}

int TLS_Handshake(LPSTR szDomain, PCtxtHandle pCtx, PCredHandle pCred)
{
    SECURITY_STATUS iCode;
    SecBufferDesc   outBuffDesc;
    SecBuffer       outBuffer;
    SecBuffer       inputBuffer[2];
    ULONG           uAttribs;

    outBuffer.cbBuffer    = 0;
    outBuffer.pvBuffer    = NULL;
    outBuffer.BufferType  = SECBUFFER_TOKEN;

    outBuffDesc.cBuffers  = 1;
    outBuffDesc.pBuffers  = &outBuffer;
    outBuffDesc.ulVersion = SECBUFFER_VERSION;

    inputBufferDesc.cBuffers  = 2;
    inputBufferDesc.pBuffers  = inputBuffer;
    inputBufferDesc.ulVersion = SECBUFFER_VERSION;

    inputBuffer[0].BufferType = SECBUFFER_TOKEN;
    inputBuffer[0].cbBuffer   = TLS_PACKET_LEN;
    inputBuffer[0].pvBuffer   = pTLS->pBuffer;

    iCode = InitializeSecurityContext(
        pCred,
        NULL,
        szDomain,
        ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT  |
        ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
        0,
        0,
        NULL,
        0,
        pCtx,
        &outBuffDesc,
        &uAttribs,
        NULL
    );

    while (iCode != SEC_E_OK)
    {



        iCode = InitializeSecurityContextA(
            pCred,
            pCtx,
            NULL,
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT  |
            ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM,
            0,
            0,
            &inputBufferDesc,
            0,
            pCtx,
            &outputBufferDesc,
            &uAttribs,
            NULL
        );
    }

    return 0;
}

int main(void)
{
    // WSADATA wsaData;
    // WSAStartup(MAKEWORD(2, 0), &wsaData);
    
    CredHandle      hCred;
    SCHANNEL_CRED   credData;
    SECURITY_STATUS iCode;
    CtxtHandle      ctx;

    ZeroMemory(&credData, sizeof credData);
    credData.dwVersion             = SCHANNEL_CRED_VERSION;
    credData.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;

    iCode = AcquireCredentialsHandleA(
        NULL,
        UNISP_NAME,
        SECPKG_CRED_OUTBOUND,
        NULL,
        &credData,
        NULL, 
        NULL, 
        &hCred,
        NULL
    );

    if (iCode != SEC_E_OK)
    {
        printf("ERROR: -_-\n");
    }

    TLS_Handshake("google.com", &ctx, &hCred);
    FreeCredentialsHandle(&hCred);
    return 0;
}