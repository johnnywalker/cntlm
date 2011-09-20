#include <utils.h>

#ifndef WIN32_WINNT
#  define WIN32_WINNT 0x500
#endif

#define SECURITY_WIN32
#include <security.h>

#ifndef __GNUC__
#pragma comment(lib, "secur32.lib")
#endif

#define SPN_MAX_LENGTH  260
#define SPN_PREFIX      "HTTP/"
#define ISC_FLAGS       ISC_REQ_ALLOCATE_MEMORY

int spnego_request(const char *host, char **out_buf, void **out_creds, void **out_ctxt) {
    PCredHandle phCred;
    PCtxtHandle phCtxt;
    SecBufferDesc outputBuffers;
    PSecBuffer pBuffer;
    ULONG contextAttr;
    TimeStamp exp;
    SECURITY_STATUS ret = SEC_E_OK;
    char spn[SPN_MAX_LENGTH];
    int i;
    char *_buf = NULL;
    int _len = 0;

    snprintf(spn, SPN_MAX_LENGTH, "%s%s", SPN_PREFIX, host);

    phCred = (PCredHandle) new(sizeof(CredHandle));

    phCtxt = (PCtxtHandle) new(sizeof(CtxtHandle));

    ret = AcquireCredentialsHandle(NULL, "Negotiate", SECPKG_CRED_OUTBOUND,
        NULL, NULL, NULL, NULL, phCred, &exp);
    
    if (FAILED(ret)) {
        free(phCtxt);
        free(phCred);
        return 0;
    }

    outputBuffers.ulVersion = SECBUFFER_VERSION;
    outputBuffers.cBuffers = 0;
    outputBuffers.pBuffers = NULL;

    ret = InitializeSecurityContext(phCred, NULL, spn, ISC_FLAGS, 0, 
        SECURITY_NATIVE_DREP, NULL, 0, phCtxt, &outputBuffers, &contextAttr,
        &exp);

    if (FAILED(ret)) {
        FreeCredentialsHandle(phCred);
        free(phCred);
        free(phCtxt);
        return 0;
    }

    if (ret != SEC_I_CONTINUE_NEEDED) {
        for (i=0; i<outputBuffers.cBuffers; i++)
            FreeContextBuffer(outputBuffers.pBuffers[i]);

        DeleteSecurityContext(phCtxt);
        FreeCredentialsHandle(phCred);
        free(phCred);
        free(phCtxt);
        return 0;
    }

    pBuffer = outputBuffers[0].pBuffers;
    _len = pBuffer->cbBuffer;
    _buf = new(_len + 1);

    memcpy(_buf, pBuffer->pvBuffer, _len);
    
    for (i=0; i<outputBuffers.cBuffers; i++)
        FreeContextBuffer(outputBuffers.pBuffers[i].pvBuffer);

    *out_buf = _buf;
    *out_creds = phCred;
    *out_ctxt = phCtxt;

    return _len;
}

int spnego_response(const char *host, const char *resp, const int resp_len, const void *creds,
    const void *ctxt, char **out_buf) {
    PCredHandle phCred;
    PCtxtHandle phCtxt;
    SecBufferDesc inputBuffers;
    SecBuffer inputBuffer;
    SecBufferDesc outputBuffers;
    PSecBuffer pBuffer;
    ULONG contextAttr;
    TimeStamp exp;
    SECURITY_STATUS ret = SEC_E_OK;
    char spn[SPN_MAX_LENGTH];
    int i;
    char *_buf = NULL;
    int _len = 0;

    snprintf(spn, SPN_MAX_LENGTH, "%s%s", SPN_PREFIX, host);

    phCred = (PCredHandle) creds;
    phCtxt = (PCtxtHandle) ctxt;

    inputBuffers.cBuffers = 1;
    inputBuffers.ulVersion = SECBUFFER_VERSION;
    inputBuffers.pBuffers = &inputBuffer;

    inputBuffer.cbBuffer = resp_len;
    inputBuffer.BufferType = SECBUFFER_TOKEN;
    inputBuffer.pvBuffer = resp;

    outputBuffers.cBuffers = 0;
    outputBuffers.ulVersion = SECBUFFER_VERSION;
    outputBuffers.pBuffers = NULL;

    ret = InitializeSecurityContext(phCred, phCtxt, spn, ISC_FLAGS, 0, 
        SECURITY_NATIVE_DREP, &inputBuffers, 0, phCtxt, &outputBuffers, &contextAttr,
        &exp);

    if (FAILED(ret))
        return -1;

    if (ret != SEC_E_OK) {
        for (i=0; i < outputBuffers.cBuffers; i++)
            FreeContextBuffer(outputBuffers.pBuffers[i].pvBuffer)
        return -1;
    }

    if (outputBuffers.cBuffers > 0) {
        pBuffer = outputBuffers[0].pBuffers;
        _len = pBuffer->cbBuffer;
        _buf = new(_len + 1);

        memcpy(_buf, pBuffer->pvBuffer, _len);
        
        for (i=0; i<outputBuffers.cBuffers; i++)
            FreeContextBuffer(outputBuffers.pBuffers[i].pvBuffer);

        *out_buf = _buf;
    }

    return _len;
}

void spnego_free(void **creds, void **ctxt) {
    if (*creds) {
        FreeCredentialsHandle((PCredHandle) *creds);
        free(*creds);
        *creds = NULL;
    }

    if (*ctxt) {
        DeleteSecurityContext((PCtxtHandle) *ctxt);
        free(*ctxt);
        *ctxt = NULL;
    }
}
