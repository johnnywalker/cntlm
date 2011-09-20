int spnego_request(const char *host, char **out_buf, void **out_creds, void **out_ctxt);

int spnego_response(const char *host, const char *resp, const int resp_len, const void *creds,
    const void *ctxt, char **out_buf);

void spnego_free(void **creds, void **ctxt);
