/*
** mod_web_bot_auth.c -- An Apache module to verify requests using the
** web-bot-auth (HTTP Message Signatures) specification, i.e., implements the
** verification mechanism defined in
** https://github.com/thibmeu/http-message-signatures-directory
**
** This module inspects incoming requests for 'Signature', 'Signature-Input',
** and 'Signature-Agent' headers. If present, it attempts to verify the
** signature to authenticate automated clients (bots).
**
** To compile and install this module:
**
** $ apxs -c -i mod_web_bot_auth.c -lcurl -lssl -lcrypto
**
** To activate it, add the following to your httpd.conf or loader:
**
** #   httpd.conf or /etc/apache2/mods-available/web_bot_auth.load
** LoadModule web_bot_auth_module modules/mod_web_bot_auth.so
**
** #   httpd.conf or /etc/apache2/sites-available/000-default.conf
** (sudo nano /etc/apache2/sites-available/000-default.conf)
** <Location />
**   # Apply this handler to all requests
**   SetHandler web-bot-auth
** </Location>
**
** After restarting Apache (apachectl restart or systemctl restart apache2),
** requests without valid signatures will be rejected, while valid ones will
** be allowed to proceed.
**
** TODO(illyes): implement conditional header checking. For example, if
** request rate is >=N, request signature.
**
** Accessing to a protected URL will display an informational message.
**
**   $ lynx -mime_header http://localhost/web_bot_auth
*/

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "ap_config.h"
#include "apr_strings.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "httpd.h"

// Holds stuff that was fetched by libcurl.
struct MemoryStruct {
    char *memory;
    size_t size;
};

// A callback function for libcurl to write response data into our MemoryStruct
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb,
                                  void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        /* oh great. */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// libcurl URL fetcher. Used for fetching certificate.
static char *fetch_url(request_rec *r, const char *url) {
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(
        curl_handle, CURLOPT_USERAGENT,
        "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/1.2.3.4 Mobile "
        "Safari/537.36 (compatible; WebBotAuth/1.0; "
        "+https://garyillyes.com/apache-web-bot-auth)");

    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "curl_easy_perform() failed: %s for URL: %s",
                      curl_easy_strerror(res), url);
        free(chunk.memory);
        return NULL;
    }

    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();

    return chunk.memory;
}

// Helper function to decode base64url data
static int base64url_decode(apr_pool_t *pool, const char *encoded,
                            char **decoded, int *decoded_len) {
    // Replace URL-safe characters with standard base64 characters
    char *base64 = apr_pstrdup(pool, encoded);
    char *p = base64;
    while (*p) {
        if (*p == '-') *p = '+';
        if (*p == '_') *p = '/';
        p++;
    }

    // Do we need padding? Maybe add padding.
    int len = strlen(base64);
    int padding = 0;
    if (len % 4 != 0) {
        padding = 4 - (len % 4);
    }
    char *padded_base64 = apr_pcalloc(pool, len + padding + 1);
    strcpy(padded_base64, base64);
    if (padding) {
        strncat(padded_base64, "===", padding);
    }

    // Decode using OpenSSL BIO. Cos life is beautiful, innit.
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(padded_base64, -1);
    bio = BIO_push(b64, bio);

    *decoded =
        apr_palloc(pool, len);  // Big assumption here. Maybe hope? Decoded
                                // length is at most input length.
    *decoded_len = BIO_read(bio, *decoded, len);

    BIO_free_all(bio);

    return *decoded_len > 0;
}

// Helper function to find a value for a given key in a JSON string.
// This is a very basic parser and not robust for complex JSON.
static char *json_get_string(apr_pool_t *pool, const char *json,
                             const char *key) {
    char *key_str = apr_pstrcat(pool, "\"", key, "\"", NULL);
    char *key_pos = strstr(json, key_str);
    if (!key_pos) return NULL;

    char *colon_pos = strchr(key_pos, ':');
    if (!colon_pos) return NULL;

    char *start_quote = strchr(colon_pos, '"');
    if (!start_quote) return NULL;
    start_quote++;

    char *end_quote = strchr(start_quote, '"');
    if (!end_quote) return NULL;

    return apr_pstrndup(pool, start_quote, end_quote - start_quote);
}

// Function to actually verify signature.
static int verify_signature(request_rec *r, const char *signature_input_header,
                            const char *signature_header) {
    // 1. Parse Signature-Input to get keyid.
    const char *keyid_start = strstr(signature_input_header, "keyid=\"");
    if (!keyid_start) return 0;
    // Account for "keyid=\"".
    keyid_start += 7;
    const char *keyid_end = strchr(keyid_start, '"');
    if (!keyid_end) return 0;
    char *keyid = apr_pstrndup(r->pool, keyid_start, keyid_end - keyid_start);

    // 2. Now fetch the JWKS from the Signature-Agent URL.
    const char *agent_url = apr_table_get(r->headers_in, "Signature-Agent");
    if (!agent_url) return 0;

    // The URL might be enclosed in <>. Cos internet standards.
    if (agent_url[0] == '<') agent_url++;
    // We're in Apache realms so while there's plenty of nicer ways to do this,
    // we need to comply with Apache rules. We're not anarchists.
    const char *agent_url_end = strchr(agent_url, '>');
    if (agent_url_end) {
        agent_url = apr_pstrndup(r->pool, agent_url, agent_url_end - agent_url);
    }
    // Ask cURL to get the cert that will have the cert somewhere.
    char *jwks_json = fetch_url(r, agent_url);
    if (!jwks_json) return 0;

    // 3. Find the public key in the JWKS that matches the keyid.
    // We're working with something like this:
    //   {
    //     "keys": {
    //       "kty": "OKP",
    //       "crv": "Ed25519",
    //       "kid": "NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw",
    //       "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
    //       "use": "sig",
    //       "nbf": 1712793600,
    //       "exp": 1715385600
    //     }
    //   }
    char *pubkey_b64url = NULL;
    char *keys_start = strstr(jwks_json, "\"keys\":[");
    if (keys_start) {
        char *current_key = keys_start;
        while ((current_key = strstr(current_key, "\"kid\":\""))) {
            current_key += 7;  // Account for the string matching.
            char *kid = json_get_string(r->pool, current_key - 7, "kid");
            if (kid && strcmp(kid, keyid) == 0) {
                pubkey_b64url = json_get_string(r->pool, current_key - 7, "x");
                break;
            }
        }
    }
    free(jwks_json);  // Cos memory management is, in fact, fun.
    if (!pubkey_b64url) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "Public key not found for keyid: %s", keyid);
        return 0;
    }

    // 4. Construct the signature base string, i.e. what went into the actual
    // signature, by parsing the Signature-Input header. We're working with
    // something like this:
    //   Signature-Input: sig1=("@authority")\
    //   ;created=1735689600\
    //   ;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA"\
    //   ;alg="rsa-pss-sha512"\
    //   ;expires=1735693200\
    //   ;nonce="yT+sZR1glKOTemVLbmPDFwPScbB1Zj/sMNPEFZcjwJW5jK/taa7HviOXovVwiZOfrrLHS2SbLFUQBxPYZChf7g=="\
    //   ;tag="web-bot-auth"
    // We need `sig1`.
    char *signature_base = "";
    const char *components_start = strchr(signature_input_header, '(');
    if (!components_start) {
        ap_log_rerror(
            APLOG_MARK, APLOG_WARNING, 0, r,
            "Could not find start of components list in Signature-Input");
        return 0;
    }
    components_start++;  // Move past '('.
    const char *components_end = strchr(components_start, ')');
    if (!components_end) {
        ap_log_rerror(
            APLOG_MARK, APLOG_WARNING, 0, r,
            "Could not find end of components list in Signature-Input");
        return 0;
    }

    char *components_str = apr_pstrndup(r->pool, components_start,
                                        components_end - components_start);
    char *last;
    char *component = apr_strtok(components_str, " ", &last);
    // Now we actually get the values for the sig base. Note the `@` values;
    // they're just taken from env.
    while (component != NULL) {
        // Remove quotes. We hate quotes.
        if (component[0] == '"') {
            component++;
            char *end_quote = strchr(component, '"');
            if (end_quote) {
                *end_quote = '\0';
            }
        }

        const char *value = NULL;
        if (strcmp(component, "@method") == 0) {
            value = r->method;
        } else if (strcmp(component, "@path") == 0) {
            value = r->uri;
        } else if (strcmp(component, "@authority") == 0) {
            value = apr_table_get(r->headers_in, "Host");
        } else if (component[0] != '@') {  // It's a regular HTTP header. Yay.
            value = apr_table_get(r->headers_in, component);
        }

        if (value) {
            signature_base = apr_pstrcat(r->pool, signature_base, "\"",
                                         component, "\": ", value, "\n", NULL);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                          "Signed component '%s' not found in request or is "
                          "not supported.",
                          component);
            return 0;  // A signed component is missing, so verification must
                       // fail.
        }
        component = apr_strtok(NULL, " ", &last);
    }

    // Finally, add the @signature-params component itself.
    signature_base =
        apr_pstrcat(r->pool, signature_base,
                    "\"@signature-params\": ", signature_input_header, NULL);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Constructed signature base: %s", signature_base);

    // 5. Decode signature and public key.
    char *sig_b64_start = strchr(signature_header, ':');
    if (!sig_b64_start) return 0;
    sig_b64_start++;
    char *sig_b64_end = strchr(sig_b64_start, ':');
    if (!sig_b64_end) return 0;
    char *sig_b64 =
        apr_pstrndup(r->pool, sig_b64_start, sig_b64_end - sig_b64_start);

    char *decoded_sig;
    int decoded_sig_len;
    if (!base64url_decode(r->pool, sig_b64, &decoded_sig, &decoded_sig_len))
        return 0;

    char *decoded_pubkey;
    int decoded_pubkey_len;
    if (!base64url_decode(r->pool, pubkey_b64url, &decoded_pubkey,
                          &decoded_pubkey_len))
        return 0;

    // 6. Perform cryptographic verification using OpenSSL (for Ed25519 anyway).
    int result = 0;
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, NULL, (unsigned char *)decoded_pubkey,
        decoded_pubkey_len);
    if (pkey) {
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
        if (md_ctx) {
            // For pure signature schemes like Ed25519, the hash algorithm is
            // NULL. Makes life slightly nicer.
            if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) == 1) {
                if (EVP_DigestVerify(md_ctx, (unsigned char *)decoded_sig,
                                     decoded_sig_len,
                                     (unsigned char *)signature_base,
                                     strlen(signature_base)) == 1) {
                    result = 1;  // Well I'll be damned. It worked?!
                }
            }
            EVP_MD_CTX_free(md_ctx);
        }
        EVP_PKEY_free(pkey);
    }

    return result;
}

// This function will be called by Apache for each request. On all threads.
// Yeah, very efficient. Should have some conditional to only call in fire mode
// or something.
static int web_bot_auth_handler(request_rec *r) {
    // We only want to handle main requests, not sub-requests.
    if (!r->handler || strcmp(r->handler, "web-bot-auth")) {
        return DECLINED;
    }

    // Get the headers from the request.
    const char *signature_input =
        apr_table_get(r->headers_in, "Signature-Input");
    const char *signature = apr_table_get(r->headers_in, "Signature");
    const char *signature_agent =
        apr_table_get(r->headers_in, "Signature-Agent");

    // Check if the required headers are present, fail with HTTP 401 if not.
    if (!signature_input || !signature || !signature_agent) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
                      "Missing web-bot-auth headers. This is expected for "
                      "browser access.");

        ap_set_content_type(r, "text/html;charset=utf-8");

        ap_rputs(
            "<!DOCTYPE html><html><head><title>Web Bot Auth "
            "Endpoint</title></head><body>",
            r);
        ap_rputs("<h1>Web Bot Auth Verification Endpoint</h1>", r);
        ap_rputs(
            "<p>This endpoint is used to verify requests from automated bots "
            "using the <code>web-bot-auth</code> specification.</p>",
            r);
        ap_rputs(
            "<p>A regular browser will not have the required "
            "<code>Signature</code>, <code>Signature-Input</code>, and "
            "<code>Signature-Agent</code> headers, resulting in this "
            "message.</p>",
            r);
        ap_rputs(
            "<p>If you are a bot operator, please ensure your requests include "
            "the necessary signature headers.</p>",
            r);
        ap_rputs("</body></html>", r);

        // We return HTTP_UNAUTHORIZED because the request is not authenticated,
        // even though we provide a friendly HTML body.
        r->status = HTTP_UNAUTHORIZED;
        return OK;  // Return OK, otherwise the HTML body is not sent.
    }

    // Now we actually verify the signature.
    if (verify_signature(r, signature_input, signature)) {
        ap_log_rerror(
            APLOG_MARK, APLOG_INFO, 0, r,
            "web-bot-auth signature verified successfully for agent: %s",
            signature_agent);
        // Add a header to the request to ... ourselves know that the client has
        // been verified. I dunno, maybe for log analysis or something. I don't
        // make the rules.
        apr_table_set(r->headers_in, "X-Bot-Auth-Status", "verified");
        return DECLINED;  // As in, the request is verifed, other modules can
                          // now have it.
    } else {
        ap_log_rerror(
            APLOG_MARK, APLOG_WARNING, 0, r,
            "web-bot-auth signature verification FAILED for agent: %s",
            signature_agent);
        return HTTP_UNAUTHORIZED;
    }
    return OK;  // Should not be reached. SHOULD, Morty, SHOULD.
}

// And now the apache hooks. Nothing interesting here.
static void web_bot_auth_register_hooks(apr_pool_t *p) {
    ap_hook_handler(web_bot_auth_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA web_bot_auth_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                        // create per-dir    config structures
    NULL,                        // merge  per-dir    config structures
    NULL,                        // create per-server config structures
    NULL,                        // merge  per-server config structures
    NULL,                        // table of config file commands
    web_bot_auth_register_hooks  // register hooks
};
