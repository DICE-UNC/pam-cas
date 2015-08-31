/*
 *  Copyright (c) 2000-2003 Yale University. All rights reserved.
 *
 *  THIS SOFTWARE IS PROVIDED "AS IS," AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE EXPRESSLY
 *  DISCLAIMED. IN NO EVENT SHALL YALE UNIVERSITY OR ITS EMPLOYEES BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED, THE COSTS OF
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED IN ADVANCE OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 *  Redistribution and use of this software in source or binary forms,
 *  with or without modification, are permitted, provided that the
 *  following conditions are met:
 *
 *  1. Any redistribution must include the above copyright notice and
 *  disclaimer and this list of conditions in any related documentation
 *  and, if feasible, in the redistributed software.
 *
 *  2. Any redistribution must include the acknowledgment, "This product
 *  includes software developed by Yale University," in any related
 *  documentation and, if feasible, in the redistributed software.
 *
 *  3. The names "Yale" and "Yale University" must not be used to endorse
 *  or promote products derived from this software.
 */

/*
 * CAS 2.0 service- and proxy-ticket validator in C, using OpenSSL.
 *
 * Originally by Shawn Bayern, Yale ITS Technology and Planning.
 * Patches submitted by Vincent Mathieu, University of Nancy, France.
 */

#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "cas.h"
#include "xml.h"

#define END(x) { ret = (x); goto end; }
#define FAIL END(CAS_ERROR)
#define SUCCEED END(CAS_SUCCESS)

//#define DEBUG
#undef DEBUG

#ifdef DEBUG
# define LOG(X) printf("%s", (X))
#else
# define LOG(X) 
#endif

char *trusted_ca[] = {
    "/usr/local/etc/verisignserverca.pem",
    NULL
};

int cas_validate(
    char *ticket, char *service, char *outbuf, int outbuflen, char *proxies[]);
static X509 *get_cert_from_file(char *filename);
static int valid_cert(X509 *cert, char *hostname);
static int arrayContains(char *array[], char *element);

/** Returns status of certification:  0 for invalid, 1 for valid. */
static int valid_cert(X509 *cert, char *hostname)
{
  int i;
  char buf[4096];
  X509_STORE *store = X509_STORE_new();
  X509_STORE_CTX *ctx = X509_STORE_CTX_new();
  for (i = 0; trusted_ca[i] != NULL; i++) {
    X509 *cacert = get_cert_from_file(trusted_ca[i]);
    if (cacert)
      X509_STORE_add_cert(store, cacert);
  }
  X509_STORE_CTX_init(ctx, store, cert, sk_X509_new_null());
  if (X509_verify_cert(ctx) == 0)
    return 0;
  X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName,
    buf, sizeof(buf) - 1);
  // anal-retentive:  make sure the hostname isn't as long as the
  // buffer, since we don't want to match only because of truncation
  if (strlen(hostname) >= sizeof(buf) - 1)
    return 0;
  return (!strcmp(buf, hostname));
}

/** Returns status of ticket by filling 'buf' with a NetID if the ticket
 *  is valid and buf is large enough and returning 1.  If not, 0 is
 *  returned.
 */
int cas_validate(
    char *ticket, char *service, char *outbuf, int outbuflen, char *proxies[])
{
  int s = 0, err, b, ret, total;
  struct sockaddr_in sa;
  struct hostent h, *hp2;
  SSL_CTX *ctx = NULL;
  SSL *ssl = NULL;
  X509 *s_cert = NULL;
  char buf[4096];
  SSL_METHOD *method = NULL;
  char *full_request, *str, *tmp;
  char netid[14];
  char parsebuf[128];
  int i;

  SSLeay_add_ssl_algorithms();
  method = SSLv23_client_method();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(method);
  if (!ctx)
    END(CAS_SSL_ERROR_CTX);
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    END(CAS_ERROR_CONN);

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  hp2 = gethostbyname(CAS_HOST);
  memcpy(&h, hp2, sizeof(h));
  //  gethostbyname_r(CAS_HOST, &h, buf, sizeof(buf), &hp2, &b);

  memcpy(&(sa.sin_addr.s_addr), h.h_addr_list[0], sizeof(long));
  sa.sin_port = htons(CAS_PORT);
  if (connect(s, (struct sockaddr*) &sa, sizeof(sa)) == -1)
     END(CAS_ERROR_CONN);
  if (!(ssl = SSL_new(ctx)))
    END(CAS_SSL_ERROR_CTX);
  if (!SSL_set_fd(ssl, s))
    END(CAS_SSL_ERROR_CTX);
  if (! (err = SSL_connect(ssl)))
    END(CAS_SSL_ERROR_CONN);
  if (!(s_cert = SSL_get_peer_certificate(ssl)))
    END(CAS_SSL_ERROR_CERT);
  if (!valid_cert(s_cert, CAS_HOST))
    END(CAS_SSL_ERROR_CERT);

  X509_free(s_cert);

  full_request = malloc(strlen(CAS_METHOD) + strlen(" ")
    + strlen(CAS_VALIDATE) + strlen("?ticket=") + strlen(ticket) + 
    + strlen("&service=") + strlen(service) + strlen(" ") 
    + strlen(CAS_PROT) + strlen("\n\n") + 1);
  sprintf(full_request, "%s %s?ticket=%s&service=%s %s\n\n",
    CAS_METHOD, CAS_VALIDATE, ticket, service, CAS_PROT);
  if (!SSL_write(ssl, full_request, strlen(full_request)))
    END(CAS_SSL_ERROR_HTTPS);

  total = 0;
  do {
    b = SSL_read(ssl, buf + total, (sizeof(buf) - 1) - total);
    total += b;
  } while (b > 0);
  buf[total] = '\0';

  if (b != 0 || total >= sizeof(buf) - 1)
    END(CAS_SSL_ERROR_HTTPS);		// unexpected read error or response too large

  str = (char *)strstr(buf, "\r\n\r\n");  // find the end of the header

  if (!str)
    END(CAS_SSL_ERROR_HTTPS);			  // no header
  
  /*
   * 'str' now points to the beginning of the body, which should be an
   * XML document
   */

  // make sure that the authentication succeeded
  
  if (!element_body(
    str, "cas:authenticationSuccess", 1, parsebuf, sizeof(parsebuf))) {
    LOG("authentication failure\n");
    LOG(str);
    LOG("\n");
    END(CAS_AUTHENTICATION_FAILURE);
  }

  // retrieve the NetID
  if (!element_body(str, "cas:user", 1, netid, sizeof(netid))) {
    LOG("unable to determine username\n");
    END(CAS_PROTOCOL_FAILURE);
  }


  // check the first proxy (if present)
  if (element_body(str, "cas:proxies", 1, parsebuf, sizeof(parsebuf)))
    if (element_body(str, "cas:proxy", 1, parsebuf, sizeof(parsebuf)))
      if (!arrayContains(proxies, parsebuf)) {
        LOG("bad proxy: ");
        LOG(parsebuf);
        LOG("\n");
        END(CAS_BAD_PROXY);
      }

  /*
   * without enough space, fail entirely, since a partial NetID could
   * be dangerous
   */
  if (outbuflen < strlen(netid) + 1) {
    LOG("output buffer too short\n");
    END(CAS_PROTOCOL_FAILURE);
  }

  strcpy(outbuf, netid);
  SUCCEED;

   /* cleanup and return */

end:
  if (ssl)
    SSL_shutdown(ssl);
  if (s > 0)
    close(s);
  if (ssl)
    SSL_free(ssl);
  if (ctx)
    SSL_CTX_free(ctx);
  return ret;
}

static X509 *get_cert_from_file(char *filename) {
    X509 *c;
    FILE *f = fopen(filename, "r");
    if (! f )
      return NULL;
    c = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return c;
}

// returns 1 if a char* array contains the given element, 0 otherwise
static int arrayContains(char *array[], char *element) {
  char *p;
  int i = 0;

  for (p = array[0]; p; p = array[++i]) {
    LOG("  checking element ");
    LOG(p);
    LOG("\n");
    if (!strcmp(p, element))
      return 1;
  }
  return 0;
}
