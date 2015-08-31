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

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <string.h>
#include <syslog.h>
#include <sys/param.h>
#include "cas.h"

typedef enum Flags { NONE = 0, DEBUG = 1 } Flags;

char **add_proxy(char **proxies, const char *proxy);
void free_proxies(char **proxies);
int auth(char *user, char *pw, Flags f);

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, 
     const char **argv)
{
    char *user, *pw;
    char *service;
    char **proxies;
    char netid[14];
    int i, success;
    Flags f = NONE;

    /* initialize proxy array */
    proxies = (char **)malloc(sizeof(char **));
    proxies[0] = NULL;

    /* get username and password */
    if (pam_get_user(pamh, (const char**) &user, NULL) != PAM_SUCCESS)
	return PAM_AUTH_ERR;
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void**) &pw) != PAM_SUCCESS)
	return PAM_AUTH_ERR;

    /*
     * Abort if the password doesn't look like a ticket.  This speeds things
     * up and reduces the likelihood that the user's password will end up
     * in an HTTPD log.
     */
   if ((strncmp(CAS_BEGIN_PT, pw, strlen(CAS_BEGIN_PT)) != 0)
       && (strncmp(CAS_BEGIN_ST, pw, strlen(CAS_BEGIN_ST)) != 0))
         return PAM_AUTH_ERR;

    /* prepare log */
    openlog("PAM_cas", LOG_PID, LOG_AUTH);

    /* check arguments */
    for (i = 0; i < argc; i++) {
	if (!strcmp(argv[i], "debug"))
	    f |= DEBUG;
        else if (!strncmp(argv[i], "-s", 2)) {
	    service = strdup(argv[i] + 2);
	} else if (!strncmp(argv[i], "-p", 2)) {
	    proxies = add_proxy(proxies, argv[i] + 2);
        } else if (!strncmp(argv[i], "-e", 2)) {
	    /* don't let the username pass through if it's excluded */
	    if (!strcmp(argv[i] + 2, user)) {
		syslog(LOG_NOTICE, "user '%s' is excluded from the CAS PAM",
		    user);
		free_proxies(proxies);
		return PAM_AUTH_ERR;
	    }
	} else
	    syslog(LOG_ERR, "invalid option '%s'", argv[i]);
    }

    /* determine the CAS-authenticated username */
    success = cas_validate(pw, 
                           service, 
                           netid, 
                           sizeof(netid),
                           proxies);

    /* free the memory used by the proxy array */
    free_proxies(proxies);

    /* Confirm the user and return appropriately. */
    if ((success == CAS_SUCCESS) && (!strcmp(user, netid))) {
        closelog();
        return PAM_SUCCESS;
    } else {
        syslog(LOG_NOTICE,
          "authentication failure code %d for user '%s'", success, user);
       closelog();
       return PAM_AUTH_ERR;
    }
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
     const char **argv)
{
    return PAM_SUCCESS;
}

/* adds another proxy to the proxy array, NULL-terminating it */
char **add_proxy(char **proxies, const char *p) {

    char *proxy;
    int i = 0;

    proxy = strdup(p);

    /* find the end of the proxy array */
    while(proxies[i++]);

    /* realloc proxies to be sizeof(proxies + new_proxy + NULL) */
    proxies = (char **)realloc(proxies, sizeof(*proxies) * (i + 1));

    proxies[i-1] = proxy;
    proxies[i] = NULL;

    return proxies;
}

void free_proxies(char **proxies) {

    int i = 0;

    while(proxies[i]) {
	free(proxies[i++]);
    }

    free(proxies);
}
