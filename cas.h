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

/* Default CAS information */

#define CAS_LOGIN_URL "https://secure.its.yale.edu/cas/login"
#define CAS_HOST "secure.its.yale.edu"
#define CAS_PORT 443
#define CAS_METHOD "GET"
#define CAS_VALIDATE "/cas/proxyValidate"
#define CAS_PROT "HTTP/1.0"

/**
 * Ticket identifiers to avoid needless validating passwords that
 * aren't tickets
 */
#define CAS_BEGIN_PT "PT-"
#define CAS_BEGIN_ST "ST-"


/* Error codes (decided upon by ESUP-Portail group) */
#define CAS_SUCCESS                 0
#define CAS_AUTHENTICATION_FAILURE -1
#define CAS_ERROR                  -2

#define CAS_SSL_ERROR_CTX          -10
#define CAS_SSL_ERROR_CONN         -11
#define CAS_SSL_ERROR_CERT         -12
#define CAS_SSL_ERROR_HTTPS        -13

#define CAS_ERROR_CONN             -20
#define CAS_PROTOCOL_FAILURE       -21
#define CAS_BAD_PROXY              -22
