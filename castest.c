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

#include <stdio.h>
#include "cas.h"

// dumb, simple test of cas_validate() function
int main(int argc, char **argv) {
  char *ticket, *service, *proxy1, *proxy2;
  char *proxies[3];
  char netid[10];

  if (argc < 2) {
    ticket = "foo";
    service = "foo";
  } else {
    ticket = argv[1];
    service = argv[2];
    proxy1 = argv[3];
    proxy2 = argv[4];
  }

  proxies[0] = proxy1;
  proxies[1] = proxy2;
  proxies[2] = NULL;

  if (cas_validate(ticket, service, netid, sizeof(netid), proxies)
      == CAS_SUCCESS)
    printf("valid ticket for '%s'\n", netid);
  else
    printf("invalid ticket\n");
}
