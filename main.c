/*
 *  Copyright (C) 2020 Hsiang Chen, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time            time
#define mbedtls_time_t          time_t
#define mbedtls_fprintf         fprintf
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_RSA_C) ||         \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C) || \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_X509_CRT_PARSE_C)

int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_CLI_C and/or "
           "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
           "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
           "not defined.\n");
    return( 0 );
}

#else

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#ifdef WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef ssize_t
#define ssize_t long
#endif

#ifndef size_t
#define size_t unsigned long
#endif

#ifndef socklen_t
#define socklen_t unsigned int
#endif

#pragma comment(lib,"Ws2_32.lib")

#else

#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/select.h>
#include <pthread.h>
#include <netinet/in.h>
#ifdef JACKPOT_EMBED_IN6
#include <netinet/in6.h>
#endif

#endif

#include <string.h>
#include <signal.h>
#include <errno.h>

#include "config.h"
#include "list.h"

#define DEBUG_LEVEL 1

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

List list;

struct Server {
  int     service;
  int     fd;
  char    hostip[BUFSIZE];
  int     port;
  char    sport[16];
  char    serial[BUFSIZE];
  char    pers[BUFSIZE];
  time_t  timeout;
  // mbedtls
  mbedtls_x509_crt cacert;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  ////
  int     ready;
  int     ssl_ready;
} server;

struct Client {
  int       done;
#ifdef WIN32
  HANDLE    handle;
  DWORD     tid;
  SOCKET    fd;
#else
  pthread_t tid;
  int       fd;
#endif
  struct    sockaddr_storage addr;
  socklen_t addr_len;
  // mbedtls
  mbedtls_net_context server_fd;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
};

int server_ssl_init()
{
  mbedtls_x509_crt_init(&server.cacert);
  mbedtls_ctr_drbg_init(&server.ctr_drbg);
  mbedtls_entropy_init(&server.entropy);

  if (mbedtls_ctr_drbg_seed(&server.ctr_drbg, mbedtls_entropy_func, &server.entropy, (const unsigned char*) server.pers, strlen(server.pers)) != 0) {
    mbedtls_printf("mbedtls_ctr_drbg_seed(): failed\n");
    return -1;
  }

  if (mbedtls_x509_crt_parse(&server.cacert, (const unsigned char*) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len) < 0) {
    mbedtls_printf("mbedtls_x509_crt_parse(): failed\n");
    return -1;
  }

  server.ssl_ready = 1;

  return 0;
}

void server_ssl_free()
{
  if (server.ssl_ready) {
    mbedtls_x509_crt_free(&server.cacert);
    mbedtls_ctr_drbg_free(&server.ctr_drbg);
    mbedtls_entropy_free(&server.entropy);
    server.ssl_ready = 0;
  }
}

int client_ssl_init(struct Client* cli, int verify)
{
  int ret;

  mbedtls_net_init(&cli->server_fd);
  mbedtls_ssl_init(&cli->ssl);
  mbedtls_ssl_config_init(&cli->conf);
  
  /* start connection */
  if (mbedtls_net_connect(&cli->server_fd, server.hostip, server.sport, MBEDTLS_NET_PROTO_TCP) != 0) {
    mbedtls_printf("mbedtls_net_connect(): failed\n");
    return -1;
  }
  
  /* setup */
  if (mbedtls_ssl_config_defaults(&cli->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    mbedtls_printf("mbedtls_ssl_config_defaults(): failed\n");
    return -1;
  }

  mbedtls_ssl_conf_authmode(&cli->conf, verify ? MBEDTLS_SSL_VERIFY_OPTIONAL : MBEDTLS_SSL_VERIFY_NONE);
  if (verify) mbedtls_ssl_conf_ca_chain(&cli->conf, &server.cacert, NULL);
  mbedtls_ssl_conf_rng(&cli->conf, mbedtls_ctr_drbg_random, &server.ctr_drbg);
  mbedtls_ssl_conf_dbg(&cli->conf, my_debug, stdout);

  if (mbedtls_ssl_setup(&cli->ssl, &cli->conf) != 0) {
    mbedtls_printf("mbedtls_ssl_setup(): failed\n");
    return -1;
  }

  if (mbedtls_ssl_set_hostname(&cli->ssl, server.hostip) != 0) {
    mbedtls_printf("mbedtls_ssl_set_hostname(): failed\n");
    return -1;
  }

  mbedtls_ssl_set_bio(&cli->ssl, &cli->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  /* handshake */
  while ((ret = mbedtls_ssl_handshake(&cli->ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      mbedtls_printf("mbedtls_ssl_handshake(): failed (-0x%x)\n", -ret);
      return -1;
    }
  }

  /* verify certificate */
  if (verify && (ret = mbedtls_ssl_get_verify_result(&cli->ssl)) != 0) {
    char vrfy_buf[BUFSIZE];
    mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), " ! ", ret);
    mbedtls_printf("mbedtls_ssl_get_verify_result(): failed (%s)\n", vrfy_buf);
    return -1;
  }

  return 0;
}

void client_ssl_free(struct Client* cli)
{
  mbedtls_ssl_close_notify(&cli->ssl);
  mbedtls_net_free(&cli->server_fd);
  mbedtls_ssl_config_free(&cli->conf);
}

int client_switch(struct Client* cli)
{
  char buf[BUFSIZE * 2];
  ssize_t len;

  if ((len = snprintf(buf, sizeof(buf), "GET /%s HTTP/1.1\r\nHost: %s:%s\r\nConnection: keep-alive\r\n\r\n", server.serial, server.hostip, server.sport)) > 0) {
    int ret;
    while ((ret = mbedtls_ssl_write(&cli->ssl, (unsigned char*) buf, len)) <= 0) {
      if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        break;
      }
    }
    if (ret > 0) {
      while ((ret = mbedtls_ssl_read(&cli->ssl, (unsigned char*) buf, sizeof(buf))) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
          break;
        }
      }
      if (ret > 0 && !strncmp(buf + 9, "200", 3)) {
        return 0;
      }
    }
  }
  
  return -1;
}

void client_socks_loop(struct Client* cli)
{
  fd_set fds, rfds;

  FD_ZERO(&fds);
  FD_ZERO(&rfds);

  FD_SET(cli->fd, &rfds);
  FD_SET(cli->server_fd.fd, &rfds);

  while (1) {
    unsigned char buf[BUFSIZE];
    struct timeval tmv = { .tv_sec = server.timeout, .tv_usec = 0 };
      
    memcpy(&fds, &rfds, sizeof(fds));

    switch (select(MAX(cli->fd, cli->server_fd.fd) + 1, &fds, 0, 0, &tmv)) {
      case -1: // error
        if (errno == EINTR) continue;
      case 0: // timeout
        return;
        break;
    }

    if (FD_ISSET(cli->fd, &fds)) { // from local
      ssize_t len;

      if ((len = recv(cli->fd, buf, sizeof(buf), 0)) > 0) {
        int ret;

        while ((ret = mbedtls_ssl_write(&cli->ssl, buf, len)) <= 0) {
          if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return;
          }
        }
      } else return;
    } else { // from remote server
      ssize_t ret = 0;

      while ((ret = mbedtls_ssl_read(&cli->ssl, buf, sizeof(buf))) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
          return;
        }
      }
      if (ret > 0) {
        send(cli->fd, buf, ret, 0);
      } else {
        return;
      }
    }
  }
}

#ifdef WIN32
DWORD WINAPI client_td(void* arg)
#else
void* client_td(void* arg)
#endif
{
#ifdef WIN32
	DWORD ret = 0;
#else
  int ret = 0;
#endif

  struct Client* cli = (struct Client*) arg;

  if (!client_ssl_init(cli, 0)) {
    switch (client_switch(cli)) {
      case 0:
        client_socks_loop(cli);
        break;
      default:
        break;
    }
    client_ssl_free(cli);
  }

  cli->done = 1;

  ret = 0;

#ifdef WIN32
  ExitThread(ret);
#else
  pthread_exit(&ret);
#endif

  return 0;
}

int server_setup(int atype)
{
#ifdef WIN32
  static WORD wsaData;
#endif
  
  list_init(&list);

#ifdef WIN32
  if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) return -1;
#endif

  if ((server.fd = socket(atype, SOCK_STREAM, 0)) > 0) {
    struct sockaddr* paddr = NULL;
    socklen_t addr_len = 0;
    union {
      struct sockaddr_in in;
      struct sockaddr_in6 in6;
    } addr;
    int opt = 1;

    if (atype == AF_INET) {
      memset(&addr.in, 0, sizeof(addr.in));

      addr.in.sin_family = AF_INET;
      addr.in.sin_port = htons(server.service);
      addr.in.sin_addr.s_addr = INADDR_ANY;

      paddr = (struct sockaddr*) &addr.in;
      addr_len = sizeof(addr.in);
    } else {
      memset(&addr.in6, 0, sizeof(addr.in6));

      addr.in6.sin6_family = AF_INET6;
      addr.in6.sin6_port = htons(server.service);
      addr.in6.sin6_addr = in6addr_any;

      paddr = (struct sockaddr*) &addr.in6;
      addr_len = sizeof(addr.in6);
    }

    setsockopt(server.fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (!bind(server.fd, paddr, addr_len) && !listen(server.fd, 0)) {
      server.ready = 1;
      return 0;
    } else perror("bind() or listen()");
  }

  return -1;
}

void server_shutdown()
{
  if (server.ready) {
    list_uinit(&list);
#ifdef WIN32
    shutdown(server.fd, SD_BOTH);
    closesocket(server.fd);
    WSACleanup();
#else
    shutdown(server.fd, SHUT_RDWR);
    close(server.fd);
#endif
    server.ready = 0;
  }
}

void server_idle()
{
  size_t i, len = list_length(&list);

  for (i = 0; i < len; i++) {
    ListNode* ln = list_get(&list, i);
    if (ln == NULL) break;
    if (ln->tags.sub & SUB_PTR) {
      struct Client* cli = (struct Client*) ln->data.ptr;
      if (cli->done) {
#ifdef WIN32
        closesocket(cli->fd);
        CloseHandle(cli->handle);
#else
        close(cli->fd);
        pthread_kill(cli->tid, 0);
#endif
        list_remove(&list, i);
      }
    }
  }
}

void server_loop()
{
  int endl = 0;

  while (!endl) {
    int newc = 0;
    struct timeval tmv = { .tv_sec = server.timeout, .tv_usec = 0 };

    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(server.fd, &fds);

    switch (select(server.fd + 1, &fds, 0, 0, &tmv)) {
      case 0:
        server_idle();
        newc = 0;
        break;
      case -1:
        endl = 1;
        newc = 0;
        break;
      default:
        newc = 1;
        break;
    }

    if (newc) {
      int okay = 0;
      struct Client* cli = 0;

      if ((cli = (struct Client*) malloc(sizeof(struct Client))) != NULL) {
        memset(cli, 0, sizeof(struct Client));

        cli->addr_len = sizeof(cli->addr);
      
        if ((cli->fd = accept(server.fd, (struct sockaddr*) &cli->addr, &cli->addr_len)) > 0) {
          ListNode lno;

          memset(&lno, 0, sizeof(lno));

          lno.tags.sub = SUB_DATA | SUB_PTR | SUB_FREE | SUB_LEN;
          lno.data.ptr = cli;
          lno.data.len = sizeof(struct Client);

#ifdef WIN32
          if ((cli->handle = CreateThread(NULL, 0, client_td, cli, 0, &cli->tid)) != 0) {
            list_insert(&list, -1, &lno);
            okay = 1;
          }
#else
          if (!pthread_create(&cli->tid, 0, client_td, cli)) {
            list_insert(&list, -1, &lno);
            okay = 1;
          }
#endif

        }
      }

      if (!okay && cli) free(cli);
    }
  }
}

void sigexit(int sig)
{
  server_idle();
  server_ssl_free();
  server_shutdown();
  mbedtls_printf("\rExiting...\n");
  exit(EXIT_SUCCESS);
}

void init_defaults(char* pers)
{
  server.service = 1080;
  server.fd = -1;
  server.timeout = DEF_CTIMEOUT;
  server.port = 443;
  snprintf(server.sport, sizeof(server.sport), "%u", (unsigned int) server.port);
  strncpy(server.pers, pers, sizeof(server.pers));
}

int parse_arguments(int argc, char* argv[])
{
  int ret = 0x01;
  int i;

  init_defaults(argv[0]);

  for (i = 0; i < argc; i++) {
    if (!strcmp(argv[i], "-4")) {
      ret |= 0x01;
    } else if (!strcmp(argv[i], "-6")) {
      ret |= 0x02;
    } else if (!strcmp(argv[i], "-i") && i + 1 < argc) {
      /* hostip */
      strncpy(server.hostip, argv[i + 1], sizeof(server.hostip));
      i++;
      ret |= 0x04;
    } else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      /* port */
      strncpy(server.sport, argv[i + 1], sizeof(server.sport));
      server.port = atoi(server.sport);
      i++;
      ret |= 0x08;
    } else if (!strcmp(argv[i], "-w") && i + 1 < argc) {
      /* service */
      server.service = atoi(argv[i + 1]);
      i++;
    } else if (!strcmp(argv[i], "-t") && i + 1 < argc) {
      /* timeout */
      server.timeout = (time_t) atol(argv[i + 1]);
      i++;
    } else if (!strcmp(argv[i], "-s") && i + 1 < argc) {
      /* serial */
      strncpy(server.serial, argv[i + 1], sizeof(server.serial));
      i++;
      ret |= 0x10;
    }
  }

  return ret;
}

#ifdef EXPORT_MODULE

int okay[2] = {0};

extern int export_module_runJackpotProxy (
  int vpnIsIp6,
  char* vpnIpAddressStr,
  char* vpnPortStr,
  int vpnService,
  int vpnTimeout,
  char* vpnSerialStr
) {
#if defined(MBETLS_DEBUG_C)
  mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif
  
  memset(&server, 0, sizeof(server));

  init_defaults("jackpot-embed");

  strncpy(server.hostip, vpnIpAddressStr, sizeof(server.hostip));
  strncpy(server.sport, vpnPortStr, sizeof(server.sport));
  server.port = atoi(vpnPortStr);
  if (vpnService > 0) server.service = vpnService;
  if (vpnTimeout > 0) server.timeout = vpnTimeout;
  strncpy(server.serial, vpnSerialStr, sizeof(server.serial));

  if (!server_setup(vpnIsIp6 > 0 ? AF_INET6 : AF_INET)) {
    okay[0] = 1;
    if (!server_ssl_init()) {
      okay[1] = 1;
      server_loop();
    }
  }

  return okay[0] > 0 && okay[1] > 0;
}

extern int export_module_terminateJackpotProxy () 
{
  if (okay[1] > 0) server_ssl_free();
  if (okay[0] > 0) server_shutdown();
  return 0;
}

#else

void usage()
{
  mbedtls_printf( "%s version %s (client)\n" \
                  "Server version 1.4.1 or later required\n" \
                  "Copyright (C) 2020 Hsiang Chen, All Rights Reserved\n" \
                  "This program is under the Apache License 2.0\n\n" \
                  "Usage: %s [option]...\n" \
                  "option:\n" \
                  "  -4             IPv4 SOCKS4 server\n" \
                  "  -6             IPv6 SOCKS6 server\n" \
                  "  -i [hostip]    hostname or ip of jackpot server\n" \
                  "  -p [port]      port of jackpot server\n" \
                  "  -w [service]   port of SOCKS5 server\n" \
                  "  -t [timeout]   timeout of connection\n" \
                  "  -s [serial]    serial string\n\n" \
                  "Report bugs to <%s>.\n", PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_NAME, PACKAGE_BUGREPORT);
}

int main(int argc, char* argv[])
{
  int exit_code = MBEDTLS_EXIT_FAILURE, ret;

#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

  memset(&server, 0, sizeof(server));

  ret = parse_arguments(argc, argv);

  if ((ret & 0x14) == 0x14) {
    if (!server_setup(ret & 0x02 ? AF_INET6 : AF_INET)) {
      if (!server_ssl_init()) {
        signal(SIGINT, sigexit);
        server_loop();
        server_ssl_free();
        exit_code = MBEDTLS_EXIT_SUCCESS;
      }
      server_shutdown();
    }
  } else {
    usage();
  }

  return(exit_code);
}

#endif

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&
          MBEDTLS_CERTS_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_CTR_DRBG_C &&
          MBEDTLS_X509_CRT_PARSE_C */
