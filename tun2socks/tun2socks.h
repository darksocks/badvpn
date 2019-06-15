/*
 * Copyright (C) Ambroz Bizjak <ambrop7@gmail.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <misc/version.h>
#include <misc/loggers_string.h>
#include <misc/loglevel.h>
#include <misc/minmax.h>
#include <misc/offset.h>
#include <misc/dead.h>
#include <misc/ipv4_proto.h>
#include <misc/ipv6_proto.h>
#include <misc/udp_proto.h>
#include <misc/byteorder.h>
#include <misc/balloc.h>
#include <misc/open_standard_streams.h>
#include <misc/read_file.h>
#include <misc/ipaddr6.h>
#include <misc/concat_strings.h>
#include <structure/LinkedList1.h>
#include <base/BLog.h>
#include <system/BReactor.h>
#include <system/BSignal.h>
#include <system/BAddr.h>
#include <system/BNetwork.h>
#include <flow/SinglePacketBuffer.h>
#include <socksclient/BSocksClient.h>
#include <tuntap/BTap.h>
#include <lwip/init.h>
#include <lwip/ip_addr.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/ip4_frag.h>
#include <lwip/nd6.h>
#include <lwip/ip6_frag.h>
#include <tun2socks/SocksUdpGwClient.h>

// name of the program
#define PROGRAM_NAME "tun2socks"

// size of temporary buffer for passing data from the SOCKS server to TCP for sending
#define CLIENT_SOCKS_RECV_BUF_SIZE 8192

// maximum number of udpgw connections
#define DEFAULT_UDPGW_MAX_CONNECTIONS 256

// udpgw per-connection send buffer size, in number of packets
#define DEFAULT_UDPGW_CONNECTION_BUFFER_SIZE 8

// udpgw reconnect time after connection fails
#define UDPGW_RECONNECT_TIME 5000

// udpgw keepalive sending interval
#define UDPGW_KEEPALIVE_TIME 10000

// option to override the destination addresses to give the SOCKS server
//#define OVERRIDE_DEST_ADDR "10.111.0.2:2000"

struct options{
    int help;
    int version;
    int logger;
    #ifndef BADVPN_USE_WINAPI
    char *logger_syslog_facility;
    char *logger_syslog_ident;
    #endif
    int loglevel;
    int loglevels[BLOG_NUM_CHANNELS];
    char *tundev;
    char *netif_ipaddr;
    char *netif_netmask;
    char *netif_ip6addr;
    char *socks_server_addr;
    char *username;
    char *password;
    char *password_file;
    int append_source_to_username;
    char *udpgw_remote_server_addr;
    int udpgw_max_connections;
    int udpgw_connection_buffer_size;
    int udpgw_transparent_dns;
};

// TCP client
struct tcp_client {
    int aborted;
    dead_t dead_aborted;
    LinkedList1Node list_node;
    BAddr local_addr;
    BAddr remote_addr;
    struct tcp_pcb *pcb;
    int client_closed;
    uint8_t buf[TCP_WND];
    int buf_used;
    char *socks_username;
    BSocksClient socks_client;
    int socks_up;
    int socks_closed;
    StreamPassInterface *socks_send_if;
    StreamRecvInterface *socks_recv_if;
    uint8_t socks_recv_buf[CLIENT_SOCKS_RECV_BUF_SIZE];
    int socks_recv_buf_used;
    int socks_recv_buf_sent;
    int socks_recv_waiting;
    int socks_recv_tcp_pending;
};

void terminate (void);
void print_help (const char *name);
void print_version (void);
int parse_arguments (int argc, char *argv[]);
int process_arguments (void);
void signal_handler (void *unused);
BAddr baddr_from_lwip (const ip_addr_t *ip_addr, uint16_t port_hostorder);
void lwip_init_job_hadler (void *unused);
void tcp_timer_handler (void *unused);
void device_error_handler (void *unused);
void device_read_handler_send (void *unused, uint8_t *data, int data_len);
int process_device_udp_packet (uint8_t *data, int data_len);
err_t netif_init_func (struct netif *netif);
err_t netif_output_func (struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);
err_t netif_output_ip6_func (struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr);
err_t common_netif_output (struct netif *netif, struct pbuf *p);
err_t netif_input_func (struct pbuf *p, struct netif *inp);
void client_logfunc (struct tcp_client *client);
void client_log (struct tcp_client *client, int level, const char *fmt, ...);
err_t listener_accept_func (void *arg, struct tcp_pcb *newpcb, err_t err);
void client_handle_freed_client (struct tcp_client *client);
void client_free_client (struct tcp_client *client);
void client_abort_client (struct tcp_client *client);
void client_abort_pcb (struct tcp_client *client);
void client_free_socks (struct tcp_client *client);
void client_murder (struct tcp_client *client);
void client_dealloc (struct tcp_client *client);
void client_err_func (void *arg, err_t err);
err_t client_recv_func (void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
void client_socks_handler (struct tcp_client *client, int event);
void client_send_to_socks (struct tcp_client *client);
void client_socks_send_handler_done (struct tcp_client *client, int data_len);
void client_socks_recv_initiate (struct tcp_client *client);
void client_socks_recv_handler_done (struct tcp_client *client, int data_len);
int client_socks_recv_send_out (struct tcp_client *client);
err_t client_sent_func (void *arg, struct tcp_pcb *tpcb, u16_t len);
void udpgw_client_handler_received (void *unused, BAddr local_addr, BAddr remote_addr, const uint8_t *data, int data_len);
int main_run (int argc, char **argv);
