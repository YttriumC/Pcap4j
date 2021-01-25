/*
 * @Author : Lucifer_程曾
 * @Date: 2020-02-22 12:36:15
 * @LastEditTime: 2020-04-09 20:56:01
 * @Description: Programmed by Lucifer
 * @FilePath: \CProgram\Include\env.h
 */

#define HAVE_REMOTE

#include "pcap.h"

#if _MSC_VER >= 1900
#include "stdio.h"
_ACRTIMP_ALT FILE *__cdecl __acrt_iob_func(unsigned);
#ifdef __cplusplus
extern "C"
#endif
    FILE *__cdecl __iob_func(unsigned i)
{
  return __acrt_iob_func(i);
}
#endif /* _MSC_VER>=1900 */

#define UNKNOWN_ERR 0xFF
#define OK 0x0
#define FIND_DEVS_ERR 0xB
#define OPEN_DEV_ERR 0xC
#define EOF_ERR 0xD
#define READ_PAC_ERR 0xE

#define PCAP_OPENFLAG_PROMISCUOUS 1
#define PCAP_OPENFLAG_DATATX_UDP 2
#define PCAP_OPENFLAG_NOCAPTURE_RPCAP 4
#define PCAP_OPENFLAG_NOCAPTURE_LOCAL 8
#define PCAP_OPENFLAG_MAX_RESPONSIVENESS 16
#define PCAP_SAMP_NOSAMP 0
#define PCAP_SAMP_1_EVERY_N 1
#define PCAP_SAMP_FIRST_AFTER_N_MS 2

#ifndef _STDIO_H
#include <stdio.h>
#endif
#ifndef _STDLIB_H
#include <stdlib.h>
#endif

#include <windows.h>

#include "Win32-Extensions.h"
#define PCAP_OPENFLAG_PROMISCUOUS 1
#ifndef ushort
typedef unsigned short ushort;
#endif
#ifndef ubyte
typedef unsigned char ubyte;
#endif
typedef struct
{
  ubyte mac1;
  ubyte mac2;
  ubyte mac3;
  ubyte mac4;
  ubyte mac5;
  ubyte mac6;
} mac_addr;
typedef struct
{
  mac_addr dist_mac; //当前帧目的mac地址
  mac_addr src_mac;  //当前帧源mac地址
  ushort type;
} eth_mac_header;

typedef struct pppoe
{
  //it usually is 1
  unsigned short versoion;
  //it's 1 too
  unsigned short type;
  //0x00
  ubyte session_data;
  //waitting to get
  unsigned short session_id;
  unsigned short payload_length;
  //IPv4 is 0x0021
  unsigned short ppp_protocal;
} ppp_datalink;

typedef struct ip_address
{
  u_char byte1;
  u_char byte2;
  u_char byte3;
  u_char byte4;
} ip_address;

/* IPv4 首部 */
typedef struct ip_header
{
  u_char ver_ihl;         // 版本 (4 bits) + 首部长度 (4 bits)
  u_char tos;             // 服务类型(Type of service)
  u_short tlen;           // 总长(Total length)
  u_short identification; // 标识(Identification)
  u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
  u_char ttl;             // 存活时间(Time to live)
  u_char proto;           // 协议(Protocol)
  u_short crc;            // 首部校验和(Header checksum)
  ip_address saddr;       // 源地址(Source address)
  ip_address daddr;       // 目的地址(Destination address)
  u_int op_pad;           // 选项与填充(Option + Padding)
} ip_header;

/* UDP 首部*/
typedef struct udp_header
{
  u_short sport; // 源端口(Source port)
  u_short dport; // 目的端口(Destination port)
  u_short len;   // UDP数据包长度(Datagram length)
  u_short crc;   // 校验和(Checksum)
} udp_header;

int println(const char *__format, ...)
{
  register int __retval;
  __builtin_va_list __local_argv;
  __builtin_va_start(__local_argv, __format);
  __retval = __mingw_vprintf(__format, __local_argv);

  __builtin_va_end(__local_argv);
  printf("\n");
  return __retval;
}

int printInt(int i)
{
  return printf("%d\n", i);
}
#ifndef EXIT_SUCCESS
#include "stdlib.h"
#endif
void pause()
{
  system("pause");
}

void quit(const char *INFO, int err_code)
{
  println("\n\nexit in %s ,with exit code:%X(%d)", INFO, err_code, err_code);
  pause();
  exit(err_code);
}

int print_mac_addr(mac_addr *mac)
{
  return printf("%02X:%02X:%02X:%02X:%02X:%02X",
                mac->mac1,
                mac->mac2,
                mac->mac3,
                mac->mac4,
                mac->mac5,
                mac->mac6);
}

/*
BOOL CtrlHandler(DWORD fdwCtrlType)
{
  switch (fdwCtrlType)
  {
  // Handle the CTRL-C signal.
  case CTRL_C_EVENT:
    printf("Ctrl-C event\n\n");
    Beep(750, 300);
    return (TRUE);

  // CTRL-CLOSE: confirm that the user wants to exit.
  case CTRL_CLOSE_EVENT:
    Beep(600, 200);
    printf("Ctrl-Close event\n\n");
    return (TRUE);

  // Pass other signals to the next handler.
  case CTRL_BREAK_EVENT:
    Beep(900, 200);
    printf("Ctrl-Break event\n\n");
    return FALSE;

  case CTRL_LOGOFF_EVENT:
    Beep(1000, 200);
    printf("Ctrl-Logoff event\n\n");
    return FALSE;

  case CTRL_SHUTDOWN_EVENT:
    Beep(750, 500);
    printf("Ctrl-Shutdown event\n\n");
    return FALSE;

  default:
    return FALSE;
  }
};
*/
