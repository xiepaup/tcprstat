/**
 *   tcprstat -- Extract stats about TCP response times
 *   Copyright (C) 2010  Ignacio Nin
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
**/

#include "tcprstat.h"
#include "capture.h"
#include "process-packet.h"

#include <pcap.h>

pcap_t *pcap;

void *capture(void *arg) {

    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[30];
    int r;

    // Second argument 0 stands for non-promiscuous mode
    pcap = pcap_open_live("any", CAPTURE_LENGTH, 0, READ_TIMEOUT, errbuf);
    /*1）获取数据包捕获描述字
     * pcap_t * pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf);
     * 函数参数：
     * - snaplen参数定义捕获数据的最大字节数， 一般使用BUFSIZ， 该参数一般位于<pcap.h>中若没有定义，应使用unsigned int的最大值。
     * - promisc指定是否将网络接口置于混杂模式， 如果设置为true(当promisc>0时)可以使用混杂模式进行数据包的抓取。
     * - to_ms参数指定超时时间（毫秒），如果设置为0意味着没有超时等待这一说法。
     * - ebuf参数则仅在pcap_open_live()函数出错返回NULL时用于传递错误消息。
     */

    if (!pcap) {
        fprintf(stderr, "pcap: %s\n", errbuf);
        return NULL;

    }

    // Capture only TCP
    if (port)
        sprintf(filter, "tcp port %d", port);
    else
        sprintf(filter, "tcp");

    //2)编译字串至过滤程序,过滤程序在这里被初始化!
    if (pcap_compile(pcap, &bpf, filter, 1, 0)) {
        fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
        return NULL;

    }

    //3)指定过滤程序
    if (pcap_setfilter(pcap, &bpf)) {
        fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
        return NULL;

    }

    //4)捕获并处理数据包
    // The -1 here stands for "infinity"
    r = pcap_loop(pcap, -1, process_packet, (unsigned char *) pcap);
    /*
     *  函数名称：int pcap_loop(pcap_t *p, int cnt,pcap_handler callback, u_char *user)
     *  函数功能：功能基本与pcap_dispatch()函数相同，只不过此函数在cnt个数据包被处理或出现错误时才返回，但读取超时不会返回。
     *           而如果为pcap_open_live()函数指定了一个非零值的超时设置，然后调用pcap_dispatch()函数，则当超时发生时pcap_dispatch()函数会返回。
     *           cnt参数为负值时pcap_loop()函数将始终循环运行，除非出现错误。
     *
     */
    if (r == -1) {
        fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
        return NULL;

    }

    return NULL;

}

int offline_capture(FILE *fcapture) {
    struct bpf_program bpf;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter[30];
    int r;

    pcap = pcap_fopen_offline(fcapture, errbuf);
    /*
     * 函数名称：pcap_t *pcap_open_offline(char *fname,char *errbuf);
     * 函数功能：获得保存在fname文件中的以前捕捉的数据。如果出错，错误保存在errbuf中。
     * 参数说明：fname，要打开的文件名。
     *          errbuf，出错时保存错误的地方。errbuf至少大于PCAP_ERRBUF_SZIE。
     */
    if (!pcap) {
        fprintf(stderr, "pcap: %s\n", errbuf);
        return 1;

    }

    // Capture only TCP
    if (port)
        sprintf(filter, "tcp port %d", port);
    else
        sprintf(filter, "tcp");

    if (pcap_compile(pcap, &bpf, filter, 1, 0)) {
        fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
        return 1;

    }

    if (pcap_setfilter(pcap, &bpf)) {
        fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
        return 1;

    }

    // The -1 here stands for "infinity"
    r = pcap_loop(pcap, -1, process_packet, (unsigned char *) pcap);
    if (r == -1) {
        fprintf(stderr, "pcap: %s\n", pcap_geterr(pcap));
        return 1;

    }

    return 1;

}

void endcapture(void) {
    if (pcap)
        pcap_breakloop(pcap);

}
