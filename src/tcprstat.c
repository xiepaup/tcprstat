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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "tcprstat.h"
#include "functions.h"
#include "local-addresses.h"
#include "capture.h"
#include "output.h"
#include "stats.h"

/*********************************************************************************
 *    libpcap的包捕获机制就是在数据链路层加一个旁路处理。
 *    当一个数据包到达网络接口时，libpcap
 *         首先利用已经创建的Socket从链路层驱动程序中获得该数据包的拷贝，
 *         再通过Tap函数将数据包发给BPF过滤器。
 *    BPF过滤器根据用户已经定义好的过滤规则对数据包进行逐一匹配，
 *    匹配成功则放入内核缓冲区，并传递给用户缓冲区，
 *    匹配失败则直接丢弃。
 *    如果没有设置过滤规则，所有数据包都将放入内核缓冲区，并传递给用户层缓冲区。
 ********************************************************************************/

/*********************************************************************************
 *
 * 基于pcap的嗅探器程序的总体架构，其流程如下：
 *
 *1）选择嗅探接口：在Linux中，这可能是eth0，而在BSD系统中则可能是xl1等等。也可以用一个字符串来定义这个设备，或者采用pcap提供的接口名来工作。
 *
 *2）初始化pcap：告诉pcap对何设备进行嗅探，使用文件句柄进行设备的区分，必须命名该嗅探“会话”，以此使它们各自区别开来。
 *
 *3）创建规则集合：用于只想嗅探特定的传输，这个过程分为三个相互紧密关联的阶段。规则集合被置于一个字符串内，并且被转换成能被pcap读的格式(因此编译它)。
 *               编译实际上就是在程序里调用一个不被外部程序使用的函数。接下来告诉 pcap使用它来过滤出所要的那一个会话。(此步骤可选)
 *
 *4）进入主体执行循环：在这个阶段内pcap一直工作到它接收了所有我们想要的包为止。
 *                  每当它收到一个包就调用另一个已经定义好的函数，这个函数可以实现任何要求，
 *                  它可以剖析所部获的包并给用户打印出结果，它可以将结果保存为一个文件。
 *
 *5）关闭会话：在嗅探到所需的数据后，关闭会话并结束。
 *
 *
 ********************************************************************************/

struct option long_options[] = {
        {"help",       no_argument,       NULL, 'h'},
        {"version",    no_argument,       NULL, 'V'},

        {"local",      required_argument, NULL, 'l'},
        {"port",       required_argument, NULL, 'p'},
        {"format",     required_argument, NULL, 'f'},
        {"header",     optional_argument, NULL, 's'},
        {"no-header",  no_argument,       NULL, 'S'},
        {"interval",   required_argument, NULL, 't'},
        {"iterations", required_argument, NULL, 'n'},
        {"read",       required_argument, NULL, 'r'},

        {NULL, 0,                         NULL, '\0'}

};
char *short_options = "hVp:f:t:n:r:l:";

int specified_addresses = 0;

pthread_t capture_thread_id, output_thread_id;   //申明 抓包线程 、 输出线程 ID

// Global options
char *program_name;
int port;
//int interval = 30;
FILE *capture_file = NULL;
struct output_options output_options = {
        DEFAULT_OUTPUT_FORMAT,
        DEFAULT_OUTPUT_INTERVAL,
        DEFAULT_OUTPUT_ITERATIONS,

        DEFAULT_SHOW_HEADER,
        NULL,

};

// Operation timestamp
time_t timestamp;

int
main(int argc, char *argv[]) {
    struct sigaction sa;
    char c;
    int option_index = 0;

    // Program name
    program_name = strrchr(argv[0], '/'); //strrchr() 函数用于查找某字符在字符串中最后一次出现的位置
    if (program_name)
        program_name++;
    else
        program_name = argv[0];

    // Parse command line options
    do {
        c = getopt_long(argc, argv, short_options, long_options, &option_index);

        switch (c) {

            case -1:
                break;

            case 'r':
                capture_file = fopen(optarg, "r");
                if (!capture_file) {
                    fprintf(stderr, "Cannot open file `%s': %s\n", optarg,
                            strerror(errno));
                    return EXIT_FAILURE;

                }
                break;

            case 'l':
                specified_addresses = 1;
                if (parse_addresses(optarg)) {
                    fprintf(stderr, "Error parsing local addresses\n");
                    return EXIT_FAILURE;

                }

                break;

            case 'p':
                port = strtol(optarg, NULL, 0);
                // long int strtol (const char* str, char** endptr, int base);
                // strtol() 会扫描参数 str 字符串，跳过前面的空白字符（例如空格，tab缩进等，可以通过 isspace() 函数来检测），直到遇上数字或正负符号才开始做转换，再遇到非数字或字符串结束时('\0')结束转换，并将结果返回。
                // 当 base 的值为 0 时，默认采用 10 进制转换，但如果遇到 '0x' / '0X' 前置字符则会使用 16 进制转换，遇到 '0' 前置字符则会使用 8 进制转换。
                // 若endptr 不为NULL，则会将遇到的不符合条件而终止的字符指针由 endptr 传回；若 endptr 为 NULL，则表示该参数无效，或不使用该参数。
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "Invalid port\n");
                    return EXIT_FAILURE;
                }

                break;

            case 'f':
                if (!check_format(optarg)) {
                    fprintf(stderr, "Bad format provided: `%s'\n", optarg);
                    return EXIT_FAILURE;
                }

                output_options.format = optarg;

                break;

            case 't':
                output_options.interval = strtoul(optarg, NULL, 10);
                int interval = output_options.interval;
                if (interval <= 0 || interval >= MAX_OUTPUT_INTERVAL) {
                    fprintf(stderr, "Bad interval provided\n");
                    return EXIT_FAILURE;
                }

                break;

            case 'n':
                output_options.iterations = strtol(optarg, NULL, 10);
                int iterations = output_options.iterations;
                if (iterations < 0) {
                    fprintf(stderr, "Bad iterations provided\n");
                    return EXIT_FAILURE;
                }

                break;

            case 's':
                output_options.header = optarg;
                output_options.show_header = 1;
                break;

            case 'S':
                output_options.show_header = 0;
                break;

            case 'h':
                dump_help(stdout);
                return EXIT_SUCCESS;

            case 'V':
//                dump_version(stdout);
                return EXIT_SUCCESS;

            default:
                dump_usage(stderr);
                return EXIT_FAILURE;

        }

    }
    while (c != -1);

    // Set up signals
    sa.sa_handler = terminate;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTERM);
    sigaddset(&sa.sa_mask, SIGINT);
    sa.sa_flags = 0;

    // sa_flags 用来设置信号处理的其他相关操作, 下列的数值可用：
    // A_NOCLDSTOP: 如果参数signum 为SIGCHLD, 则当子进程暂停时并不会通知父进程
    // SA_ONESHOT/SA_RESETHAND: 当调用新的信号处理函数前, 将此信号处理方式改为系统预设的方式.
    // SA_RESTART: 被信号中断的系统调用会自行重启
    // SA_NOMASK/SA_NODEFER: 在处理此信号未结束前不理会此信号的再次到来. 如果参数oldact 不是NULL 指针, 则原来的信号处理方式会由此结构sigaction 返回.
    //    sa.sa_restorer = NULL; //sa_restorer 此参数没有使用.

    //定义函数：int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
    //函数说明：sigaction()会依参数signum 指定的信号编号来设置该信号的处理函数. 参数signum 可以指定SIGKILL 和SIGSTOP 以外的所有信号。
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Get local addresses
    if (!specified_addresses && get_addresses() != 0)
        return EXIT_FAILURE;

    // Operations timestamp
    time(&timestamp);
    // 定义函数：time_t time(time_t *t);
    // 函数说明：此函数会返回从公元 1970 年1 月1 日的UTC 时间从0 时0 分0 秒算起到现在所经过的秒数。如果t 并非空指针的话，此函数也会将返回值存到t 指针所指的内存。

    // Stats
    /*
     *   初始化 存放 数据包信息 链表
     */
    init_stats();

    /*
     * 如果有已经抓好包的文件,则直接解析!
     * 否则:边抓包,边解析!
     */
    if (capture_file) {
        output_offline_start(&output_options);

        offline_capture(capture_file);

        fclose(capture_file);

    }
    else {
        // Fire up capturing thread
        pthread_create(&capture_thread_id, NULL, capture, NULL);

        // Options thread
        pthread_create(&output_thread_id, NULL, output_thread, &output_options);

        pthread_join(capture_thread_id, NULL);
        pthread_kill(output_thread_id, SIGINT);

    }

    free_stats();
    free_addresses();

    return EXIT_SUCCESS;

}

void
terminate(int signal) {
    endcapture();

}
