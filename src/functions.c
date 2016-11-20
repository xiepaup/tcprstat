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

#include <stdio.h>
#include <pcap.h>

//#include "config.h"
#include "functions.h"
#include "tcprstat.h"

char *usage_msg =
    "Usage: %s [--port <port>] [--format=<format>] [--interval=<sec>]\n"
    "             [--header[=<header>] | --no-header] [--iterations=<it>]\n"
    "             [--read=<file>]\n"
    "       %s --version | --help\n"
    "\n"
    "\t--read <file>, -r    Capture from pcap file <file>, not live.\n"
    "\t--local <addresses>, -l\n"
    "\t                     <addresses> is a comma-separated list of ip\n"
    "\t                     addresses, which are used as the local list of\n"
    "\t                     addresses instead of pcap getting the list.\n"
    "\t                     This is useful when working with a pcap file got\n"
    "\t                     from another host with different addresses.\n"
    "\t--port <port>, -p    Capture traffic only for tcp/<port>.\n"
    "\t--format <format>, -f\n"
    "\t                     Output format. Argument is a string detailing\n"
    "\t                     how the information is presented. Accepted codes:\n"
    "\t                         %%n - Response time count\n"
    "\t                         %%a - Response time media in microseconds\n"
    "\t                         %%s - Response time sum\n"
    "\t                         %%x - Response time squares sum\n"
    "\t                         %%m - Minimum value\n"
    "\t                         %%M - Maximum value\n"
    "\t                         %%h - Median value\n"
    "\t                         %%S - Standard deviation\n"
    "\t                         %%v - Variance (square stddev)\n"
    "\t                         %%I - Iteration number\n"
    "\t                         %%t - Timestamp since iteration zero\n"
    "\t                         %%T - Unix timestamp\n"
    "\t                         %%%% - A literal %%\n"
    "\t                     Default is:\n"
    "    \"%s\".\n"
    "\t                     Statistics may contain a percentile between\n"
    "\t                     the percentage sign and the code: %%99n, %%95a.\n"
    "\t--header[=<header>], --no-header\n"
    "\t                     Whether to output a header. If not supplied, a\n"
    "\t                     header is created out of the format. By default,\n"
    "\t                     the header is shown.\n"
    "\t--interval <seconds>, -t\n"
    "\t                     Output interval. Default is %d.\n"
    "\t--iterations <n>, -n\n"
    "\t                     Output iterations. Default is %d, 0 is infinity\n"
    "\n"
    "\t--help               Shows program information and usage.\n"
    "\t--version            Shows version information.\n"
    "\n"
;

int
dump_usage(FILE *stream) {
    fprintf(stream, usage_msg, program_name, program_name, 
    DEFAULT_OUTPUT_FORMAT, DEFAULT_OUTPUT_INTERVAL, DEFAULT_OUTPUT_ITERATIONS);

    return 0;

}

int
dump_help(FILE *stream) {
    dump_version(stream);
    dump_usage(stream);

    return 0;

}

//int
//dump_version(FILE *stream) {
//    fprintf(stream, "%s %s, %s.\n", PACKAGE_NAME, PACKAGE_VERSION,
//            pcap_lib_version());
//
//    return 0;
//
//}
