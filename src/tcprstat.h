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

#if !defined(TCPRSTAT_H)
#define TCPRSTAT_H

#include <time.h>
#include <stdio.h>

#define DEFAULT_OUTPUT_FORMAT \
    "%T\\t%n\\t%M\\t%m\\t%a\\t%h\\t%S\\t" \
    "%95M\\t%95a\\t%95S\\t%99M\\t%99a\\t%99S\\n"
#define DEFAULT_OUTPUT_INTERVAL 10
#define MAX_OUTPUT_INTERVAL 60 * 60 * 24
#define DEFAULT_OUTPUT_ITERATIONS 1

#define DEFAULT_SHOW_HEADER 1

extern int port;  // Extern 该关键字告诉编译器，其声明的函数和变量可以在本模块或其它模块中使用。
extern char *program_name;
extern time_t timestamp;

extern FILE *capture_file;

void terminate(int signal);

#endif
