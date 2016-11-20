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

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct address_list {
    struct in_addr in_addr;
    struct address_list *next;
    
} address_list;

int
get_addresses(void) {
    pcap_if_t *devlist, *curr;
    pcap_addr_t *addr;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct address_list *address_list_curr;

    if (pcap_findalldevs(&devlist, errbuf)) {
        fprintf(stderr, "pcap: %s\n", errbuf);
        return 1;
    }
    
    address_list_curr = &address_list;
    
    for (curr = devlist; curr; curr = curr->next) {
        if (curr->flags & PCAP_IF_LOOPBACK)
            continue;
            
        for (addr = curr->addresses; addr; addr = addr->next) {
            struct sockaddr *realaddr;
            
            if (addr->addr)
                realaddr = addr->addr;
            else if (addr->dstaddr)
                realaddr = addr->dstaddr;
            else
                continue;
            
            if (realaddr->sa_family == AF_INET ||
                    realaddr->sa_family == AF_INET6)
            {
                struct sockaddr_in *sin;
                
                sin = (struct sockaddr_in *) realaddr;
                
                address_list_curr->next = malloc(sizeof(struct address_list));
                if (!address_list_curr->next)
                    abort();
                
                address_list_curr->next->in_addr = sin->sin_addr;
                address_list_curr->next->next = NULL;
                address_list_curr = address_list_curr->next;
                
            }
            
        }
        
    }
    
    pcap_freealldevs(devlist);
    
    return 0;

}

int
parse_addresses(char addresses[]) {
    char *next, *comma;
    struct address_list *address_list_curr;
    
    next = addresses;
    address_list_curr = &address_list;
    
    while ((comma = strchr(next, ','))) {
        char *current;
        
        current = malloc((comma - next) + 1);
        if (!current)
            abort();
        
        strncpy(current, next, (comma - next));
        //strncpy()会将字符串src前n个字符拷贝到字符串dest|char * strncpy(char *dest, const char *src, size_t n)
        //不像strcpy()，strncpy()不会向dest追加结束标记'\0'，这就引发了很多不合常理的问题，将在下面的示例中说明。
        //strcpy() 把src所指的由NULL结束的字符串复制到dest 所指的数组中，返回指向 dest 字符串的起始地址。
        current[comma - next] = '\0';

        address_list_curr->next = malloc(sizeof(struct address_list));
        if (!address_list_curr->next)
            abort();
        
        address_list_curr->next->next = NULL;
        
        if (!inet_aton(current, &address_list_curr->next->in_addr)) {
            free(current);
            return 1;
            
        }
        
        address_list_curr = address_list_curr->next;
            
        free(current);

        next = comma + 1;
        
    }
    
    address_list_curr->next = malloc(sizeof(struct address_list));
    if (!address_list_curr->next)
        abort();
    
    address_list_curr->next->next = NULL;
    
    if (!inet_aton(next, &address_list_curr->next->in_addr))
        return 1;
    
    address_list_curr = address_list_curr->next;
            
    return 0;
    
}

int
free_addresses(void) {
    struct address_list *next;
    
    while (address_list.next) {
        next = address_list.next->next;
        free(address_list.next);
        address_list.next = next;
        
    }
    
    return 0;
    
}

int
is_local_address(struct in_addr addr) {
    struct address_list *curr;
    
    for (curr = address_list.next; curr; curr = curr->next)
        if (curr->in_addr.s_addr == addr.s_addr)
            return 1;
        
    return 0;
    
}
