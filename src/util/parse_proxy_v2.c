/*-
 * Copyright (c) 2015 Varnish Software AS
 * All rights reserved.
 *
 * Author: Pål Hermunn Johansen <hermunn@varnish-software.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/*
 * Very simple utility for parsing a proxy protocol header (version 1 or 2)
 * and printing the contents to standard out.
 *
 * The program simply does a single read, and according to the spec
 * (http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt), this is the
 * correct thing to do.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/opensslv.h>

unsigned char PROXY_V2_HEADER[12] = { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
				      0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

#define MAX_HEADER_SIZE 536

int main(int argc, const char **argv);
ssize_t read_from_socket(const char *port, unsigned char *buf, int len);
void print_addr_with_ports(int af, int len, unsigned char *p);
int print_extensions(unsigned char *extension_start, int extensions_len);

int main(int argc, const char **argv) {
	unsigned char proxy_header[MAX_HEADER_SIZE + 1];
	ssize_t n = 0;
	int address_len = 0;

#if OPENSSL_VERSION_NUMBER < 0x1000100fL
	printf("Warning:\tThis OpenSSL version is too old for NPN.\n");
#elif OPENSSL_VERSION_NUMBER < 0x1000200fL
	printf("Warning:\tThis OpenSSL version is too old for ALPN.\n");
#endif
	if (argc == 1)
		n = read(STDIN_FILENO, proxy_header, MAX_HEADER_SIZE);
	else if (argc == 2)
		n = read_from_socket(argv[1], proxy_header, MAX_HEADER_SIZE);
	else {
		fprintf(stderr, "Usage: parse_proxy_v2 [port]\n");
		return (1);
	}

	if (n < 16) {
		printf("ERROR:\tread too few bytes.\n");
		return (1);
	}
	proxy_header[n] = '\0';

	if (strncmp("PROXY TCP", (char *)proxy_header, 9) == 0) {
		/* PROXY version 1 over TCP */
		fprintf(stdout,
		    "ERROR:\tPROXY v1 parsing not supported in this tool.\n");
		return (1);
	} else if (memcmp(PROXY_V2_HEADER, proxy_header, 12) != 0) {
		printf("ERROR:\tNot a valid PROXY header\n");
		return (1);
	}
	printf("PROXY v2 detected.\n");
	switch (proxy_header[12]) {
	case 0x20:
		printf("ERROR:\tLOCAL connection\n");
		return (1);
	case 0x21:
		printf("Connection:\tPROXYed connection detected\n");
		break;
	default:
		printf("ERROR:\t13th byte has illegal value %d\n",
		    (int)proxy_header[12]);
		return (1);
	}
	switch (proxy_header[13]) {
	case 0x00:
		printf("ERROR:\tProtocol:\tUnspecified/unsupported\n");
		return (1);
	case 0x11:
		printf("Protocol:\tTCP over IPv4\n");
		address_len = 12;
		break;
	case 0x12:
		printf("Protocol:\tUDP over IPv4\n");
		printf("ERROR:\tProtocol unsupported in hitch seen\n");
		address_len = 12;
		break;
	case 0x21:
		printf("Protocol:\tTCP over IPv6\n");
		address_len = 36;
		break;
	case 0x22:
		printf("Protocol:\tUDP over IPv6\n");
		printf("ERROR:\tProtocol unsupported in hitch\n");
		address_len = 36;
		break;
	case 0x31:
		printf("Protocol:\tUNIX stream\n");
		address_len = 216;
		break;
	case 0x32:
		printf("Protocol:\tUNIX datagram\n");
		printf("ERROR:\tProtocol unsupported in hitch\n");
		address_len = 216;
		break;
	default:
		printf("ERROR:\t14th byte has illegal value %d\n",
		    (int)proxy_header[13]);
		return (1);
	}
	int additional_len = (proxy_header[14] << 8) + proxy_header[15];
	if (additional_len < address_len) {
		printf("ERROR:\tThe the total header length %d does"
		    " not leave room for the addresses\n",
		    additional_len + 16);
		return (1);
	}
	if (additional_len + 16 > n) {
		printf("ERROR:\tToo few bytes was read; %zd\n", n);
		return (1);
	}
	if (address_len == 12)
		print_addr_with_ports(AF_INET, 4, proxy_header + 16);
	else if (address_len == 36)
		print_addr_with_ports(AF_INET6, 16, proxy_header + 16);
	else {
		printf("ERROR:\tPrinting of UNIX socket addresses"
		    " not implemented.\n");
	}
	if (address_len < additional_len)
		return print_extensions(proxy_header + 16 + address_len,
		    additional_len - address_len);
	return (0);
}

ssize_t read_from_socket(const char *port, unsigned char *buf, int len) {
	struct addrinfo hints;
	struct addrinfo *result;
	struct addrinfo *rp;
	int listen_socket = -1;

	(void)port;
	(void)buf;
	(void)len;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;     /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	int s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(s));
		exit(1);
	}

	// getaddrinfo just returned a list of address structures. Try
	// each address until we successfully bind(2).  If socket(2) (or
	// bind(2)) fails, we (close the socket and) try the next address.

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		listen_socket = socket(rp->ai_family, rp->ai_socktype,
		    rp->ai_protocol);
		if (listen_socket == -1)
			continue;
		if (bind(listen_socket, rp->ai_addr, rp->ai_addrlen) == 0)
			break; // success!
		close(listen_socket);
		listen_socket = -1;
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		printf("ERROR: Could not create and bind listen socket.\n");
		exit(1);
	}

	if (0 != listen(listen_socket, 1)) {
		perror("Call to listen() failed");
		exit(1);
	}
	fprintf(stderr, "Listening on port %s\n", port);
	int sock = accept(listen_socket, NULL, NULL);
	if (sock < 0) {
		close(listen_socket);
		perror("Calling accept failed");
		exit(1);
	}
	ssize_t n = recv(sock, buf, len, 0);
	fprintf(stderr, "Read %zd bytes in recv\n", n);
	close(sock);
	close(listen_socket);
	return n;
}

void print_addr_with_ports(int af, int len, unsigned char *p) {
	char buf1[256], buf2[256];
	const char *addr1 = inet_ntop(af, p, buf1, 256);
	const char *addr2 = inet_ntop(af, p + len, buf2, 256);
	if (addr1 == NULL || addr2 == NULL) {
		printf("ERROR:\tIP addresses printing failed.\n");
		exit(1);
	}
	int src_port = (p[2 * len] << 8) + p[2 * len + 1];
	int dest_port = (p[2 * len + 2] << 8) + p[2 * len + 3];

	printf("Source IP:\t%s\n", addr1);
	printf("Destination IP:\t%s\n", addr2);
	printf("Source port:\t%d\n", src_port);
	printf("Destination port:\t%d\n", dest_port);
}

int print_extensions(unsigned char *extensions, int extensions_len) {
	int i, l, type;

	for (i = 0; i < extensions_len; i++) {
		if(i > extensions_len - 4)
			goto ext_parse_error;
		type = extensions[i];
		l = (extensions[i + 1] << 8) + extensions[i + 2];
		i += 3;
		if (l <= 0 || i + l > extensions_len)
			goto ext_parse_error;
		switch(type) {
		case 0x1: // PP2_TYPE_ALPN
			printf("ALPN extension:\t%.*s\n", l, extensions + i);
			break;
		default:
			printf("ERROR:\tUnknown extension %d\n", type);
		}
		i += l - 1;
	}
	if (i != extensions_len) {
		printf("ERROR:\tBuffer overrun (%d / %d)\n", i, extensions_len);
		return (1);
	}
	return (0);

 ext_parse_error:
	printf("ERROR:\tExtension parse error\n");
	printf("Extensions data:");
	for (i = 0; i < extensions_len; i++)
		printf(" 0x%x", (int)extensions[i]);
	printf("\n");
	return (1);
}
