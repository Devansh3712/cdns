#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "dns.h"

int main(int argc, char* argv[]) {
	if (argc != 2) {
		fprintf(stderr, "ERROR: domain name required\n");
		return EXIT_FAILURE;
	}
	char* hostname = argv[1];

	size_t packet_len = 0;
	uint8_t* packet = build_packet(hostname, &packet_len);

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(53),
		.sin_addr = { .s_addr = inet_addr("8.8.8.8") },
	};
	sendto(sockfd, packet, packet_len, 0, (struct sockaddr*)&addr, (socklen_t)sizeof(addr));

	socklen_t len = 0;
	uint8_t response[512];
	memset(&response, 0, 512);
	recvfrom(sockfd, response, 512, 0, (struct sockaddr*)&addr, &len);

	parse_message(response);

	return EXIT_SUCCESS;
}
