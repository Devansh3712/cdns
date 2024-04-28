#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns.h"

char* encode_name(char* hostname) {
	char* name = calloc(strlen(hostname) + 2, sizeof(uint8_t));
	memcpy(name + 1, hostname, strlen(hostname));
	uint8_t count = 0;
	uint8_t* prev = (uint8_t*)name;

	for (int i = 0; i < strlen(hostname); i++) {
		if (hostname[i] == '.') {
			*prev = count;
			prev = (uint8_t*)name + i + 1;
			count = 0;
		} else count++;
	}
	*prev = count;
	return name;
}

uint8_t* build_packet(char* hostname, size_t* packet_len) {
	dns_header header = {
		.id = htons(1002),
		.qr = htons(0),
		.opcode = htons(0),
		.aa = htons(0),
		.tc = htons(0),
		.rd = htons(0),
		.ra = htons(0),
		.z = htons(0),
		.rcode = htons(NO_ERROR),
		.qdcount = htons(1),
		.ancount = htons(0),
		.nscount = htons(0),
		.arcount = htons(0),
	};
	dns_question question = {
		.qname = encode_name(hostname),
		.qtype = htons(A),
		.qclass = htons(IN),
	};

	*packet_len = sizeof(header) + strlen(hostname) + 2
		+ sizeof(question.qtype) + sizeof(question.qclass);
	uint8_t *packet = calloc(*packet_len, sizeof(uint8_t));
	uint8_t *p = (uint8_t*)packet;

	memcpy(p, &header, sizeof(header));
	p += sizeof(header);

	memcpy(p, question.qname, strlen(hostname) + 2);
	p += strlen(hostname) + 2;
	memcpy(p, &question.qtype, sizeof(question.qtype));
	p += sizeof(question.qtype);
	memcpy(p, &question.qclass, sizeof(question.qclass));

	return packet;
}

void parse_message(uint8_t* response) {
	dns_header* header = (dns_header*)response;

	uint8_t* start_of_question = response + sizeof(dns_header);
	dns_question* questions = calloc(sizeof(dns_question), header->ancount);
	for (int i = 0; i < ntohs(header->ancount); i++) {
		questions[i].qname = (char*)start_of_question;
		uint8_t total = 0;
		uint8_t* label_len = (uint8_t*)questions[i].qname;
		while (*label_len != 0) {
			total += *label_len + 1;
			*label_len = '.';
			label_len = (uint8_t*)questions[i].qname + total;
		}
		questions[i].qname++;
		// Skip null byte, type, class
		start_of_question = label_len + 5;
	}

	dns_record* records = (dns_record*)start_of_question;
	for (int i = 0; i < ntohs(header->ancount); i++) {
		printf("Record for %s\n", questions[i].qname);
		printf("TYPE: %" PRId16 "\n", ntohs(records[i].qtype));
		printf("CLASS: %" PRId16 "\n", ntohs(records[i].qclass));
		printf("TTL: %" PRId32 "\n", ntohl(records[i].ttl));
		printf("IPv4: %s\n", inet_ntoa(records[i].rdata));
	}
}
