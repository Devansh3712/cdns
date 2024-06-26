#pragma once

#include <arpa/inet.h>
#include <stdint.h>

enum RCode {
	NO_ERROR = 0,
	FORMAT_ERROR = 0,
	SERVER_ERROR = 1,
	NAME_ERROR = 2,
	NOT_IMPLEMENTED = 4,
	REFUSED = 5,
};

enum QType {
	A = 1,
	NS = 2,
	CNAME = 5,
	_NULL = 10,
	MX = 15,
	TXT = 16,
	AAAA = 28,
};

enum QClass {
	IN = 1,
	CS = 2,
	CH = 3,
	HS = 4,
};

typedef struct {
	uint16_t id;
	uint8_t qr: 1;
	uint8_t opcode: 4;
	uint8_t aa: 1;
	uint8_t tc: 1;
	uint8_t rd: 1;
	uint8_t ra: 1;
	uint8_t z: 3;
	uint8_t rcode:4;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed)) dns_header;

typedef struct {
	char* qname;
	uint16_t qtype;
	uint16_t qclass;
} __attribute__((packed)) dns_question;

typedef struct {
	uint16_t compression;
	uint16_t qtype;
	uint16_t qclass;
	uint32_t ttl;
	uint16_t rdlength;
	struct in_addr rdata;
} __attribute__((packed)) dns_record;

char* encode_name(char*);
uint8_t* build_packet(char*, size_t*);
void parse_message(uint8_t*);
