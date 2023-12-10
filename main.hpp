#pragma once

#include <unistd.h>
#include <string>
#include <vector>

#define LOG_LEVEL 3
#define log(level, format, ...)                                                                                        \
    do {                                                                                                               \
        if (level <= LOG_LEVEL) {                                                                                      \
            printf(format, ##__VA_ARGS__);                                                                             \
        }                                                                                                              \
    } while (0)

constexpr ssize_t DNS_HEADER_SIZE = 12;

typedef struct {
    bool is_response;
    unsigned char opcode;
    bool authoritative_answer;
    bool truncated;
    bool recursion_desired;
    bool recursion_available;
    unsigned char response_code;
} dns_flags;


typedef struct {
    unsigned short id;                // identification number
    dns_flags flags;                  // flags
    unsigned short num_questions;     // number of question entries
    unsigned short num_answers;       // number of answer entries
    unsigned short num_authorities;   // number of authority entries
    unsigned short num_additional_rr; // number of resource entries
    unsigned char* raw_packet;        // packet data
    ssize_t packet_size;              // packet size
} dns_header;

int main();
int fill_in_dns_header(dns_header* header, unsigned char* buf, ssize_t buf_size);
int create_dns_response(dns_header *header, unsigned char *response_buf, ssize_t *response_size);
int dns_myself(dns_header *header, unsigned char *response_buf, ssize_t *response_size);
int dns_forward(dns_header *header, unsigned char *response_buf, ssize_t *response_size);
void print_packet(const dns_header &packet);
std::string get_query_url_string(const dns_header &packet);
std::vector<std::string> get_query_url_vector(const dns_header &packet);
