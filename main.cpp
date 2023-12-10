#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <algorithm>

#include "main.hpp"
#include "blocklist.hpp"

#if __cplusplus < 202002L
    #error "C++ version must be at least C++20"
#endif

using namespace std;

constexpr int PORT = 5353;
constexpr ssize_t BUFFER_SIZE = 2048; //Oversized but whatever
constexpr char FORWARDING_DNS_IP[] = "8.8.8.8";
constexpr int DNS_PORT = 53;
constexpr bool EXACT_MATCH = true;


int main()
{
    //Initialize blocklists
    cout << "Initializing Blocklist..." << endl;
    if (init_blocklists(EXACT_MATCH) < 0) {
        cerr << "Failed to initialize blocklists" << endl;
        return -1;
    }
    cout << "Blocklist initialized" << endl;

    // Start listening for DNS queries
    int main_socket_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    unsigned char recv_buffer[BUFFER_SIZE];
    unsigned char send_buffer[BUFFER_SIZE];

    // Create socket
    main_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (main_socket_fd < 0)
    {
        perror("Error opening socket");
        exit(1);
    }

    // Bind socket to port
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(main_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error binding socket");
        exit(1);
    }

    log(1, "Listening on UDP port %d...\n", PORT);

    while (1)
    {
        // Receive data from client
        memset(recv_buffer, 0, BUFFER_SIZE);
        client_len = sizeof(client_addr);
        ssize_t recv_len = recvfrom(main_socket_fd, recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (recv_len < 0)
        {
            perror("Error receiving data");
            exit(1);
        }
        if (recv_len == 0)
        {
            log(1, "Received empty message\n");
            continue;
        }
        if (recv_len >= BUFFER_SIZE)
        {
            log(1, "Received message too large (%ld bytes)\n", recv_len);
            continue;
        }
        if (recv_len < (ssize_t)sizeof(dns_header))
        {
            log(1, "Received message too small (%ld bytes)\n", recv_len);
            continue;
        }

        // Print received data
        log(2, "Received %zd bytes\n", recv_len);
        if (LOG_LEVEL >= 3)
        {
            string packet_text(reinterpret_cast<const char *>(recv_buffer), static_cast<size_t>(recv_len));
            cout << packet_text << endl;
            for (int i = 0; i < recv_len; i++)
            {
                printf("%02x ", recv_buffer[i]);
                if ((i + 1) % 16 == 0)
                {
                    printf("\n");
                }
            }
            printf("\n");
        }

        dns_header header;
        if (0 != fill_in_dns_header(&header, recv_buffer, recv_len)){
            log(1, "Failed to fill in DNS header, dropping packet\n");
            continue;
        }

        if (LOG_LEVEL >= 2){
            print_packet(header);
        }

        ssize_t response_size = 0;
        int result = create_dns_response(&header, send_buffer, &response_size);
        if ( result < 0) {
            log(1, "Failed to create DNS response [Error code: %d]\n", result);
            continue;
        }

        // Send response to client
        if (sendto(main_socket_fd, send_buffer, response_size, 0, (struct sockaddr *)&client_addr, client_len) < 0)
        {
            perror("Error sending data");
            exit(1);
        }
    }

    // Close socket
    close(main_socket_fd);

    return 0;
}

/**
 * Creates a DNS response based on the given DNS query
 * - If the query is for a domain that is not on the blacklist, the query is forwarded to real DNS servers
 * - If the query is for a domain that is on the blacklist, the query is answered with NXDOMAIN
 * 
 * @param p Pointer to the dns_header struct containing the DNS query
 * @param response_buf Filled in with the response to send
 * @param response_size Filled in with the size of the response
*/
int create_dns_response(dns_header *header, unsigned char *response_buf, ssize_t *response_size) {
    // First, sanity checks:
    // Check that the message is a query
    if (header->flags.is_response) {
        log(1, "Received a non-query message\n");
        return -1;
    }
    // Check that the message has no answers
    if (header->num_answers != 0) {
        log(1, "Received a message with %d answers\n", header->num_answers);
        return -1;
    }
    // Check that the message has no authorities
    if (header->num_authorities != 0) {
        log(1, "Received a message with %d authorities\n", header->num_authorities);
        return -1;
    }

    //The important part: check if we need to block this request
    vector<string> query_vector = get_query_url_vector(*header);
    if (is_whitelisted(query_vector)) {
        log(1, "Domain %s is whitelisted, getting response from whitelist\n", get_query_url_string(*header).c_str());
        throw runtime_error("Whitelist not implemented yet");
    }

    if (is_blacklisted(query_vector)) {
        log(1, "Domain %s is blacklisted, returning 0.0.0.0\n", get_query_url_string(*header).c_str());
        throw runtime_error("Blacklist not implemented yet");
    }
    
    //At the moment, we just forward this entire packet to Google's DNS servers
    return dns_forward(header, response_buf, response_size); 
}

int dns_myself(dns_header *header, unsigned char *response_buf, ssize_t *response_size){
    dns_forward(header, response_buf, response_size);
    return 0;
}

int dns_forward(dns_header *header, unsigned char *response_buf, ssize_t *response_size){
    int google_socket_fd;
    struct sockaddr_in servaddr;

    // Create a socket
    if ((google_socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return -2;
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Google DNS server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DNS_PORT);
    servaddr.sin_addr.s_addr = inet_addr(FORWARDING_DNS_IP);

    // Send DNS query to Google's DNS server over TCP
    // This skips the rigamarole of dealing with requests that are over 512 bytes
    if (connect(google_socket_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("Connection with the server failed");
        return -3;
    }

    // Send the query to Google's DNS server
    if (send(google_socket_fd, header->raw_packet, header->packet_size, 0) < 0) {
        perror("Send failed");
        return -4;
    }

    // Receive the response from Google's DNS server
    *response_size = recv(google_socket_fd, response_buf, BUFFER_SIZE, 0);
    if (*response_size < 0) {
        perror("Receive failed");
        *response_size = 0;
        return -5;
    }

    close(google_socket_fd);
    return 0;
}

/**
 * Fills in the dns_header struct with the data from the buffer
 * @param header Pointer to the dns_header struct to fill in
 * @param buf Pointer to the buffer containing the DNS packet
 * @param buf_size Size of the buffer
 *
 * @return 0 on success, negative value on failure
 *
 * NOTE: The buffer passed to this function must remain valid for the lifetime of the dns_header struct
 */
int fill_in_dns_header(dns_header *header, unsigned char *buf, ssize_t buf_size) {
    if (buf_size < DNS_HEADER_SIZE) {
        // Buffer is too small
        log(1, "Buffer is too small to contain a DNS header [Size is %zd, minimum of %zd]\n", buf_size,
            DNS_HEADER_SIZE);
        return -1;
    }

    memset(header, 0, sizeof(dns_header));
    // Copy the header into the struct
    header->id = ntohs(*(unsigned short *)buf);                 // Convert from network byte order to host byte order
    header->flags.is_response = (buf[2] & 0b10000000);          // Bit 1
    header->flags.opcode = (buf[2] & 0b01111000) >> 3;          // Bits 2-5
    header->flags.authoritative_answer = (buf[2] & 0b00000100); // Bit 6
    header->flags.truncated = (buf[2] & 0b00000010);            // Bit 7
    header->flags.recursion_desired = (buf[2] & 0b00000001);    // Bit 8
    header->flags.recursion_available = (buf[3] & 0b10000000);  // Bit 9
    // Bits 10,11,12 are reserved
    header->flags.response_code = (buf[3] & 0b00001111); // Bits 13-16

    // 2 bytes for each of the following fields
    header->num_questions = ntohs(*(unsigned short *)(buf + 4));
    header->num_answers = ntohs(*(unsigned short *)(buf + 6));
    header->num_authorities = ntohs(*(unsigned short *)(buf + 8));
    header->num_additional_rr = ntohs(*(unsigned short *)(buf + 10));

    header->raw_packet = buf;
    header->packet_size = buf_size;
    return 0;
}

/**
 * Prints the given DNS packet to stdout
*/
void print_packet(const dns_header &packet) {
    printf("DNS Packet:\n");
    printf("ID: %hu\n", packet.id);
    printf("Flags:\n");
    printf("  Is Response: %s\n", packet.flags.is_response ? "Yes" : "No");
    printf("  Opcode: %u\n", packet.flags.opcode);
    printf("  Authoritative Answer: %s\n", packet.flags.authoritative_answer ? "Yes" : "No");
    printf("  Truncated: %s\n", packet.flags.truncated ? "Yes" : "No");
    printf("  Recursion Desired: %s\n", packet.flags.recursion_desired ? "Yes" : "No");
    printf("  Recursion Available: %s\n", packet.flags.recursion_available ? "Yes" : "No");
    printf("  Response Code: %u\n", packet.flags.response_code);
    printf("Questions: %hu\n", packet.num_questions);
    printf("Answers: %hu\n", packet.num_answers);
    printf("Authorities: %hu\n", packet.num_authorities);
    printf("Additional Resource Records: %hu\n", packet.num_additional_rr);
    printf("Packet Size: %zd bytes\n", packet.packet_size);
    printf("Question: ");

    //Parse the actual question -- Assuming there is only one question present
    if (packet.num_questions == 0) {
        printf("[!] No question present in DNS query\n");
        return;
    }
    if (packet.num_questions > 1) {
        printf("[!] More than one question present in DNS query [!] ");
        //Don't return, might as well print the first question
    }
    printf("%s\n", get_query_url_string(packet).c_str());
}

string get_query_url_string(const dns_header &packet) {
    vector<string> url = get_query_url_vector(packet);
    //Combine the vector into a single string with dots in between
    string url_string("");
    for (string url_part : url) {
        url_string += url_part + ".";
    }
    return url_string;
}

vector<string> get_query_url_vector(const dns_header &packet) {
    vector<string> url;
    unsigned char *question_ptr = packet.raw_packet + DNS_HEADER_SIZE;

    unsigned char label_len;
    while ((label_len = *question_ptr) != 0) {
        string url_part("");
        question_ptr++;
        for (int i = 0; i < label_len; i++) {
            url_part.push_back(*question_ptr);
            question_ptr++;
        }
        url.push_back(url_part);
    }
    //Before returning, flip the vector so that the domain is in the correct order (tld first)
    reverse(url.begin(), url.end());
    return url;
}