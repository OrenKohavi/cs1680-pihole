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
#include <csignal>

#include "main.hpp"
#include "blocklist.hpp"

#if __cplusplus < 202002L
    #error "C++ version must be at least C++20"
#endif

using namespace std;

constexpr int PORT = 53;
constexpr ssize_t BUFFER_SIZE = 2048; //Oversized but whatever
constexpr char FORWARDING_DNS_IP[] = "8.8.8.8";
constexpr char DNS_ROOT_SERVER_IP[] = "108.179.34.214";
constexpr int DNS_PORT = 53;
constexpr bool EXACT_MATCH = true;
constexpr int TCP_TIMEOUT_SECONDS = 1;
constexpr int TCP_TIMEOUT_MICROSECONDS = 0;

void sigint_handler(int signum) {
    cout << "Received SIGINT, (Signal " << signum << ") exiting..." << endl;
    exit(0);
}

int main() {
    //Initialize signal handler
    signal(SIGINT, sigint_handler);
    //Initialize blocklists
    cout << "Initializing Blocklist..." << endl;
    if (init_blocklists(EXACT_MATCH) < 0) {
        cerr << "Failed to initialize blocklists" << endl;
        return -1;
    }
    cout << "Blocklist initialized" << endl;

    // Start listening for DNS queries
    struct sockaddr_in server_addr = {};
    struct sockaddr_in client_addr = {};
    socklen_t client_len = 0;
    unsigned char recv_buffer[BUFFER_SIZE];
    memset(recv_buffer, 0, BUFFER_SIZE);
    unsigned char send_buffer[BUFFER_SIZE];
    memset(send_buffer, 0, BUFFER_SIZE);

    // Create socket
    int udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket_fd < 0)
    {
        perror("Error opening UDP socket");
        exit(1);
    }

    int tcp_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_socket_fd < 0) {
        perror("Error opening TCP socket");
        exit(1);
    }

    // Bind UDP socket to port
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(udp_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error binding UDP socket");
        exit(1);
    }

    // Bind TCP socket to the same port
    if (bind(tcp_socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding TCP socket");
        exit(1);
    }

    // Start listening on TCP socket
    if (listen(tcp_socket_fd, 10) < 0) // 10 is the max backlog
    {
        perror("Error listening on TCP socket");
        exit(1);
    }

    log(1, "Listening on port %d...\n", PORT);

    fd_set readfds;
    int max_sd;
    int tcp_connection;
    bool is_tcp = false;
    ssize_t recv_len = 0;
    struct timeval tcp_timeout = {};
    tcp_timeout.tv_sec = TCP_TIMEOUT_SECONDS;
    tcp_timeout.tv_usec = TCP_TIMEOUT_MICROSECONDS;

    while (true) {
        log(3, "[Re]Entering While-Loop\n");
        //Just in case, clear everything
        memset(recv_buffer, 0, BUFFER_SIZE);
        memset(send_buffer, 0, BUFFER_SIZE);
        recv_len = 0;
        tcp_connection = 0;

        // Now, I need to use the super-shitty old C-style select() function to listen on both sockets at once
        // This is the only part where I really with I decided to use golang
        FD_ZERO(&readfds);

        // Add sockets to set
        FD_SET(udp_socket_fd, &readfds);
        FD_SET(tcp_socket_fd, &readfds);
        max_sd = (udp_socket_fd > tcp_socket_fd) ? udp_socket_fd : tcp_socket_fd;

        int activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if (activity < 0) {
            perror("Error in select");
            exit(1);
        }

        // Handle UDP socket
        if (FD_ISSET(udp_socket_fd, &readfds)) {
            is_tcp = false;
            client_len = sizeof(client_addr);
            recv_len = recvfrom(udp_socket_fd, recv_buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        }
        else if (FD_ISSET(tcp_socket_fd, &readfds)) {
            is_tcp = true;
            log(3, "Calling accept with fd: %d\n", tcp_socket_fd);
            if ((tcp_connection = accept(tcp_socket_fd, (struct sockaddr *)&client_addr, &client_len)) < 0) {
                perror("Error accepting TCP connection");
                exit(1);
            }

            //Read data from TCP socket
            //First, read the first two bytes, which contain the length of the message
            if (setsockopt(tcp_connection, SOL_SOCKET, SO_RCVTIMEO, (char *)&tcp_timeout, sizeof(tcp_timeout)) < 0) {
                perror("Error setting socket timeout");
                exit(1);
            }

            unsigned char tcp_len_buf[2];
            if (recv(tcp_connection, tcp_len_buf, 2, 0) < 0) {
                //Check for timeout
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    log(1, "TCP connection timed out [reading size]\n");
                    close(tcp_connection);
                    continue;
                }
                perror("Error receiving data");
                exit(1);
            }
            
            //Convert the length to a 16-bit integer
            unsigned short tcp_len = ntohs(*(unsigned short *)tcp_len_buf);
            log(2, "Expecting TCP message of length %d\n", tcp_len);
            //Now, read the actual message
            while(recv_len < tcp_len){
                ssize_t recv_len_temp = recv(tcp_connection, recv_buffer + recv_len, BUFFER_SIZE - recv_len, 0);
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    log(1, "TCP connection timed out (inside loop) [reading data, %zd/%d]\n", recv_len, tcp_len);
                    close(tcp_connection);
                    break; //Break out of while loop, and then we need to check if recv_len == tcp_len
                }
                if (recv_len_temp < 0) {
                    perror("Error receiving data");
                    exit(1);
                }
                recv_len += recv_len_temp;
            }
            if (recv_len != tcp_len) {
                log(1, "TCP connection timed out (outside loop) [reading data, %zd/%d]\n", recv_len, tcp_len);
                close(tcp_connection);
                continue;
            }

        } else {
            log(1, "Select returned with no activity\n");
            continue;
        }

        if (recv_len < 0) {
            perror("Error receiving data");
            exit(1);
        }
        if (recv_len == 0) {
            log(1, "Received empty message\n");
            continue;
        }
        if (recv_len >= BUFFER_SIZE) {
            log(1, "Received message too large (%ld bytes)\n", recv_len);
            continue;
        }
        if (recv_len < DNS_HEADER_SIZE) {
            log(1, "Received message too small (%ld bytes)\n", recv_len);
            continue;
        }

        // Print received data
        log(2, "Received %zd bytes (is_tcp: %d)\n", recv_len, is_tcp);
        if (LOG_LEVEL >= 3) {
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
        if (0 != deserialize_dns_header(&header, recv_buffer, recv_len)) {
            log(1, "Failed to fill in DNS header, dropping packet\n");
            continue;
        }

        print_packet(header);

        ssize_t response_size = 0;
        int result = create_dns_response(&header, send_buffer, &response_size);
        if ( result < 0) {
            log(1, "Failed to create DNS response [Error code: %d]\n", result);
            continue;
        }

        // Send response to client
        if (!is_tcp) {
            if (sendto(udp_socket_fd, send_buffer, response_size, 0, (struct sockaddr *)&client_addr, client_len) < 0) {
                perror("Error sending data");
                exit(1);
            }
        } else {
            //First, send the length
            unsigned short tcp_len = htons(response_size);
            if (send(tcp_connection, &tcp_len, 2, 0) < 0) {
                perror("Error sending length to client");
                exit(1);
            }
            if (send(tcp_connection, send_buffer, response_size, 0) < 0) {
                perror("Error sending data to client");
                exit(1);
            }
            close(tcp_connection);
        }
    }

    // Close socket
    close(udp_socket_fd);

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
    memset(response_buf, 0, BUFFER_SIZE);
    *response_size = 0;
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
    int result;
    if (is_whitelisted(query_vector)) {
        log(1, "Domain %s is whitelisted, getting response from whitelist\n", get_query_url_string(*header).c_str());
        result = dns_whitelist(header, response_buf, response_size);
    } else if (is_blacklisted(query_vector)) {
        log(1, "Domain %s is blacklisted, returning 0.0.0.0\n", get_query_url_string(*header).c_str());
        result = dns_block(header, response_buf, response_size);
    } else {
        log(1, "Domain %s is not blacklisted, forwarding...\n", get_query_url_string(*header).c_str());
        result = dns_forward(header, response_buf, response_size);
    }
    log(3, "DNS result: %d\n", result);
    return result;
}

int dns_whitelist(dns_header *header, unsigned char *response_buf, ssize_t *response_size){
    //We can actually just use dns_block and replace the IP at the very end
    int result = dns_block(header, response_buf, response_size);
    if (result < 0) {
        return result;
    }
    //Now, we need to replace the IP address with the one from the whitelist
    vector<string> query_vector = get_query_url_vector(*header);
    const char* ip = is_whitelisted(query_vector);
    if (ip == nullptr) [[unlikely]] {
        log(1, "Domain %s is whitelisted, but no IP address is present in the whitelist\n", get_query_url_string(*header).c_str());
        return -1;
    }
    //Convert the string IP to a 32-bit integer
    unsigned int ip_int = inet_addr(ip);
    //Last 4 bytes should be the IP, so just replace them
    memcpy(response_buf + (*response_size - 4), &ip_int, sizeof(ip_int));
    return 0;
}

int dns_block(dns_header *header, unsigned char *response_buf, ssize_t *response_size){
    //Craft and return a response with the IP as 0.0.0.0
    memcpy(response_buf, header->raw_packet, header->packet_size);   // Copy the entire original packet, since the response still contains the query
    response_buf[2] |= 0b10000000; //Set the response bit
    response_buf[3] |= 0b00000001; //Set the recursion available bit
    response_buf[7] = 0x01; //Set the number of answers to 1
    
    //Now, we need to actually populate the answer field, which should be placed right after the question field
    unsigned char *answer_ptr = response_buf + header->packet_size;
    unsigned char *question_start_ptr = header->raw_packet + DNS_HEADER_SIZE;
    //Unorthodox, but strlen is actually very useful here, since it finds the length of the name until the terminating null
    //int question_size = strlen(static_cast<const char *>(question_start_ptr));
    int question_size = strlen((char *)question_start_ptr) + 1; //Add one for null byte
    memcpy(answer_ptr, question_start_ptr, question_size);
    answer_ptr += question_size;
    //cerr << "Question size is " + to_string(question_size) << endl;
    // Now, we need to add the type and class fields
    // Annoyingly, these can have any alignment whatsoever, so we need to memcpy or manually set things instead of being normal
    unsigned int temp_int;

    // Type: A
    answer_ptr++; //skip MSB
    *answer_ptr++ = 0x01;

    // Class: IN
    answer_ptr++; // skip MSB
    *answer_ptr++ = 0x01;

    // Set TTL to max
    temp_int = htonl(0x0000FFFF);
    memcpy(answer_ptr, &temp_int, sizeof(temp_int));
    answer_ptr += 4;

    // Set the data length to 4 bytes
    answer_ptr++; // skip MSB
    *answer_ptr++ = 0x04;

    // Set the IP addr to zero
    temp_int = 0;
    memcpy(answer_ptr, &temp_int, sizeof(temp_int));
    answer_ptr += 4;

    *response_size = answer_ptr - response_buf;

    

    return 0;
}

int dns_forward(dns_header *header, unsigned char *response_buf, ssize_t *response_size){
    int forwarding_socket_fd;
    struct sockaddr_in servaddr;

    // Create a socket
    log(3, "Creating socket to forward DNS query to real DNS server\n");
    if ((forwarding_socket_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return -2;
    }
    log(3, "Socket created\n");

    memset(&servaddr, 0, sizeof(servaddr));

    // Google DNS server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DNS_PORT);
    servaddr.sin_addr.s_addr = inet_addr(FORWARDING_DNS_IP);

    // Send DNS query to Google's DNS server over TCP
    // This skips the rigamarole of dealing with requests that are over 512 bytes
    log(3, "Connecting to forwarding DNS server...\n");
    if (connect(forwarding_socket_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("Connection with the server failed");
        return -3;
    }
    log(3, "Connected to forwarding DNS server\n");

    // Send the query to Google's DNS server
    //First, send 2 bytes containing the length of the message
    /*
    log(2, "Sending size of %zd to forwarding DNS server\n", header->packet_size);
    unsigned short tcp_len = htons(header->packet_size);
    if (send(forwarding_socket_fd, &tcp_len, 2, 0) < 0) {
        perror("Length send failed");
        return -4;
    }
    */
    //Now, send the actual message
    log(3, "Sending message to forwarding DNS server\n");
    if (send(forwarding_socket_fd, header->raw_packet, header->packet_size, 0) < 0) {
        perror("Send failed");
        return -4;
    }

    // Receive the response from Google's DNS server
    *response_size = recv(forwarding_socket_fd, response_buf, BUFFER_SIZE, 0);
    if (*response_size < 0) {
        perror("Receive failed");
        *response_size = 0;
        return -5;
    }

    close(forwarding_socket_fd);
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
int deserialize_dns_header(dns_header *header, unsigned char *buf, ssize_t buf_size) {
    if (buf_size < DNS_HEADER_SIZE) {
        // Buffer is too small
        log(1, "Buffer is too small to contain a DNS header [Size is %zd, minimum of %zd]\n", buf_size, DNS_HEADER_SIZE);
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
    if (LOG_LEVEL < 2) {
        return;
    }
    if (LOG_LEVEL >= 3) {
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
    }
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