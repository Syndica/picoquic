/*
 * Author: Christian Huitema
 * Copyright (c) 2020, Private Octopus, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* The "sample" project builds a simple file transfer program that can be
 * instantiated in client or server mode. The "sample_client" implements
 * the client components of the sample application.
 *
 * Developing the client requires two main components:
 *  - the client "callback" that implements the client side of the
 *    application protocol, managing the client side application context
 *    for the conn.
 *  - the client loop, that reads messages on the socket, submits them
 *    to the Quic context, let the client prepare messages, and send
 *    them on the appropriate socket.
 *
 * The Sample Client uses the "qlog" option to produce Quic Logs as defined
 * in https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/.
 * This is an optional feature, which requires linking with the "loglib" library,
 * and using the picoquic_set_qlog() API defined in "autoqlog.h". When a conn
 * completes, the code saves the log as a file named after the Initial conn
 * ID (in hexa), with the suffix ".client.qlog".
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <autoqlog.h>
#include <picoquic_packet_loop.h>
#include "picoquic_sample.h"

/* READ PACKETS */

#define MAX_ADDRESS_LEN 256 // Maximum address length
#define MAX_BYTES_SIZE 1232 // Maximum byte array size
#define BUFFER_SIZE 2048    // Buffer size for incoming data
#define SOL_ALPN "solana-tpu"
#define SOL_SNI NULL
// #define SOL_ALPN "picoquic_sample"
// #define SOL_SNI "localhost"

// Struct to hold parsed data
typedef struct st_sol_transaction_info_t
{
    char address[MAX_ADDRESS_LEN];
    int bytes_size;
    unsigned char bytes[MAX_BYTES_SIZE];
} sol_transaction_info_t;

struct sockaddr_storage string_to_sockaddr_storage(const char *address)
{
    char ip[INET_ADDRSTRLEN];
    int port;
    struct sockaddr_storage ss;

    // Zero out the structure
    memset(&ss, 0, sizeof(struct sockaddr_storage));

    // Cast to sockaddr_in since we are working with IPv4
    struct sockaddr_in *sa_in = (struct sockaddr_in *)&ss;

    // Set the family to AF_INET (IPv4)
    sa_in->sin_family = AF_INET;

    // Split the string into IP and port
    sscanf(address, "%[^:]:%d", ip, &port);

    // Set the port in network byte order
    sa_in->sin_port = htons(port);

    // Convert the IP address from text to binary form
    if (inet_pton(AF_INET, ip, &sa_in->sin_addr) <= 0)
    {
        perror("inet_pton failed");
        exit(EXIT_FAILURE);
    }

    // Return the sockaddr_storage structure
    return ss;
}

// Safe parsing function for "cin: address=... bytes_size=... bytes={...}"
int parse_output(const char *input, sol_transaction_info_t *data)
{
    // Initialize the struct to zero
    memset(data, 0, sizeof(sol_transaction_info_t));

    // Find the position of `bytes_size` and `bytes`
    char *address_start = strstr(input, "address=");
    char *bytes_size_start = strstr(input, "bytes_size=");
    char *bytes_start = strstr(input, "bytes={");

    if (!address_start || !bytes_size_start || !bytes_start)
    {
        printf("Error: Invalid input format.\n");
        return -1; // Input string format is incorrect
    }

    // Parse the address (use a length limit to avoid overflow)
    if (sscanf(address_start, "address=%255s", data->address) != 1)
    {
        printf("Error: Failed to parse the address.\n");
        return -1; // Failed to parse the address
    }

    // Parse the bytes size
    if (sscanf(bytes_size_start, "bytes_size=%d", &data->bytes_size) != 1)
    {
        printf("Error: Failed to parse bytes size.\n");
        return -1; // Failed to parse bytes size
    }

    if (data->bytes_size > MAX_BYTES_SIZE || data->bytes_size < 0)
    {
        printf("Error: Bytes size out of range.\n");
        return -1; // Bytes size is out of valid range
    }

    // Parse the bytes array (comma-separated list inside curly braces)
    bytes_start += strlen("bytes={");
    char *bytes_end = strchr(bytes_start, '}');
    if (!bytes_end)
    {
        printf("Error: Missing closing brace in bytes array.\n");
        return -1; // Malformed input, missing closing brace
    }

    // Create a copy of the bytes string to tokenize safely
    char bytes_str[BUFFER_SIZE];
    strncpy(bytes_str, bytes_start, bytes_end - bytes_start);
    bytes_str[bytes_end - bytes_start] = '\0'; // Null terminate the copied string

    // Now parse the comma-separated bytes
    int byte_count = 0;
    char *byte_token = strtok(bytes_str, ", ");
    while (byte_token && byte_count < data->bytes_size)
    {
        int byte_value;
        if (sscanf(byte_token, "%d", &byte_value) != 1 || byte_value < 0 || byte_value > 255)
        {
            printf("Error: Invalid byte value.\n");
            return -1; // Invalid byte value
        }
        data->bytes[byte_count++] = (unsigned char)byte_value;
        byte_token = strtok(NULL, ", ");
    }

    if (byte_count != data->bytes_size)
    {
        printf("Error: Parsed byte count %d does not match bytes_size %d.\n", byte_count, data->bytes_size);
        return -1; // Parsed byte count does not match bytes_size
    }

    return 0; // Success
}

// Function to continuously read input from stdin and parse it
int read_and_parse_from_stdin(sol_transaction_info_t *data)
{
    char buffer[BUFFER_SIZE]; // Buffer to hold each line of input
    fd_set readfds;           // File descriptor set
    struct timeval tv;        // Timeout structure

    // Set up the timeout value (0 for immediate return)
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    // Clear the file descriptor set
    FD_ZERO(&readfds);

    // Add stdin (file descriptor 0) to the set
    FD_SET(STDIN_FILENO, &readfds);

    // Use select to check if there is input available on stdin
    int result = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);

    if (result > 0 && FD_ISSET(STDIN_FILENO, &readfds))
    {
        // Data is available on stdin, read it
        if (fgets(buffer, sizeof(buffer), stdin) != NULL)
        {
            // Remove the newline character, if any
            buffer[strcspn(buffer, "\n")] = '\0';

            // Attempt to parse the input
            if (parse_output(buffer, data) == 0)
            {
                return data->bytes_size;
            }
            else
            {
                return -1;
            }
        }
    }

    // No data available
    return 0;
}

// Function to print bytes from index 0 to length
void print_bytes(const unsigned char *bytes, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf("%02X ", bytes[i]); // Print each byte in hexadecimal
    }
}

/* Client context and callback management:
 *
 * The client application context is created before the conn
 * is created. It contains the list of files that will be required
 * from the server.
 * On initial start, the client creates all the stream contexts
 * that will be needed for the requested files, and marks all
 * these contexts as active.
 * Each stream context includes:
 *  - description of the stream state:
 *      name sent or not, FILE open or not, stream reset or not,
 *      stream finished or not.
 *  - index of the file in the list.
 *  - number of file name bytes sent.
 *  - stream ID.
 *  - the FILE pointer for reading the data.
 * Server side stream context is created when the client starts the
 * stream. It is closed when the file transmission
 * is finished, or when the stream is abandoned.
 *
 * The server side callback is a large switch statement, with one entry
 * for each of the call back events.
 */

#define MAX_CACHE_SIZE 1000

typedef struct st_sol_conn_cache_t
{
    char address[INET6_ADDRSTRLEN]; // Store IP address as a string
    picoquic_cnx_t *cnx;            // Cached QUIC conn
} sol_conn_cache_t;

typedef struct st_sol_stream_ctx_t
{
    sol_transaction_info_t data;
    int data_sent;
} sol_stream_ctx_t;

typedef struct st_sol_client_ctx_t
{
    sol_conn_cache_t conn_cache[MAX_CACHE_SIZE];
    int cache_size;
} sol_client_ctx_t;

int sol_client_callback(picoquic_cnx_t *cnx,
                        uint64_t stream_id, uint8_t *bytes, size_t length,
                        picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx)
{
    sol_client_ctx_t *client_ctx = (sol_client_ctx_t *)callback_ctx;
    // sol_stream_ctx_t *stream_ctx = (sol_stream_ctx_t *)v_stream_ctx;

    if (client_ctx == NULL)
    {
        /* This should never happen, because the callback context for the client is initialized
         * when creating the client conn. */
        printf("Error in sol_client_callback: Client context is NULL.\n");
        return -1;
    }

    switch (fin_or_event)
    {
    case picoquic_callback_stream_data: /* Data arrival on stream #x */
        printf("picoquic_callback_stream_data: stream_id=%d\n", (int)stream_id);
        break;
    case picoquic_callback_stream_fin: /* Data arrival on stream #x, maybe with fin mark */
        printf("Dpicoquic_callback_stream_fin: stream_id=%d\n", (int)stream_id);
        break;
    case picoquic_callback_stream_reset:
        printf("picoquic_callback_stream_reset: stream_id=%d\n", (int)stream_id);
        break;
    case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
        printf("picoquic_callback_stop_sending: stream_id=%d\n", (int)stream_id);
        break;
    case picoquic_callback_stateless_reset:
        printf("picoquic_callback_stateless_reset\n");
        break;
    case picoquic_callback_close: /* Received connection close */
        printf("picoquic_callback_close\n");
        break;
    case picoquic_callback_application_close: /* Received application close */
        printf("picoquic_callback_application_close\n");
        break;
    case picoquic_callback_stream_gap: /* bytes=NULL, len = length-of-gap or 0 (if unknown) */
        printf("picoquic_callback_stream_gap\n");
        break;
    case picoquic_callback_prepare_to_send: /* Active sending API */
        printf("picoquic_callback_prepare_to_send\n");
        break;
        // if (stream_ctx == NULL)
        // {
        //     printf("Stream context is NULL\n");
        //     return -1;
        // }

        // printf("Prepare to send on stream %d\n", (int)stream_id);

        // if (MAX_BYTES_SIZE > length)
        // {
        //     printf("Bytes size is too large\n");
        //     return -1;
        // }

        // printf("Load buffer on stream %d\n", (int)stream_id);
        // uint8_t *buffer = picoquic_provide_stream_data_buffer(bytes, length, 0, 1);

        // if (buffer == NULL)
        // {
        //     printf("Failed to provide stream data buffer\n");
        //     return -1;
        // }

        // printf("Write buffer on stream %d\n", (int)stream_id);
        // memcpy(buffer, stream_ctx->data.bytes, stream_ctx->data.bytes_size);

        // stream_ctx->data_sent = 1;
    case picoquic_callback_almost_ready:
        printf("picoquic_callback_almost_ready\n");
        break;
    case picoquic_callback_ready:
        printf("picoquic_callback_ready\n");
        break;
    case picoquic_callback_datagram:
        printf("picoquic_callback_datagram\n");
        break;
    case picoquic_callback_version_negotiation:
        printf("picoquic_callback_version_negotiation\n");
        break;
    case picoquic_callback_request_alpn_list:
        printf("picoquic_callback_request_alpn_list\n");
        break;
    case picoquic_callback_set_alpn: /* Set ALPN to negotiated value */
        printf("picoquic_callback_set_alpn\n");
        break;
    case picoquic_callback_pacing_changed: /* Pacing rate for the connection changed */
        printf("picoquic_callback_pacing_changed\n");
        break;
    case picoquic_callback_prepare_datagram: /* Prepare the next datagram */
        printf("picoquic_callback_prepare_datagram\n");
        break;
    case picoquic_callback_datagram_acked: /* Ack for packet carrying datagram-frame received from peer */
        printf("picoquic_callback_datagram_acked\n");
        break;
    case picoquic_callback_datagram_lost: /* Packet carrying datagram-frame probably lost */
        printf("picoquic_callback_datagram_lost\n");
        break;
    case picoquic_callback_datagram_spurious: /* Packet carrying datagram-frame was not really lost */
        printf("picoquic_callback_datagram_spurious\n");
        break;
    case picoquic_callback_path_available: /* A new path is available, or a suspended path is available again */
        printf("picoquic_callback_path_available\n");
        break;
    case picoquic_callback_path_suspended: /* An available path is suspended */
        printf("picoquic_callback_path_suspended\n");
        break;
    case picoquic_callback_path_deleted: /* An existing path has been deleted */
        printf("picoquic_callback_path_deleted\n");
        break;
    case picoquic_callback_path_quality_changed: /* Some path quality parameters have changed */
        printf("picoquic_callback_path_quality_changed\n");
        break;
    case picoquic_callback_path_address_observed: /* The peer has reported an address for the path */
        printf("picoquic_callback_path_address_observed\n");
        break;
    }

    return 0;
}

picoquic_cnx_t *sol_get_or_create_cnx(picoquic_quic_t *quic, sol_client_ctx_t *ctx, const char *ip_addr)
{
    for (int i = 0; i < ctx->cache_size; i++)
    {
        if (strcmp(ctx->conn_cache[i].address, ip_addr) == 0)
        {
            picoquic_cnx_t *cnx = ctx->conn_cache[i].cnx;
            if (picoquic_get_cnx_state(cnx) != 19)
            {

                printf("found cached connection to %s: state=%d\n", ip_addr, picoquic_get_cnx_state(cnx));
                return ctx->conn_cache[i].cnx;
            } else {
                printf("found cached connection to %s: state=%d, deleting\n", ip_addr, picoquic_get_cnx_state(cnx));
                picoquic_delete_cnx(cnx);
                break;
            }
        }
    }

    printf("creating new connection to %s\n", ip_addr);

    struct sockaddr_storage sockaddr = string_to_sockaddr_storage(ip_addr);
    
    picoquic_cnx_t *cnx = picoquic_create_client_cnx(
        quic, (struct sockaddr *)&sockaddr, picoquic_current_time(), 
        0, SOL_SNI, SOL_ALPN, sol_client_callback, ctx);
    
    if (cnx == NULL)
    {
        fprintf(stderr, "Could not create connection context\n");
        return NULL;
    }

    if (ctx->cache_size < MAX_CACHE_SIZE)
    {
        strncpy(ctx->conn_cache[ctx->cache_size].address, ip_addr, INET6_ADDRSTRLEN);
        ctx->conn_cache[ctx->cache_size].cnx = cnx;
        ctx->cache_size++;
    }
    else
    {
        printf("Cache is full! Consider increasing MAX_CACHE_SIZE.\n");
        return NULL;
    }

    return cnx;
}

int sol_read_and_send_from_stdin(picoquic_quic_t *quic, sol_client_ctx_t *ctx)
{
    sol_transaction_info_t data = {0};

    if (read_and_parse_from_stdin(&data) < 0)
    {
        fprintf(stderr, "Failed to parse input\n");
        return -1;
    };

    if (data.bytes_size == 0)
    {
        return 0;
    }

    picoquic_cnx_t *cnx = sol_get_or_create_cnx(quic, ctx, data.address);

    if (cnx == NULL)
    {
        fprintf(stderr, "Could not get or create connection\n");
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    // sol_stream_ctx_t *stream_ctx = (sol_stream_ctx_t *)malloc(sizeof(sol_stream_ctx_t));

    // if (stream_ctx == NULL)
    // {
    //     fprintf(stderr, "Memory Error, cannot create stream\n");
    //     return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    // }

    // memset(stream_ctx, 0, sizeof(sol_stream_ctx_t));

    // stream_ctx->data = data;
    // stream_ctx->data_sent = 0;

    // uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 0);

    // if (picoquic_mark_active_stream(cnx, stream_id, 1, &stream_ctx) < 0)
    // {
    //     printf("Failed to mark stream as active\n ");
    //     return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    // }

    // printf("marked stream active: stream_ctx->data.address=%s stream_ctx->data.size=%d\n", stream_ctx->data.address, stream_ctx->data.bytes_size);

    return 0;
}

int sol_client_loop_cb(picoquic_quic_t *quic, picoquic_packet_loop_cb_enum cb_mode,
                       void *callback_ctx, void *callback_arg)
{
    sol_client_ctx_t *ctx = (sol_client_ctx_t *)callback_ctx;

    if (ctx == NULL)
    {
        printf("Error in sol_client_loop_cb: Client context is NULL.\n");
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    switch (cb_mode)
    {
    case picoquic_packet_loop_ready: /* Argument type: packet loop options */
        printf("picoquic_packet_loop_ready\n");
        break;
    case picoquic_packet_loop_after_receive: /* Argument type size_t*: nb packets received */
        printf("picoquic_packet_loop_after_receive: bytes_received=%ld\n", *(size_t *)callback_arg);
        break;
    case picoquic_packet_loop_after_send: /* Argument type size_t*: nb packets sent */
        printf("picoquic_packet_loop_after_send: bytes_sent=%ld\n", *(size_t *)callback_arg);
        sol_read_and_send_from_stdin(quic, ctx);
        break;
    case picoquic_packet_loop_port_update: /* argument type struct_sockaddr*: new address for wakeup */
        printf("picoquic_packet_loop_port_update\n");
        break;
    case picoquic_packet_loop_time_check: /* argument type packet_loop_time_check_arg_t*. Optional. */
        printf("picoquic_packet_loop_time_check\n");
        break;
    case picoquic_packet_loop_system_call_duration: /* argument type packet_loop_system_call_duration_t*. Optional. */
        printf("picoquic_packet_loop_system_call_duration\n");
        break;
    case picoquic_packet_loop_wake_up: /* no argument (void* NULL). Used when loop wakeup is supported */
        printf("picoquic_packet_loop_wake_up\n");
        break;
    case picoquic_packet_loop_alt_port: /* Provide alt port for testing multipath or migration */
        printf("picoquic_packet_loop_alt_port\n");
        break;
    }

    return 0;
}

picoquic_quic_t *sol_quic_init()
{
    /* INITIALISE QUIC */
    char const *ticket_store_filename = PICOQUIC_SAMPLE_CLIENT_TICKET_STORE;
    char const *token_store_filename = PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE;

    picoquic_quic_t *quic = picoquic_create(1000, NULL, NULL, NULL, SOL_ALPN,
                                            NULL, NULL, NULL, NULL, NULL, picoquic_current_time(), 
                                            NULL, ticket_store_filename, NULL, 0);
    
    if (quic == NULL)
    {
        fprintf(stderr, "Could not create quic context\n");
        return NULL;
    }

    // picoquic_load_retry_tokens(quic, token_store_filename);
    // picoquic_save_retry_tokens(quic, ticket_store_filename);
    picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);
    picoquic_set_key_log_file_from_env(quic);
    picoquic_set_qlog(quic, "./logs");
    picoquic_set_log_level(quic, 1);

    return quic;
}

int picoquic_sample_client()
{
    /* Intialise quic */
    picoquic_quic_t *quic = sol_quic_init();

    /* Create client context */
    sol_client_ctx_t client_ctx = {0};

    /* Create packet loop params */
    picoquic_packet_loop_param_t params = {0};
    params.local_port = 5432;
    params.local_af = AF_INET;

    /* Start packet loop */
    if (picoquic_packet_loop_v2(quic, &params, sol_client_loop_cb, &client_ctx) < 0)
    {
        fprintf(stderr, "Packet loop failed!\n");
        return -1;
    }

    printf("Packet loop completed.\n");

    /* Exit success */
    return 0;
}