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


#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "qlog.h"


/* This file includes a series of tests covering edge cases, typically
 * derived from observing failures in the interop runner. The failures
 * correspond to specific sequences in which specific packets were dropped,
 * leading to a failure state from which the connection did not
 * recover. Many of these failures involve 0-RTT connections.
 */

static char const* edge_case_ticket_file = "edge_case_ticket_file.bin";
static char const* edge_case_token_file = "edge_case_token_file.bin";

static test_api_stream_desc_t test_scenario_edge_case[] = {
    { 4, 0, 128, 1000 }
};

void edge_case_reset_scenario(picoquic_test_tls_api_ctx_t* test_ctx)
{

    for (size_t i = 0; i < test_ctx->nb_test_streams; i++) {
        test_ctx->test_stream[i].q_received = 0;
        test_ctx->test_stream[i].q_sent = 0;
        test_ctx->test_stream[i].r_received = 0;
        test_ctx->test_stream[i].r_sent = 0;
        test_ctx->test_stream[i].q_recv_nb = 0;
        test_ctx->test_stream[i].r_recv_nb = 0;
    }
    test_ctx->sum_data_received_at_server = 0;
    test_ctx->sum_data_received_at_client = 0;
    test_ctx->test_finished = 0;
    test_ctx->streams_finished = 0;
}

int edge_case_prepare(picoquic_test_tls_api_ctx_t** p_test_ctx, uint8_t edge_case_id, int zero_rtt, uint64_t* simulated_time, uint64_t loss_mask, int nb_init_rounds)
{
    picoquic_connection_id_t initial_cid = { { 0xed, 0x9e, 0xca, 0x5e, 0, 0, 0, 0}, 8 };
    uint64_t latency = 18000;
    int ret = 0;
    FILE* F;

    initial_cid.id[4] = edge_case_id;
    initial_cid.id[5] = zero_rtt;

    /* Make sure that the ticket and token files are empty */
    F = picoquic_file_open(edge_case_ticket_file, "wb");
    if (F != NULL) {
        picoquic_file_close(F);
    }
    F = picoquic_file_open(edge_case_token_file, "wb");
    if (F != NULL) {
        picoquic_file_close(F);
    }
    /* Create the test context */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(p_test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, simulated_time, edge_case_ticket_file, edge_case_token_file, 0, 1, 0, &initial_cid);
    }
    /* Set the binlog */
    if (ret == 0) {
        picoquic_set_binlog((*p_test_ctx)->qclient, ".");
        picoquic_set_binlog((*p_test_ctx)->qserver, ".");
    }
    /* Set the link latency */
    if (ret == 0) {
        (*p_test_ctx)->c_to_s_link->microsec_latency = latency;
        (*p_test_ctx)->s_to_c_link->microsec_latency = latency;
    }

    if (ret == 0 && edge_case_id == 0xcf) {
        (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
        picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(*p_test_ctx, test_scenario_edge_case, sizeof(test_scenario_edge_case));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* If zero RTT is required, run a single connection */
    if (ret == 0) {
        if (!zero_rtt) {
            int ret = picoquic_start_client_cnx((*p_test_ctx)->cnx_client);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "Could not initialize connection for the client\n");
            }
        }
        else {
            uint32_t ticket_version = 0;
            int ret = tls_api_one_scenario_body_connect(*p_test_ctx, simulated_time, 0, 0, 0);

            /* Finish sending data */
            if (ret == 0) {
                uint64_t zero_loss = 0;
                ret = tls_api_data_sending_loop(*p_test_ctx, &zero_loss, simulated_time, 0);

                if (ret != 0)
                {
                    DBG_PRINTF("Data sending loop returns %d\n", ret);
                }
            }

            if (ret == 0) {
                /* wait for the session ticket to arrive */
                ret = session_resume_wait_for_ticket(*p_test_ctx, simulated_time);
            }

            if (ret == 0) {
                ret = tls_api_one_scenario_body_verify(*p_test_ctx, simulated_time, 1000000);
            }

            if (ret == 0 && (*p_test_ctx)->qclient->p_first_ticket == NULL) {
                DBG_PRINTF("No session ticket after first connection, t=%" PRIu64, *simulated_time);
            }
            else {
                ticket_version = (*p_test_ctx)->qclient->p_first_ticket->version;
            }

            if (ret == 0) {
                /* delete the client connection and create a new one. */
                picoquic_delete_cnx((*p_test_ctx)->cnx_client);
                (*p_test_ctx)->cnx_client = NULL;
                (*p_test_ctx)->cnx_server = NULL;
                edge_case_reset_scenario(*p_test_ctx);
                initial_cid.id[5] = 0;

                (*p_test_ctx)->cnx_client = picoquic_create_cnx((*p_test_ctx)->qclient, initial_cid,
                    picoquic_null_connection_id,
                    (struct sockaddr*)&(*p_test_ctx)->server_addr, *simulated_time,
                    ticket_version, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

                if ((*p_test_ctx)->cnx_client == NULL) {
                    ret = -1;

                    if (ret != 0)
                    {
                        DBG_PRINTF("Create second connection returns %d\n", ret);
                    }
                }
            }
            if (ret == 0) {
                /* Start the client connection */
                ret = picoquic_start_client_cnx((*p_test_ctx)->cnx_client);

                if (ret != 0)
                {
                    DBG_PRINTF("Start second connection returns %d\n", ret);
                }
                else {
                    ret = test_api_queue_initial_queries((*p_test_ctx), 0);

                    if (ret != 0)
                    {
                        DBG_PRINTF("Restart scenario returns %d\n", ret);
                    }
                }
            }
        }
    }


    /* Execute the expected number of rounds */
    if (ret == 0) {
        int nb_trials = 0;
        int nb_inactive = 0;
        uint64_t loss_target = loss_mask >> nb_init_rounds;
        loss_target |= loss_mask << (64 - nb_init_rounds);

        (*p_test_ctx)->c_to_s_link->loss_mask = &loss_mask;
        (*p_test_ctx)->s_to_c_link->loss_mask = &loss_mask;

        /* Set preemtive repeat on server */
        picoquic_set_preemptive_repeat_policy((*p_test_ctx)->qserver, 1);

        while (ret == 0 && nb_trials < 4*nb_init_rounds && nb_inactive < 256 && loss_mask != loss_target) {
            int was_active = 0;

            nb_trials++;

            ret = tls_api_one_sim_round(*p_test_ctx, simulated_time, 0, &was_active);

            if (ret < 0)
            {
                break;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }

            if ((*p_test_ctx)->test_finished) {
                break;
            }
        }
    }

    return ret;
}

int edge_case_complete(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time, uint64_t duration_max)
{
    int ret = 0;
    uint64_t loss_mask = 0;
    
    ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, simulated_time);
    if (ret != 0)
    {
        DBG_PRINTF("Connect loop returns %d\n", ret);
    }

    /* Finish sending data */
    test_ctx->immediate_exit = 1;

    if (ret == 0) {
        uint64_t zero_loss = 0;
        ret = tls_api_data_sending_loop(test_ctx, &zero_loss, simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, simulated_time, duration_max);
    }

    return ret;
}

/* Edge case zero: verify that the common code
 * works.
 */
int ec00_zero_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = edge_case_prepare(&test_ctx, 0, 1, &simulated_time, 0, 4);

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 100000);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->nb_zero_rtt_acked == 0) {
            DBG_PRINTF("Nb 0RTT acked = %d", test_ctx->cnx_client->nb_zero_rtt_acked);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Reproduce and fix a specific error:
 * - 0RTT packet was lost
 * - Client second flight arrives at peer, but handshake ACK is lost
 * - Handshake Done is lost
 * Client appears stuck repeating second flight, intead of trying to
 * make progress and send data.
 * 
 * This is unlocked by enabling retransmission of data in "client almost ready"
 * state. 
 */

int ec2f_second_flight_nack_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0x181;
    uint8_t test_case_id = 0x2f;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 1, &simulated_time, initial_losses, 10);

    if (ret == 0) {
        if (test_ctx->cnx_client->cnx_state >= picoquic_state_ready ||
            test_ctx->cnx_server->cnx_state != picoquic_state_ready) {
            DBG_PRINTF("Unexpected state, client: %d, server: %d",
                test_ctx->cnx_client->cnx_state, test_ctx->cnx_server->cnx_state);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 360000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Reproduce and fix a corrupt file transmission occuring
 * during a lossy handshake. At some point, the server
 * sent random content instead of repeating the original packet
 * content.
 */
int eccf_corrupted_file_test()
{

    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b11110010011001001010101010000000;
    /*                          ....^^.^^^......................*/
    uint8_t test_case_id = 0xcf;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 40);

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 400000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

void eccf_corrupted_file_fuzz(int nb_trials, uint64_t seed, FILE* F)
{
    uint64_t random_context = (0x1234567887654321ull) ^ seed;

    for (int i=0; i< nb_trials; i++) {

        uint64_t simulated_time = 0;
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;
        uint64_t initial_losses = picoquic_test_random(&random_context) & 0xFFFFFFFF84ull;
        uint8_t test_case_id = 0xcf;
        int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 40);

        if (ret == 0) {
            ret = edge_case_complete(test_ctx, &simulated_time, 400000);
        }

        if (ret != 0 && F != NULL) {
            fprintf(F, "0x%" PRIx64 ", %" PRIu64 ", %d, %" PRIu64 "\n",
                initial_losses, initial_losses, ret, simulated_time);
        }

        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }
    }
}

int eccf_corrupted_file_fuzz_test()
{
    int ret = 0;
    FILE* F = picoquic_file_open("ECCF_Fuzz_report.csv", "w");
    if (F == NULL) {
        ret = -1;
    }
    else {
        fprintf(F, "Seed_hex, Seed, Ret, Elapsed\n");
        eccf_corrupted_file_fuzz(1000, 0, F);
        picoquic_file_close(F);
    }
    return ret;
}