/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "picoquic_internal.h"

int picoquic_store_ticket(picoquic_stored_ticket_t ** pp_first_ticket,
    uint64_t current_time,
    char const * sni, uint16_t sni_length, char const * alpn, uint16_t alpn_length,
    uint8_t * ticket, uint16_t ticket_length)
{
    int ret = 0;

    /* TO DO: remove other tickets for that SNI/ALPN */

    if (ticket_length < 17)
    {
        ret = PICOQUIC_ERROR_INVALID_TICKET;
    }
    else
    {
        uint64_t ticket_issued_time;
        uint64_t ttl_seconds;
        uint64_t time_valid_until;

        ticket_issued_time = PICOPARSE_64(ticket);
        ttl_seconds = PICOPARSE_32(ticket + 13);

        if (ttl_seconds > (7 * 24 * 3600))
        {
            ttl_seconds = (7 * 24 * 3600);
        }

        time_valid_until = (ticket_issued_time * 1000) + (ttl_seconds * 1000000);

        if (current_time != 0 && time_valid_until < current_time)
        {
            ret = PICOQUIC_ERROR_INVALID_TICKET;
        }
        else
        {
            size_t ticket_size =
                sizeof(picoquic_stored_ticket_t) +
                sni_length + 1 + alpn_length + 1 + ticket_length;
            picoquic_stored_ticket_t * stored = (picoquic_stored_ticket_t *)malloc(ticket_size);
            char * next_p = ((char *)stored) + sizeof(picoquic_stored_ticket_t);

            if (stored == NULL)
            {
                ret = PICOQUIC_ERROR_MEMORY;
            }
            else
            {
                stored->time_valid_until = time_valid_until;
                stored->sni = next_p;
                stored->sni_length = sni_length;
                memcpy(next_p, sni, sni_length);
                next_p += sni_length;
                *next_p++ = 0;

                stored->alpn = next_p;
                stored->alpn_length = alpn_length;
                memcpy(next_p, alpn, alpn_length);
                next_p += alpn_length;
                *next_p++ = 0;

                stored->ticket = (uint8_t *)next_p;
                stored->ticket_length = ticket_length;
                memcpy(next_p, ticket, ticket_length);

                stored->next_ticket = *pp_first_ticket;
                *pp_first_ticket = stored;
            }
        }
    }

    return ret;
}

int picoquic_get_ticket(picoquic_stored_ticket_t * p_first_ticket,
    uint64_t current_time,
    char const * sni, uint16_t sni_length, char const * alpn, uint16_t alpn_length,
    uint8_t ** ticket, uint16_t * ticket_length)
{
    int ret = 0;
    picoquic_stored_ticket_t * next = p_first_ticket;

    while (next != NULL)
    {
        if (next->time_valid_until > current_time &&
            next->sni_length == sni_length &&
            next->alpn_length == alpn_length &&
            memcmp(next->sni, sni, sni_length) == 0 &&
            memcmp(next->alpn, alpn, alpn_length) == 0)
        {
            break;
        }
        else
        {
            next = next->next_ticket;
        }
    }

    if (next == NULL)
    {
        *ticket = NULL;
        *ticket_length = 0;
        ret = -1;
    }
    else
    {
        *ticket = next->ticket;
        *ticket_length = next->ticket_length;
    }

    return ret;
}

int picoquic_save_tickets(picoquic_stored_ticket_t * first_ticket,
    uint64_t current_time,
    char const  * ticket_file_name)
{
    int ret = 0;
    FILE * F = NULL;
    picoquic_stored_ticket_t * next = first_ticket;
#ifdef _WINDOWS
    errno_t err = fopen_s(&F, ticket_file_name, "wb");
    if (err != 0) {
        ret = -1;
    }
#else
    F = fopen(ticket_file_name, "wb");
    if (F == NULL) {
        ret = -1;
    }
#endif

    while (ret == 0 && next != NULL)
    {
        /* Only store the tickets that are valid going forward */
        if (next->time_valid_until > current_time)
        {
            /* Compute the serialized size */
            uint32_t record_size =
                sizeof(picoquic_stored_ticket_t) 
                - offsetof(struct st_picoquic_stored_ticket_t, time_valid_until) +
                next->sni_length + 1 + next->alpn_length + 1 + next->ticket_length;
            char * record_start = ((char *)next) + offsetof(struct st_picoquic_stored_ticket_t, time_valid_until);

            if (fwrite(&record_size, 4, 1, F) != 1 ||
                fwrite(record_start, 1, record_size, F) != record_size)
            {
                ret = PICOQUIC_ERROR_INVALID_FILE;
                break;
            }
        }
        next = next->next_ticket;
    }

    if (F != NULL)
    {
        fclose(F);
    }

    return ret;
}

int picoquic_load_tickets(picoquic_stored_ticket_t ** pp_first_ticket,
    uint64_t current_time, char const * ticket_file_name)
{
    int ret = 0;
    FILE * F = NULL;
    picoquic_stored_ticket_t * previous = NULL;
    picoquic_stored_ticket_t * next;
    uint32_t record_size;
    uint32_t storage_size;

#ifdef _WINDOWS
    errno_t err = fopen_s(&F, ticket_file_name, "rb");
    if (err != 0) {
        ret = -1;
    }
#else
    F = fopen(ticket_file_name, "rb");
    if (F == NULL) {
        ret = -1;
    }
#endif
    while (ret == 0)
    {
        if (fread(&storage_size, 4, 1, F) != 1)
        {
            /* end of file */
            break;
        }
        else
        {
            record_size = storage_size + offsetof(struct st_picoquic_stored_ticket_t, time_valid_until);
            next = (picoquic_stored_ticket_t *)malloc(record_size);

            if (next == NULL)
            {
                ret = PICOQUIC_ERROR_MEMORY;
                break;
            }
            else
            {
                if (fread(((char*)next) + offsetof(struct st_picoquic_stored_ticket_t, time_valid_until),
                    1, storage_size, F) != storage_size)
                {
                    ret = PICOQUIC_ERROR_INVALID_FILE;
                    free(next);
                }
                else if (next->time_valid_until < current_time)
                {
                    free(next);
                }
                else
                {
                    next->sni = ((char*)next) + sizeof(picoquic_stored_ticket_t);
                    next->alpn = next->sni + next->sni_length + 1;
                    next->ticket = (uint8_t *)(next->alpn + next->alpn_length + 1);
                    next->next_ticket = NULL;
                    if (previous == NULL)
                    {
                        *pp_first_ticket = next;
                    }
                    else
                    {
                        previous->next_ticket = next;
                    }

                    previous = next;
                }
            }
        }
    } 

    if (F != NULL)
    {
        fclose(F);
    }

    return ret;
}


void picoquic_free_tickets(picoquic_stored_ticket_t ** pp_first_ticket)
{
    picoquic_stored_ticket_t * next;

    while ((next = *pp_first_ticket) != NULL)
    {
        *pp_first_ticket = next->next_ticket;

        free(next);
    }
}