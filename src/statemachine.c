/**
 * libnoknow - The Nothing Or Knowledge (Oblivious Transfer) Library
 * Copyright (C) 2015 Matthew Finkel
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

/* libnok include */
#include <statemachine.h>


int
libnok_state_fill_sequence(libnok_state_base_t *ctx_base)
{
  int i;
  if (ctx_base == NULL)
    return -1;
  if (ctx_base->sequence == NULL)
    return -1;
  if (ctx_base->len < 1)
    return -1;

  for (i = 0; i < ctx_base->len; ++i) {
    ctx_base->sequence[i] = i;
  }
  return 0;
}

libnok_state_base_t *
libnok_state_init_base(int len, int *seq)
{
  libnok_state_base_t *ctx_base = NULL;
  if (seq == NULL)
    return NULL;
  if (len < 1)
    return NULL;

  ctx_base = (libnok_state_base_t *) malloc(sizeof(*ctx_base));
  if (ctx_base == NULL)
    return NULL;
  ctx_base->sequence = (int *) malloc(sizeof(*(ctx_base->sequence))*len);
  if (ctx_base->sequence == NULL) {
    free(ctx_base);
    return NULL;
  }
  ctx_base->len = len;
  memcpy(ctx_base->sequence, seq, sizeof(*(ctx_base->sequence))*len);
  return ctx_base;
}

libnok_state_t *
libnok_state_init(int (*statetrans)(int *prev, int *curr, int *next),
                  libnok_state_base_t *ctx_base)
{
  libnok_state_t *ctx = NULL;

  if (statetrans == NULL)
    return NULL;
  if (ctx_base == NULL) {
    ctx_base = (libnok_state_base_t *) malloc(sizeof(*ctx_base));
    if (ctx_base == NULL)
      return NULL;
  }

  ctx = (libnok_state_t *) malloc(sizeof(*ctx));
  if (ctx == NULL)
    return NULL;

  ctx->base = ctx_base;
  ctx->prev_state = -1;
  ctx->curr_state = -1;
  ctx->next_state = -1;
  ctx->statetrans = statetrans;

  return ctx;
}

int
libnok_state_get_next_state(libnok_state_t *ctx)
{
  int prev = -1, curr = -1, next = -1;

  if (ctx == NULL)
    return -1;
  if (ctx->statetrans == NULL)
    return -1;

  prev = ctx->prev_state;
  curr = ctx->curr_state;
  next = ctx->next_state;
  if (ctx->statetrans(&prev, &curr, &next) == -1)
    return -1;
  ctx->prev_state = prev;
  ctx->curr_state = curr;
  ctx->next_state = next;

  return 0;
}
