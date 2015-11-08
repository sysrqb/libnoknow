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


#include <gtest/gtest.h>
#include <statemachine.h>

/* Test state_fill_sequence() with NULL input */
TEST(StateFillSequence, NullList)
{
  libnok_state_t *ctx = NULL;
  ctx = (libnok_state_t *)malloc(sizeof(*ctx));
  ASSERT_NE((libnok_state_t *)NULL, ctx);
  ctx->base = NULL;
  EXPECT_EQ(-1, libnok_state_fill_sequence(ctx->base));
  ctx->base = (libnok_state_base_t *)malloc(sizeof(ctx->base));
  EXPECT_NE((libnok_state_base_t *)NULL, ctx->base);
  if (ctx->base == NULL)
    goto err_free;
  memset(&(ctx->base), 0, sizeof(ctx->base));
  EXPECT_EQ(-1, libnok_state_fill_sequence(ctx->base));

err_free:
  free(ctx->base);
  free(ctx);
}

/* Test state_fill_sequence() with valid input */
TEST(StateFillSequence, EmptyList)
{
  int i;
  libnok_state_t *ctx = NULL;
  ctx = (libnok_state_t *)malloc(sizeof(*ctx));
  EXPECT_NE((libnok_state_t *)NULL, ctx);
  ctx->base = (libnok_state_base_t *)malloc(sizeof(ctx->base));
  EXPECT_NE((libnok_state_base_t *)NULL, ctx->base);
  if (ctx->base == NULL)
    goto err_free;
  memset(ctx->base, 0, sizeof(*(ctx->base)));
  ctx->base->len = 13;
  ctx->base->sequence = (int *) malloc(sizeof(int)*ctx->base->len);
  EXPECT_NE((int *)NULL, ctx->base->sequence);
  if (ctx->base->sequence == NULL)
    goto err_free;
  memset(ctx->base->sequence, 0, sizeof(int)*ctx->base->len);
  EXPECT_EQ(0, libnok_state_fill_sequence(ctx->base));
  for (i = 0; i < ctx->base->len; ++i) {
    EXPECT_EQ(i, ctx->base->sequence[i]);
  }

err_free:
  free(ctx->base->sequence);
  free(ctx->base);
  free(ctx);
}

int state_trans_state_transition_test(int *prev, int *curr, int *next)
{
  if (prev == NULL)
    return -1;
  if (curr == NULL)
    return -1;
  if (next == NULL)
    return -1;

  if ((*prev == *curr) && (*curr == *next) && (*next == -1)) {
    *prev = *curr = 0;
    *next = 1;
  } else {
    *prev = *curr;
    *curr = *next;
    (*next)++;
  }
  return 0;
}

/* Test state_init_base() with invalid and valid inputs */
TEST(StateInit, BaseInitialValues)
{
  int len, i;
  int seq[10];
  libnok_state_base_t *state_base = NULL;

  len = 0;
  state_base = libnok_state_init_base(len, NULL);
  EXPECT_EQ(NULL, state_base);
  if (state_base != NULL)
    goto err_free;

  len = -1;
  state_base = libnok_state_init_base(len, NULL);
  EXPECT_EQ(NULL, state_base);
  if (state_base != NULL)
    goto err_free;

  len = 1;
  state_base = libnok_state_init_base(len, NULL);
  EXPECT_EQ(NULL, state_base);
  if (state_base != NULL)
    goto err_free;

  len = 0;
  state_base = libnok_state_init_base(len, seq);
  EXPECT_EQ(NULL, state_base);
  if (state_base != NULL)
    goto err_free;

  len = 3;
  state_base = libnok_state_init_base(len, seq);
  ASSERT_NE((libnok_state_base_t *)NULL, state_base);
  EXPECT_EQ(len, state_base->len);
  for (i = 0; i < len; ++i) {
    EXPECT_EQ(seq[i], state_base->sequence[i]);
  }

err_free:
  free(state_base);
}

/* Test state_init() with invalid and valid inputs */
TEST(StateInit, InitialValues)
{
  int seq[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  int len = sizeof(seq)/sizeof(seq[0]);
  libnok_state_t *state = NULL;
  libnok_state_base_t *state_base = NULL;

  state = libnok_state_init(NULL, NULL);
  EXPECT_EQ(NULL, state);
  if (state != NULL)
    goto err_free;

  state = libnok_state_init(&state_trans_state_transition_test, state_base);
  EXPECT_NE((libnok_state_t *)NULL, state);
  if (state != NULL)
    free(state);

  state_base = libnok_state_init_base(len, seq);
  EXPECT_NE((libnok_state_base_t *)NULL, state_base);
  if (state_base != NULL)
    goto err_free;

  state = libnok_state_init(NULL, state_base);
  EXPECT_EQ(NULL, state);
  if (state != NULL)
    goto err_free;

  state = libnok_state_init(&state_trans_state_transition_test, state_base);
  EXPECT_NE((libnok_state_t *)NULL, state);
  if (state != NULL)
    goto err_free;

err_free:
  free(state);
  free(state_base);
}

/* Test state_get_next_state() - verify structure values were updated */
TEST(StateTrans, GetNextState)
{
  int prev, curr, next;
  int seq[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  int len = sizeof(seq)/sizeof(seq[0]);
  libnok_state_base_t *state_base = NULL;
  libnok_state_t *state = NULL;

  EXPECT_EQ(-1, libnok_state_get_next_state(NULL));
  state_base = libnok_state_init_base(len, seq);
  state = libnok_state_init(&state_trans_state_transition_test, state_base);
  state->statetrans = NULL;
  EXPECT_EQ(-1, libnok_state_get_next_state(NULL));
  state->statetrans = &state_trans_state_transition_test;
  ASSERT_NE((libnok_state_t *)NULL, state);
  EXPECT_EQ(0, libnok_state_get_next_state(state));
  EXPECT_EQ(0, state->prev_state);
  EXPECT_EQ(0, state->curr_state);
  EXPECT_EQ(1, state->next_state);
  EXPECT_EQ(0, libnok_state_get_next_state(state));
  EXPECT_EQ(0, state->prev_state);
  EXPECT_EQ(1, state->curr_state);
  EXPECT_EQ(2, state->next_state);
  curr = state->curr_state;
  next = state->next_state;
  EXPECT_EQ(0, libnok_state_get_next_state(state));
  EXPECT_EQ(curr, state->prev_state);
  EXPECT_EQ(next, state->curr_state);
  EXPECT_EQ(next + 1, state->next_state);

  free(state);
}
