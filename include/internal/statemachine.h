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

#ifndef NOK_STATEMACHINE_INT_H
#define NOK_STATEMACHINE_INT_H 1

#include <stddef.h>
#include <stdint.h>

#include <nokstatemachine.h>

struct libnok_state_base_s {
  size_t len;
  int *sequence;
};

struct libnok_state_s {
  libnok_state_base_t *base;

  /* Explicit assumption there are fewer than INT_MAX (2^32) states */
  int32_t prev_state;
  int32_t curr_state;
  int32_t next_state;
  int (*statetrans)(int *prev, int *curr, int *next);
};

#endif /* NOK_STATEMACHINE_INT_H */
