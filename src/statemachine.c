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

#include <statemachine.h>


int
libnok_state_fill_sequence(libnok_state_base_t *ctx_base)
{
  return -1;
}

libnok_state_base_t *
libnok_state_init_base(int len, int *seq)
{
  return NULL;
}

libnok_state_t *
libnok_state_init(int (*statetrans)(int *prev, int *curr, int *next),
                  libnok_state_base_t *ctx_base)
{
  return NULL;
}

int
libnok_state_get_next_state(libnok_state_t *ctx)
{
  return -1;
}
