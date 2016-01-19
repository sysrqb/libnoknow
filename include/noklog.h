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

#ifndef NOKNOW_LOG_H
#define NOKNOW_LOG_H 1
#include <stdio.h>

#include <noknow.h>

typedef enum libnok_log_level {
  NOK_VERBOSITY_ERROR,
  NOK_VERBOSITY_WARNING,
  NOK_VERBOSITY_NOTICE,
  NOK_VERBOSITY_INFO = 4,
  NOK_VERBOSITY_DEBUG = 8
} libnok_log_level_t;

int libnok_log_set_logs(libnok_context_t *ctx, FILE *out, FILE *err);
int libnok_log_set_log_verbosity(libnok_context_t *ctx,
                                 libnok_log_level_t level);

#endif /* NOKNOW_LOG_H */
