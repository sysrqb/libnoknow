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

#ifndef NOK_SNPRINTF_H
#define NOK_SNPRINTF_H

#ifdef __cplusplus
extern "C" {
#endif


#include <limits.h>
#include <stdlib.h>
#include <string.h>

int nok_vsnprintf(char *str, size_t size, const char *format, va_list ap);
int nok_snprintf(char *str, size_t size, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* NOK_SNPRINTF_H */
