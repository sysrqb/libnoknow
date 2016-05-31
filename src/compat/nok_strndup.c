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

/* Compatibility layer when str[n]{0,1}dup aren't supported by libc */

#include <string.h>
#include <stdlib.h>

/* Max string length */
#define MAXLEN 1024

char *nok_strndup(const char *s, size_t n)
{
#if _POSIX_C_SOURCE >= 200809L || _XOPEN_SOURCE >= 700 || _GNU_SOURCE
  return strndup(s, n);
#else
  char *buf;
  size_t len;
  len = strlen(s);

  len = n > len ? len : n;
  buf = (char *)malloc(sizeof(*buf)*len);
  if (buf != NULL) {
    memcpy(buf, s, len);
  }
  return buf;
#endif
}

char *nok_strdup(const char *s)
{
#if _SVID_SOURCE || _BSD_SOURCE || _XOPEN_SOURCE >= 500 || _XOPEN_SOURCE && _XOPEN_SOURCE_EXTENDED || /* Since glibc 2.12: */ _POSIX_C_SOURCE >= 200809L
  return strdup(s);
#else
  size_t len;
  len = strlen(s);
  return nok_strndup(s, len > MAXLEN ? MAXLEN:len);
#endif
}
