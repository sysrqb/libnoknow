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

/* Compatibility layer when [v]{0,1}snprintf aren't supported by libc */

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int nok_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
  size_t rsize;
#if defined( _BSD_SOURCE) || (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 500) || defined(_ISOC99_SOURCE) || (defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L)
  return vsnprintf(str, size, format, ap);
#elif (defined(_XOPEN_SOURCE) && _XOPEN_SOURCE >= 700) || (defined(_POSIX_C_SOURCE) && _POSIZ_C_SOUCE >= 200809L)
  FILE *f;
  char *strbuf;

  f = open_memstream(&strbuf, &rsize);
  rsize = vfprintf(f, format, ap);
  fclose(f);
  if (rsize >= size) {
    memcpy(buf, strbuf, size-1);
    buf[size-1] = '\0';
  } else {
    memcpy(buf, strbuf, rsize-1);
    buf[rsize-1] = '\0';
  }
  free(strbuf);
#else
  uint64_t largebufsz = (1<<30);
  char *strbuf;

  strbuf = malloc(sizeof(*strbuf)*(largebufsz));
  if (strbuf != NULL) {
    rsize = vsprintf(strbuf, format, ap);
    strbuf = realloc(strbuf, sizeof(*strbuf)*rsize);
    if (strbuf != NULL) {
      if (rsize >= size) {
        memcpy(str, strbuf, size-1);
        str[size-1] = '\0';
      } else {
        memcpy(str, strbuf, rsize-1);
        str[rsize-1] = '\0';
      }
    }
  }
  if (strbuf == NULL)
    rsize = -1;
  free(strbuf);
#endif
  return rsize;
}

int nok_snprintf(char *str, size_t size, const char *format, ...)
{
  int r;
  va_list ap;
  va_start(ap, format);
  r = nok_snprintf(str, size, format, ap);
  va_end(ap);
  return r;
}


