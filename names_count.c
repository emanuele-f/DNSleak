/*
 * ----------------------------------------------------------------------------
 * DNSleak - A tool to locally detect DNS leaks
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2016 - Emanuele Faranda
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */

#include <string.h>
#include <stdlib.h>
#include "names_count.h"

#define NAME_TOTAL_SIZE (NAME_PREFIX_MAX_LENGTH + sizeof(NAME_SUFFIX))
#define NAME_NTH(i) (search_names+i*NAME_TOTAL_SIZE)

static char * search_names;
static u_int8_t * search_hits = NULL;
static int search_n = -1;

static const char * random_name() {
  static const char charset[] = NAME_PREFIX_CHARSET;
  static char rv[NAME_TOTAL_SIZE];

  int len = NAME_PREFIX_MIN_LENGTH + rand() % (NAME_PREFIX_MAX_LENGTH - NAME_PREFIX_MIN_LENGTH + 1);
  
  for (int i=0; i<len; i++)
    rv[i] = charset[rand() % (sizeof(NAME_PREFIX_CHARSET) - 1)];
    
  strcpy(rv+len, NAME_SUFFIX);
  
  return rv;
}

void names_generate(int n) {
  search_names = (char *) calloc(n, NAME_TOTAL_SIZE);
  search_hits = (u_int8_t *) calloc(n, 1);
  search_n = n;

  for (int i=0; i<search_n; i++)
    strcpy(NAME_NTH(i), random_name());
}

const char * names_get_nth(int i) {
  if (i<0 || i>=search_n)
    return NULL;

  return NAME_NTH(i);
}

int names_mark(const char * name) {
  for (int i=0; i<search_n; i++) {
    if (strcmp(name, NAME_NTH(i)) == 0) {
      search_hits[i] = 1;
      return 1;
    }
  }

  return 0;
}

int names_get_marked() {
  int count = 0;
  
  for (int i=0; i<search_n; i++)
    count += search_hits[i] ? 1 : 0;

  return count;
}

void names_end() {
  if (search_names) { free(search_names); search_names = NULL; }
  if (search_hits) { free(search_hits); search_hits = NULL; }
}
