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

#ifndef __NAME_COUNT_H__
#define __NAME_COUNT_H__

#define NAME_PREFIX_MIN_LENGTH 6
#define NAME_PREFIX_MAX_LENGTH 9
#define NAME_PREFIX_CHARSET "abcdefghijklmnopqrstuvwxyz"
#define NAME_SUFFIX ".com"

void names_generate(int n);
const char * names_get_nth(int i);
int names_mark(const char * name);
int names_get_marked();
void names_end();

#endif
