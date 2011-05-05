/*
 * Copyright (C) 2008-2009 Timothy D. Morgan
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
 *
 * $Id$
 */

/**
 * @file
 */

#include "lru_cache.h"


#define LRU_CACHE_DEBUG 0

/* XXX: really should replace this with a real universal hash or other
 *      fast HMAC.
 */ 
static uint32_t lru_cache_compute_hash(uint32_t num_buckets,
				       uint32_t secret,
				       const void* buf,
				       uint32_t buf_len)
{
  uint32_t i;
  uint32_t ret_val = 0x243f6a88;
  unsigned char* s = (unsigned char*)&secret;
  const unsigned char* b = (unsigned char*)buf;

  for(i=0; i<buf_len; i++)
    ret_val = (ret_val+(i^s[i%4])*b[i]) % num_buckets;
  
  return ret_val;
}

/* Returns approximately floor(log_2(n)) (log base 2 of n, floored) 
 * If n == 0, returns 0
 */
static uint32_t lru_cache_floor_log2(uint32_t n)
{
  uint32_t ret_val;
  
  for(ret_val=31; ret_val > 1; ret_val--)
    if((n & (1 << ret_val)) != 0)
      return ret_val;

  return 0;
}

#if 0
static void lru_cache_print(lru_cache* ht)
{
  uint32_t i;
  lru_cache_element* cur;

  printf("from newest to oldest:\n");
  for(cur=ht->newest; cur != NULL; cur=cur->older)
  {
    /*    write(STDOUT_FILENO, cur->index, cur->index_len);*/
    printf("%p", (void*)cur);
    printf("\n");
    if(cur->older == ht->newest)
    {
      printf("??? Loop in LRU list!!");
      break;
    }
  }
  printf("\n");

  printf("table:\n");
  for(i=0; i<ht->num_buckets; i++)
  {
    printf("%.8X: ", i);
    for(cur=ht->table[i]; cur != NULL; cur=cur->next)
    {
      /*      write(STDOUT_FILENO, cur->index, cur->index_len);*/
      printf("%p", (void*)cur);
      printf("|");

      if(cur->next == ht->table[i])
      {
	printf("??? Loop in table chain!!");
	break;
      }
    }
    printf("\n");
  }
}
#endif


lru_cache* lru_cache_create(uint32_t max_keys, uint32_t secret)
{
  return lru_cache_create_ctx(NULL, max_keys, secret, false);
}


lru_cache* lru_cache_create_ctx(void* talloc_ctx, uint32_t max_keys, 
				uint32_t secret, bool talloc_data)
{
  lru_cache* ret_val;

  ret_val = talloc(talloc_ctx, lru_cache);
  if(ret_val == NULL)
    return NULL;

  if(max_keys == 0)
    ret_val->num_buckets = 1024;
  else if(max_keys == 1)
    ret_val->num_buckets = 1;    
  else
  {
    ret_val->num_buckets = max_keys/lru_cache_floor_log2(max_keys);
    if(ret_val->num_buckets < 1)
      ret_val->num_buckets = 1;
  }
  
  ret_val->table = talloc_array(ret_val, 
				lru_cache_element*, ret_val->num_buckets);
  if(ret_val->table == NULL)
  {
    talloc_free(ret_val);
    return NULL;
  }
  
  ret_val->oldest = NULL;
  ret_val->newest = NULL;
  ret_val->max_keys = max_keys;
  ret_val->secret = secret;
  ret_val->talloc_data = talloc_data;
  ret_val->num_keys = 0;
  memset(ret_val->table, 0, ret_val->num_buckets*sizeof(lru_cache_element*));

  return ret_val;
}


void lru_cache_destroy(lru_cache* ht)
{
  ht->secret = 0;
  talloc_unlink(NULL, ht);
}



bool lru_cache_update(lru_cache* ht, const void* index, 
		      uint32_t index_len, void* data)
{
  uint32_t hash, lru_hash;
  lru_cache_element* cur;
  lru_cache_element* last = NULL;
  lru_cache_element* e = NULL;
  void* tmp_index;

  hash = lru_cache_compute_hash(ht->num_buckets, ht->secret, index, index_len);
  for(cur = ht->table[hash]; cur != NULL && e == NULL; cur=cur->next)
  {
    if((index_len == cur->index_len) 
       && memcmp(cur->index, index, index_len) == 0)
    { e = cur; }
  }
  
  if(e != NULL)
  { /* We found the index, so we're going to overwrite the data.
     * We also need to reposition the element to the newest position,
     * so remove it from the list for now.
     */
    if(ht->talloc_data)
      talloc_unlink(e, e->data);

    if(e->newer == NULL)
      ht->newest = e->older;
    else
      e->newer->older = e->older;

    if(e->older == NULL)
      ht->oldest = e->newer;
    else
      e->older->newer = e->newer;
  }
  else
  { /* We didn't find an identical index. */
    
    if((ht->max_keys != 0) && (ht->num_keys >= ht->max_keys))
    { /* Eliminate the least recently used item, but reuse the element
       * structure to minimize reallocation. 
       */
      e = ht->oldest;
      if(ht->newest == ht->oldest)
      {
	ht->newest = NULL;
	ht->oldest = NULL;
      }
      else
      {
	ht->oldest = e->newer;
	e->newer->older = NULL;
      }
      e->newer = NULL;
      e->older = NULL;

      last = NULL;
      lru_hash = lru_cache_compute_hash(ht->num_buckets, ht->secret, 
					e->index, e->index_len);
      for(cur = ht->table[lru_hash]; cur != e && cur != NULL; 
	  last=cur, cur=cur->next)
      {	continue; }

      if(last == NULL)
	ht->table[lru_hash] = e->next;
      else
	last->next = e->next;
      e->next = NULL;

      if(ht->talloc_data)
	talloc_unlink(e, e->data);

      tmp_index = talloc_realloc_size(e, e->index, index_len);
      if(tmp_index == NULL)
      {
	talloc_free(e);
	return false;
      }
      else
	e->index = tmp_index;
    }
    else
    { /* Brand new element because we have room to spare. */

      e = talloc(ht->table, lru_cache_element);
      if(e == NULL)
	return false;
      
      e->index = talloc_size(e, index_len);
      if(e->index == NULL)
      {
	talloc_free(e);
	return false;
      }
      
      /* New entry, increment counters. */
      ht->num_keys++;
    }
    memcpy(e->index, index, index_len);
    e->index_len = index_len;

    e->next = ht->table[hash];
    ht->table[hash] = e;
  }
  e->data = data;
  if(ht->talloc_data)
    talloc_reference(e, e->data);

  /* Finally, let's insert the element to the newest position in the LRU list.*/
  if(ht->newest != NULL)
    ht->newest->newer = e;
  e->newer = NULL;
  e->older = ht->newest;
  ht->newest = e;
  if(ht->oldest == NULL)
    ht->oldest = e;

  return true;
}


void* lru_cache_find(lru_cache* ht, const void* index,
		     uint32_t index_len)
{
  uint32_t hash;
  lru_cache_element* cur;

  hash = lru_cache_compute_hash(ht->num_buckets, ht->secret, index, index_len);
  for(cur = ht->table[hash]; (cur != NULL); cur = cur->next)
  {
    if((index_len == cur->index_len)
       && memcmp(cur->index, index, index_len) == 0)
    { break; }
  }
  
  if(cur != NULL && cur->newer != NULL)
  { /* Need to move this element up to the newest slot. */

    cur->newer->older = cur->older;

    if(cur->older == NULL)
      ht->oldest = cur->newer;
    else
      cur->older->newer = cur->newer;

    cur->newer = NULL;
    cur->older = ht->newest;
    ht->newest->newer = cur;
    ht->newest = cur;
  }

  if(cur != NULL)
    return cur->data;
  else
    return NULL;
}



bool lru_cache_remove(lru_cache* ht, const void* index, 
		      uint32_t index_len)
{
  uint32_t hash;
  lru_cache_element* cur;
  lru_cache_element* last = NULL;

  hash = lru_cache_compute_hash(ht->num_buckets, ht->secret,
				index, index_len);
  for(cur=ht->table[hash]; (cur != NULL);
      last=cur, cur=cur->next)
  {
    if((index_len == cur->index_len) 
       && memcmp(cur->index, index, index_len) == 0)
    { break; }
  }

  if(cur == NULL)
    return false;

  /* Detach from list */
  if(cur->newer == NULL)
    ht->newest = cur->older;
  else
    cur->newer->older = cur->older;
  
  if(cur->older == NULL)
    ht->oldest = cur->newer;
  else
    cur->older->newer = cur->newer;

  /* Detach from hash table */
  if(last == NULL)
    ht->table[hash] = cur->next;
  else
    last->next = cur->next;

  talloc_free(cur);
  
  /* Removing entry, decrement counters. */
  ht->num_keys--;
  
  return true;
}
