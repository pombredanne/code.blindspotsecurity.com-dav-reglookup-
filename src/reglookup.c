/*
 * $Id$
 *
 * A utility to read a Windows NT/2K etc registry file.
 *
 * This code was taken from Richard Sharpe''s editreg utility, in the 
 * Samba CVS tree.  It has since been simplified and turned into a
 * strictly read-only utility.
 *
 * Copyright (C) 2005 Timothy D. Morgan
 * Copyright (C) 2002 Richard Sharpe, rsharpe@richardsharpe.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  
 */
 
/*************************************************************************

 A note from Richard Sharpe:
  Many of the ideas in here come from other people and software. 
  I first looked in Wine in misc/registry.c and was also influenced by
  http://www.wednesday.demon.co.uk/dosreg.html

  Which seems to contain comments from someone else. I reproduce them here
  incase the site above disappears. It actually comes from 
  http://home.eunet.no/~pnordahl/ntpasswd/WinReg.txt. 
 
 NOTE: the comments he refers to have been moved to doc/winntreg.txt

**************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>

#define False 0
#define True 1
#define REG_KEY_LIST_SIZE 10

/*
 * Structures for dealing with the on-disk format of the registry
 */

#define IVAL(buf) ((unsigned int) \
                   (unsigned int)*((unsigned char *)(buf)+3)<<24| \
                   (unsigned int)*((unsigned char *)(buf)+2)<<16| \
                   (unsigned int)*((unsigned char *)(buf)+1)<<8| \
                   (unsigned int)*((unsigned char *)(buf)+0)) 

#define SVAL(buf) ((unsigned short) \
                   (unsigned short)*((unsigned char *)(buf)+1)<<8| \
                   (unsigned short)*((unsigned char *)(buf)+0)) 

#define CVAL(buf) ((unsigned char)*((unsigned char *)(buf)))

#define SIVAL(buf, val) \
            ((((unsigned char *)(buf))[0])=(unsigned char)((val)&0xFF),\
             (((unsigned char *)(buf))[1])=(unsigned char)(((val)>>8)&0xFF),\
             (((unsigned char *)(buf))[2])=(unsigned char)(((val)>>16)&0xFF),\
             (((unsigned char *)(buf))[3])=(unsigned char)((val)>>24))

#define SSVAL(buf, val) \
  ((((unsigned char *)(buf))[0])=(unsigned char)((val)&0xFF),\
   (((unsigned char *)(buf))[1])=(unsigned char)((val)>>8))

static int verbose = 0;
static int print_security = 0;
static int full_print = 0;
static const char *def_owner_sid_str = NULL;

/* 
 * These definitions are for the in-memory registry structure.
 * It is a tree structure that mimics what you see with tools like regedit
 */

/*
 * DateTime struct for Windows
 */

typedef struct date_time_s {
  unsigned int low, high;
} NTTIME;

/*
 * Definition of a Key. It has a name, classname, date/time last modified,
 * sub-keys, values, and a security descriptor
 */

#define REG_ROOT_KEY 1
#define REG_SUB_KEY  2
#define REG_SYM_LINK 3

typedef struct key_sec_desc_s KEY_SEC_DESC;

typedef struct reg_key_s {
  char *name;         /* Name of the key                    */
  char *class_name;
  int type;           /* One of REG_ROOT_KEY or REG_SUB_KEY */
  NTTIME last_mod; /* Time last modified                 */
  struct reg_key_s *owner;
  struct key_list_s *sub_keys;
  struct val_list_s *values;
  KEY_SEC_DESC *security;
  unsigned int offset;  /* Offset of the record in the file */
} REG_KEY;

/*
 * The KEY_LIST struct lists sub-keys.
 */

typedef struct key_list_s {
  int key_count;
  int max_keys;
  REG_KEY *keys[1];
} KEY_LIST;

typedef struct val_key_s {
  char *name;
  int has_name;
  int data_type;
  int data_len;
  void *data_blk;    /* Might want a separate block */
} VAL_KEY;

typedef struct val_list_s {
  int val_count;
  int max_vals;
  VAL_KEY *vals[1];
} VAL_LIST;

#ifndef MAXSUBAUTHS
#define MAXSUBAUTHS 15
#endif

typedef struct sid_s {
  unsigned char ver, auths;
  unsigned char auth[6];
  unsigned int sub_auths[MAXSUBAUTHS];
} sid_t;

typedef struct ace_struct_s {
  unsigned char type, flags;
  unsigned int perms;   /* Perhaps a better def is in order */
  sid_t *trustee;
} ACE; 

typedef struct acl_struct_s {
  unsigned short rev, refcnt;
  unsigned short num_aces;
  ACE *aces[1];
} ACL;

typedef struct sec_desc_s {
  unsigned int rev, type;
  sid_t *owner, *group;
  ACL *sacl, *dacl;
} SEC_DESC;

#define SEC_DESC_NON 0
#define SEC_DESC_RES 1
#define SEC_DESC_OCU 2
#define SEC_DESC_NBK 3
typedef struct sk_struct SK_HDR;
struct key_sec_desc_s {
  struct key_sec_desc_s *prev, *next;
  int ref_cnt;
  int state;
  int offset;
  SK_HDR *sk_hdr;     /* This means we must keep the registry in memory */
  SEC_DESC *sec_desc;
}; 

/* 
 * All of the structures below actually have a four-byte length before them
 * which always seems to be negative. The following macro retrieves that
 * size as an integer
 */

#define BLK_SIZE(b) ((int)*(int *)(((int *)b)-1))

typedef unsigned int DWORD;
typedef unsigned short WORD;

#define REG_REGF_ID 0x66676572

typedef struct regf_block {
  DWORD REGF_ID;     /* regf */
  DWORD uk1;
  DWORD uk2;
  DWORD tim1, tim2;
  DWORD uk3;             /* 1 */
  DWORD uk4;             /* 3 */
  DWORD uk5;             /* 0 */
  DWORD uk6;             /* 1 */
  DWORD first_key;       /* offset */
  unsigned int dblk_size;
  DWORD uk7[116];        /* 1 */
  DWORD chksum;
} REGF_HDR;

typedef struct hbin_sub_struct {
  DWORD dblocksize;
  char data[1];
} HBIN_SUB_HDR;

#define REG_HBIN_ID 0x6E696268

typedef struct hbin_struct {
  DWORD HBIN_ID; /* hbin */
  DWORD off_from_first;
  DWORD off_to_next;
  DWORD uk1;
  DWORD uk2;
  DWORD uk3;
  DWORD uk4;
  DWORD blk_size;
  HBIN_SUB_HDR hbin_sub_hdr;
} HBIN_HDR;

#define REG_NK_ID 0x6B6E

typedef struct nk_struct {
  WORD NK_ID;
  WORD type;
  DWORD t1, t2;
  DWORD uk1;
  DWORD own_off;
  DWORD subk_num;
  DWORD uk2;
  DWORD lf_off;
  DWORD uk3;
  DWORD val_cnt;
  DWORD val_off;
  DWORD sk_off;
  DWORD clsnam_off;
  DWORD unk4[4];
  DWORD unk5;
  WORD nam_len;
  WORD clsnam_len;
  char key_nam[1];  /* Actual length determined by nam_len */
} NK_HDR;

#define REG_SK_ID 0x6B73

struct sk_struct {
  WORD SK_ID;
  WORD uk1;
  DWORD prev_off;
  DWORD next_off;
  DWORD ref_cnt;
  DWORD rec_size;
  char sec_desc[1];
};

typedef struct ace_struct {
    unsigned char type;
    unsigned char flags;
    unsigned short length;
    unsigned int perms;
    sid_t trustee;
} REG_ACE;

typedef struct acl_struct {
  WORD rev;
  WORD size;
  DWORD num_aces;
  REG_ACE *aces;   /* One or more ACEs */
} REG_ACL;

typedef struct sec_desc_rec {
  WORD rev;
  WORD type;
  DWORD owner_off;
  DWORD group_off;
  DWORD sacl_off;
  DWORD dacl_off;
} REG_SEC_DESC;

typedef struct hash_struct {
  DWORD nk_off;
  char hash[4];
} HASH_REC;

#define REG_LF_ID 0x666C

typedef struct lf_struct {
  WORD LF_ID;
  WORD key_count;
  struct hash_struct hr[1];  /* Array of hash records, depending on key_count */
} LF_HDR;

typedef DWORD VL_TYPE[1];  /* Value list is an array of vk rec offsets */

#define REG_VK_ID 0x6B76

typedef struct vk_struct {
  WORD VK_ID;
  WORD nam_len;
  DWORD dat_len;    /* If top-bit set, offset contains the data */
  DWORD dat_off;   
  DWORD dat_type;
  WORD flag;        /* =1, has name, else no name (=Default). */
  WORD unk1;
  char dat_name[1]; /* Name starts here ... */
} VK_HDR;

#define REG_TYPE_DELETE    -1
#define REG_TYPE_NONE      0
#define REG_TYPE_REGSZ     1
#define REG_TYPE_EXPANDSZ  2
#define REG_TYPE_BIN       3  
#define REG_TYPE_DWORD     4
#define REG_TYPE_MULTISZ   7
/* Not a real type in the registry */
#define REG_TYPE_KEY       255

typedef struct _val_str { 
  unsigned int val;
  const char * str;
} VAL_STR;

/* A map of sk offsets in the regf to KEY_SEC_DESCs for quick lookup etc */
typedef struct sk_map_s {
  int sk_off;
  KEY_SEC_DESC *key_sec_desc;
} SK_MAP;

/*
 * This structure keeps track of the output format of the registry
 */
#define REG_OUTBLK_HDR 1
#define REG_OUTBLK_HBIN 2

typedef struct hbin_blk_s {
  int type, size;
  struct hbin_blk_s *next;
  char *data;                /* The data block                */
  unsigned int file_offset;  /* Offset in file                */
  unsigned int free_space;   /* Amount of free space in block */
  unsigned int fsp_off;      /* Start of free space in block  */
  int complete, stored;
} HBIN_BLK;

/*
 * This structure keeps all the registry stuff in one place
 */
typedef struct regf_struct_s {
  int reg_type;
  char *regfile_name, *outfile_name;
  int fd;
  struct stat sbuf;
  char *base;
  int modified;
  NTTIME last_mod_time;
  REG_KEY *root;  /* Root of the tree for this file */
  int sk_count, sk_map_size;
  SK_MAP *sk_map;
  const char *owner_sid_str;
  SEC_DESC *def_sec_desc;
  /*
   * These next pointers point to the blocks used to contain the 
   * keys when we are preparing to write them to a file
   */
  HBIN_BLK *blk_head, *blk_tail, *free_space;
} REGF;


/* Function prototypes */

static int nt_val_list_iterator(REGF *regf,  REG_KEY *key_tree, int bf, 
                                char *path, int terminal);
static int nt_key_iterator(REGF *regf, REG_KEY *key_tree, int bf,
			   const char *path);
static REG_KEY *nt_find_key_by_name(REG_KEY *tree, char *key);
static int print_key(const char *path, char *name, char *class_name, int root,
                     int terminal, int vals, char* newline);
static int print_val(const char *path, char *val_name, int val_type, 
                     int data_len, void *data_blk, int terminal, int first, 
                     int last);

static int print_sec(SEC_DESC *sec_desc);


/* Globals */

char* prefix_filter = "";
int type_filter = 0;
bool type_filter_enabled = false;


unsigned int str_is_prefix(const char* p, const char* s)
{
  const char* cp;
  const char* cs;
  
  cs = s;
  for(cp=p; (*cp) != '\0'; cp++)
  {
    if((*cp)!=(*cs))
      return 0;
    cs++;
  }

  return 1;
}


/* Returns a newly malloc()ed string which contains original buffer,
 * except for non-printable or special characters are quoted in hex
 * with the syntax '\xQQ' where QQ is the hex ascii value of the quoted
 * character.  A null terminator is added, as only ascii, not binary, 
 * is returned.
 */
static
char* quote_buffer(const unsigned char* str, char* special, unsigned int len)
{
  unsigned int i;
  unsigned int num_written=0;
  unsigned int out_len = sizeof(char)*len+1;
  char* ret_val = malloc(out_len);

  if(ret_val == NULL)
    return NULL;

  for(i=0; i<len; i++)
  {
    if(str[i] < 32 || str[i] > 126 || strchr(special, str[i]) != NULL)
    {
      out_len += 3;
      /* XXX: may not be the most efficient way of getting enough memory. */
      ret_val = realloc(ret_val, out_len);
      if(ret_val == NULL)
	break;
      num_written += snprintf(ret_val+num_written, (out_len)-num_written,
			      "\\x%.2X", str[i]);
    }
    else
      ret_val[num_written++] = str[i];
  }
  ret_val[num_written] = '\0';

  return ret_val;
}


/* Returns a newly malloc()ed string which contains original string, 
 * except for non-printable or special characters are quoted in hex
 * with the syntax '\xQQ' where QQ is the hex ascii value of the quoted
 * character.
 */
static
char* quote_string(const char* str, char* special)
{
  unsigned int len = strlen(str);
  char* ret_val = quote_buffer((const unsigned char*)str, special, len);

  return ret_val;
}



/*
 * Iterate over the keys, depth first, calling a function for each key
 * and indicating if it is terminal or non-terminal and if it has values.
 *
 * In addition, for each value in the list, call a value list function
 */

static
int nt_val_list_iterator(REGF *regf,  REG_KEY *key_tree, int bf, char *path,
			 int terminal)
{
  int i;
  VAL_LIST* val_list = key_tree->values;

  for (i=0; i<val_list->val_count; i++) 
  {
    /*XXX: print_key() is doing nothing right now, can probably be removed. */
    if (!print_key(path, key_tree->name,
		   key_tree->class_name,
		   (key_tree->type == REG_ROOT_KEY),
		   (key_tree->sub_keys == NULL),
		   (key_tree->values?(key_tree->values->val_count):0),
		   "\n") ||
	!print_val(path, val_list->vals[i]->name,val_list->vals[i]->data_type,
		   val_list->vals[i]->data_len, val_list->vals[i]->data_blk,
		   terminal,
		   (i == 0),
		   (i == val_list->val_count)))
    { return 0; }
  }

  return 1;
}

static
int nt_key_list_iterator(REGF *regf, KEY_LIST *key_list, int bf, 
			 const char *path)
{
  int i;

  if (!key_list) 
    return 1;

  for (i=0; i < key_list->key_count; i++) 
  {
    if (!nt_key_iterator(regf, key_list->keys[i], bf, path)) 
      return 0;
  }
  return 1;
}

static
int nt_key_iterator(REGF *regf, REG_KEY *key_tree, int bf, 
		    const char *path)
{
  int path_len = strlen(path);
  char *new_path;

  if (!regf || !key_tree)
    return -1;

  new_path = (char *)malloc(path_len + 1 + strlen(key_tree->name) + 1);
  if (!new_path) 
    return 0; /* Errors? */
  new_path[0] = '\0';
  strcat(new_path, path);
  strcat(new_path, key_tree->name);
  strcat(new_path, "/");

  /* List the key first, then the values, then the sub-keys */
  /*printf("prefix_filter: %s, path: %s\n", prefix_filter, path);*/
  if (str_is_prefix(prefix_filter, new_path))
  {
    if (!type_filter_enabled || (type_filter == REG_TYPE_KEY))
      printf("%s%s:KEY\n", path, key_tree->name);

    /*XXX: print_key() is doing nothing right now, can probably be removed. */
    if (!print_key(path, key_tree->name,
		   key_tree->class_name,
		   (key_tree->type == REG_ROOT_KEY),
		   (key_tree->sub_keys == NULL),
		   (key_tree->values?(key_tree->values->val_count):0),
		   "\n"))
    { return 0; }

    /*
     * If we have a security print routine, call it
     * If the security print routine returns false, stop.
     */
    if (key_tree->security && !print_sec(key_tree->security->sec_desc))
      return 0;
  }

  /*
   * Now, iterate through the values in the val_list 
   */
  if (key_tree->values &&
      !nt_val_list_iterator(regf, key_tree, bf, new_path, 
			    (key_tree->values!=NULL)))
  {
    free(new_path);
    return 0;
  }

  /* 
   * Now, iterate through the keys in the key list
   */
  if (key_tree->sub_keys && 
      !nt_key_list_iterator(regf, key_tree->sub_keys, bf, 
                            new_path)) 
  {
    free(new_path);
    return 0;
  } 

  free(new_path);
  return 1;
}


/*
 * Find key by name in a list ...
 * Take the first component and search for that in the list
 */
static
REG_KEY *nt_find_key_in_list_by_name(KEY_LIST *list, char *key)
{
  int i;
  REG_KEY *res = NULL;

  if (!list || !key || !*key) return NULL;

  for (i = 0; i < list->key_count; i++)
    if ((res = nt_find_key_by_name(list->keys[i], key)))
      return res;
  
  return NULL;
}


/* 
 * Find key by name in a tree ... We will assume absolute names here, but we
 * need the root of the tree ...
 */
static REG_KEY* nt_find_key_by_name(REG_KEY* tree, char* key)
{
  char* lname = NULL;
  char* c1;
  char* c2;
  REG_KEY* tmp;

  if (!tree || !key || !*key) 
    return NULL;

  lname = strdup(key);
  if (!lname) 
    return NULL;

  /*
   * Make sure that the first component is correct ...
   */
  c1 = lname;
  c2 = strchr(c1, '/');
  if (c2) 
  { /* Split here ... */
    *c2 = 0;
    c2++;
  }
  
  if (strcmp(c1, tree->name) != 0) 
  {  
    if (lname)
      free(lname);
    return NULL;
  }
  
  if (c2) 
  {
    tmp = nt_find_key_in_list_by_name(tree->sub_keys, c2);
    free(lname);
    return tmp;
  }
  else 
  {
    if (lname) 
      free(lname);
    return tree;
  }

  return NULL;
}

/* Make, delete keys */
static
int nt_delete_val_key(VAL_KEY *val_key)
{

  if (val_key) {
    if (val_key->name) free(val_key->name);
    if (val_key->data_blk) free(val_key->data_blk);
    free(val_key);
  };
  return 1;
}


/* 
 * Add a key to the tree ... We walk down the components matching until
 * we don't find any. There must be a match on the first component ...
 * We return the key structure for the final component as that is 
 * often where we want to add values ...
 */

/*
 * Convert a string of the form S-1-5-x[-y-z-r] to a SID
 */
/* MIGHT COME IN HANDY LATER.
static
int sid_string_to_sid(sid_t **sid, const char *sid_str)
{
  int i = 0;
  unsigned int auth;
  const char *lstr;

  *sid = (sid_t *)malloc(sizeof(sid_t));
  if (!*sid) return 0;

  memset(*sid, 0, sizeof(sid_t));

  if (strncmp(sid_str, "S-1-5", 5)) {
    fprintf(stderr, "Does not conform to S-1-5...: %s\n", sid_str);
    return 0;
  }

//We only allow strings of form S-1-5...

  (*sid)->ver = 1;
  (*sid)->auth[5] = 5;

  lstr = sid_str + 5;

  while (1) 
  {
    if (!lstr || !lstr[0] || sscanf(lstr, "-%u", &auth) == 0) 
    {
      if (i < 1) 
      {
	fprintf(stderr, "Not of form -d-d...: %s, %u\n", lstr, i);
	return 0;
      }
      (*sid)->auths=i;
      return 1;
    }

    (*sid)->sub_auths[i] = auth;
    i++;
    lstr = strchr(lstr + 1, '-'); 
  }

  return 1;
}
*/


/*
 * We will implement inheritence that is based on what the parent's SEC_DESC
 * says, but the Owner and Group SIDs can be overwridden from the command line
 * and additional ACEs can be applied from the command line etc.
 */
static
KEY_SEC_DESC *nt_inherit_security(REG_KEY *key)
{

  if (!key) return NULL;
  return key->security;
}

/*
 * Add a sub-key 
 */
static
REG_KEY *nt_add_reg_key_list(REGF *regf, REG_KEY *key, char * name, int create)
{
  int i;
  REG_KEY *ret = NULL, *tmp = NULL;
  KEY_LIST *list;
  char *lname, *c1, *c2;

  if (!key || !name || !*name) return NULL;
  
  list = key->sub_keys;
  if (!list) { /* Create an empty list */

    list = (KEY_LIST *)malloc(sizeof(KEY_LIST) + (REG_KEY_LIST_SIZE - 1) * sizeof(REG_KEY *));
    list->key_count = 0;
    list->max_keys = REG_KEY_LIST_SIZE;

  }

  lname = strdup(name);
  if (!lname) return NULL;

  c1 = lname;
  c2 = strchr(c1, '/');
  if (c2) { /* Split here ... */
    *c2 = 0;
    c2++;
  }

  for (i = 0; i < list->key_count; i++) {
    if (strcmp(list->keys[i]->name, c1) == 0) {
      ret = nt_add_reg_key_list(regf, list->keys[i], c2, create);
      free(lname);
      return ret;
    }
  }

  /*
   * If we reach here we could not find the the first component
   * so create it ...
   */

  if (list->key_count < list->max_keys){
    list->key_count++;
  }
  else { /* Create more space in the list ... */
    if (!(list = (KEY_LIST *)realloc(list, sizeof(KEY_LIST) + 
				     (list->max_keys + REG_KEY_LIST_SIZE - 1) 
				     * sizeof(REG_KEY *))))
      goto error;

    list->max_keys += REG_KEY_LIST_SIZE;
    list->key_count++;
  }

  /*
   * add the new key at the new slot 
   * XXX: Sort the list someday
   */

  /*
   * We want to create the key, and then do the rest
   */

  tmp = (REG_KEY *)malloc(sizeof(REG_KEY)); 

  memset(tmp, 0, sizeof(REG_KEY));

  tmp->name = strdup(c1);
  if (!tmp->name) goto error;
  tmp->owner = key;
  tmp->type = REG_SUB_KEY;
  /*
   * Next, pull security from the parent, but override with
   * anything passed in on the command line
   */
  tmp->security = nt_inherit_security(key);

  list->keys[list->key_count - 1] = tmp;

  if (c2) {
    ret = nt_add_reg_key_list(regf, key, c2, True);
  }

  if (lname) free(lname);

  return ret;

 error:
  if (tmp) free(tmp);
  if (lname) free(lname);
  return NULL;
}


/*
 * Load and unload a registry file.
 *
 * Load, loads it into memory as a tree, while unload sealizes/flattens it
 */

/*
 * Get the starting record for NT Registry file 
 */

/* 
 * Where we keep all the regf stuff for one registry.
 * This is the structure that we use to tie the in memory tree etc 
 * together. By keeping separate structs, we can operate on different
 * registries at the same time.
 * Currently, the SK_MAP is an array of mapping structure.
 * Since we only need this on input and output, we fill in the structure
 * as we go on input. On output, we know how many SK items we have, so
 * we can allocate the structure as we need to.
 * If you add stuff here that is dynamically allocated, add the 
 * appropriate free statements below.
 */

#define REGF_REGTYPE_NONE 0
#define REGF_REGTYPE_NT   1
#define REGF_REGTYPE_W9X  2

#define TTTONTTIME(r, t1, t2) (r)->last_mod_time.low = (t1); \
                              (r)->last_mod_time.high = (t2);

#define REGF_HDR_BLKSIZ 0x1000 

#define OFF(f) ((f) + REGF_HDR_BLKSIZ + 4) 
#define LOCN(base, f) ((base) + OFF(f))

const VAL_STR reg_type_names[] = {
   { REG_TYPE_REGSZ,    "SZ" },
   { REG_TYPE_EXPANDSZ, "EXPAND_SZ" },
   { REG_TYPE_BIN,      "BIN" },
   { REG_TYPE_DWORD,    "DWORD" },
   { REG_TYPE_MULTISZ,  "MULTI_SZ" },
   { REG_TYPE_KEY,      "KEY" },
   { 0, NULL },
};


static
const char *val_to_str(unsigned int val, const VAL_STR *val_array)
{
  int i;

  if (!val_array) 
    return NULL;

  for(i=0; val_array[i].val && val_array[i].str; i++) 
    if (val_array[i].val == val) 
      return val_array[i].str;

  return NULL;
}


/* Returns 0 on error */
static
int str_to_val(const char* str, const VAL_STR *val_array)
{
  int i;

  if (!val_array) 
    return 0;

  for(i=0; val_array[i].val && val_array[i].str; i++) 
    if (strcmp(val_array[i].str, str) == 0) 
      return val_array[i].val;

  return 0;
}


/*
 * Convert from UniCode to Ascii ... Does not take into account other lang
 * Restrict by ascii_max if > 0
 */
static
int uni_to_ascii(unsigned char *uni, unsigned char *ascii, int ascii_max, 
		 int uni_max)
{
  int i = 0; 

  while (i < ascii_max && (uni[i*2] || uni[i*2+1]))
  {
    if (uni_max > 0 && (i*2) >= uni_max) break;
    ascii[i] = uni[i*2];
    i++;
  }
  ascii[i] = '\0';

  return i;
}

/*
 * Convert a data value to a string for display
 */
static
unsigned char* data_to_ascii(unsigned char *datap, int len, int type)
{
  unsigned char *asciip;
  unsigned int i;
  unsigned short num_nulls;
  unsigned char* ascii;
  unsigned char* cur_str;
  unsigned char* cur_ascii;
  char* cur_quoted;
  unsigned int cur_str_len;
  unsigned int ascii_max, cur_str_max;
  unsigned int str_rem, cur_str_rem, alen;

  switch (type) 
  {
  case REG_TYPE_REGSZ:
    if (verbose)
      fprintf(stderr, "Len: %d\n", len);
    
    ascii_max = sizeof(char)*len;
    ascii = malloc(ascii_max+4);
    if(ascii == NULL)
      return NULL;
    
    /* XXX: This has to be fixed. It has to be UNICODE */
    uni_to_ascii(datap, ascii, len, ascii_max);
    return ascii;
    break;

  case REG_TYPE_EXPANDSZ:
    ascii_max = sizeof(char)*len;
    ascii = malloc(ascii_max+2);
    if(ascii == NULL)
      return NULL;

    uni_to_ascii(datap, ascii, len, ascii_max);
    return ascii;
    break;

  case REG_TYPE_BIN:
    ascii = (unsigned char*)quote_buffer(datap, "\\", len);
    return ascii;
    break;

  case REG_TYPE_DWORD:
    ascii_max = sizeof(char)*10;
    ascii = malloc(ascii_max+1);
    if(ascii == NULL)
      return NULL;

    if (*(int *)datap == 0)
      snprintf((char*)ascii, ascii_max, "0");
    else
      snprintf((char*)ascii, ascii_max, "0x%x", *(int *)datap);
    return ascii;
    break;

  case REG_TYPE_MULTISZ:
    ascii_max = sizeof(char)*len*4;
    cur_str_max = sizeof(char)*len+1;
    cur_str = malloc(cur_str_max);
    cur_ascii = malloc(cur_str_max);
    ascii = malloc(ascii_max+4);
    if(ascii == NULL)
      return NULL;

    /* Reads until it reaches 4 consecutive NULLs, 
     * which is two nulls in unicode, or until it reaches len, or until we
     * run out of buffer.  The latter should never happen, but we shouldn't
     * trust our file to have the right lengths/delimiters.
     */
    asciip = ascii;
    num_nulls = 0;
    str_rem = ascii_max;
    cur_str_rem = cur_str_max;
    cur_str_len = 0;

    for(i=0; (i < len) && str_rem > 0; i++)
    {
      *(cur_str+cur_str_len) = *(datap+i);
      if(*(cur_str+cur_str_len) == 0)
	num_nulls++;
      else
	num_nulls = 0;
      cur_str_len++;

      if(num_nulls == 2)
      {
	uni_to_ascii(cur_str, cur_ascii, cur_str_max, 0);
	/* XXX: Should backslashes be quoted as well? */
	cur_quoted = quote_string((char*)cur_ascii, "|");
	alen = snprintf((char*)asciip, str_rem, "%s", cur_quoted);
	asciip += alen;
	str_rem -= alen;
	free(cur_quoted);

	if(*(datap+i+1) == 0 && *(datap+i+2) == 0)
	  break;
	else
	{
	  alen = snprintf((char*)asciip, str_rem, "%c", '|');
	  asciip += alen;
	  str_rem -= alen;
	  memset(cur_str, 0, cur_str_max);
	  cur_str_len = 0;
	  num_nulls = 0;
	  /* To eliminate leading nulls in subsequent strings. */
	  i++;
	}
      }
    }
    *asciip = 0;
    return ascii;
    break;

  default:
    return NULL;
    break;
  } 

  return NULL;
}

static
REG_KEY *nt_get_key_tree(REGF *regf, NK_HDR *nk_hdr, int size, REG_KEY *parent);

static
int nt_set_regf_input_file(REGF *regf, char *filename)
{
  return ((regf->regfile_name = strdup(filename)) != NULL); 
}


/* Create a regf structure and init it */

static
REGF *nt_create_regf(void)
{
  REGF *tmp = (REGF *)malloc(sizeof(REGF));
  if (!tmp) return tmp;
  memset(tmp, 0, sizeof(REGF));
  tmp->owner_sid_str = def_owner_sid_str;
  return tmp;
} 


/* Get the header of the registry. Return a pointer to the structure 
 * If the mmap'd area has not been allocated, then mmap the input file
 */
static
REGF_HDR *nt_get_regf_hdr(REGF *regf)
{
  if (!regf)
    return NULL; /* What about errors */

  if (!regf->regfile_name)
    return NULL; /* What about errors */

  if (!regf->base) { /* Try to mmap etc the file */

    if ((regf->fd = open(regf->regfile_name, O_RDONLY, 0000)) <0) {
      return NULL; /* What about errors? */
    }

    if (fstat(regf->fd, &regf->sbuf) < 0) {
      return NULL;
    }

    regf->base = mmap(0, regf->sbuf.st_size, PROT_READ, MAP_SHARED, regf->fd, 0);

    if ((int)regf->base == 1) {
      fprintf(stderr, "Could not mmap file: %s, %s\n", regf->regfile_name,
	      strerror(errno));
      return NULL;
    }
  }

  /* 
   * At this point, regf->base != NULL, and we should be able to read the 
   * header 
   */

  assert(regf->base != NULL);

  return (REGF_HDR *)regf->base;
}

/*
 * Validate a regf header
 * For now, do nothing, but we should check the checksum
 */
static
int valid_regf_hdr(REGF_HDR *regf_hdr)
{
  if (!regf_hdr) return 0;

  return 1;
}

/*
 * Process an SK header ...
 * Every time we see a new one, add it to the map. Otherwise, just look it up.
 * We will do a simple linear search for the moment, since many KEYs have the 
 * same security descriptor. 
 * We allocate the map in increments of 10 entries.
 */

/*
 * Create a new entry in the map, and increase the size of the map if needed
 */
static
SK_MAP *alloc_sk_map_entry(REGF *regf, KEY_SEC_DESC *tmp, int sk_off)
{
 if (!regf->sk_map) { /* Allocate a block of 10 */
    regf->sk_map = (SK_MAP *)malloc(sizeof(SK_MAP) * 10);
    if (!regf->sk_map) {
      free(tmp);
      return NULL;
    }
    regf->sk_map_size = 10;
    regf->sk_count = 1;
    (regf->sk_map)[0].sk_off = sk_off;
    (regf->sk_map)[0].key_sec_desc = tmp;
  }
  else { /* Simply allocate a new slot, unless we have to expand the list */ 
    int ndx = regf->sk_count;
    if (regf->sk_count >= regf->sk_map_size) {
      regf->sk_map = (SK_MAP *)realloc(regf->sk_map, 
				       (regf->sk_map_size + 10)*sizeof(SK_MAP));
      if (!regf->sk_map) {
	free(tmp);
	return NULL;
      }
      /*
       * ndx already points at the first entry of the new block
       */
      regf->sk_map_size += 10;
    }
    (regf->sk_map)[ndx].sk_off = sk_off;
    (regf->sk_map)[ndx].key_sec_desc = tmp;
    regf->sk_count++;
  }
 return regf->sk_map;
}

/*
 * Search for a KEY_SEC_DESC in the sk_map, but don't create one if not
 * found
 */
static
KEY_SEC_DESC *lookup_sec_key(SK_MAP *sk_map, int count, int sk_off)
{
  int i;

  if (!sk_map) return NULL;

  for (i = 0; i < count; i++) {

    if (sk_map[i].sk_off == sk_off)
      return sk_map[i].key_sec_desc;

  }

  return NULL;

}

/*
 * Allocate a KEY_SEC_DESC if we can't find one in the map
 */
static
KEY_SEC_DESC *lookup_create_sec_key(REGF *regf, SK_MAP *sk_map, int sk_off)
{
  KEY_SEC_DESC *tmp = lookup_sec_key(regf->sk_map, regf->sk_count, sk_off);

  if (tmp) {
    return tmp;
  }
  else { /* Allocate a new one */
    tmp = (KEY_SEC_DESC *)malloc(sizeof(KEY_SEC_DESC));
    if (!tmp) {
      return NULL;
    }
    memset(tmp, 0, sizeof(KEY_SEC_DESC)); /* Neatly sets offset to 0 */
    tmp->state = SEC_DESC_RES;
    if (!alloc_sk_map_entry(regf, tmp, sk_off)) {
      return NULL;
    }
    return tmp;
  }
}

/*
 * Allocate storage and duplicate a SID 
 * We could allocate the SID to be only the size needed, but I am too lazy. 
 */
static
sid_t *dup_sid(sid_t *sid)
{
  sid_t *tmp = (sid_t *)malloc(sizeof(sid_t));
  int i;
  
  if (!tmp) return NULL;
  tmp->ver = sid->ver;
  tmp->auths = sid->auths;
  for (i=0; i<6; i++) {
    tmp->auth[i] = sid->auth[i];
  }
  for (i=0; i<tmp->auths&&i<MAXSUBAUTHS; i++) {
    tmp->sub_auths[i] = sid->sub_auths[i];
  }
  return tmp;
}

/*
 * Allocate space for an ACE and duplicate the registry encoded one passed in
 */
static
ACE *dup_ace(REG_ACE *ace)
{
  ACE *tmp = NULL; 

  tmp = (ACE *)malloc(sizeof(ACE));

  if (!tmp) 
    return NULL;

  tmp->type = CVAL(&ace->type);
  tmp->flags = CVAL(&ace->flags);
  tmp->perms = IVAL(&ace->perms);
  tmp->trustee = dup_sid(&ace->trustee);
  return tmp;
}

/*
 * Allocate space for an ACL and duplicate the registry encoded one passed in 
 */
static
ACL *dup_acl(REG_ACL *acl)
{
  ACL *tmp = NULL;
  REG_ACE* ace;
  int i, num_aces;

  num_aces = IVAL(&acl->num_aces);

  tmp = (ACL *)malloc(sizeof(ACL) + (num_aces - 1)*sizeof(ACE *));
  if (!tmp) return NULL;

  tmp->num_aces = num_aces;
  tmp->refcnt = 1;
  tmp->rev = SVAL(&acl->rev);
  if (verbose) fprintf(stdout, "ACL: refcnt: %u, rev: %u\n", tmp->refcnt, 
		       tmp->rev);
  ace = (REG_ACE *)&acl->aces;
  for (i=0; i<num_aces; i++) {
    tmp->aces[i] = dup_ace(ace);
    ace = (REG_ACE *)((char *)ace + SVAL(&ace->length));
    /* XXX: should handle NULLs returned from dup_ace() */
  }

  return tmp;
}

static
SEC_DESC *process_sec_desc(REGF *regf, REG_SEC_DESC *sec_desc)
{
  SEC_DESC *tmp = NULL;
  
  tmp = (SEC_DESC *)malloc(sizeof(SEC_DESC));

  if (!tmp) {
    return NULL;
  }
  
  tmp->rev = SVAL(&sec_desc->rev);
  tmp->type = SVAL(&sec_desc->type);
  if (verbose) fprintf(stdout, "SEC_DESC Rev: %0X, Type: %0X\n", 
		       tmp->rev, tmp->type);
  if (verbose) fprintf(stdout, "SEC_DESC Owner Off: %0X\n",
		       IVAL(&sec_desc->owner_off));
  if (verbose) fprintf(stdout, "SEC_DESC Group Off: %0X\n",
		       IVAL(&sec_desc->group_off));
  if (verbose) fprintf(stdout, "SEC_DESC DACL Off: %0X\n",
		       IVAL(&sec_desc->dacl_off));
  tmp->owner = dup_sid((sid_t *)((char *)sec_desc + IVAL(&sec_desc->owner_off)));
  if (!tmp->owner) {
    free(tmp);
    return NULL;
  }
  tmp->group = dup_sid((sid_t *)((char *)sec_desc + IVAL(&sec_desc->group_off)));
  if (!tmp->group) {
    free(tmp);
    return NULL;
  }

  /* Now pick up the SACL and DACL */

  if (sec_desc->sacl_off)
    tmp->sacl = dup_acl((REG_ACL *)((char *)sec_desc + IVAL(&sec_desc->sacl_off)));
  else
    tmp->sacl = NULL;

  if (sec_desc->dacl_off)
    tmp->dacl = dup_acl((REG_ACL *)((char *)sec_desc + IVAL(&sec_desc->dacl_off)));
  else
    tmp->dacl = NULL;

  return tmp;
}

static
KEY_SEC_DESC *process_sk(REGF *regf, SK_HDR *sk_hdr, int sk_off, int size)
{
  KEY_SEC_DESC *tmp = NULL;
  int sk_next_off, sk_prev_off, sk_size;
  REG_SEC_DESC *sec_desc;

  if (!sk_hdr) return NULL;

  if (SVAL(&sk_hdr->SK_ID) != REG_SK_ID) {
    fprintf(stderr, "Unrecognized SK Header ID: %08X, %s\n", (int)sk_hdr,
	    regf->regfile_name);
    return NULL;
  }

  if (-size < (sk_size = IVAL(&sk_hdr->rec_size))) {
    fprintf(stderr, "Incorrect SK record size: %d vs %d. %s\n",
	    -size, sk_size, regf->regfile_name);
    return NULL;
  }

  /* 
   * Now, we need to look up the SK Record in the map, and return it
   * Since the map contains the SK_OFF mapped to KEY_SEC_DESC, we can
   * use that
   */

  if (regf->sk_map &&
      ((tmp = lookup_sec_key(regf->sk_map, regf->sk_count, sk_off)) != NULL)
      && (tmp->state == SEC_DESC_OCU)) {
    tmp->ref_cnt++;
    return tmp;
  }

  /* Here, we have an item in the map that has been reserved, or tmp==NULL. */

  assert(tmp == NULL || (tmp && tmp->state != SEC_DESC_NON));

  /*
   * Now, allocate a KEY_SEC_DESC, and parse the structure here, and add the
   * new KEY_SEC_DESC to the mapping structure, since the offset supplied is 
   * the actual offset of structure. The same offset will be used by
   * all future references to this structure
   * We could put all this unpleasantness in a function.
   */

  if (!tmp) {
    tmp = (KEY_SEC_DESC *)malloc(sizeof(KEY_SEC_DESC));
    if (!tmp) return NULL;
    memset(tmp, 0, sizeof(KEY_SEC_DESC));
    
    /*
     * Allocate an entry in the SK_MAP ...
     * We don't need to free tmp, because that is done for us if the
     * sm_map entry can't be expanded when we need more space in the map.
     */
    
    if (!alloc_sk_map_entry(regf, tmp, sk_off)) {
      return NULL;
    }
  }

  tmp->ref_cnt++;
  tmp->state = SEC_DESC_OCU;

  /*
   * Now, process the actual sec desc and plug the values in
   */

  sec_desc = (REG_SEC_DESC *)&sk_hdr->sec_desc[0];
  tmp->sec_desc = process_sec_desc(regf, sec_desc);

  /*
   * Now forward and back links. Here we allocate an entry in the sk_map
   * if it does not exist, and mark it reserved
   */

  sk_prev_off = IVAL(&sk_hdr->prev_off);
  tmp->prev = lookup_create_sec_key(regf, regf->sk_map, sk_prev_off);
  assert(tmp->prev != NULL);
  sk_next_off = IVAL(&sk_hdr->next_off);
  tmp->next = lookup_create_sec_key(regf, regf->sk_map, sk_next_off);
  assert(tmp->next != NULL);

  return tmp;
}

/*
 * Process a VK header and return a value
 */
static
VAL_KEY *process_vk(REGF *regf, VK_HDR *vk_hdr, int size)
{
  char val_name[1024];
  int nam_len, dat_len, flag, dat_type, dat_off, vk_id;
  const char *val_type;
  VAL_KEY *tmp = NULL; 

  if (!vk_hdr) return NULL;

  if ((vk_id = SVAL(&vk_hdr->VK_ID)) != REG_VK_ID) {
    fprintf(stderr, "Unrecognized VK header ID: %0X, block: %0X, %s\n",
	    vk_id, (int)vk_hdr, regf->regfile_name);
    return NULL;
  }

  nam_len = SVAL(&vk_hdr->nam_len);
  val_name[nam_len] = '\0';
  flag = SVAL(&vk_hdr->flag);
  dat_type = IVAL(&vk_hdr->dat_type);
  dat_len = IVAL(&vk_hdr->dat_len);  /* If top bit, offset contains data */
  dat_off = IVAL(&vk_hdr->dat_off);

  tmp = (VAL_KEY *)malloc(sizeof(VAL_KEY));
  if (!tmp) {
    goto error;
  }
  memset(tmp, 0, sizeof(VAL_KEY));
  tmp->has_name = flag;
  tmp->data_type = dat_type;

  if (flag & 0x01) {
    strncpy(val_name, vk_hdr->dat_name, nam_len);
    tmp->name = strdup(val_name);
    if (!tmp->name) {
      goto error;
    }
  }
  else
    strncpy(val_name, "<No Name>", 10);

  /*
   * Allocate space and copy the data as a BLOB
   */

  if (dat_len) {
    
    char *dtmp = (char *)malloc(dat_len&0x7FFFFFFF);
    
    if (!dtmp) {
      goto error;
    }

    tmp->data_blk = dtmp;

    if ((dat_len&0x80000000) == 0) 
    { /* The data is pointed to by the offset */
      char *dat_ptr = LOCN(regf->base, dat_off);
      memcpy(dtmp, dat_ptr, dat_len);
    }
    else { /* The data is in the offset or type */
      /*
       * XXX:
       * Some registry files seem to have wierd fields. If top bit is set,
       * but len is 0, the type seems to be the value ...
       * Not sure how to handle this last type for the moment ...
       */
      dat_len = dat_len & 0x7FFFFFFF;
      memcpy(dtmp, &dat_off, dat_len);
    }

    tmp->data_len = dat_len;
  }

  val_type = val_to_str(dat_type, reg_type_names);

  /*
   * We need to save the data area as well
   */
  if (verbose) 
    fprintf(stdout, "  %s : %s : \n", val_name, val_type);

  return tmp;

 error:
  if (tmp) nt_delete_val_key(tmp);
  return NULL;

}

/*
 * Process a VL Header and return a list of values
 */
static
VAL_LIST *process_vl(REGF *regf, VL_TYPE vl, int count, int size)
{
  int i, vk_off;
  VK_HDR *vk_hdr;
  VAL_LIST *tmp = NULL;

  if (!vl) return NULL;

  if (-size < (count+1)*sizeof(int)){
    fprintf(stderr, "Error in VL header format. Size less than space required. %d\n", -size);
    return NULL;
  }

  tmp = (VAL_LIST *)malloc(sizeof(VAL_LIST) + (count - 1) * sizeof(VAL_KEY *));
  if (!tmp) {
    goto error;
  }

  for (i=0; i<count; i++) {
    vk_off = IVAL(&vl[i]);
    vk_hdr = (VK_HDR *)LOCN(regf->base, vk_off);
    tmp->vals[i] = process_vk(regf, vk_hdr, BLK_SIZE(vk_hdr));
    if (!tmp->vals[i]){
      goto error;
    }
  }

  tmp->val_count = count;
  tmp->max_vals = count;

  return tmp;

 error:
  /* XXX: free the partially allocated structure */
  return NULL;
} 

/*
 * Process an LF Header and return a list of sub-keys
 */
static
KEY_LIST *process_lf(REGF *regf, LF_HDR *lf_hdr, int size, REG_KEY *parent)
{
  int count, i, nk_off;
  unsigned int lf_id;
  KEY_LIST *tmp;

  if (!lf_hdr) return NULL;

  if ((lf_id = SVAL(&lf_hdr->LF_ID)) != REG_LF_ID) {
    fprintf(stderr, "Unrecognized LF Header format: %0X, Block: %0X, %s.\n",
	    lf_id, (int)lf_hdr, regf->regfile_name);
    return NULL;
  }

  assert(size < 0);

  count = SVAL(&lf_hdr->key_count);
  if (verbose) 
    fprintf(stdout, "Key Count: %u\n", count);
  if (count <= 0) return NULL;

  /* Now, we should allocate a KEY_LIST struct and fill it in ... */

  tmp = (KEY_LIST *)malloc(sizeof(KEY_LIST) + (count - 1) * sizeof(REG_KEY *));
  if (!tmp) {
    goto error;
  }

  tmp->key_count = count;
  tmp->max_keys = count;

  for (i=0; i<count; i++) {
    NK_HDR *nk_hdr;

    nk_off = IVAL(&lf_hdr->hr[i].nk_off);
    if (verbose) 
      fprintf(stdout, "NK Offset: %0X\n", nk_off);
    nk_hdr = (NK_HDR *)LOCN(regf->base, nk_off);
    tmp->keys[i] = nt_get_key_tree(regf, nk_hdr, BLK_SIZE(nk_hdr), parent);
    if (!tmp->keys[i]) {
      goto error;
    }
  }

  return tmp;

 error:
  /*if (tmp) nt_delete_key_list(tmp, False);*/
  return NULL;
}


/*
 * This routine is passed an NK_HDR pointer and retrieves the entire tree
 * from there down. It returns a REG_KEY *.
 */
static
REG_KEY *nt_get_key_tree(REGF *regf, NK_HDR *nk_hdr, int size, REG_KEY *parent)
{
  REG_KEY *tmp = NULL, *own;
  int name_len, clsname_len, lf_off, val_off, val_count, sk_off, own_off;
  unsigned int nk_id;
  LF_HDR *lf_hdr;
  VL_TYPE *vl;
  SK_HDR *sk_hdr;
  char key_name[1024];
  unsigned char cls_name[1024];

  if (!nk_hdr) return NULL;

  if ((nk_id = SVAL(&nk_hdr->NK_ID)) != REG_NK_ID) {
    fprintf(stderr, "Unrecognized NK Header format: %08X, Block: %0X. %s\n", 
            nk_id, (int)nk_hdr, regf->regfile_name);
    return NULL;
  }

  assert(size < 0);

  name_len = SVAL(&nk_hdr->nam_len);
  clsname_len = SVAL(&nk_hdr->clsnam_len);

  /*
   * The value of -size should be ge 
   * (sizeof(NK_HDR) - 1 + name_len)
   * The -1 accounts for the fact that we included the first byte of 
   * the name in the structure. clsname_len is the length of the thing 
   * pointed to by clsnam_off
   */

  if (-size < (sizeof(NK_HDR) - 1 + name_len)) {
    fprintf(stderr, "Incorrect NK_HDR size: %d, %0X\n", -size, (int)nk_hdr);
    fprintf(stderr, "Sizeof NK_HDR: %d, name_len %d, clsname_len %d\n",
            sizeof(NK_HDR), name_len, clsname_len);
    /*return NULL;*/
  }

  if (verbose) fprintf(stdout, "NK HDR: Name len: %d, class name len: %d\n", 
                       name_len, clsname_len);

  /* Fish out the key name and process the LF list */

  assert(name_len < sizeof(key_name));

  /* Allocate the key struct now */
  tmp = (REG_KEY *)malloc(sizeof(REG_KEY));
  if (!tmp) return tmp;
  memset(tmp, 0, sizeof(REG_KEY));

  tmp->type = (SVAL(&nk_hdr->type)==0x2C?REG_ROOT_KEY:REG_SUB_KEY);
  
  strncpy(key_name, nk_hdr->key_nam, name_len);
  key_name[name_len] = '\0';

  if (verbose) fprintf(stdout, "Key name: %s\n", key_name);

  tmp->name = strdup(key_name);
  if (!tmp->name) {
    goto error;
  }

  /*
   * Fish out the class name, it is in UNICODE, while the key name is 
   * ASCII :-)
   */

  if (clsname_len) 
  { /* Just print in Ascii for now */
    unsigned char *clsnamep;
    unsigned int clsnam_off;

    clsnam_off = IVAL(&nk_hdr->clsnam_off);
    clsnamep = (unsigned char*)LOCN(regf->base, clsnam_off);
    if (verbose) fprintf(stdout, "Class Name Offset: %0X\n", clsnam_off);
 
    memset(cls_name, 0, clsname_len);
    uni_to_ascii(clsnamep, cls_name, sizeof(cls_name), clsname_len);
    
    /*
     * XXX:
     * I am keeping class name as an ascii string for the moment.
     * That means it needs to be converted on output.
     * It will also piss off people who need Unicode/UTF-8 strings. Sorry. 
     */
    tmp->class_name = strdup((char*)cls_name);
    if (!tmp->class_name) {
      goto error;
    }

    if (verbose) fprintf(stdout, "  Class Name: %s\n", cls_name);

  }

  /*
   * Process the owner offset ...
   */
  own_off = IVAL(&nk_hdr->own_off);
  own = (REG_KEY *)LOCN(regf->base, own_off);
  if (verbose) 
    fprintf(stdout, "Owner Offset: %0X\n", own_off);

  if (verbose) 
    fprintf(stdout, "  Owner locn: %0X, Our locn: %0X\n", 
		       (unsigned int)own, (unsigned int)nk_hdr);

  /* 
   * We should verify that the owner field is correct ...
   * for now, we don't worry ...
   */
  tmp->owner = parent;

  /*
   * If there are any values, process them here
   */

  val_count = IVAL(&nk_hdr->val_cnt);
  if (verbose) 
    fprintf(stdout, "Val Count: %d\n", val_count);
  if (val_count) 
  {
    val_off = IVAL(&nk_hdr->val_off);
    vl = (VL_TYPE *)LOCN(regf->base, val_off);
    if (verbose) 
      fprintf(stdout, "Val List Offset: %0X\n", val_off);

    tmp->values = process_vl(regf, *vl, val_count, BLK_SIZE(vl));
    if (!tmp->values) {
      goto error;
    }

  }

  /* 
   * Also handle the SK header ...
   */

  sk_off = IVAL(&nk_hdr->sk_off);
  sk_hdr = (SK_HDR *)LOCN(regf->base, sk_off);
  if (verbose) 
    fprintf(stdout, "SK Offset: %0X\n", sk_off);

  if (sk_off != -1) {

    tmp->security = process_sk(regf, sk_hdr, sk_off, BLK_SIZE(sk_hdr));

  } 

  lf_off = IVAL(&nk_hdr->lf_off);
  if (verbose) 
    fprintf(stdout, "SubKey list offset: %0X\n", lf_off);

  /*
   * No more subkeys if lf_off == -1
   */
  if (lf_off != -1) 
  {
    lf_hdr = (LF_HDR *)LOCN(regf->base, lf_off);
    
    tmp->sub_keys = process_lf(regf, lf_hdr, BLK_SIZE(lf_hdr), tmp);
    if (!tmp->sub_keys)
      goto error;
  }

  return tmp;

 error:
  /*if (tmp) nt_delete_reg_key(tmp, False);*/
  return NULL;
}

static
int nt_load_registry(REGF *regf)
{
  REGF_HDR *regf_hdr;
  unsigned int regf_id, hbin_id;
  HBIN_HDR *hbin_hdr;
  NK_HDR *first_key;

  /* Get the header */

  if ((regf_hdr = nt_get_regf_hdr(regf)) == NULL) {
    return -1;
  }

  /* Now process that header and start to read the rest in */

  if ((regf_id = IVAL(&regf_hdr->REGF_ID)) != REG_REGF_ID) {
    fprintf(stderr, "Unrecognized NT registry header id: %0X, %s\n",
	    regf_id, regf->regfile_name);
    return -1;
  }

  /*
   * Validate the header ...
   */
  if (!valid_regf_hdr(regf_hdr)) {
    fprintf(stderr, "Registry file header does not validate: %s\n",
	    regf->regfile_name);
    return -1;
  }

  /* Update the last mod date, and then go get the first NK record and on */

  TTTONTTIME(regf, IVAL(&regf_hdr->tim1), IVAL(&regf_hdr->tim2));

  /* 
   * The hbin hdr seems to be just uninteresting garbage. Check that
   * it is there, but that is all.
   */

  hbin_hdr = (HBIN_HDR *)(regf->base + REGF_HDR_BLKSIZ);

  if ((hbin_id = IVAL(&hbin_hdr->HBIN_ID)) != REG_HBIN_ID) {
    fprintf(stderr, "Unrecognized registry hbin hdr ID: %0X, %s\n", 
	    hbin_id, regf->regfile_name);
    return -1;
  } 

  /*
   * Get a pointer to the first key from the hreg_hdr
   */

  if (verbose) 
    fprintf(stdout, "First Key: %0X\n", IVAL(&regf_hdr->first_key));

  first_key = (NK_HDR *)LOCN(regf->base, IVAL(&regf_hdr->first_key));
  if (verbose) fprintf(stdout, "First Key Offset: %0X\n", 
		       IVAL(&regf_hdr->first_key));

  if (verbose) fprintf(stdout, "Data Block Size: %d\n",
		       IVAL(&regf_hdr->dblk_size));

  if (verbose) fprintf(stdout, "Offset to next hbin block: %0X\n",
		       IVAL(&hbin_hdr->off_to_next));

  if (verbose) fprintf(stdout, "HBIN block size: %0X\n",
		       IVAL(&hbin_hdr->blk_size));

  /*
   * Now, get the registry tree by processing that NK recursively
   */

  regf->root = nt_get_key_tree(regf, first_key, BLK_SIZE(first_key), NULL);

  assert(regf->root != NULL);

  /*
   * Unmap the registry file, as we might want to read in another
   * tree etc.
   */

  if (regf->base) munmap(regf->base, regf->sbuf.st_size);
  regf->base = NULL;
  close(regf->fd);    /* Ignore the error :-) */

  return 1;
}


/*
 * Routines to parse a REGEDIT4 file
 * 
 * The file consists of:
 * 
 * REGEDIT4
 * \[[-]key-path\]\n
 * <value-spec>*
 *
 * Format:
 * [cmd:]name=type:value
 *
 * cmd = a|d|c|add|delete|change|as|ds|cs
 *
 * There can be more than one key-path and value-spec.
 *
 * Since we want to support more than one type of file format, we
 * construct a command-file structure that keeps info about the command file
 */

#define FMT_UNREC -1
#define FMT_REGEDIT4 0
#define FMT_EDITREG1_1 1

#define FMT_STRING_REGEDIT4 "REGEDIT4"
#define FMT_STRING_EDITREG1_0 "EDITREG1.0"

#define CMD_NONE     0
#define CMD_ADD_KEY  1
#define CMD_DEL_KEY  2

#define CMD_KEY 1
#define CMD_VAL 2

typedef struct val_spec_list {
  struct val_spec_list *next;
  char *name;
  int type;
  char *val;    /* Kept as a char string, really? */
} VAL_SPEC_LIST;

typedef struct command_s {
  int cmd;
  char *key;
  int val_count;
  VAL_SPEC_LIST *val_spec_list, *val_spec_last;
} CMD;

typedef struct cmd_line {
  int len, line_len;
  char *line;
} CMD_LINE;



#define INIT_ALLOC 10 


/* prints a key */
static
int print_key(const char *path, char *name, char *class_name, int root, 
	      int terminal, int vals, char* newline)
{
  if (full_print)
    fprintf(stdout, "%s%s/%s", path, name, newline);

  return 1;
}

/*
 * Sec Desc print functions 
 */
static
void print_type(unsigned char type)
{
  switch (type) {
  case 0x00:
    fprintf(stdout, "    ALLOW");
    break;
  case 0x01:
    fprintf(stdout, "     DENY");
    break;
  case 0x02:
    fprintf(stdout, "    AUDIT");
    break;
  case 0x03:
    fprintf(stdout, "    ALARM");
    break;
  case 0x04:
    fprintf(stdout, "ALLOW CPD");
    break;
  case 0x05:
    fprintf(stdout, "OBJ ALLOW");
    break;
  case 0x06:
    fprintf(stdout, " OBJ DENY");
    break;
  default:
    fprintf(stdout, "  UNKNOWN");
    break;
  }
}

static
void print_flags(unsigned char flags)
{
  char flg_output[21];
  int some = 0;

  flg_output[0] = 0;
  if (!flags) {
    fprintf(stdout, "         ");
    return;
  }
  if (flags & 0x01) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "OI");
  }
  if (flags & 0x02) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "CI");
  }
  if (flags & 0x04) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "NP");
  }
  if (flags & 0x08) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "IO");
  }
  if (flags & 0x10) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "IA");
  }
  if (flags == 0xF) {
    if (some) strcat(flg_output, ",");
    some = 1;
    strcat(flg_output, "VI");
  }
  fprintf(stdout, " %s", flg_output);
}

static
void print_perms(int perms)
{
  fprintf(stdout, " %8X", perms);
}

static
void print_sid(sid_t *sid)
{
  int i, comps = sid->auths;
  fprintf(stdout, "S-%u-%u", sid->ver, sid->auth[5]);

  for (i = 0; i < comps; i++) 
    fprintf(stdout, "-%u", sid->sub_auths[i]);

  /*fprintf(stdout, "\n");*/
}

static
void print_acl(ACL *acl, const char *prefix)
{
  int i;

  for (i = 0; i < acl->num_aces; i++) {
    fprintf(stdout, ";;%s", prefix);
    print_type(acl->aces[i]->type);
    print_flags(acl->aces[i]->flags);
    print_perms(acl->aces[i]->perms);
    fprintf(stdout, " ");
    print_sid(acl->aces[i]->trustee);
  }
}

static
int print_sec(SEC_DESC *sec_desc)
{
  if (!print_security) return 1;
  fprintf(stdout, ";;  SECURITY\n");
  fprintf(stdout, ";;   Owner: ");
  print_sid(sec_desc->owner);
  fprintf(stdout, ";;   Group: ");
  print_sid(sec_desc->group);
  if (sec_desc->sacl) {
    fprintf(stdout, ";;    SACL:\n");
    print_acl(sec_desc->sacl, " ");
  }
  if (sec_desc->dacl) {
    fprintf(stdout, ";;    DACL:\n");
    print_acl(sec_desc->dacl, " ");
  }
  return 1;
}

/*
 * Value print function here ...
 */
static
int print_val(const char *path, char *val_name, int val_type, int data_len, 
	      void *data_blk, int terminal, int first, int last)
{
  unsigned char* data_asc;
  char* new_path;
  const char* str_type;

  if(!val_name)
    val_name = "";
  if(!path)
    path = "";

  new_path = (char *)malloc(strlen(path)+ strlen(val_name) + 1);
  if (!new_path)
    return 0; /* Errors? */
  new_path[0] = '\0';
  strcat(new_path, path);
  strcat(new_path, val_name);

  if (str_is_prefix(prefix_filter, new_path))
  {
    if (!type_filter_enabled || (type_filter == val_type))
    {
      if(!val_name)
	val_name = "<No Name>";

      str_type = val_to_str(val_type,reg_type_names);
      if(!str_type)
	str_type = "";
      
      data_asc = data_to_ascii((unsigned char *)data_blk, data_len, val_type);
      fprintf(stdout, "%s:%s=%s\n", new_path, str_type, data_asc);
      
      free(data_asc);
    }
  }

  free(new_path);
  return 1;
}

static
void usage(void)
{
  fprintf(stderr, "Usage: readreg [-f<PREFIX_FILTER>] [-t<TYPE_FILTER>] "
                  "[-v] [-p] [-k] [-s] <REGISTRY_FILE>\n");
  /* XXX: replace version string with Subversion tag? */
  fprintf(stderr, "Version: 0.1\n");
  fprintf(stderr, "\n\t-v\t sets verbose mode.");
  fprintf(stderr, "\n\t-f\t a simple prefix filter.");
  fprintf(stderr, "\n\t-t\t restrict results to a specific type.");
  fprintf(stderr, "\n\t-s\t prints security descriptors.");
  fprintf(stderr, "\n");
}


int main(int argc, char *argv[])
{
  REGF *regf;
  extern char *optarg;
  extern int optind;
  int opt; 
  int regf_opt = 1;

  if (argc < 2)
  {
    usage();
    exit(1);
  }
  
  /* 
   * Now, process the arguments
   */

  while ((opt = getopt(argc, argv, "svkf:t:o:c:")) != EOF)
  {
    switch (opt)
    {
    case 'f':
      /*full_print = 1;*/
      prefix_filter = strdup(optarg);
      regf_opt++;
      break;

    case 't':
      type_filter = str_to_val(optarg, reg_type_names);
      type_filter_enabled = true;
      regf_opt++;
      break;

    case 's':
      print_security++;
      full_print++;
      regf_opt++;
      break;

    case 'v':
      verbose++;
      regf_opt++;
      break;

    case 'k':
      regf_opt++;
      break;

    default:
      usage();
      exit(1);
      break;
    }
  }

  /*
   * We only want to complain about the lack of a default owner SID if
   * we need one. This approximates that need 
   */
  if (!def_owner_sid_str) {
    def_owner_sid_str = "S-1-5-21-1-2-3-4";
    if (verbose)
      fprintf(stderr, "Warning, default owner SID not set. Setting to %s\n",
	      def_owner_sid_str);
  }

  if ((regf = nt_create_regf()) == NULL) 
  {
    fprintf(stderr, "Could not create registry object: %s\n", strerror(errno));
    exit(2);
  }

  if (regf_opt < argc) 
  { /* We have a registry file */
    if (!nt_set_regf_input_file(regf, argv[regf_opt])) 
    {
      fprintf(stderr, "Could not set name of registry file: %s, %s\n", 
	      argv[regf_opt], strerror(errno));
      exit(3);
    }

    /* Now, open it, and bring it into memory :-) */
    if (nt_load_registry(regf) < 0) 
    {
      fprintf(stderr, "Could not load registry: %s\n", argv[1]);
      exit(4);
    }
  }

  /*
   * At this point, we should have a registry in memory and should be able
   * to iterate over it.
   */
  nt_key_iterator(regf, regf->root, 0, "");

  return 0;
}
