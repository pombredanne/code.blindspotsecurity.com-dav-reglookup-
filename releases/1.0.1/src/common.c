/*
 * This file stores code common to the command line tools.
 * XXX: This should be converted to a proper library.
 *
 * Copyright (C) 2005-2008,2011 Timothy D. Morgan
 * Copyright (C) 2002 Richard Sharpe, rsharpe@richardsharpe.com
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

#include <iconv.h>
iconv_t conv_desc;

const char* key_special_chars = ",\"/";
const char* subfield_special_chars = ",\"|";
const char* common_special_chars = ",\"";

#define REGLOOKUP_EXIT_OK       0
#define REGLOOKUP_EXIT_OSERR   71
#define REGLOOKUP_EXIT_USAGE   64
#define REGLOOKUP_EXIT_DATAERR 65
#define REGLOOKUP_EXIT_NOINPUT 66


/* Windows is lame */
#ifdef O_BINARY
#define REGLOOKUP_OPEN_FLAGS O_RDONLY|O_BINARY
#else
#define REGLOOKUP_OPEN_FLAGS O_RDONLY
#endif


void bailOut(int code, char* message)
{
  fprintf(stderr, "%s", message);
  exit(code);
}

void printMsgs()
{
  char* msgs = regfi_log_get_str();
  if(msgs != NULL)
  {
    fprintf(stderr, "%s", msgs);
    free(msgs);
  }
}

void clearMsgs()
{
  char* msgs = regfi_log_get_str();
  if(msgs != NULL)
    free(msgs);
}


/* Returns a newly malloc()ed string which contains original buffer,
 * except for non-printable or special characters are quoted in hex
 * with the syntax '%QQ' where QQ is the hex ascii value of the quoted
 * character.  A null terminator is added, since only ascii, not binary,
 * is returned.
 */
static char* quote_buffer(const unsigned char* str, 
			  unsigned int len, const char* special)
{
  unsigned int i, added_len;
  unsigned int num_written = 0;

  unsigned int buf_len = sizeof(char)*(len+1);
  char* ret_val = NULL; 
  char* tmp_buf;

  if(buf_len > 0) 
    ret_val = malloc(buf_len);
  if(ret_val == NULL)
    return NULL;

  for(i=0; i<len; i++)
  {
    if(buf_len <= (num_written+5))
    {
      /* Expand the buffer by the memory consumption rate seen so far 
       * times the amount of input left to process.  The expansion is bounded 
       * below by a minimum safety increase, and above by the maximum possible 
       * output string length.  This should minimize both the number of 
       * reallocs() and the amount of wasted memory.
       */
      added_len = (len-i)*num_written/(i+1);
      if((buf_len+added_len) > (len*4+1))
	buf_len = len*4+1;
      else
      {
	if (added_len < 5)
	  buf_len += 5;
	else
	  buf_len += added_len;
      }

      tmp_buf = realloc(ret_val, buf_len);
      if(tmp_buf == NULL)
      {
	free(ret_val);
	return NULL;
      }
      ret_val = tmp_buf;
    }
    
    if(str[i] < 32 || str[i] > 126 
       || str[i] == '%' || strchr(special, str[i]) != NULL)
    {
      num_written += snprintf(ret_val + num_written, buf_len - num_written,
			      "%%%.2X", str[i]);
    }
    else
      ret_val[num_written++] = str[i];
  }
  ret_val[num_written] = '\0';

  return ret_val;
}


/* Returns a newly malloc()ed string which contains original string, 
 * except for non-printable or special characters are quoted in hex
 * with the syntax '%QQ' where QQ is the hex ascii value of the quoted
 * character.
 */
static char* quote_string(const char* str, const char* special)
{
  unsigned int len;

  if(str == NULL)
    return NULL;

  len = strlen(str);
  return quote_buffer((const unsigned char*)str, len, special);
}


/*
 * Convert a data value to a string for display.  Returns NULL on error,
 * and the string to display if there is no error, or a non-fatal
 * error.  On any error (fatal or non-fatal) occurs, (*error_msg) will
 * be set to a newly allocated string, containing an error message.  If
 * a memory allocation failure occurs while generating the error
 * message, both the return value and (*error_msg) will be NULL.  It
 * is the responsibility of the caller to free both a non-NULL return
 * value, and a non-NULL (*error_msg).
 */
static char* data_to_ascii(const REGFI_DATA* data, char** error_msg)
{
  char* ret_val;
  char* cur_quoted;
  char* tmp_ptr;
  char* delim;
  uint32_t ret_val_left, i, tmp_len;

  if(data == NULL || data->size == 0)
  {
    *error_msg = (char*)malloc(37);
    if(*error_msg == NULL)
      return NULL;
    strcpy(*error_msg, "Data pointer was NULL or size was 0.");
    return NULL;
  }
  *error_msg = NULL;


  if(data->interpreted_size == 0)
  {
    *error_msg = (char*)malloc(51);
    if(*error_msg == NULL)
      return NULL;
    strcpy(*error_msg, "Data could not be interpreted, quoting raw buffer.");
    return quote_buffer(data->raw, data->size, subfield_special_chars);
  }

  switch (data->type) 
  {
  case REG_SZ:
    ret_val = quote_string((char*)data->interpreted.string, common_special_chars);
    if(ret_val == NULL && (*error_msg = (char*)malloc(49)) != NULL)
	strcpy(*error_msg, "Buffer could not be quoted due to unknown error.");

    return ret_val;
    break;

    
  case REG_EXPAND_SZ:
    ret_val = quote_string((char*)data->interpreted.expand_string, 
			   common_special_chars);
    if(ret_val == NULL && (*error_msg = (char*)malloc(49)) != NULL)
	strcpy(*error_msg, "Buffer could not be quoted due to unknown error.");

    return ret_val;
    break;

  case REG_LINK:
    ret_val = quote_string((char*)data->interpreted.link, common_special_chars);
    if(ret_val == NULL && (*error_msg = (char*)malloc(49)) != NULL)
	strcpy(*error_msg, "Buffer could not be quoted due to unknown error.");

    return ret_val;
    break;

  case REG_DWORD:
    ret_val = malloc(sizeof(char)*(8+2+1));
    if(ret_val == NULL)
      return NULL;

    sprintf(ret_val, "0x%.8X", data->interpreted.dword);
    return ret_val;
    break;

  case REG_DWORD_BE:
    ret_val = malloc(sizeof(char)*(8+2+1));
    if(ret_val == NULL)
      return NULL;

    sprintf(ret_val, "0x%.8X", data->interpreted.dword_be);
    return ret_val;
    break;

  case REG_QWORD:
    ret_val = malloc(sizeof(char)*(16+2+1));
    if(ret_val == NULL)
      return NULL;

    sprintf(ret_val, "0x%.16llX", 
	    (long long unsigned int)data->interpreted.qword);
    return ret_val;
    break;

  case REG_MULTI_SZ:
    ret_val_left = data->interpreted_size*4+1;
    ret_val = malloc(ret_val_left);
    if(ret_val == NULL)
      return NULL;

    tmp_ptr = ret_val;
    tmp_ptr[0] = '\0';
    delim = "";
    for(i=0; data->interpreted.multiple_string[i] != NULL; i++)
    {
      cur_quoted = quote_string((char*)data->interpreted.multiple_string[i],
				subfield_special_chars);
      if(cur_quoted != NULL)
      {
	tmp_len = snprintf(tmp_ptr, ret_val_left, "%s%s",delim, cur_quoted);
	tmp_ptr += tmp_len;
	ret_val_left -= tmp_len;
	free(cur_quoted);
      }
      delim = "|";
    }

    return ret_val;
    break;

    
  case REG_NONE:
    return quote_buffer(data->interpreted.none, data->interpreted_size,
			common_special_chars);

    break;

  case REG_RESOURCE_LIST:
    return quote_buffer(data->interpreted.resource_list, data->interpreted_size,
			common_special_chars);

    break;

  case REG_FULL_RESOURCE_DESCRIPTOR:
    return quote_buffer(data->interpreted.full_resource_descriptor, 
			data->interpreted_size, common_special_chars);

    break;

  case REG_RESOURCE_REQUIREMENTS_LIST:
    return quote_buffer(data->interpreted.resource_requirements_list,
			data->interpreted_size, common_special_chars);

    break;

  case REG_BINARY:
    return quote_buffer(data->interpreted.binary, data->interpreted_size,
			common_special_chars);

    break;

  default:
    /* This shouldn't happen, since the regfi routines won't interpret 
     * unknown types, but just as a safety measure against library changes... 
     */
    *error_msg = (char*)malloc(65);
    if(*error_msg == NULL)
      return NULL;
    sprintf(*error_msg,
	    "Unrecognized registry data type (0x%.8X); quoting as binary.",
	    data->type);
    return quote_buffer(data->raw, data->size, common_special_chars);
  }
    
  return NULL;
}


static char* get_quoted_keyname(const REGFI_NK* nk)
{
  char* ret_val;

  if(nk->name == NULL)
    ret_val = quote_buffer(nk->name_raw, nk->name_length, key_special_chars);
  else
    ret_val = quote_string(nk->name, key_special_chars);

  return ret_val;
}


static char* get_quoted_valuename(const REGFI_VK* vk)
{
  char* ret_val;

  if(vk->name == NULL)
    ret_val = quote_buffer(vk->name_raw, vk->name_length, 
			   key_special_chars);
  else
    ret_val = quote_string(vk->name, key_special_chars);

  return ret_val;
}


int openHive(const char* filename)
{
  int ret_val;

  /* open an existing file */
  if ((ret_val = open(filename, REGLOOKUP_OPEN_FLAGS)) == -1)
  {
    fprintf(stderr, "ERROR: Failed to open hive.  Error returned: %s\n", 
	    strerror(errno));
    return -1;
  }

  return ret_val;
}


void formatTime(REGFI_NTTIME nttime, char* output)
{
  time_t tmp_time[1];
  struct tm* tmp_time_s = NULL;

  *tmp_time = (time_t)regfi_nt2unix_time(nttime);
  tmp_time_s = gmtime(tmp_time);
  strftime(output, 
	   (4+1+2+1+2)+1+(2+1+2+1+2)+1, 
              "%Y-%m-%d %H:%M:%S", 
	   tmp_time_s);
}
