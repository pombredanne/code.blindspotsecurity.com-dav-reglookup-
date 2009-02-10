/*
 * This file stores code common to the command line tools.
 * XXX: This should be converted to a proper library.
 *
 * Copyright (C) 2005-2008 Timothy D. Morgan
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

const char* key_special_chars = ",\"\\/";
const char* subfield_special_chars = ",\"\\|";
const char* common_special_chars = ",\"\\";

#define REGLOOKUP_VERSION "0.10.0"


void bailOut(int code, char* message)
{
  fprintf(stderr, message);
  exit(code);
}

void printMsgs(REGFI_FILE* f)
{
  char* msgs = regfi_get_messages(f);
  if(msgs != NULL)
  {
    fprintf(stderr, "%s", msgs);
    free(msgs);
  }
}

void clearMsgs(REGFI_FILE* f)
{
  char* msgs = regfi_get_messages(f);
  if(msgs != NULL)
    free(msgs);
}


/* Returns a newly malloc()ed string which contains original buffer,
 * except for non-printable or special characters are quoted in hex
 * with the syntax '\xQQ' where QQ is the hex ascii value of the quoted
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
    
    if(str[i] < 32 || str[i] > 126 || strchr(special, str[i]) != NULL)
    {
      num_written += snprintf(ret_val + num_written, buf_len - num_written,
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
static char* quote_string(const char* str, const char* special)
{
  unsigned int len;

  if(str == NULL)
    return NULL;

  len = strlen(str);
  return quote_buffer((const unsigned char*)str, len, special);
}


/*
 * Convert from UTF-16LE to ASCII.  Accepts a Unicode buffer, uni, and
 * it's length, uni_max.  Writes ASCII to the buffer ascii, whose size
 * is ascii_max.  Writes at most (ascii_max-1) bytes to ascii, and null
 * terminates the string.  Returns the length of the data written to
 * ascii.  On error, returns a negative errno code.
 */
static int uni_to_ascii(unsigned char* uni, char* ascii, 
			uint32 uni_max, uint32 ascii_max)
{
  char* inbuf = (char*)uni;
  char* outbuf = ascii;
  size_t in_len = (size_t)uni_max;
  size_t out_len = (size_t)(ascii_max-1);
  int ret;

  /* Set up conversion descriptor. */
  conv_desc = iconv_open("US-ASCII//TRANSLIT", "UTF-16LE");

  ret = iconv(conv_desc, &inbuf, &in_len, &outbuf, &out_len);
  if(ret == -1)
  {
    iconv_close(conv_desc);
    return -errno;
  }
  *outbuf = '\0';

  iconv_close(conv_desc);  
  return ascii_max-out_len-1;
}


static char* quote_unicode(unsigned char* uni, uint32 length, 
			   const char* special, char** error_msg)
{
  char* ret_val;
  char* ascii = NULL;
  char* tmp_err;
  int ret_err;
  *error_msg = NULL;

  if(length+1 > 0)
    ascii = malloc(length+1);
  if(ascii == NULL)
  {
    *error_msg = (char*)malloc(27);
    if(*error_msg == NULL)
      return NULL;
    strcpy(*error_msg, "Memory allocation failure.");
    return NULL;
  }
  
  ret_err = uni_to_ascii(uni, ascii, length, length+1);
  if(ret_err < 0)
  {
    free(ascii);
    tmp_err = strerror(-ret_err);
    *error_msg = (char*)malloc(61+strlen(tmp_err));
    if(*error_msg == NULL)
      return NULL;

    sprintf(*error_msg, 
	    "Unicode conversion failed with '%s'. Quoting as binary.", tmp_err);
    ret_val = quote_buffer(uni, length, special);
  }
  else
  {
    ret_val = quote_string(ascii, special);
    free(ascii);
  }
  
  return ret_val;
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
/* XXX: Part of this function's logic should be pushed into the regfi API.
 *      The structures should be parsed and stored with VK records and only 
 *      escaped/encoded later in reglookup and reglookup-recover.
 */
static char* data_to_ascii(unsigned char* datap, uint32 len, uint32 type, 
			   char** error_msg)
{
  char* asciip;
  char* ascii;
  char* ascii_tmp;
  char* cur_quoted;
  char* tmp_err = NULL;
  const char* delim;
  uint32 i;
  uint32 cur_str_len;
  uint32 ascii_max;
  uint32 str_rem, alen;
  int ret_err;

  if(datap == NULL)
  {
    *error_msg = (char*)malloc(24);
    if(*error_msg == NULL)
      return NULL;
    strcpy(*error_msg, "Data pointer was NULL.");
    return NULL;
  }
  *error_msg = NULL;

  switch (type) 
  {
  case REG_SZ:
  case REG_EXPAND_SZ:
    /* REG_LINK is a symbolic link, stored as a unicode string. */
  case REG_LINK:
    /* Sometimes values have binary stored in them.  If the unicode
     * conversion fails, just quote it raw.
     */
    cur_quoted = quote_unicode(datap, len, common_special_chars, &tmp_err);
    if(cur_quoted == NULL)
    {
      if(tmp_err == NULL && (*error_msg = (char*)malloc(49)) != NULL)
	strcpy(*error_msg, "Buffer could not be quoted due to unknown error.");
      else if((*error_msg = (char*)malloc(42+strlen(tmp_err))) != NULL)
      {
	sprintf(*error_msg, "Buffer could not be quoted due to error: %s", 
		tmp_err);
	free(tmp_err);
      }
    }
    else if (tmp_err != NULL)
      *error_msg = tmp_err;
    return cur_quoted;
    break;

  case REG_DWORD:
    ascii_max = sizeof(char)*(8+2+1);
    ascii = malloc(ascii_max);
    if(ascii == NULL)
      return NULL;

    snprintf(ascii, ascii_max, "0x%.2X%.2X%.2X%.2X", 
	     datap[3], datap[2], datap[1], datap[0]);
    return ascii;
    break;

  case REG_DWORD_BE:
    ascii_max = sizeof(char)*(8+2+1);
    ascii = malloc(ascii_max);
    if(ascii == NULL)
      return NULL;

    snprintf(ascii, ascii_max, "0x%.2X%.2X%.2X%.2X", 
	     datap[0], datap[1], datap[2], datap[3]);
    return ascii;
    break;

  case REG_QWORD:
    ascii_max = sizeof(char)*(16+2+1);
    ascii = malloc(ascii_max);
    if(ascii == NULL)
      return NULL;

    snprintf(ascii, ascii_max, "0x%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",
	     datap[7], datap[6], datap[5], datap[4],
	     datap[3], datap[2], datap[1], datap[0]);
    return ascii;
    break;
    
  case REG_MULTI_SZ:
    ascii_max = sizeof(char)*(len*4+1);
    ascii_tmp = malloc(ascii_max);
    if(ascii_tmp == NULL)
      return NULL;

    /* Attempt to convert entire string from UTF-16LE to ASCII, 
     * then parse and quote fields individually.
     * If this fails, simply quote entire buffer as binary. 
     */
    ret_err = uni_to_ascii(datap, ascii_tmp, len, ascii_max);
    if(ret_err < 0)
    {
      tmp_err = strerror(-ret_err);
      *error_msg = (char*)malloc(61+strlen(tmp_err));
      if(*error_msg == NULL)
      {
	free(ascii_tmp);
	return NULL;
      }

      sprintf(*error_msg, "MULTI_SZ unicode conversion"
	      " failed with '%s'. Quoting as binary.", tmp_err);
      ascii = quote_buffer(datap, len, subfield_special_chars);
    }
    else
    {
      ascii = malloc(ascii_max);
      if(ascii == NULL)
      {
	free(ascii_tmp);
	return NULL;
      }
      asciip = ascii;
      asciip[0] = '\0';
      str_rem = ascii_max;
      delim = "";
      for(i=0; i<ret_err; i+=cur_str_len+1)
      {
	cur_str_len = strlen(ascii_tmp+i);
	if(ascii_tmp[i] != '\0')
	{
	  cur_quoted = quote_string(ascii_tmp+i, subfield_special_chars);
	  if(cur_quoted != NULL)
	  {
	    alen = snprintf(asciip, str_rem, "%s%s", delim, cur_quoted);
	    asciip += alen;
	    str_rem -= alen;
	    free(cur_quoted);
	  }
	}
	delim = "|";
      }
    }

    free(ascii_tmp);
    return ascii;
    break;

  /* XXX: Dont know what to do with these yet, just print as binary... */
  default:
    *error_msg = (char*)malloc(65);
    if(*error_msg == NULL)
      return NULL;
    sprintf(*error_msg,
	    "Unrecognized registry data type (0x%.8X); quoting as binary.",
	    type);
    
  case REG_NONE:
  case REG_RESOURCE_LIST:
  case REG_FULL_RESOURCE_DESCRIPTOR:
  case REG_RESOURCE_REQUIREMENTS_LIST:

  case REG_BINARY:
    return quote_buffer(datap, len, common_special_chars);
    break;
  }

  return NULL;
}
