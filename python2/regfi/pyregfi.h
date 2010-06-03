/*
** regfi.h
** 
** Made by mic
** Login   <mic@laptop>
** 
** Started on  Fri Apr 30 02:06:43 2010 mic
** Last update Fri Apr 30 02:06:43 2010 mic
*/

#ifndef   	PYREGFI_H_
# define   	PYREGFI_H_
#include "class.h"
#include "aff4_errors.h"
#include "regfi.h"

/** Forward declerations */
struct RegistryFile_t;
struct ValueIterator_t;

BIND_STRUCT(REGFI_NK_REC)
BIND_STRUCT(REGFI_VK_REC)
BIND_STRUCT(REGFI_DATA)

/** This is the base class for data objects */
CLASS(RawData, Object)
    const REGFI_DATA *data;
    const REGFI_VK_REC *rec;

    RawData METHOD(RawData, Con, REGFI_DATA *data, REGFI_VK_REC *record);

    /** Return the raw buffer as a string. By default we only return
        this much data - specify a required length to return more.

        DEFAULT(len) = 4096;
    */
    int METHOD(RawData, get_value, OUT char *buffer, int len);
END_CLASS

CLASS(DataString, RawData)
     BORROWED char *METHOD(DataString, get_value);
END_CLASS

CLASS(DWORDData, RawData)
     uint64_t METHOD(DWORDData, get_value);
END_CLASS

/** This is an iterator for reading keys from the registry */
CLASS(KeyIterator, Object)
     PRIVATE REGFI_ITERATOR *iter;
     PRIVATE bool first_called;

     KeyIterator METHOD(KeyIterator, Con, struct RegistryFile_t *file, char **path,
                        REGFI_ENCODING encoding);

     struct ValueIterator_t *METHOD(KeyIterator, list_values);

     KeyIterator METHOD(KeyIterator, __iter__);
     REGFI_NK_REC *METHOD(KeyIterator, iternext);

     int METHOD(KeyIterator, down);
     int METHOD(KeyIterator, up);
END_CLASS

/** This is an iterator for reading values from the registry */
CLASS(ValueIterator, Object)
     PRIVATE REGFI_ITERATOR *iter;
     PRIVATE bool first_called;
     
     ValueIterator METHOD(ValueIterator, Con, KeyIterator key);

     void METHOD(ValueIterator, __iter__);
     RawData METHOD(ValueIterator, iternext);
END_CLASS

CLASS(RegistryFile, Object)
  REGFI_FILE *reg;
  int fd;

  RegistryFile METHOD(RegistryFile, Con, char *filename);

  /* Get an iterator for a specific path in the register if path is
     specified.

     DEFAULT(path) == NULL;
     DEFAULT(encoding) = REGFI_ENCODING_ASCII;
  */
  KeyIterator METHOD(RegistryFile, get_key, char **path, REGFI_ENCODING encoding);

  /** Set the verbosity level of messages generated by the library for the 
 *  current thread.
 *
 * @param mask   An integer representing the types of messages desired.
 *               Acceptable values are created through bitwise ORs of 
 *               REGFI_LOG_* values.  For instance, if only errors and
 *               informational messages were desired (but not warnings),
 *               then one would specify: REGFI_LOG_ERROR|REGFI_LOG_INFO
 *               By default the message mask is: REGFI_LOG_ERROR|REGFI_LOG_WARN.
 *
 * @return       true on success and false on failure.  Failure occurs if 
 *               underlying pthread functions fail.  errno is set in this case.
 *
 * Message masks are set in a thread-specific way.  If one were to set a message
 * mask in one thread and then spawn a new thread, then the new thread will have
 * it's message mask reset to the default.  This function may be called at any 
 * time and will take effect immediately for the current thread.
 *
 * @note When a non-zero message mask is set, messages will
 *       accumulate in memory without limit if they are not fetched using
 *       @ref regfi_get_log_str and subsequently freed by the caller.  It is
 *       recommended that messsages be fetched after each regfi API call in
 *       order to provide the most context.
 *
 * @ingroup regfiBase
 */
  int METHOD(RegistryFile, set_log_mask, uint16_t mask);

  
END_CLASS


void pyregfi_init();

#endif 	    /* !PYREGFI_H_ */
