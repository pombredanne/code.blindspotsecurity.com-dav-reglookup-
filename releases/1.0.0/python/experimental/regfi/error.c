/*
** error.c
** 
** Made by (mic)
** Login   <mic@laptop>
** 
** Started on  Mon Mar 15 20:45:09 2010 mic
** Last update Sun May 12 01:17:25 2002 Speed Blue
*/

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <talloc.h>
#include "aff4_errors.h"

/** These slots carry the TLS error keys */
static pthread_key_t error_str_slot;
static pthread_key_t error_value_slot;

void error_dest(void *slot) {
  if(slot) talloc_free(slot);
}

void *raise_errors(enum _error_type t, char *reason, ...) {
  char *error_buffer;
  // This has to succeed:
  enum _error_type *type = aff4_get_current_error(&error_buffer);

  if(reason) {
    va_list ap;
    va_start(ap, reason);

    vsnprintf(error_buffer, ERROR_BUFFER_SIZE-1, reason,ap);
    error_buffer[ERROR_BUFFER_SIZE-1]=0;
    va_end(ap);
  };

  //update the error type
  *type = t;

  return NULL;
}

static int error_subsystem_initialised=0;

enum _error_type *aff4_get_current_error(char **error_buffer) {
  enum _error_type *type;

  if(!error_subsystem_initialised) error_init();

  type = pthread_getspecific(error_value_slot);

  // This is optional
  if(error_buffer) {
    *error_buffer = pthread_getspecific(error_str_slot);

  // If TLS buffers are not set we need to create them
    if(!*error_buffer) {
      *error_buffer =talloc_size(NULL, ERROR_BUFFER_SIZE);
      pthread_setspecific(error_str_slot, *error_buffer);
    };
  };

  if(!type) {
    type = talloc(NULL, enum _error_type);
    pthread_setspecific(error_value_slot, type);
  };

  return type;
}

/** Initialise the error subsystem */
void error_init() {
  error_subsystem_initialised = 1;

  // We create the error buffer slots
  if(pthread_key_create(&error_str_slot, error_dest) ||
     pthread_key_create(&error_value_slot, error_dest)) {
    printf("Unable to set up TLS variables\n");
    abort();
  };
}
