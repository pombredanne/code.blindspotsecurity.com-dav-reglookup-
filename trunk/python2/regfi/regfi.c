/*
 * pyregfi/libregfi glue code 
 *
 * Copyright (C) 2010 Michael I. Cohen
 * Copyright (C) 2010 Timothy D. Morgan
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
 * $Id: $
 */

#include "pyregfi.h"

static int RegistryFile_dest(void *self) 
{
  RegistryFile this = (RegistryFile)self;

  regfi_free(this->reg);
  close(this->fd);

  return 0;
}

static RegistryFile RegistryFile_Con(RegistryFile self, char *filename) 
{
  self->fd = open(filename, O_RDONLY);
  if(self->fd < 0) 
  {
    RaiseError(EIOError, "Unable to open %s", filename);
    goto error;
  }

  self->reg = regfi_alloc(self->fd);

  if(!self->reg) 
  {
    RaiseError(ERuntimeError, "REGFI Error: %s", regfi_log_get_str());
    /*char* e = regfi_log_get_str();*/
    /*fprintf(stderr, "%p\n", e);*/
    goto error;
  }

  talloc_set_destructor((void *)self, RegistryFile_dest);
  return self;

 error:
  talloc_free(self);
  return NULL;
}

static TreeIterator RegistryFile_TreeIterator(RegistryFile self, char **path, REGFI_ENCODING encoding) 
{
  return CONSTRUCT(TreeIterator, TreeIterator, Con, NULL, self, path, encoding);
}


VIRTUAL(RegistryFile, Object) {
  VMETHOD(Con) = RegistryFile_Con;
  VMETHOD(TreeIterator) = RegistryFile_TreeIterator;
} END_VIRTUAL


static int RegistryKey_dest(void *self) 
{
  RegistryKey this = (RegistryKey)self;

  talloc_unlink(this, (void*)this->key);

  return 0;
}

static RegistryKey RegistryKey_Con(RegistryKey self, 
				   RegistryFile file, REGFI_NK_REC* base_key)
{
  if(base_key == NULL)
    goto error;

  self->key = base_key;
  self->file = file;
  talloc_reference(self, self->key);
  talloc_set_destructor((void *)self, RegistryKey_dest);

  return self;

 error:
  talloc_free(self);
  return NULL;
}

/* XXX: would be nice to change this into a property, rather than a function,
 *      but that would require a custom __getattr__.  Can that be done? */
static SubkeyIterator RegistryKey_subkeys(RegistryKey self)
{
  return CONSTRUCT(SubkeyIterator, SubkeyIterator, Con, NULL, self->file, self->key);
}

/* XXX: would be nice to change this into a property, rather than a function,
 *      but that would require a custom __getattr__.  Can that be done? */
static SubkeyIterator RegistryKey_values(RegistryKey self)
{
  return CONSTRUCT(ValueIterator, ValueIterator, Con, NULL, self->file, self->key);
}


VIRTUAL(RegistryKey, Object) {
  VMETHOD(Con) = RegistryKey_Con;
  VMETHOD(subkeys) = RegistryKey_subkeys;
  VMETHOD(values) = RegistryKey_values;
} END_VIRTUAL


static int TreeIterator_dest(void *self) 
{
  TreeIterator this = (TreeIterator)self;

  regfi_iterator_free(this->iter);
  return 0;
}

static TreeIterator TreeIterator_Con(TreeIterator self, 
				     RegistryFile file, 
				     char **path,
				     REGFI_ENCODING encoding)
{
  self->iter = regfi_iterator_new(file->reg, encoding);
  self->file = file;

  if(!self->iter) 
  {
    RaiseError(ERuntimeError, "Error: %s", regfi_log_get_str());
    goto error;
  }

  talloc_set_destructor((void*)self, TreeIterator_dest);

  /* Traverse to the path */
  if(path[0]) 
  {
    if(!regfi_iterator_walk_path(self->iter, (const char **)path)) 
    {
      RaiseError(ERuntimeError, "Unable to walk down key path");
      goto error;
    }
  }

  self->root_traversed = false;

  return self;
 error:
  return NULL;
}

static void TreeIterator__iter__(TreeIterator self) 
{
  return;
}


static RegistryKey TreeIterator_next(TreeIterator self)
{
  if(!self->root_traversed)
    self->root_traversed = true;
  else if(!regfi_iterator_down(self->iter))
  {
    do
    {
      if(!regfi_iterator_up(self->iter))
	return NULL;
    } while(!regfi_iterator_next_subkey(self->iter));

    /* XXX: This is an error condition.  
     *      Probably should throw an exception or something. */
    if(!regfi_iterator_down(self->iter))
      return NULL;
  }

  regfi_iterator_first_subkey(self->iter);
  return CONSTRUCT(RegistryKey, RegistryKey, Con, NULL, self->file,
		   regfi_iterator_cur_key(self->iter));
}


static int TreeIterator_down(TreeIterator self) 
{
  int result = regfi_iterator_down(self->iter);
  regfi_iterator_first_subkey(self->iter);
  regfi_iterator_first_value(self->iter);
  return result;
}

static int TreeIterator_up(TreeIterator self) 
{
  return regfi_iterator_up(self->iter);
}

/*
static ValueIterator TreeIterator_list_values(TreeIterator self) 
{
  return CONSTRUCT(ValueIterator, ValueIterator, Con, NULL, self);
}
*/

VIRTUAL(TreeIterator, Object) {
  VMETHOD(Con) = TreeIterator_Con;
  VMETHOD(iternext) = TreeIterator_next;
  VMETHOD(down) = TreeIterator_down;
  VMETHOD(up) = TreeIterator_up;
  VMETHOD(__iter__) = TreeIterator__iter__;
  /*  VMETHOD(list_values) = TreeIterator_list_values;*/
} END_VIRTUAL



static int SubkeyIterator_dest(void *self) 
{
  SubkeyIterator this = (SubkeyIterator)self;

  talloc_unlink(this, (void*)this->list);

  return 0;
}

static SubkeyIterator SubkeyIterator_Con(SubkeyIterator self, 
					 struct RegistryFile_t* file, 
					 REGFI_NK_REC* key)
{
  /* XXX: add a talloc reference? */
  self->file = file;

  /* Add a reference to the list */
  self->list = key->subkeys;
  talloc_reference(self, self->list);

  self->cur = 0;
  talloc_set_destructor((void *)self, SubkeyIterator_dest);

  return self;
}

static void SubkeyIterator__iter__(SubkeyIterator self)
{
  return;
}

static RegistryKey SubkeyIterator_iternext(SubkeyIterator self)
{
  const REGFI_NK_REC* nk;

  if(self->cur < self->list->num_keys)
  {
    /* XXX: can we switch to UTF-8 and have Python properly import that? */
    nk = regfi_load_key(self->file->reg, 
			self->list->elements[self->cur].offset+REGFI_REGF_SIZE,
			REGFI_ENCODING_ASCII, true);
    self->cur++;
    return CONSTRUCT(RegistryKey, RegistryKey, Con, NULL, self->file, nk);
  }

  return NULL;
}

VIRTUAL(SubkeyIterator, Object) {
  VMETHOD(Con) = SubkeyIterator_Con;
  VMETHOD(__iter__) = SubkeyIterator__iter__;
  VMETHOD(iternext) = SubkeyIterator_iternext;
} END_VIRTUAL



static int ValueIterator_dest(void *self) 
{
  ValueIterator this = (ValueIterator)self;

  if(this->list != NULL)
    talloc_unlink(this, (void*)this->list);

  return 0;
}

static ValueIterator ValueIterator_Con(ValueIterator self,
				       struct RegistryFile_t* file, 
				       REGFI_NK_REC* key)
{
  /* XXX: add a talloc reference? */
  self->file = file;
  self->cur = 0;

  /* Add a reference to the list */
  self->list = key->values;
  if(self->list != NULL)
    talloc_reference(self, self->list);

  talloc_set_destructor((void *)self, ValueIterator_dest);

  return self;
}

static void ValueIterator__iter__(ValueIterator self)
{
  return;
}

static REGFI_VK_REC* ValueIterator_iternext(ValueIterator self)
{
  const REGFI_VK_REC* vk;

  if(self->list != NULL && self->cur < self->list->num_values)
  {
    /* XXX: can we switch to UTF-8 and have Python properly import that? */
    vk = regfi_load_value(self->file->reg, 
			  self->list->elements[self->cur]+REGFI_REGF_SIZE,
			  REGFI_ENCODING_ASCII, true);
    self->cur++;
    /*return CONSTRUCT(RegistryKey, RegistryKey, Con, NULL, vk);    */
    return vk; 
  }

  return NULL;


  /* XXX: shouldn't parse data here every time we walk over a value.  
   *      Instead, make data fetching a method and parse it then. 
   */
  /*
  data = (REGFI_DATA *)regfi_iterator_fetch_data(self->iter, rec);
  if(!data) {
    RaiseError(ERuntimeError, "Unable to fetch data: %s", regfi_log_get_str());
    goto error;
  }

  switch(rec->type) {
  case REG_EXPAND_SZ:
  case REG_SZ:
    result = (RawData)CONSTRUCT(DataString, RawData, Con, NULL, data, rec);
    break;

  case REG_DWORD:
    result = (RawData)CONSTRUCT(DWORDData, RawData, Con, NULL, data, rec);
    break;

  case REG_BINARY:
  default:
    result = (RawData)CONSTRUCT(RawData, RawData, Con, NULL, data, rec);
    break;
  }

  return result;
 error:
  talloc_free(self);
  return NULL;
  */
}

VIRTUAL(ValueIterator, Object) {
  VMETHOD(Con) = ValueIterator_Con;
  VMETHOD(__iter__) = ValueIterator__iter__;
  VMETHOD(iternext) = ValueIterator_iternext;
} END_VIRTUAL



static int RawData_dest(void *self)
{
  RawData this = (RawData)self;

  if(this->data) {
    regfi_free_record(this->data);
  };

  if(this->rec) {
    regfi_free_record(this->rec);
  };

  return 0;
}

static RawData RawData_Con(RawData self, REGFI_DATA *data, REGFI_VK_REC *record)
{
  self->rec = record;
  self->data = data;

  talloc_set_destructor((void *)self, RawData_dest);

  return self;
}

static int RawData_get_value(RawData self, char *buff, int len)
{
  int available_to_read = min(len, self->data->interpreted_size);

  memcpy(buff, self->data->raw, available_to_read);

  return available_to_read;
}

VIRTUAL(RawData, Object) {
  VMETHOD(Con) = RawData_Con;
  VMETHOD(get_value) = RawData_get_value;
} END_VIRTUAL

static char* DataString_get_value(DataString self)
{
  RawData this = (RawData)self;

  return (char*)this->data->interpreted.string;
}

VIRTUAL(DataString, RawData) {
  VMETHOD(get_value) = DataString_get_value;
} END_VIRTUAL

static uint64_t DWORDData_get_value(DWORDData self)
{
  RawData this = (RawData)self;

  return this->data->interpreted.dword;
}

VIRTUAL(DWORDData, RawData) {
  VMETHOD(get_value) = DWORDData_get_value;
} END_VIRTUAL

void pyregfi_init()
{
  INIT_CLASS(RegistryFile);
}
