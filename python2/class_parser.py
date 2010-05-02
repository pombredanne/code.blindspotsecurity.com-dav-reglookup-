import sys, os, re, pdb, StringIO
 
DEBUG = 0

def log(msg):
    if DEBUG>0:
        sys.stderr.write(msg+"\n")

def escape_for_string(string):
    result = string
    result = result.encode("string-escape")
    result = result.replace('"',r'\"')

    return result

class Module:
    def __init__(self, name):
        self.name = name
        self.constants = set()
        self.classes = {}
        self.headers = '#include <Python.h>\n'
        self.files = []

    def __str__(self):
        result = "Module %s\n" % (self.name)
        l = self.classes.values()
        l.sort()
        for attr in l:
            if attr.is_active():
                result += "    %s\n" % attr

        l = list(self.constants)
        l.sort()
        result += 'Constants:\n'
        for attr, type in l:
            result += " %s\n" % attr

        return result

    init_string = ''
    def initialization(self):
        result = self.init_string + """
talloc_set_log_fn((void *)printf);
//talloc_enable_leak_report();
"""
        for cls in self.classes.values():
            if cls.is_active():
                result += cls.initialise()

        return result

    def add_constant(self, constant, type="numeric"):
        """ This will be called to add #define constant macros """
        self.constants.add((constant, type))

    def add_class(self, cls, handler):
        self.classes[cls.class_name] = cls

        ## Make a wrapper in the type dispatcher so we can handle
        ## passing this class from/to python
        type_dispatcher[cls.class_name] = handler

    def private_functions(self):
        """ Emits hard coded private functions for doing various things """
        return """
/* The following is a static array mapping CLASS() pointers to their
python wrappers. This is used to allow the correct wrapper to be
chosen depending on the object type found - regardless of the
prototype.

This is basically a safer way for us to cast the correct python type
depending on context rather than assuming a type based on the .h
definition. For example consider the function

AFFObject Resolver.open(uri, mode)

The .h file implies that an AFFObject object is returned, but this is
not true as most of the time an object of a derived class will be
returned. In C we cast the returned value to the correct type. In the
python wrapper we just instantiate the correct python object wrapper
at runtime depending on the actual returned type. We use this lookup
table to do so.
*/
static int TOTAL_CLASSES=0;

/* This is a global reference to this module so classes can call each
   other.
*/
static PyObject *g_module = NULL;

static struct python_wrapper_map_t {
       Object class_ref;
       PyTypeObject *python_type;
} python_wrappers[%s];

/** This is a generic wrapper type */
typedef struct {
  PyObject_HEAD
  void *base;
  void *ctx;
} Gen_wrapper;

/* Create the relevant wrapper from the item based on the lookup
table.
*/
Gen_wrapper *new_class_wrapper(Object item) {
   int i;
   Gen_wrapper *result;
   Object cls;

   /* Hack to get the current null_context */
   void* null_context;
   int* tmp = talloc(NULL, int);
   null_context = talloc_parent(tmp);
   talloc_free(tmp);

   // Return None for a NULL pointer
   if(!item) {
     Py_INCREF(Py_None);
     return (Gen_wrapper *)Py_None;
   };

   // Search for subclasses
   for(cls=(Object)item->__class__; cls != cls->__super__; cls=cls->__super__) {
     for(i=0; i<TOTAL_CLASSES; i++) {
       if(python_wrappers[i].class_ref == cls) {
         PyErr_Clear();

         result = (Gen_wrapper *)_PyObject_New(python_wrappers[i].python_type);
         result->ctx = talloc_asprintf(NULL, "new_class_wrapper %%s@%%p", NAMEOF(item), item);
         result->base = (void *)item;

         /* If its owned by the null_context it means that the function does
            not want to own the memory - we therefore steal it so it gets freed
            with the python object. */
         if(talloc_parent(result->base) == null_context)
                  talloc_steal(result->ctx, result->base);

         return result;
       };
     };
   };

  PyErr_Format(PyExc_RuntimeError, "Unable to find a wrapper for object %%s", NAMEOF(item));
  return NULL;
};

static PyObject *resolve_exception(char **error_buff) {
  enum _error_type *type = aff4_get_current_error(error_buff);
  switch(*type) {
case EProgrammingError:
    return PyExc_SystemError;
case EKeyError:
    return PyExc_KeyError;
case ERuntimeError:
    return PyExc_RuntimeError;
case EWarning:
    return PyExc_AssertionError;
default:
    return PyExc_RuntimeError;
};
};

static int type_check(PyObject *obj, PyTypeObject *type) {
   PyTypeObject *tmp;

   // Recurse through the inheritance tree and check if the types are expected
   if(obj)
     for(tmp = obj->ob_type; tmp && tmp != &PyBaseObject_Type; tmp = tmp->tp_base) {
       if(tmp == type) return 1;
     };

  return 0;
};

static int check_error() {
   if(!CheckError(EZero)) {
         char *buffer;
         PyObject *exception = resolve_exception(&buffer);

         PyErr_Format(exception, "%%s", buffer);
         ClearError();
         return 1;
   };
  return 0;
};

#define CHECK_ERROR if(check_error()) goto error;

""" % (len(self.classes)+1)

    def initialise_class(self, class_name, out, done = None):
        if done and class_name in done: return

        done.add(class_name)

        cls = self.classes[class_name]
        """ Write out class initialisation code into the main init function. """
        if cls.is_active():
            base_class = self.classes.get(cls.base_class_name)

            if base_class and base_class.is_active():
                ## We have a base class - ensure it gets written out
                ## first:
                self.initialise_class(cls.base_class_name, out, done)

                ## Now assign ourselves as derived from them
                out.write(" %s_Type.tp_base = &%s_Type;" % (
                        cls.class_name, cls.base_class_name))
            
            out.write("""
 %(name)s_Type.tp_new = PyType_GenericNew;
 if (PyType_Ready(&%(name)s_Type) < 0)
     return;

 Py_INCREF((PyObject *)&%(name)s_Type);
 PyModule_AddObject(m, "%(name)s", (PyObject *)&%(name)s_Type);
""" % {'name': cls.class_name})

    def write(self, out):
        ## Prepare all classes
        for cls in self.classes.values():
            cls.prepare()

        out.write("""
/**********************************************************************
     Autogenerated module %s

This module was autogenerated from the following files:
""" % self.name)
        for file in self.files:
            out.write("%s\n" % file)

        out.write("\nThis module implements the following classes:\n")
        out.write(self.__str__())
        out.write("""***********************************************************************/
""")
        out.write(self.headers)
        out.write(self.private_functions())

        for cls in self.classes.values():
            if cls.is_active():
                out.write("/******************** %s ***********************/" % cls.class_name)
                cls.struct(out)
                cls.prototypes(out)

        out.write("/*****************************************************\n             Implementation\n******************************************************/\n\n")
        for cls in self.classes.values():
            if cls.is_active():
                cls.PyMethodDef(out)
                cls.code(out)
                cls.PyTypeObject(out)

        ## Write the module initializer
        out.write("""
static PyMethodDef %(module)s_methods[] = {
     {NULL}  /* Sentinel */
};

PyMODINIT_FUNC init%(module)s(void) {
   /* Make sure threads are enabled */
   PyEval_InitThreads();

   /* create module */
   PyObject *m = Py_InitModule3("%(module)s", %(module)s_methods,
                                   "%(module)s module.");
   PyObject *d = PyModule_GetDict(m);
   PyObject *tmp;

   g_module = m;
""" % {'module': self.name})

        ## The trick is to initialise the classes in order of their
        ## inheritance. The following code will order initializations
        ## according to their inheritance tree
        done = set()
        for class_name in self.classes.keys():
            self.initialise_class(class_name, out, done)

        ## Add the constants in here
        for constant, type in self.constants:
            if type == 'integer':
                out.write(""" tmp = PyLong_FromUnsignedLongLong((int64_t)%s); \n""" % constant)
            elif type == 'string':
                out.write(" tmp = PyString_FromString((char *)%s); \n" % constant)
            else:
                out.write(" // I dont know how to convert %s type %s\n" % (constant, type))
                continue

            out.write("""
 PyDict_SetItemString(d, "%s", tmp);
 Py_DECREF(tmp);\n""" % (constant))

        out.write(self.initialization())
        out.write("}\n\n")

class Type:
    interface = None
    buildstr = 'O'
    sense = 'IN'
    error_value = "return 0;"
    active = True

    def __init__(self, name, type):
        self.name = name
        self.type = type
        self.attributes = set()

    def comment(self):
        return "%s %s " % (self.type, self.name)

    def python_name(self):
        return self.name

    def python_proxy_post_call(self):
        """ This is called after a proxy call """
        return ''

    def returned_python_definition(self, *arg, **kw):
        return self.definition(*arg, **kw)

    def definition(self, default=None, **kw):
        if default:
            return "%s %s=%s;\n" % (self.type, self.name, default)
        else:
            return "%s __attribute__((unused)) %s;\n" % (self.type, self.name)

    def byref(self):
        return "&%s" % self.name

    def call_arg(self):
        return self.name

    def pre_call(self, method):
        return ''

    def assign(self, call, method, target=None):
        return "Py_BEGIN_ALLOW_THREADS\n%s = %s;\nPy_END_ALLOW_THREADS\n" % (target or self.name, call)

    def post_call(self, method):
        if "DESTRUCTOR" in self.attributes:
            return "talloc_free(self->ctx); self->base = NULL;\n"

        return ''

    def from_python_object(self, source, destination, method, **kw):
        return ''

    def return_value(self, value):
        return "return %s;" % value

    def __str__(self):
        if self.name == 'func_return':
            return self.type
        if 'void' in self.type:
            return ''

        result = "%s : %s" % (self.type, self.name)

        return result

class String(Type):
    interface = 'string'
    buildstr = 's'
    error_value = "return NULL;"

    def __init__(self, name, type):
        Type.__init__(self, name, type)
        self.length = "strlen(%s)" % name

    def byref(self):
        return "&%s" % self.name

    def to_python_object(self, name=None, result='py_result',**kw):
        name = name or self.name

        result = """PyErr_Clear();
   if(!%(name)s) { PyErr_Format(PyExc_RuntimeError, "%(name)s is NULL"); goto error; };
   %(result)s = PyString_FromStringAndSize((char *)%(name)s, %(length)s);\nif(!%(result)s) goto error;
""" % dict(name=name, result=result,length=self.length)

        if "BORROWED" not in self.attributes and 'BORROWED' not in kw:
            result += "talloc_unlink(NULL, %s);\n" % name

        return result

    def from_python_object(self, source, destination, method, context='NULL'):
        method.error_set = True
        return """
{
  char *buff; Py_ssize_t length;

  PyErr_Clear();
  if(-1==PyString_AsStringAndSize(%(source)s, &buff, &length))
     goto error;

  %(destination)s = talloc_size(%(context)s, length + 1);
  memcpy(%(destination)s, buff, length);
  %(destination)s[length]=0;
};
""" % dict(source = source, destination = destination, context =context)

class ZString(String):
    interface = 'null_terminated_string'

class BorrowedString(String):
    def to_python_object(self, name=None, result='py_result', **kw):
        name = name or self.name
        return "PyErr_Clear();\n" +\
            "%s = PyString_FromStringAndSize((char *)%(name)s, %(length)s);\n" % dict(
            name=name, length=self.length, result=result)

class Char_and_Length(Type):
    interface = 'char_and_length'
    buildstr = 's#'
    error_value = "return NULL;"

    def __init__(self, data, data_type, length, length_type):
        Type.__init__(self, data, data_type)

        self.name = data
        self.data_type=data_type
        self.length = length
        self.length_type = length_type

    def comment(self):
        return "%s %s, %s %s" % (self.data_type, self.name,
                                 self.length_type, self.length)

    def definition(self, default = '""', **kw):
        return "char *%s=%s; Py_ssize_t %s=strlen(%s);\n" % (
            self.name, default,
            self.length, default)

    def byref(self):
        return "&%s, &%s" % (self.name, self.length)

    def call_arg(self):
        return "(%s)%s, (%s)%s" % (self.data_type, self.name, self.length_type,
                                   self.length)

    def to_python_object(self, name=None, result='py_result', **kw):
        return "PyErr_Clear();\n"\
            "%s = PyString_FromStringAndSize(%s, %s);\nif(!%s) goto error;" % (
            result, self.name, self.length, result);

class Integer(Type):
    interface = 'integer'
    buildstr = 'K'

    def __init__(self, name,type):
        Type.__init__(self,name,type)
        self.type = 'uint64_t'
        self.original_type = type

    def definition(self, default = 0, **kw):
        return Type.definition(self, default)

    def to_python_object(self, name=None, result='py_result', **kw):
        name = name or self.name
        return "PyErr_Clear();\n%s = PyLong_FromLongLong(%s);\n" % (result, name)

    def from_python_object(self, source, destination, method, **kw):
        return "PyErr_Clear();\n"\
            "%(destination)s = PyLong_AsUnsignedLong(%(source)s);\n" % dict(
            source = source, destination= destination)

    def comment(self):
        return "%s %s " % (self.original_type, self.name)

class Integer32(Integer):
    buildstr = 'I'

    def __init__(self, name,type):
        Type.__init__(self,name,type)
        self.type = 'unsigned int '
        self.original_type = type

    def to_python_object(self, name=None, result='py_result', **kw):
        name = name or self.name
        return "PyErr_Clear();\n%s = PyLong_FromLong(%s);\n" % (result, name)

class Integer64(Integer):
    buildstr = 'K'
    type = 'unsigned int'

class Char(Integer):
    buildstr = "s"
    interface = 'small_integer'

    def to_python_object(self, name = None, result = 'py_result', **kw):
        ## We really want to return a string here
        return """{ char *str_%(name)s = &%(name)s;
    PyErr_Clear();
    %(result)s = PyString_FromStringAndSize(str_%(name)s, 1);
if(!%(result)s) goto error;
};
""" % dict(result=result, name = name or self.name)

    def definition(self, default = '"\\x0"', **kw):
        ## Shut up unused warnings
        return "char %s __attribute__((unused))=0;\nchar *str_%s __attribute__((unused)) = %s;\n" % (
            self.name,self.name, default)

    def byref(self):
        return "&str_%s" % self.name

    def pre_call(self, method):
        method.error_set = True
        return """
if(strlen(str_%(name)s)!=1) {
  PyErr_Format(PyExc_RuntimeError,
          "You must only provide a single character for arg %(name)r");
  goto error;
};

%(name)s = str_%(name)s[0];
""" % dict(name = self.name)

class StringOut(String):
    sense = 'OUT'

class IntegerOut(Integer):
    sense = 'OUT_DONE'
    buildstr = ''

    def python_name(self):
        return None

    def byref(self):
        return ''

    def call_arg(self):
        return "&%s" % self.name

class Integer32Out(Integer32):
    sense = 'OUT_DONE'
    buildstr = ''

    def python_name(self):
        return None

    def byref(self):
        return ''

    def call_arg(self):
        return "&%s" % self.name

class Char_and_Length_OUT(Char_and_Length):
    sense = 'OUT_DONE'
    buildstr = 'l'

    def definition(self, default = 0, **kw):
        return "char *%s=NULL; Py_ssize_t %s=%s;\n" % (
            self.name,
            self.length, default) + "PyObject *tmp_%s;\n" % self.name

    def python_name(self):
        return self.length

    def byref(self):
        return "&%s" % self.length

    def pre_call(self, method):
        return """PyErr_Clear();
tmp_%s = PyString_FromStringAndSize(NULL, %s);
if(!tmp_%s) goto error;
PyString_AsStringAndSize(tmp_%s, &%s, (Py_ssize_t *)&%s);
""" % (self.name, self.length, self.name, self.name, self.name, self.length)

    def to_python_object(self, name=None, result='py_result', sense='in', **kw):
        name = name or self.name
        if 'results' in kw:
            kw['results'].pop(0)

        if sense=='proxied':
            return "py_%s = PyLong_FromLong(%s);\n" % (self.name, self.length)

        return  """if(func_return > %(length)s) {
  func_return = 0;
};

_PyString_Resize(&tmp_%(name)s, func_return); \n%(result)s = tmp_%(name)s;\n""" % \
            dict(name= name, result= result, length=self.length)


    def python_proxy_post_call(self, result='py_result'):
        return """
{
    char *tmp_buff; int tmp_len;
    if(-1==PyString_AsStringAndSize(%(result)s, &tmp_buff, &tmp_len)) goto error;

    memcpy(%(name)s,tmp_buff, tmp_len);
    Py_DECREF(%(result)s);
    %(result)s = PyLong_FromLong(tmp_len);
};
""" % dict(result = result, name=self.name)

class TDB_DATA_P(Char_and_Length_OUT):
    bare_type = "TDB_DATA"

    def __init__(self, name, type):
        Type.__init__(self, name, type)

    def definition(self, default=None, **kw):
        return Type.definition(self)

    def byref(self):
        return "%s.dptr, &%s.dsize" % (self.name, self.name)

    def pre_call(self, method):
        return ''

    def call_arg(self):
        return Type.call_arg(self)

    def to_python_object(self, name=None,result='py_result', **kw):
        name = name or self.name
        return "PyErr_Clear();"\
            "%s = PyString_FromStringAndSize((char *)%s->dptr, %s->dsize);"\
            "\ntalloc_free(%s);" % (result,
                                    name, name, name)

    def from_python_object(self, source, destination, method, **kw):
        method.error_set = True
        return """
%(destination)s = talloc(self, %(bare_type)s);
{ Py_ssize_t tmp; char *buf;

  PyErr_Clear();
  if(-1==PyString_AsStringAndSize(%(source)s, &buf, &tmp)) {
  goto error;
};

  // Take a copy of the python string
  %(destination)s->dptr = talloc_memdup(%(destination)s, buf, tmp);
  %(destination)s->dsize = tmp;
}
// We no longer need the python object
Py_DECREF(%(source)s);
""" % dict(source = source, destination = destination, 
           bare_type = self.bare_type)

class TDB_DATA(TDB_DATA_P):
    def to_python_object(self, name = None, result='py_result', **kw):
        name = name or self.name

        return "PyErr_Clear();\n"\
            "%s = PyString_FromStringAndSize((char *)%s.dptr, %s.dsize);\n" % (
            result,
            name, name)

class Void(Type):
    buildstr = ''
    error_value = "return;"
    original_type = ''

    def __init__(self, *args):
        Type.__init__(self, None, 'void *')

    def definition(self, default = None, **kw):
        return ''

    def to_python_object(self, name=None, result = 'py_result', **kw):
        return "Py_INCREF(Py_None); py_result = Py_None;\n"

    def call_arg(self):
        return "NULL"

    def byref(self):
        return None

    def assign(self, call, method, target=None):
        ## We dont assign the result to anything
        return "Py_BEGIN_ALLOW_THREADS\n%s;\nPy_END_ALLOW_THREADS\n" % call

    def return_value(self, value):
        return "return;"

class StringArray(String):
    interface = 'array'
    buildstr = 'O'

    def definition(self, default = '""', **kw):
        return "char **%s=NULL; PyObject *py_%s=NULL;\n" % (
            self.name, self.name)

    def byref(self):
        return "&py_%s" % (self.name)

    def from_python_object(self, source, destination, method, context='NULL'):
        method.error_set = True
        return """{
Py_ssize_t i,size=0;

if(%(source)s) {
   if(!PySequence_Check(%(source)s)) {
     PyErr_Format(PyExc_ValueError, "%(destination)s must be a sequence");
     goto error;
   };

   size = PySequence_Size(%(source)s);
};

%(destination)s = talloc_zero_array(NULL, char *, size + 1);

for(i=0; i<size;i++) {
 PyObject *tmp = PySequence_GetItem(%(source)s, i);
 if(!tmp) goto error;
 %(destination)s[i] = PyString_AsString(tmp);
 if(!%(destination)s[i]) {
   Py_DECREF(tmp);
   goto error;
 };
 Py_DECREF(tmp);
};

};""" % dict(source = source, destination = destination, context = context)

    def pre_call(self, method):
        return self.from_python_object("py_%s" % self.name, self.name, method)

    def error_condition(self):
        return """if(%s) talloc_free(%s);\n""" % (self.name, self.name)

class Wrapper(Type):
    """ This class represents a wrapped C type """
    sense = 'IN'
    error_value = "return NULL;"

    def from_python_object(self, source, destination, method, **kw):
        return """
/* First check that the returned value is in fact a Wrapper */
if(!type_check(%(source)s, &%(type)s_Type)) {
  PyErr_Format(PyExc_RuntimeError, "function must return an %(type)s instance");
  goto error;
};

%(destination)s = ((Gen_wrapper *)%(source)s)->base;
""" % dict(source = source, destination = destination, type = self.type)

    def to_python_object(self, **kw):
        return ''

    def returned_python_definition(self, default = 'NULL', sense='in', **kw):
        return "%s %s;\n" % (self.type, self.name)

    def definition(self, default = 'NULL', sense='in', **kw):
        result = "Gen_wrapper *%s __attribute__((unused)) = %s;\n" % (self.name, default)
        if sense == 'in' and not 'OUT' in self.attributes:
            result += " %s __attribute__((unused)) call_%s;\n" % (self.type, self.name)

        return result

    def call_arg(self):
        return "call_%s" % self.name

    def pre_call(self, method):
        if 'OUT' in self.attributes or self.sense == 'OUT':
            return ''

        return """
if(!%(name)s || (PyObject *)%(name)s==Py_None) {
   call_%(name)s = NULL;
} else if(!type_check((PyObject *)%(name)s,&%(type)s_Type)) {
     PyErr_Format(PyExc_RuntimeError, "%(name)s must be derived from type %(type)s");
     goto error;
} else {
   call_%(name)s = %(name)s->base;
};\n""" % self.__dict__

    def assign(self, call, method, target=None):
        method.error_set = True;
        args = dict(name = target or self.name, call = call, type = self.type)

        result = """{
       Object returned_object;

       ClearError();

       Py_BEGIN_ALLOW_THREADS
       returned_object = (Object)%(call)s;
       Py_END_ALLOW_THREADS

       CHECK_ERROR;
""" % args

        ## Is NULL an acceptable return type? In some python code NULL
        ## can be returned (e.g. in iterators) but usually it should
        ## be converted to None.
        if "NULL_OK" in self.attributes:
            result += """if(returned_object == NULL) {
     %(name)s = NULL; """ % args
        else:
            result += """
       // A NULL return without errors means we return None
       if(!returned_object) {
         %(name)s = (Gen_wrapper *)Py_None;
         Py_INCREF(Py_None);
""" % args

        result += """
       } else {
         //printf("%%s: Wrapping %%s@%%p\\n", __FUNCTION__, NAMEOF(returned_object), returned_object);
         %(name)s = new_class_wrapper(returned_object);
         if(!%(name)s) goto error;
""" % args

        if "BORROWED" in self.attributes:
            result += "           talloc_reference(%(name)s->ctx, %(name)s->base);\n" % args

        result += """       };
    }
"""
        return result

    def to_python_object(self, name=None, result = 'py_result', sense='in', **kw):
        name = name or self.name
        args = dict(result=result,
                    name = name)

        if sense=='proxied':
            return "%(result)s = (PyObject *)new_class_wrapper((Object)%(name)s);\n" % args

        return "%(result)s = (PyObject *)%(name)s;\n" % args

class PointerWrapper(Wrapper):
    """ A pointer to a wrapped class """
    def __init__(self, name, type):
        type = type.split()[0]
        Wrapper.__init__(self,name, type)

    def definition(self, default = 'NULL', sense='in', **kw):
        result = "Gen_wrapper *%s = %s;" % (self.name, default)
        if sense == 'in' and not 'OUT' in self.attributes:
            result += " %s *call_%s;\n" % (self.type, self.name)

        return result

    def pre_call(self, method):
        if 'OUT' in self.attributes or self.sense == 'OUT':
            return ''

        return """
if(!%(name)s || (PyObject *)%(name)s==Py_None) {
   call_%(name)s = NULL;
} else if(!type_check((PyObject *)%(name)s,&%(type)s_Type)) {
     PyErr_Format(PyExc_RuntimeError, "%(name)s must be derived from type %(type)s");
     goto error;
} else {
   call_%(name)s = (%(type)s *)&%(name)s->base;
};\n""" % self.__dict__

class StructWrapper(Wrapper):
    """ A wrapper for struct classes """
    def assign(self, call, method, target = None):
        args = dict(name = target or self.name, call = call, type = self.type)
        result = """
PyErr_Clear();
%(name)s = (Gen_wrapper *)PyObject_New(py%(type)s, &%(type)s_Type);
%(name)s->ctx = talloc_size(NULL, 1);
%(name)s->base = %(call)s;
""" % args

        if "NULL_OK" in self.attributes:
            result += "if(!%(name)s->base) { Py_DECREF(%(name)s); return NULL; };" % args

        result += """
// A NULL object gets translated to a None
 if(!%(name)s->base) {
   Py_DECREF(%(name)s);
   Py_INCREF(Py_None);
   %(name)s = (Gen_wrapper *)Py_None;
 } else {
""" % args

        if "FOREIGN" in self.attributes:
            result += '// Not taking references to foreign memory\n'
        elif "BORROWED" in self.attributes:
            result += "talloc_reference(%(name)s->ctx, %(name)s->base);\n" % args
        else:
            result += "talloc_steal(%(name)s->ctx, %(name)s->base);\n" % args

        result += "}\n"

        return result

    def byref(self):
        return "&%s" % self.name

    def definition(self, default = 'NULL', sense='in', **kw):
        result = "Gen_wrapper *%s = %s;" % (self.name, default)
        if sense == 'in' and not 'OUT' in self.attributes:
            result += " %s *call_%s;\n" % (self.type, self.name)

        return result;

class PointerStructWrapper(StructWrapper):
    def __init__(self, name, type):
        type = type.split()[0]
        Wrapper.__init__(self,name, type)

class Timeval(Type):
    """ handle struct timeval values """
    interface = 'numeric'
    buildstr = 'f'

    def definition(self, default = None, **kw):
        return "float %(name)s_flt; struct timeval %(name)s;\n" % self.__dict__

    def byref(self):
        return "&%s_flt" % self.name

    def pre_call(self, method):
        return "%(name)s.tv_sec = (int)%(name)s_flt; %(name)s.tv_usec = (%(name)s_flt - %(name)s.tv_sec) * 1e6;\n" % self.__dict__

    def to_python_object(self, name=None, result = 'py_result', **kw):
        name = name or self.name
        return """%(name)s_flt = (double)(%(name)s.tv_sec) + %(name)s.tv_usec;
%(result)s = PyFloat_FromDouble(%(name)s_flt);
""" % dict(name = name, result=result)

class PyObject(Type):
    """ Accept an opaque python object """
    interface = 'opaque'
    buildstr = 'O'
    def definition(self, default = 'NULL', **kw):
        self.default = default
        return 'PyObject *%(name)s = %(default)s;\n' % self.__dict__

    def byref(self):
        return "&%s" % self.name

type_dispatcher = {
    "IN char *": String,
    "IN unsigned char *": String,
    "unsigned char *": String,
    "char *": String,
    "ZString": ZString,

    "OUT char *": StringOut,
    "OUT unsigned char *": StringOut,
    "unsigned int": Integer,
    'int': Integer,
    'OUT uint64_t *': IntegerOut,
    'OUT uint32_t *': Integer32Out,
    'char': Char,
    'void': Void,
    'void *': Void,

    'TDB_DATA *': TDB_DATA_P,
    'TDB_DATA': TDB_DATA,
    'uint64_t': Integer,
    'uint32_t': Integer32,
    'time_t': Integer32,
    'uint16_t': Integer,
    'uint8_t': Integer,
    'int64_t': Integer,
    'ssize_t': Integer,
    'size_t': Integer,
    'unsigned long int': Integer,
    'struct timeval': Timeval,
    'char **': StringArray,

    'PyObject *': PyObject,
    }

method_attributes = ['BORROWED', 'DESTRUCTOR','IGNORE']

def dispatch(name, type):
    if not type: return Void()

    m = re.match("struct ([a-zA-Z0-9]+)_t *", type)
    if m:
        type = m.group(1)

    type_components = type.split()
    attributes = set()

    if type_components[0] in method_attributes:
        attributes.add(type_components.pop(0))

    type = " ".join(type_components)
    result = type_dispatcher[type](name, type)

    result.attributes = attributes

    return result

class ResultException:
    value = 0
    exception = "PyExc_IOError"

    def __init__(self, check, exception, message):
        self.check = check
        self.exception = exception
        self.message = message

    def write(self, out):
        out.write("\n//Handle exceptions\n")
        out.write("if(%s) {\n    PyErr_Format(PyExc_%s, %s);\n  goto error; \n};\n\n" % (
                self.check, self.exception, self.message))

class Method:
    default_re = re.compile("DEFAULT\(([A-Z_a-z0-9]+)\) =(.+)")
    exception_re = re.compile("RAISES\(([^,]+),\s*([^\)]+)\) =(.+)")
    typedefed_re = re.compile(r"struct (.+)_t \*")

    def __init__(self, class_name, base_class_name, method_name, args, return_type,
                 myclass = None):
        self.name = method_name
        ## myclass needs to be a class generator
        if not isinstance(myclass, ClassGenerator): raise RuntimeError("myclass must be a class generator")

        self.myclass = myclass
        self.docstring = ''
        self.defaults = {}
        self.exception = None
        self.error_set = False
        self.class_name = class_name
        self.base_class_name = base_class_name
        self.args = []
        self.definition_class_name = class_name
        for type,name in args:
            self.add_arg(type, name)

        try:
            self.return_type = dispatch('func_return', return_type)
            self.return_type.attributes.add("OUT")
            self.return_type.original_type = return_type
        except KeyError:
            ## Is it a wrapped type?
            if return_type:
                log("Unable to handle return type %s.%s %s" % (self.class_name, self.name, return_type))
                #pdb.set_trace()
            self.return_type = Void()

    def clone(self, new_class_name):
        self.find_optional_vars()

        result = self.__class__(new_class_name, self.base_class_name, self.name,
                                [], 'void *',
                                myclass = self.myclass)
        result.args = self.args
        result.return_type = self.return_type
        result.definition_class_name = self.definition_class_name
        result.defaults = self.defaults
        result.exception = self.exception

        return result

    def find_optional_vars(self):
        for line in self.docstring.splitlines():
            m =self.default_re.search(line)
            if m:
                name = m.group(1)
                value = m.group(2)
                log("Setting default value for %s of %s" % (m.group(1),
                                                            m.group(2)))
                self.defaults[name] = value

            m =self.exception_re.search(line)
            if m:
                self.exception = ResultException(m.group(1), m.group(2), m.group(3))

    def write_local_vars(self, out):
        self.find_optional_vars()

        ## We do it in two passes - first mandatory then optional
        kwlist = """static char *kwlist[] = {"""
        ## Mandatory
        for type in self.args:
            python_name = type.python_name()
            if python_name and python_name not in self.defaults:
                kwlist += '"%s",' % python_name

        for type in self.args:
            python_name = type.python_name()
            if python_name and python_name in self.defaults:
                kwlist += '"%s",' % python_name

        kwlist += ' NULL};\n'

        for type in self.args:
            python_name = type.python_name()
            try:
                out.write(type.definition(default = self.defaults[python_name]))
            except KeyError:
                out.write(type.definition())

        ## Make up the format string for the parse args in two pases
        parse_line = ''
        for type in self.args:
            python_name = type.python_name()
            if type.buildstr and python_name not in self.defaults:
                parse_line += type.buildstr

        parse_line += '|'
        for type in self.args:
            python_name = type.python_name()
            if type.buildstr and python_name in self.defaults:
                parse_line += type.buildstr

        if parse_line != '|':
            ## Now parse the args from python objects
            out.write(kwlist)
            out.write("\nif(!PyArg_ParseTupleAndKeywords(args, kwds, \"%s\", kwlist, " % parse_line)
            tmp = []
            for type in self.args:
                ref = type.byref()
                if ref:
                    tmp.append(ref)

            out.write(",".join(tmp))
            self.error_set = True
            out.write("))\n goto error;\n\n")

    def error_condition(self):
        result = ""
        if "DESTRUCTOR" in self.return_type.attributes:
            result += "talloc_free(self->ctx); self->base = NULL;\n"

        return result +"return NULL;\n";

    def write_definition(self, out):
        args = dict(method = self.name, class_name = self.class_name)
        out.write("\n/********************************************************\nAutogenerated wrapper for function:\n")
        out.write(self.comment())
        out.write("********************************************************/\n")

        self._prototype(out)
        out.write("""{
       PyObject *returned_result, *py_result;
""" % args)

        out.write(self.return_type.definition())

        self.write_local_vars( out);

        out.write("""// Make sure that we have something valid to wrap
if(!self->base) return PyErr_Format(PyExc_RuntimeError, "%(class_name)s object no longer valid");
""" % args)

        ## Precall preparations
        out.write("// Precall preparations\n")
        out.write(self.return_type.pre_call(self))
        for type in self.args:
            out.write(type.pre_call(self))

        out.write("""// Check the function is implemented
  {  void *method = ((%(def_class_name)s)self->base)->%(method)s;
     if(!method || (void *)unimplemented == (void *)method) {
         PyErr_Format(PyExc_RuntimeError, "%(class_name)s.%(method)s is not implemented");
         goto error;
     };
  };
""" % dict(def_class_name = self.definition_class_name, method=self.name,
           class_name = self.class_name))

        out.write("\n// Make the call\n ClearError();")
        call = "((%s)self->base)->%s(((%s)self->base)" % (self.definition_class_name, self.name, self.definition_class_name)
        tmp = ''
        for type in self.args:
            tmp += ", " + type.call_arg()

        call += "%s)" % tmp

        ## Now call the wrapped function
        out.write(self.return_type.assign(call, self))
        if self.exception:
            self.exception.write(out)

        self.error_set = True

        out.write("\n// Postcall preparations\n")
        ## Postcall preparations
        out.write(self.return_type.post_call(self))
        for type in self.args:
            out.write(type.post_call(self))

        ## Now assemble the results
        results = [self.return_type.to_python_object()]
        for type in self.args:
            if type.sense == 'OUT_DONE':
                results.append(type.to_python_object(results = results))

        ## If all the results are returned by reference we dont need
        ## to prepend the void return value at all.
        if isinstance(self.return_type, Void) and len(results)>1:
            results.pop(0)

        out.write("\n// prepare results\n")
        ## Make a tuple of results and pass them back
        if len(results)>1:
            out.write("returned_result = PyList_New(0);\n")
            for result in results:
                out.write(result)
                out.write("PyList_Append(returned_result, py_result); Py_DECREF(py_result);\n");
            out.write("return returned_result;\n")
        else:
            out.write(results[0])
            ## This useless code removes compiler warnings
            out.write("returned_result = py_result;\nreturn returned_result;\n");

        ## Write the error part of the function
        if self.error_set:
            out.write("\n// error conditions:\n")
            out.write("error:\n    " + self.error_condition());

        out.write("\n};\n\n")

    def add_arg(self, type, name):
        try:
            t = type_dispatcher[type](name, type)
        except KeyError:
            ## Sometimes types must be typedefed in advance
            try:
                m = self.typedefed_re.match(type)
                type = m.group(1)
                log( "Trying %s for %s" % (type, m.group(0)))
                t = type_dispatcher[type](name, type)
            except (KeyError, AttributeError):
                log( "Unable to handle type %s.%s %s" % (self.class_name, self.name, type))
                return

        ## Here we collapse char * + int type interfaces into a
        ## coherent string like interface.
        try:
            previous = self.args[-1]
            if t.interface == 'integer' and \
                    previous.interface == 'string':

                ## We make a distinction between IN variables and OUT
                ## variables
                if previous.sense == 'OUT':
                    cls = Char_and_Length_OUT
                else:
                    cls = Char_and_Length


                cls = cls(
                    previous.name,
                    previous.type,
                    name, type)

                self.args[-1] = cls

                return
        except IndexError:
            pass

        self.args.append(t)

    def comment(self):
        result = self.return_type.original_type+" "+self.class_name+"."+self.name+"("
        args = []
        for type in self.args:
            args.append( type.comment())

        result += ",".join(args) + ");\n"

        return result

    def prototype(self, out):
        self._prototype(out)
        out.write(";\n")

    def _prototype(self, out):
        out.write("""static PyObject *py%(class_name)s_%(method)s(py%(class_name)s *self, PyObject *args, PyObject *kwds) """ % dict(method = self.name, class_name = self.class_name))

    def __str__(self):
        result = "def %s %s(%s):" % (
            self.return_type,
            self.name, ' , '.join([a.__str__() for a in self.args]))
        return result

    def PyMethodDef(self, out):
        docstring = self.comment() + "\n\n" + self.docstring
        out.write('     {"%s",(PyCFunction)py%s_%s, METH_VARARGS|METH_KEYWORDS, "%s"},\n' % (
                self.name,
                self.class_name,
                self.name, escape_for_string(docstring)))

class IteratorMethod(Method):
    """ A Method which implements an iterator """
    def __init__(self, *args, **kw):
        Method.__init__(self, *args, **kw)

        ## Tell the return type that a NULL python return is ok
        self.return_type.attributes.add("NULL_OK")

    def _prototype(self, out):
        out.write("""static PyObject *py%(class_name)s_%(method)s(py%(class_name)s *self)""" % dict(method = self.name, class_name = self.class_name))

    def __str__(self):
        result = "Iterator returning %s." % (
            self.return_type)
        return result

    def PyMethodDef(self, out):
        ## This method should not go in the method table as its linked
        ## in directly
        pass

class SelfIteratorMethod(IteratorMethod):
    def write_definition(self, out):
        args = dict(method = self.name, class_name = self.class_name)
        out.write("\n/********************************************************\nAutogenerated wrapper for function:\n")
        out.write(self.comment())
        out.write("********************************************************/\n")

        self._prototype(out)
        out.write("""{
          ((%(class_name)s)self->base)->%(method)s((%(class_name)s)self->base);
          return PyObject_SelfIter((PyObject *)self);
};
""" % args)

class ConstructorMethod(Method):
    ## Python constructors are a bit different than regular methods
    def _prototype(self, out):
        out.write("""
static int py%(class_name)s_init(py%(class_name)s *self, PyObject *args, PyObject *kwds)
""" % dict(method = self.name, class_name = self.class_name))

    def write_destructor(self, out):
        ## We make sure that we unlink exactly the reference we need
        ## (the object will persist if it has some other
        ## references). Note that if we just used talloc_free here it
        ## will remove some random reference which may not actually be
        ## the reference we own (which is NULL).
        free = """
    if(self->base) {
        //printf("Unlinking %s@%p\\n", NAMEOF(self->base), self->base);
        talloc_free(self->ctx);
        self->base=NULL;
    };
"""
        out.write("""static void
%(class_name)s_dealloc(py%(class_name)s *self) {
%(free)s
 PyObject_Del(self);
};\n
""" % dict(class_name = self.class_name, free=free))

    def error_condition(self):
        return "return -1;";

    def write_definition(self, out):
        self._prototype(out)
        out.write("""{\n""")
        self.write_local_vars(out)

        ## Precall preparations
        for type in self.args:
            out.write(type.pre_call(self))

        ## Now call the wrapped function
        out.write("\nself->ctx = talloc_strdup(NULL, \"%s\");" % self.class_name)
        out.write("\n ClearError();\nPy_BEGIN_ALLOW_THREADS\nself->base = CONSTRUCT(%s, %s, %s, self->ctx" % (
                self.class_name,
                self.definition_class_name,
                self.name))
        tmp = ''
        for type in self.args:
            tmp += ", " + type.call_arg()

        self.error_set = True
        out.write("""%s);\nPy_END_ALLOW_THREADS\n
       if(!CheckError(EZero)) {
         char *buffer;
         PyObject *exception = resolve_exception(&buffer);

         PyErr_Format(exception,
                    "%%s", buffer);
         ClearError();
         goto error;
  } else if(!self->base) {
    PyErr_Format(PyExc_IOError, "Unable to construct class %s");
    goto error;
  };
""" % (tmp, self.class_name))

        out.write("  return 0;\n");

        ## Write the error part of the function
        if self.error_set:
            out.write("error:\n    " + self.error_condition());

        out.write("\n};\n\n")

class GetattrMethod(Method):
    def __init__(self, class_name, base_class_name, myclass):
        self.base_class_name = base_class_name
        self._attributes = []
        self.error_set = True
        self.return_type = Void()
        self.myclass = myclass
        self.rename_class_name(class_name)

    def add_attribute(self, attr):
        if attr.name:
            self._attributes.append([self.class_name, attr])

    def rename_class_name(self, new_name):
        """ This allows us to rename the class_name at a later stage.
        Required for late initialization of Structs whose name is not
        know until much later on.
        """
        self.class_name = new_name
        self.name = "py%s_getattr" % new_name
        for x in self._attributes:
            x[0] = new_name

    def get_attributes(self):
        for class_name, attr in self._attributes:
            try:
                if not self.myclass.module.classes[attr.type].active:
                    continue
            except KeyError: pass

            yield class_name, attr

    def __str__(self):
        result = ""
        for class_name, attr in self.get_attributes():
            result += "    %s\n" % attr.__str__()

        return result


    def clone(self, class_name):
        result = self.__class__(class_name, self.base_class_name, self.myclass)
        result._attributes = self._attributes[:]

        return result

    def prototype(self, out):
        if self.name:
            out.write("""
static PyObject *%(name)s(py%(class_name)s *self, PyObject *name);
""" % self.__dict__)

    def built_ins(self, out):
        """ check for some built in attributes we need to support """
        out.write("""  if(!strcmp(name, "__members__")) {
     PyObject *result = PyList_New(0);
     PyObject *tmp;
     PyMethodDef *i;

     if(!result) goto error;
""")
        ## Add attributes
        for class_name, attr in self.get_attributes():
            out.write(""" tmp = PyString_FromString("%(name)s");
    PyList_Append(result, tmp); Py_DECREF(tmp);
""" % dict(name = attr.name))

        ## Add methods
        out.write("""

    for(i=%s_methods; i->ml_name; i++) {
     tmp = PyString_FromString(i->ml_name);
    PyList_Append(result, tmp); Py_DECREF(tmp);
    }; """ % self.class_name)

        out.write("""
     return result; 
   }\n""")

    def write_definition(self, out):
        if not self.name: return
        out.write("""
static PyObject *py%(class_name)s_getattr(py%(class_name)s *self, PyObject *pyname) {
  char *name;
  // Try to hand it off to the python native handler first
  PyObject *result = PyObject_GenericGetAttr((PyObject*)self, pyname);

  if(result) return result;

  PyErr_Clear();
  // No - nothing interesting was found by python
  name = PyString_AsString(pyname);

  if(!self->base) return PyErr_Format(PyExc_RuntimeError, "Wrapped object (%(class_name)s.%(name)s) no longer valid");
  if(!name) return NULL;
""" % self.__dict__)

        self.built_ins(out)

        for class_name, attr in self.get_attributes():
            ## what we want to assign
            if self.base_class_name:
                call = "(((%s)self->base)->%s)" % (class_name, attr.name)
            else:
                call = "(self->base->%s)" % (attr.name)

            out.write("""
if(!strcmp(name, "%(name)s")) {
    PyObject *py_result;
    %(python_def)s

    %(python_assign)s
    %(python_obj)s
    return py_result;
};""" % dict(name = attr.name, python_obj = attr.to_python_object(),
             python_assign = attr.assign(call, self),
             python_def = attr.definition(sense='out')))

        out.write("""

  return PyObject_GenericGetAttr((PyObject *)self, pyname);
""" % self.__dict__)

        ## Write the error part of the function
        if self.error_set:
            out.write("error:\n" + self.error_condition());

        out.write("}\n\n")

class ProxiedGetattr(GetattrMethod):
    def built_ins(self,out):
        out.write("""  if(!strcmp(name, "__members__")) {
     PyObject *result;
     PyObject *tmp;
     PyMethodDef *i;

     PyErr_Clear();
     // Get the list of members from our proxied object
     result  = PyObject_GetAttrString(self->base->proxied, name);
     if(!result) goto error;
""")
        ## Add attributes
        for class_name, attr in self.get_attributes():
            out.write(""" tmp = PyString_FromString("%(name)s");
    PyList_Append(result, tmp); Py_DECREF(tmp);
""" % dict(name = attr.name))

        ## Add methods
        out.write("""

    for(i=%s_methods; i->ml_name; i++) {
     tmp = PyString_FromString(i->ml_name);
    PyList_Append(result, tmp); Py_DECREF(tmp);
    }; """ % self.class_name)

        out.write("""
     return result;
   }\n""")

        out.write(""" /** Just try to get the attribute from our proxied object */  {
   PyObject *result = PyObject_GetAttrString(self->base->proxied, name);
   if(result) return result;
}; """)

class ProxiedMethod(Method):
    def __init__(self, method, myclass):
        self.name = method.name
        self.method = method
        self.myclass = myclass
        self.class_name = method.class_name
        self.base_class_name = method.base_class_name
        self.args = method.args
        self.definition_class_name = method.definition_class_name
        self.return_type = method.return_type
        self.docstring = "Proxy for %s" % self.name
        self.defaults = {}
        self.exception = None
        self.error_set = False

    def get_name(self):
        return "py%(class_name)s_%(name)s" % dict(class_name =self.myclass.class_name,
                                                  name = self.name)

    def _prototype(self, out):
        out.write("""
static %(return_type)s %(name)s(%(definition_class_name)s self""" % dict(
                return_type = self.return_type.original_type,
                class_name = self.myclass.class_name,
                method = self.name,
                name = self.get_name(),
                definition_class_name = self.definition_class_name))

        for arg in self.args:
            out.write(", %s" % (arg.comment()))

        out.write(")")

    def prototype(self, out):
        self._prototype(out)
        out.write(";\n")

    def write_definition(self, out):
        self._prototype(out)
        self._write_definition(out)

    def _write_definition(self, out):
        ## We need to grab the GIL before we do anything
        out.write("""{
      //Grab the GIL so we can do python stuff
      PyGILState_STATE gstate;
      gstate = PyGILState_Ensure();
      """)

        out.write("{\nPyObject *py_result=NULL;\n")
        out.write('PyObject *method_name = PyString_FromString("%s");\n' % self.name)
        out.write(self.return_type.returned_python_definition())

        for arg in self.args:
            out.write("PyObject *py_%s=NULL;\n" % arg.name)

        out.write("\n//Obtain python objects for all the args:\n")
        for arg in self.args:
            out.write(arg.to_python_object(result = "py_%s" % arg.name,
                                           sense='proxied', BORROWED=True))

        out.write('if(!((%s)self)->proxied) {\n RaiseError(ERuntimeError, "No proxied object in %s"); goto error;\n};\n' % (self.myclass.class_name, self.myclass.class_name))

        out.write("\n//Now call the method\n")
        out.write("""PyErr_Clear();
py_result = PyObject_CallMethodObjArgs(((%s)self)->proxied,method_name,""" % self.myclass.class_name)
        for arg in self.args:
            out.write("py_%s," % arg.name)

        ## Sentinal
        self.error_set = True
        out.write("""NULL);

/** Check for python errors */
if(PyErr_Occurred()) {
   PyObject *exception_t, *exception, *tb;
   PyObject *str;
   char *str_c;
   char *error_str;
   enum _error_type *error_type = aff4_get_current_error(&error_str);

   // Fetch the exception state and convert it to a string:
   PyErr_Fetch(&exception_t, &exception, &tb);

   str = PyObject_Repr(exception);
   str_c = PyString_AsString(str);

   if(str_c) {
      strncpy(error_str, str_c, BUFF_SIZE-1);
      error_str[BUFF_SIZE-1]=0;
      *error_type = ERuntimeError;
   };
   Py_DECREF(str);
   goto error;
};

""");

        for arg in self.args:
            out.write(arg.python_proxy_post_call())

        ## Now convert the python value back to a value
        out.write(self.return_type.from_python_object('py_result',self.return_type.name, self, context = "self"))

        out.write("if(py_result) { Py_DECREF(py_result);};\nPy_DECREF(method_name);\n\n");
        out.write("PyGILState_Release(gstate);\n")

        ## Decref all our python objects:
        for arg in self.args:
            out.write("if(py_%s) { Py_DECREF(py_%s);};\n" %( arg.name, arg.name))

        out.write(self.return_type.return_value('func_return'))
        if self.error_set:
            out.write("\nerror:\n")
            out.write("if(py_result) { Py_DECREF(py_result);};\nPy_DECREF(method_name);\n\n");
            ## Decref all our python objects:
            for arg in self.args:
                out.write("if(py_%s) { Py_DECREF(py_%s);};\n" % (arg.name, arg.name))

            out.write("PyGILState_Release(gstate);\n %s;\n" % self.error_condition())

        out.write("   };\n};\n")

    def error_condition(self):
        return self.return_type.error_value

class StructConstructor(ConstructorMethod):
    """ A constructor for struct wrappers - basically just allocate
    memory for the struct.
    """
    def write_definition(self, out):
        out.write("""static int py%(class_name)s_init(py%(class_name)s *self, PyObject *args, PyObject *kwds) {\n""" % dict(method = self.name, class_name = self.class_name))
        out.write("\nself->ctx = talloc_strdup(NULL, \"%s\");" % self.class_name)
        out.write("\nself->base = talloc(self->ctx, %s);\n" % self.class_name)
        out.write("  return 0;\n};\n\n")

    def write_destructor(self, out):
        out.write("""static void
%(class_name)s_dealloc(py%(class_name)s *self) {
   talloc_free(self->ctx);
};\n
""" % dict(class_name = self.class_name))

class ProxyConstructor(ConstructorMethod):
    def write_destructor(self, out):
        out.write("""static void
%(class_name)s_dealloc(py%(class_name)s *self) {
    if(self->base) {
        // Release the proxied object
        //Py_DECREF(self->base->proxied);
        talloc_free(self->ctx);
        self->base = NULL;
    };
};\n

static int %(class_name)s_destructor(void *this) {
  py%(class_name)s *self = (py%(class_name)s *)this;
  Py_DECREF(self->base->proxied);
  return 0;
};
""" % dict(class_name = self.class_name))

    def initialise_attributes(self, out):
        attributes = self.myclass.module.classes[self.base_class_name].attributes.get_attributes()
        for definition_class_name, attribute in attributes:
            out.write("""
{
  // Converting from %(attribute_name)s
  PyErr_Clear();
  PyObject *py_result = PyObject_GetAttrString(self->base->proxied, "%(name)s");

  if(py_result) {
       %(type)s tmp;
       %(from_python_object)s;
       ((%(definition_class_name)s)self->base)->%(name)s = tmp;
       Py_DECREF(py_result);
  };
  PyErr_Clear();
};""" % dict(definition = attribute.definition(), name=attribute.name,
             attribute_name = attribute.__class__.__name__,
             type = attribute.type,
             definition_class_name = definition_class_name,
             from_python_object = attribute.from_python_object(
                        'py_result',"tmp", method=self,
                        context = 'self->base')))


    def write_constructor_proxy(self, out):
        ## Get the base_class constructor
        self.base_cons_method = ProxiedMethod(self.myclass.module.classes[self.base_class_name].constructor, self.myclass)

        self.base_cons_method._prototype(out)
        out.write("{\nPyObject *py_result;\n")
        out.write('PyObject *method_name;')
        out.write("%(class_name)s this = (%(class_name)s)self;\n" % self.__dict__)
        out.write("PyGILState_STATE gstate;\ngstate = PyGILState_Ensure();\n")
        out.write('method_name = PyString_FromString("__class__");\n')
        for arg in self.base_cons_method.args:
            out.write("PyObject *py_%s;\n" % arg.name)

        out.write("\n//Obtain python objects for all the args:\n")
        for arg in self.base_cons_method.args:
            out.write(arg.to_python_object(result = "py_%s" % arg.name,
                                           sense = 'proxied',
                                           BORROWED=True))

        out.write('if(!((%s)self)->proxied) {\n RaiseError(ERuntimeError, "No proxied object in %s"); goto error;\n};\n' % (self.myclass.class_name, self.myclass.class_name))

        out.write("""
// Enlarge the object size to accomodate the extended class
self = talloc_realloc_size(self, self, sizeof(struct %(base_class_name)s_t));
""" % self.__dict__)
        out.write("\n//Now call the method\n")
        out.write("PyErr_Clear();\npy_result = PyObject_CallMethodObjArgs(((%s)self)->proxied,method_name," % self.myclass.class_name)

        call = ''
        for arg in self.base_cons_method.args:
            call += "py_%s," % arg.name

        ## Sentinal
        self.error_set = True
        call += """NULL"""

        out.write(call + ");\n");
        out.write("""
if(!py_result && PyCallable_Check(this->proxied)) {
   PyErr_Clear();
   py_result = PyObject_CallFunctionObjArgs(((%(name)s)self)->proxied, %(call)s);
};

/** Check for python errors */
if(PyErr_Occurred()) {
   PyObject *exception_t, *exception, *tb;
   PyObject *str;
   char *str_c;
   char *error_str;
   enum _error_type *error_type = aff4_get_current_error(&error_str);

   // Fetch the exception state and convert it to a string:
   PyErr_Fetch(&exception_t, &exception, &tb);

   str = PyObject_Repr(exception);
   str_c = PyString_AsString(str);

   if(str_c) {
      strncpy(error_str, str_c, BUFF_SIZE-1);
      error_str[BUFF_SIZE-1]=0;
      *error_type = ERuntimeError;
   };
   Py_DECREF(str);
   goto error;
};

// Take over the proxied object now
this->proxied = py_result;
""" % dict(name=self.myclass.class_name, call = call));

        ## Now we try to populate the C struct slots with proxies of
        ## the python objects
        for class_name, attr in self.myclass.module.classes[\
            self.base_class_name].attributes.get_attributes():
            out.write("""
// Converting %(name)s from proxy:
{
   PyObject *py_result = PyObject_GetAttrString(this->proxied, "%(name)s");
   if(py_result) {
""" % dict(name = attr.name))
            out.write("{ %s " % attr.definition())
            out.write(attr.from_python_object("py_result",
                                              "((%s)self)->%s" % (class_name, attr.name),
                                              self))
            out.write("}\nPy_DECREF(py_result);\n};\n};\n")

        out.write("PyGILState_Release(gstate);\n")
        out.write("\n\nreturn self;\n")
        if self.error_set:
            out.write("error:\n PyGILState_Release(gstate);\ntalloc_free(self); return NULL;\n")

        out.write("};\n\n")

    def write_definition(self, out):
        self.write_constructor_proxy(out)
        out.write("""static int py%(class_name)s_init(py%(class_name)s *self, PyObject *args, PyObject *kwds) {
      PyGILState_STATE gstate = PyGILState_Ensure();
""" % dict(method = self.name, class_name = self.class_name))

        self.write_local_vars(out)

        ## Precall preparations
        for type in self.args:
            out.write(type.pre_call(self))

        ## Make up the call
        self.call = "talloc_memdup(NULL, &__%(class_name)s, sizeof(__%(class_name)s));\n" % self.__dict__

        ## Now call the wrapped function
        out.write("""
 self->base = %(call)s

// Take over a copy of the proxied object
 self->base->proxied = proxied;

 /* We take a reference to the proxied object, and the proxied base
 class takes a reference. This way we (the python object) and the
 proxied C class can be freed independantly and only when both are
 freed the proxied object is freed.  */

 //Py_INCREF(proxied);
 Py_INCREF(proxied);
 talloc_set_destructor((void*)self->base, %(class_name)s_destructor);
""" % self.__dict__)

        ## Install the handler for the constructor. FIXME - implement
        ## shortcut bypassing here so if the proxied class is itself a
        ## python binding to a C class and it does not override
        ## anything, we call directly into the original C class method
        ## instead of converting to python, and back.
        out.write("((%(definition_class_name)s)self->base)->%(name)s = %(func)s;\n" % dict(
                definition_class_name = self.base_cons_method.definition_class_name,
                name = self.base_cons_method.name,
                func = self.base_cons_method.get_name()))

        ## Now iterate over all our methods and install handlers:
        for method in self.myclass.methods:
            out.write("""
   if(1 || PyDict_GetItemString(proxied->ob_type->tp_dict, "%(name)s")) {
     ((%(definition_class_name)s)self->base)->%(name)s = py%(class_name)s_%(name)s;
   };
""" % dict(definition_class_name = method.definition_class_name,
           name = method.name,
           class_name = self.myclass.class_name))

        ## Now fill in all attributes from the proxied object. Since
        ## the C struct attribute access is just memory access its
        ## difficult to trap it and refill attributes dynamically from
        ## the python object. Therefore for now we just read all
        ## attributes initially and populate the C struct with them.
        self.initialise_attributes(out)

        out.write("\n   PyGILState_Release(gstate);\n  return 0;\n");

        ## Write the error part of the function
        if self.error_set:
            out.write("error:\n  PyGILState_Release(gstate);\n  " + self.error_condition());

        out.write("\n};\n\n")

class EmptyConstructor(ConstructorMethod):
    def write_definition(self, out):
        out.write("""static int py%(class_name)s_init(py%(class_name)s *self, PyObject *args, PyObject *kwds) {\n""" % dict(method = self.name, class_name = self.class_name))
        out.write("""return 0;};\n\n""")

class ClassGenerator:
    docstring = ''
    def __init__(self, class_name, base_class_name, module):
        self.class_name = class_name
        self.methods = []
        self.module = module
        self.constructor = EmptyConstructor(class_name, base_class_name,
                                             "Con", [], '', myclass = self)

        self.base_class_name = base_class_name
        self.attributes = GetattrMethod(self.class_name, self.base_class_name, self)
        self.modifier = set()
        self.active = True
        self.iterator = None

    def prepare(self):
        """ This method is called just before we need to write the
        output and allows us to do any last minute fixups.
        """
        pass

    def __str__(self):
        result = "#%s\n" % self.docstring

        result += "Class %s(%s):\n" % (self.class_name, self.base_class_name)
        result += " Constructor:%s\n" % self.constructor
        result += " Attributes:\n%s\n" % self.attributes
        result += " Methods:\n"
        for a in self.methods:
            result += "    %s\n" % a.__str__()

        return result

    def is_active(self):
        """ Returns true if this class is active and should be generated """
        if not self.active or self.modifier and \
                ('PRIVATE' in self.modifier or 'ABSTRACT' in self.modifier):
            log("%s is not active %s" % (self.class_name, self.modifier))
            return False

        return True

    def clone(self, new_class_name):
        """ Creates a clone of this class - usefull when implementing
        class extensions
        """
        result = ClassGenerator(new_class_name, self.class_name, self.module)
        result.constructor = self.constructor.clone(new_class_name)
        result.methods = [ x.clone(new_class_name) for x in self.methods ]
        result.attributes = self.attributes.clone(new_class_name)

        return result

    def add_attribute(self, attr_name, attr_type, modifier):
        try:
            if not self.module.classes[attr_type].is_active(): return
        except KeyError: pass

        try:
            ## All attribute references are always borrowed - that
            ## means we dont want to free them after accessing them
            type_class = dispatch(attr_name, "BORROWED "+attr_type)
        except KeyError:
            log("Unknown attribute type %s for  %s.%s" % (attr_type,
                                                          self.class_name,
                                                          attr_name))
            return

        type_class.attributes.add(modifier)
        self.attributes.add_attribute(type_class)

    def add_constructor(self, method_name, args, return_type, docstring):
        if method_name.startswith("Con"):
            self.constructor = ConstructorMethod(self.class_name, self.base_class_name,
                                                 method_name, args, return_type,
                                                 myclass = self)
            self.constructor.docstring = docstring

    def struct(self,out):
        out.write("""\ntypedef struct {
  PyObject_HEAD
  %(class_name)s base;
  void *ctx;
} py%(class_name)s;\n
""" % dict(class_name=self.class_name))

    def code(self, out):
        if not self.constructor:
            raise RuntimeError("No constructor found for class %s" % self.class_name)

        self.constructor.write_destructor(out)
        self.constructor.write_definition(out)
        if self.attributes:
            self.attributes.write_definition(out)

        for m in self.methods:
            m.write_definition(out)

    def initialise(self):
        return "python_wrappers[TOTAL_CLASSES].class_ref = (Object)&__%s;\n" \
            "python_wrappers[TOTAL_CLASSES++].python_type = &%s_Type;\n" % (
            self.class_name, self.class_name)

    def PyMethodDef(self, out):
        out.write("static PyMethodDef %s_methods[] = {\n" % self.class_name)
        for method in self.methods:
            method.PyMethodDef(out)

        out.write("     {NULL}  /* Sentinel */\n};\n")

    def prototypes(self, out):
        """ Write prototype suitable for .h file """
        out.write("""staticforward PyTypeObject %s_Type;\n""" % self.class_name)
        self.constructor.prototype(out)

        if self.attributes:
            self.attributes.prototype(out)
        for method in self.methods:
            method.prototype(out)

    def numeric_protocol_int(self):
        pass

    def numeric_protocol_nonzero(self):
        return """
static int
%(class_name)s_nonzero(py%(class_name)s *v)
{
        return v->base != 0;
};
""" % self.__dict__

    def numeric_protocol(self, out):
        args = {'class':self.class_name}
        for type, func in [ ('nonzero', self.numeric_protocol_nonzero),
                            ('int', self.numeric_protocol_int) ]:
            definition = func()
            if definition:
                out.write(definition)
                args[type] = "%s_%s" % (self.class_name,type)
            else:
                args[type] = '0'

        out.write("""
static PyNumberMethods %(class)s_as_number = {
        (binaryfunc)    0,       /*nb_add*/
        (binaryfunc)    0,       /*nb_subtract*/
        (binaryfunc)    0,       /*nb_multiply*/
                        0,       /*nb_divide*/
                        0,       /*nb_remainder*/
                        0,       /*nb_divmod*/
                        0,       /*nb_power*/
        (unaryfunc)     0,       /*nb_negative*/
        (unaryfunc)     0,       /*tp_positive*/
        (unaryfunc)     0,       /*tp_absolute*/
        (inquiry)       %(nonzero)s,   /*tp_nonzero*/
        (unaryfunc)     0,       /*nb_invert*/
                        0,       /*nb_lshift*/
        (binaryfunc)    0,       /*nb_rshift*/
                        0,       /*nb_and*/
                        0,       /*nb_xor*/
                        0,       /*nb_or*/
                        0,       /*nb_coerce*/
         (unaryfunc)    %(int)s,       /*nb_int*/
                        0,       /*nb_long*/
                        0,       /*nb_float*/
                        0,       /*nb_oct*/
                        0,       /*nb_hex*/
        0,                              /* nb_inplace_add */
        0,                              /* nb_inplace_subtract */
        0,                              /* nb_inplace_multiply */
        0,                              /* nb_inplace_divide */
        0,                              /* nb_inplace_remainder */
        0,                              /* nb_inplace_power */
        0,                              /* nb_inplace_lshift */
        0,                              /* nb_inplace_rshift */
        0,                              /* nb_inplace_and */
        0,                              /* nb_inplace_xor */
        0,                              /* nb_inplace_or */
        0,                              /* nb_floor_divide */
        0,                              /* nb_true_divide */
        0,                              /* nb_inplace_floor_divide */
        0,                              /* nb_inplace_true_divide */
        0,                              /* nb_index */
};
"""  % args)
        return "&%(class)s_as_number" % args

    def PyTypeObject(self, out):
        args = {'class':self.class_name, 'module': self.module.name, 
                'iterator': 0,
                'iternext': 0,
                'tp_str': 0,
                'getattr_func': 0,
                'docstring': "%s: %s" % (self.class_name, 
                                         escape_for_string(self.docstring))}

        if self.attributes:
            args['getattr_func'] = self.attributes.name

        args['numeric_protocol'] = self.numeric_protocol(out)
        if "ITERATOR" in self.modifier:
            args['iterator'] = "PyObject_SelfIter"
            args['iternext'] = "py%s_iternext" % self.class_name

        if "SELF_ITER" in self.modifier:
            args['iterator'] = 'py%s___iter__' % self.class_name

        if "TP_STR" in self.modifier:
            args['tp_str'] = 'py%s___str__' % self.class_name

        out.write("""
static PyTypeObject %(class)s_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /* ob_size */
    "%(module)s.%(class)s",               /* tp_name */
    sizeof(py%(class)s),            /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)%(class)s_dealloc,/* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_compare */
    0,                         /* tp_repr */
    %(numeric_protocol)s,      /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash */
    0,                         /* tp_call */
    (reprfunc)%(tp_str)s,      /* tp_str */
    (getattrofunc)%(getattr_func)s,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        /* tp_flags */
    "%(docstring)s",     /* tp_doc */
    0,	                       /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    (getiterfunc)%(iterator)s,              /* tp_iter */
    (iternextfunc)%(iternext)s,/* tp_iternext */
    %(class)s_methods,         /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)py%(class)s_init,      /* tp_init */
    0,                         /* tp_alloc */
    0,                         /* tp_new */
};
""" % args )

class StructGenerator(ClassGenerator):
    """ A wrapper generator for structs """
    def __init__(self, class_name, module):
        self.class_name = class_name
        self.methods = []
        self.module = module
        self.base_class_name = None
        self.active = False
        self.modifier = set()
        self.constructor = None
        self.attributes = GetattrMethod(self.class_name, self.base_class_name, self)

    def prepare(self):
        ## This is needed for late stage initialization - sometimes
        ## our class_name is not know until now.
        if not self.constructor:
            self.constructor = StructConstructor(self.class_name, self.base_class_name,
                                                 'Con', [], "void", myclass = self)

            self.attributes.rename_class_name(self.class_name)
            for x in self.attributes._attributes:
                x[1].attributes.add('FOREIGN')

    def __str__(self):
        result = "#%s\n" % self.docstring

        result += "Struct %s:\n" % (self.class_name)
        result += "%s\n" % self.attributes

        return result

    def struct(self, out):
        out.write("""\ntypedef struct {
  PyObject_HEAD
  %(class_name)s *base;
  void *ctx;
} py%(class_name)s;\n
""" % dict(class_name=self.class_name))

    def initialise(self):
        return ''

class ProxyClassGenerator(ClassGenerator):
    def __init__(self, class_name, base_class_name, module, *args, **kwargs):
        ClassGenerator.__init__(self, class_name, base_class_name, module, *args, **kwargs)
        self.constructor = ProxyConstructor(self.class_name,
                                            self.base_class_name, '__init__',
                                            [('PyObject *', 'proxied')],
                                            'void', myclass = self)
        self.module = module
        self.attributes = ProxiedGetattr(self.class_name, self.base_class_name, self)


    def initialise(self):
        return "INIT_CLASS(%(class_name)s);\n" % self.__dict__ + ClassGenerator.initialise(self)

    def struct(self, out):
        out.write("""
// The proxied type is an extension of the wrapped type with a pointer
// to the proxied PyObject.
CLASS(%(class_name)s, %(base_class_name)s)
   uint32_t magic;
   PyObject *proxied;
END_CLASS

VIRTUAL(%(class_name)s, %(base_class_name)s) {
} END_VIRTUAL

typedef struct {
  PyObject_HEAD
  %(class_name)s base;
  void *ctx;
} py%(class_name)s;\n
""" % self.__dict__)

    def PyMethodDef(self, out):
        out.write("static PyMethodDef %s_methods[] = {\n" % self.class_name)
        ## For now no methods
        out.write("     {NULL}  /* Sentinel */\n};\n")

class parser:
    class_re = re.compile(r"^([A-Z]+)?\s*CLASS\(([A-Z_a-z0-9]+)\s*,\s*([A-Z_a-z0-9]+)\)")
    method_re = re.compile(r"^\s*([0-9A-Z_a-z ]+\s+\*?)METHOD\(([A-Z_a-z0-9]+),\s*([A-Z_a-z0-9]+),?")
    enum_start_re = re.compile(r'enum ([0-9A-Z_a-z]+) {')
    enum_re = re.compile(r'([0-9A-Z_a-z]+) = [^,]+,')
    enum_end_re = re.compile('}')
    arg_re = re.compile(r"\s*([0-9A-Z a-z_]+\s+\*?)([0-9A-Za-z_]+),?")
    constant_re = re.compile(r"#define\s+([A-Z_0-9]+)\s+[^\s]+")
    struct_re = re.compile(r"([A-Z]+)?\s+(typedef )?struct\s+([A-Z_a-z0-9]+)\s+{")
    proxy_class_re = re.compile(r"^([A-Z]+)?\s*PROXY_CLASS\(([A-Za-z0-9]+)\)")
    end_class_re = re.compile("END_CLASS")
    attribute_re = re.compile(r"^\s*([0-9A-Z_a-z ]+\s+\*?)\s*([A-Z_a-z]+)\s*;")
    comment_re = re.compile(r"^\s*//")
    comment_start_re = re.compile(r"/\*+")
    comment_end_re = re.compile(r"\*+/")
    blank_line_re = re.compile("\s+")
    typedef_re = re.compile("typedef ([A-Za-z_0-9]+) +([A-Za-z_0-9]+) *;")
    bind_re = re.compile("BIND\(([a-zA-Z_0-9]+)\);")
    current_class = None

    def __init__(self, module, verbosity=0):
        self.module = module
        self.current_comment = ''
        self.verbosity = verbosity
        self.state = 'DEFAULT'

        ## this is a list of objects which are to be bound
        self.to_bind = []

        global DEBUG

        DEBUG = verbosity

        io = StringIO.StringIO("""
// Base object
CLASS(Object, Obj)
END_CLASS
""")
        self.parse_fd(io, '')

    def add_class(self, class_name, base_class_name, class_type, handler, docstring, modifier):
        try:
            self.current_class = self.module.classes[base_class_name].clone(class_name)
        except (KeyError, AttributeError):
            log("Base class %s is not defined !!!!" % base_class_name)
            self.current_class = class_type(class_name, base_class_name, self.module)

        ## Now add the new class to the module object
        self.current_class.docstring = docstring
        self.current_class.modifier = modifier
        self.module.add_class(self.current_class, handler)

    def parse_filenames(self, filenames):
        ## Be quiet for the first pass as many problems will be
        ## resolved on the second pass anyway.
        global DEBUG
        DEBUG = 0
        for f in filenames:
            self._parse(f)

        DEBUG = self.verbosity
        log("Second pass: Consolidating definitions")
        for f in filenames:
            self._parse(f)

    def _parse(self, filename):
        fd = open(filename)
        self.parse_fd(fd, filename)
        fd.close()

        if filename not in self.module.files:
              self.module.headers += '#include "%s"\n' % filename
              self.module.files.append(filename)

    def parse_fd(self, fd, filename):
        self.current_class = None
        self.current_comment = ''

        while 1:
            line = fd.readline()
            if not line: break

            ## Handle binds
            m= self.bind_re.search(line)
            if m:
                print "Will bind %s" % m.group(1)
                self.to_bind.append(m.group(1))
                continue

            ## Handle enums
            if self.state == 'DEFAULT':
                m = self.enum_start_re.search(line)
                if m:
                    self.state = 'enum'
                    type_dispatcher[m.group(1)] = type_dispatcher['int']
                    continue

            elif self.state == 'enum':
                m = self.enum_re.search(line)
                if m:
                    self.module.add_constant(m.group(1), 'integer')

                if '}' in line:
                    self.state = 'DEFAULT'
                    continue

            ## Handle c++ style comments //
            m = self.comment_re.match(line)
            if m:
                self.current_comment = line[m.end():]
                while 1:
                    line = fd.readline()

                    m = self.comment_re.match(line)
                    if not m:
                        break

                    self.current_comment += line[m.end():]

            ## Multiline C style comments
            m = self.comment_start_re.search(line)
            if m:
                line = line[m.end():]
                while 1:
                    m = self.comment_end_re.search(line)
                    if m:
                        self.current_comment += line[:m.start()]
                        line = fd.readline()
                        break
                    else:
                        self.current_comment += line

                    line = fd.readline()
                    if not line: break

            ## Handle simple typdefs (as if typedef uint64_t my_fancy_type;)
            m = self.typedef_re.search(line)
            if m:
                ## We basically add a new type as a copy of the old
                ## type
                old, new = m.group(1), m.group(2)
                if old in type_dispatcher:
                    type_dispatcher[new] = type_dispatcher[old]

            ## Handle constant #define
            m = self.constant_re.search(line)
            if m:
                ## We need to determine if it is a string or integer
                if re.search('"', line):
                    ## Its a string
                    self.module.add_constant(m.group(1), 'string')
                else:
                    self.module.add_constant(m.group(1), 'integer')

            ## Wrap structs
            m = self.struct_re.search(line)
            if m:
                modifier = m.group(1)
                class_name = m.group(3)
                base_class_name = None
                ## Structs may be refered to as a pointer or absolute
                ## - its the same thing ultimatley.

                ## We only wrap structures which are explicitely bound
                if (modifier and 'BOUND' in modifier) or \
                        class_name in self.to_bind:
                    self.add_class(class_name, base_class_name, StructGenerator, StructWrapper,
                                   self.current_comment, modifier)
                    type_dispatcher["%s *" % class_name] = PointerStructWrapper

                continue

            m = self.class_re.search(line)
            if m:
                ## We need to make a new class now... We basically
                ## need to build on top of previously declared base
                ## classes - so we try to find base classes, clone
                ## them if possible:
                modifier = m.group(1)
                class_name = m.group(2)
                base_class_name = m.group(3)
                self.add_class(class_name, base_class_name, ClassGenerator, Wrapper,
                               self.current_comment, modifier)
                type_dispatcher["%s *" % class_name] = PointerWrapper

                continue

            ## Make a proxy class for python callbacks
            m = self.proxy_class_re.search(line)
            if m:
                modifier = m.group(1)
                base_class_name = m.group(2)
                class_name = "Proxied%s" % base_class_name
                try:
                    proxied_class = self.module.classes[base_class_name]
                except KeyError:
                    raise RuntimeError("Need to create a proxy for %s but it has not been defined (yet). You must place the PROXIED_CLASS() instruction after the class definition" % base_class_name)
                self.current_class = ProxyClassGenerator(class_name,
                                                         base_class_name, self.module)
                #self.current_class.constructor.args += proxied_class.constructor.args
                self.current_class.docstring = self.current_comment

                ## Create proxies for all these methods
                for method in proxied_class.methods:
                    self.current_class.methods.append(ProxiedMethod(method, self.current_class))

                self.module.add_class(self.current_class, Wrapper)

                ## Make sure that further lines are not interpreted as part of this class.
                self.current_class = None

            m = self.method_re.search(line)
            if self.current_class and m:
                args = []
                method_name = m.group(3)
                return_type = m.group(1).strip()
                ## Ignore private methods
                if return_type.startswith("PRIVATE"): continue

                ## Now parse the args
                offset = m.end()
                while 1:
                    m = self.arg_re.match(line[offset:])
                    if not m:
                        ## Allow multiline definitions if there is \\
                        ## at the end of the line
                        if line.strip().endswith("\\"):
                            line = fd.readline()
                            offset = 0
                            if line:
                                continue

                        break

                    offset += m.end()
                    args.append([m.group(1).strip(), m.group(2).strip()])

                if return_type == self.current_class.class_name and \
                        method_name.startswith("Con"):
                    self.current_class.add_constructor(method_name, args, return_type,
                                                       self.current_comment)
                else:
                    self.current_class.add_method(method_name, args, return_type,
                                                  self.current_comment)

            m = self.attribute_re.search(line)
            if self.current_class and m:
                type = m.group(1)
                name = m.group(2)
                self.current_class.add_attribute(name, type)

            m = self.end_class_re.search(line)
            if m:
                ## Just clear the current class context
                self.current_class = None

            ## If this is a shadow file we do not include it from the
            ## main module. A shadow file is a way for us to redefine
            ## other C constructs which will be imported from an
            ## external header file so we can bind them slightly
            ## differently.
            if "this is a shadow file" in self.current_comment \
                    and filename not in self.module.files:
                self.module.files.append(filename)

            ## We only care about comment immediately above methods
            ## etc as we take them to be documentation. If we get here
            ## the comment is not above anything we care about - so we
            ## clear it:
            self.current_comment = ''

    def write(self, out):
        self.module.write(out)


import lexer

class EnumConstructor(ConstructorMethod):
    def write_destructor(self, out):
        out.write("""static void
%(class_name)s_dealloc(py%(class_name)s *self) {
 Py_DECREF(self->value);
 PyObject_Del(self);
};\n
""" % dict(class_name = self.class_name))
    def write_definition(self, out):
        self.myclass.modifier.add("TP_STR")
        self._prototype(out)
        out.write("""{
static char *kwlist[] = {"value", NULL};

if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &self->value))
 goto error;

Py_INCREF(self->value);

  return 0;
error:
    return -1;
};

static PyObject *py%(class_name)s___str__(py%(class_name)s *self) {
  PyObject *result = PyDict_GetItem(%(class_name)s_rev_lookup, self->value);

  if(result) {
     Py_INCREF(result);
 } else {
     result = PyObject_Str(self->value);
 };

 return result;
};

""" % self.__dict__)

class Enum(StructGenerator):
    def __init__(self, name, module):
        StructGenerator.__init__(self, name, module)
        self.values = []
        self.name = name
        self.attributes = None
        self.active = True

    def prepare(self):
        self.constructor = EnumConstructor(self.class_name, self.base_class_name,
                                           'Con', [], "void", myclass = self)
        StructGenerator.prepare(self)

    def __str__(self):
        result = "Enum %s:\n" % (self.name)
        for attr in self.values:
            result += "    %s\n" % attr.__str__()

        return result

    def struct(self,out):
        out.write("""\ntypedef struct {
  PyObject_HEAD
  PyObject *value;
} py%(class_name)s;\n


static PyObject *%(class_name)s_Dict_lookup;
static PyObject *%(class_name)s_rev_lookup;
""" % dict(class_name=self.class_name))

    def PyMethodDef(self, out):
        out.write("static PyMethodDef %s_methods[] = {\n" % self.class_name)
        out.write("     {NULL}  /* Sentinel */\n};\n")

    def numeric_protocol_nonzero(self):
        pass

    def numeric_protocol_int(self):
        return """
static PyObject *%(class_name)s_int(py%(class_name)s *self) {
    Py_INCREF(self->value);
    return self->value;
};
""" % self.__dict__

    def initialise(self):
        result = """
%(class_name)s_Dict_lookup = PyDict_New();
%(class_name)s_rev_lookup = PyDict_New();
""" % self.__dict__

        if self.values:
            result += "{ PyObject *tmp, *tmp2;\n"
            for attr in self.values:
                result += ''' tmp = PyLong_FromLong(%(value)s);
  tmp2 = PyString_FromString("%(value)s");
  PyDict_SetItem(%(class_name)s_Dict_lookup, tmp2, tmp);
  PyDict_SetItem(%(class_name)s_rev_lookup, tmp, tmp2);
  Py_DECREF(tmp);
  Py_DECREF(tmp2);

''' % dict(value = attr, class_name=self.class_name)
            result += "};\n"

        return result

class EnumType(Integer):
    buildstr = 'i'

    def __init__(self, name, type):
        Integer.__init__(self, name, type)
        self.type = type

    def to_python_object(self, name=None, result='py_result', **kw):
        name = name or self.name
        return """PyErr_Clear();
%s = PyObject_CallMethod(g_module, "%s", "K", (uint64_t)%s);
""" % (result, self.type, name)

    def pre_call(self, method):
        method.error_set = True
        return """
// Check if the integer passed is actually a valid member of the enum
// Enum value of 0 is always allowed
if(%(name)s) { PyObject *py_%(name)s = PyLong_FromLong(%(name)s);
  PyObject *tmp = PyDict_GetItem(%(type)s_rev_lookup, py_%(name)s);

  Py_DECREF(py_%(name)s);
  if(!tmp) {
    PyErr_Format(PyExc_RuntimeError, "value %%lu is not valid for Enum %(type)s of arg '%(name)s'", (unsigned long)%(name)s);
    goto error;
  };
  Py_DECREF(tmp);
};
""" % self.__dict__

class HeaderParser(lexer.SelfFeederMixIn):
    tokens = [
        [ 'INITIAL', r'#define\s+', 'PUSH_STATE', 'DEFINE' ],
        [ 'DEFINE', r'([A-Za-z_0-9]+)\s+[^\n]+', 'DEFINE,POP_STATE', None ],
        [ 'DEFINE', r'\n', 'POP_STATE', None],

        ## Recognize ansi c comments
        [ '.', r'/\*(.)', 'PUSH_STATE', 'COMMENT' ],
        [ 'COMMENT', r'(.+?)\*/\s+', 'COMMENT_END,POP_STATE', None],
        [ 'COMMENT', r'(.+)', 'COMMENT', None],

        ## And c++ comments
        [ '.', r'//([^\n]+)', 'COMMENT', None],

        ## An empty line clears the current comment
        [ '.', r'\r?\n\r?\n', 'CLEAR_COMMENT', None],

        ## Ignore whitespace
        [ '.', r'\s+', 'SPACE', None ],
        [ '.', r'\\\n', 'SPACE', None ],

        ## Recognize CLASS() definitions
        [ 'INITIAL', r"^([A-Z]+)?\s*CLASS\(([A-Z_a-z0-9]+)\s*,\s*([A-Z_a-z0-9]+)\)",
                     'PUSH_STATE,CLASS_START', 'CLASS'],

        [ 'CLASS', r"^\s*(FOREIGN|ABSTRACT|PRIVATE)?([0-9A-Z_a-z ]+( |\*))METHOD\(([A-Z_a-z0-9]+),\s*([A-Z_a-z0-9]+),?",
                     "PUSH_STATE,METHOD_START", "METHOD"],
        [ 'METHOD', r"\s*([0-9A-Z a-z_]+\s+\*?\*?)([0-9A-Za-z_]+),?", "METHOD_ARG", None ],
        [ 'METHOD', r'\);', 'POP_STATE,METHOD_END', None],

        [ 'CLASS', r"^\s*(FOREIGN|ABSTRACT)?([0-9A-Z_a-z ]+\s+\*?)\s*([A-Z_a-z0-9]+)\s*;",
                   'CLASS_ATTRIBUTE', None],
        [ 'CLASS', "END_CLASS", 'END_CLASS,POP_STATE', None],

        ## Recognize struct definitions (With name)
        [ 'INITIAL', "([A-Z_a-z0-9 ]+)?struct\s+([A-Z_a-z0-9]+)\s+{",
                     'PUSH_STATE,STRUCT_START', 'STRUCT'],

        ## Without name (using typedef)
        [ 'INITIAL', "typedef\s+struct\s+{",
                     'PUSH_STATE,TYPEDEF_STRUCT_START', 'STRUCT'],

        [ 'STRUCT', r"^\s*([0-9A-Z_a-z ]+\s+\*?)\s*([A-Z_a-z0-9]+)\s*;",
                     'STRUCT_ATTRIBUTE', None],

        [ 'STRUCT', r"^\s*([0-9A-Z_a-z ]+)\*\s+([A-Z_a-z0-9]+)\s*;",
                     'STRUCT_ATTRIBUTE_PTR', None],

        ## Struct ended with typedef
        [ 'STRUCT', '}\s+([0-9A-Za-z_]+);', 'POP_STATE,TYPEDEF_STRUCT_END', None],
        [ 'STRUCT', '}', 'POP_STATE,STRUCT_END', None],

        ## Handle recursive struct or union definition (At the moment
        ## we cant handle them at all)
        [ '(RECURSIVE_)?STRUCT', '(struct|union)\s+([_A-Za-z0-9]+)?\s*{', 'PUSH_STATE', 'RECURSIVE_STRUCT'],
        [ 'RECURSIVE_STRUCT', '}\s+[0-9A-Za-z]+', 'POP_STATE', None],

        ## Process enums (2 forms - named and typedefed)
        [ 'INITIAL', r'enum\s+([0-9A-Za-z_]+)\s+{', 'PUSH_STATE,ENUM_START', 'ENUM' ],
        ## Unnamed
        [ 'INITIAL', r'typedef\s+enum\s+{', 'PUSH_STATE,TYPEDEF_ENUM_START', 'ENUM' ],
        [ 'ENUM', r'([0-9A-Za-z_]+)\s+=[^\n]+', 'ENUM_VALUE', None],

        ## Typedefed ending
        [ 'ENUM', r'}\s+([0-9A-Za-z_]+);', 'POP_STATE,TYPEDEFED_ENUM_END', None],
        [ 'ENUM', r'}', 'POP_STATE,ENUM_END', None],

        [ 'INITIAL', r'BIND_STRUCT\(([0-9A-Za-z_ \*]+)\)', 'BIND_STRUCT', None],

        ## A simple typedef of one type for another type:
        [ 'INITIAL', r"typedef ([A-Za-z_0-9]+) +([^;]+);", 'SIMPLE_TYPEDEF', None],

        ## Handle proxied directives
        [ 'INITIAL', r"PROXY_CLASS\(([A-Za-z0-9]+)\);", 'PROXY_CLASS', None],

        ]

    def __init__(self, name, verbose = 1):
        self.module = Module(name)
        lexer.SelfFeederMixIn.__init__(self, verbose = 0)

        io = StringIO.StringIO("""
// Base object
CLASS(Object, Obj)
END_CLASS
""")
        self.parse_fd(io)

    current_comment = ''
    def COMMENT(self, t, m):
        self.current_comment += m.group(1) + "\n"

    def COMMENT_END(self, t, m):
        self.current_comment += m.group(1)

    def CLEAR_COMMENT(self, t, m):
        self.current_comment = ''

    def DEFINE(self, t, m):
        line = m.group(0)
        line = line.split('/*')[0]
        if '"' in line:
            type = 'string'
        else:
            type = 'integer'

        name = m.group(1).strip()
        if len(name)>3 and name[0]!='_' and name==name.upper():
            self.module.add_constant(name, type)

    current_class = None
    def CLASS_START(self, t, m):
        class_name = m.group(2).strip()
        base_class_name = m.group(3).strip()

        try:
            self.current_class = self.module.classes[base_class_name].clone(class_name)
        except (KeyError, AttributeError):
            log("Base class %s is not defined !!!!" % base_class_name)
            self.current_class = ClassGenerator(class_name, base_class_name, self.module)

        self.current_class.docstring = self.current_comment
        self.current_class.modifier.add(m.group(1))
        self.module.add_class(self.current_class, Wrapper)
        type_dispatcher["%s *" % class_name] = PointerWrapper

    current_method = None
    def METHOD_START(self, t, m):
        return_type = m.group(2).strip()
        method_name = m.group(5).strip()
        modifier = m.group(1) or ''

        if 'PRIVATE' in modifier: return

        ## Is it a regular method or a constructor?
        self.current_method = Method
        if return_type == self.current_class.class_name and \
                method_name.startswith("Con"):
            self.current_method = ConstructorMethod
        elif method_name == 'iternext':
            self.current_method = IteratorMethod
            self.current_class.modifier.add("ITERATOR")
        elif method_name == '__iter__':
            self.current_method = SelfIteratorMethod
            self.current_class.modifier.add("SELF_ITER")
        elif method_name == '__str__':
            self.current_class.modifier.add("TP_STR")

        self.current_method = self.current_method(self.current_class.class_name,
                                                  self.current_class.base_class_name,
                                                  method_name, [], return_type,
                                                  myclass = self.current_class)
        self.current_method.docstring = self.current_comment
        self.current_method.modifier = modifier

    def METHOD_ARG(self, t, m):
        name = m.group(2).strip()
        type = m.group(1).strip()
        if self.current_method:
            self.current_method.add_arg(type, name)

    def METHOD_END(self, t, m):
        if not self.current_method: return

        if isinstance(self.current_method, ConstructorMethod):
            self.current_class.constructor = self.current_method
        else:
            found = False
            for i in range(len(self.current_class.methods)):
                ## Try to replace existing methods with this new method
                method = self.current_class.methods[i]
                if method.name == self.current_method.name:
                    self.current_class.methods[i] = self.current_method
                    self.current_method = None
                    return

            ## Method does not exist, just add to the end
            self.current_class.methods.append(self.current_method)

        self.current_method = None

    def CLASS_ATTRIBUTE(self, t, m):
        modifier = m.group(1) or ''
        type = m.group(2).strip()
        name = m.group(3).strip()
        self.current_class.add_attribute(name, type, modifier)

    def END_CLASS(self, t, m):
        self.current_class = None

    current_struct = None
    def STRUCT_START(self, t, m):
        self.current_struct = StructGenerator(m.group(2).strip(), self.module)
        self.current_struct.docstring = self.current_comment
        self.current_struct.modifier.add(m.group(1))

    def TYPEDEF_STRUCT_START(self, t, m):
        self.current_struct = StructGenerator(None, self.module)
        self.current_struct.docstring = self.current_comment

    def STRUCT_ATTRIBUTE(self, t, m):
        name = m.group(2).strip()
        type = m.group(1).strip()
        self.current_struct.add_attribute(name, type, '')

    def STRUCT_ATTRIBUTE_PTR(self, t, m):
        type = "%s *" % m.group(1).strip()
        name = m.group(2).strip()
        self.current_struct.add_attribute(name, type, '')

    def STRUCT_END(self, t, m):
        self.module.add_class(self.current_struct, StructWrapper)
        type_dispatcher["%s *" % self.current_struct.class_name] = PointerStructWrapper
        self.current_struct = None

    def TYPEDEF_STRUCT_END(self, t, m):
        self.current_struct.class_name = m.group(1).strip()

        self.STRUCT_END(t, m)

    current_enum = None
    def ENUM_START(self, t, m):
        self.current_enum = Enum(m.group(1).strip(), self.module)

    def TYPEDEF_ENUM_START(self, t, m):
        self.current_enum = Enum(None, self.module)

    def ENUM_VALUE(self, t, m):
        self.current_enum.values.append(m.group(1).strip())

    def ENUM_END(self, t, m):
        self.module.classes[self.current_enum.name] = self.current_enum

        ## For now we just treat enums as an integer, and also add
        ## them to the constant table. In future it would be nice to
        ## have them as a proper python object so we can override
        ## __str__ and __int__.
        for attr in self.current_enum.values:
            self.module.add_constant(attr, 'integer')

        #type_dispatcher[self.current_enum.name] = Integer
        type_dispatcher[self.current_enum.name] = EnumType
        self.current_enum = None

    def TYPEDEFED_ENUM_END(self, t, m):
        self.current_enum.name = self.current_enum.class_name = m.group(1)
        self.ENUM_END(t, m)

    def BIND_STRUCT(self, t, m):
        self.module.classes[m.group(1)].active = True

    def SIMPLE_TYPEDEF(self, t, m):
        ## We basically add a new type as a copy of the old
        ## type
        old, new = m.group(1).strip(), m.group(2).strip()
        if old in type_dispatcher:
            type_dispatcher[new] = type_dispatcher[old]

    def PROXY_CLASS(self, t, m):
        base_class_name = m.group(1).strip()
        class_name = "Proxied%s" % base_class_name
        try:
            proxied_class = self.module.classes[base_class_name]
        except KeyError:
            raise RuntimeError("Need to create a proxy for %s but it has not been defined (yet). You must place the PROXIED_CLASS() instruction after the class definition" % base_class_name)
        current_class = ProxyClassGenerator(class_name,
                                            base_class_name, self.module)
        #self.current_class.constructor.args += proxied_class.constructor.args
        current_class.docstring = self.current_comment

        ## Create proxies for all these methods
        for method in proxied_class.methods:
            current_class.methods.append(ProxiedMethod(method, current_class))

        self.module.add_class(current_class, Wrapper)

    def parse_filenames(self, filenames):
        for f in filenames:
            self._parse(f)

        ## Second pass
        for f in filenames:
            self._parse(f)

    def _parse(self, filename):
        fd = open(filename)
        self.parse_fd(fd)
        fd.close()

        if filename not in self.module.files:
              self.module.headers += '#include "%s"\n' % filename
              self.module.files.append(filename)

    def write(self, out):
        self.module.write(out)


if __name__ == '__main__':
    p = HeaderParser('pyaff4', verbose = 1)
    for arg in sys.argv[1:]:
        p.parse_fd(open(arg))

    log("second parse")
    for arg in sys.argv[1:]:
        p.parse_fd(open(arg))

    pdb.set_trace()
    p.write(sys.stdout)

#    p = parser(Module("pyaff4"))
#    for arg in sys.argv[1:]:
#        p.parse(arg)
#        log("second parse")
#        p.parse(arg)

#    p.write(sys.stdout)

