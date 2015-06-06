import sys
import os
sys.dont_write_bytecode = True
from regfi_version import REGFI_VERSION

cflags = '-std=gnu99 -pedantic -Wall -D_FILE_OFFSET_BITS=64 -fvisibility=hidden'
cflags += ' -DREGFI_VERSION=\'"%s"\' ' % REGFI_VERSION
cflags += os.environ.get('CFLAGS','-fPIE -pie -fstack-protector -D_FORTIFY_SOURCE=2')

linkflags = "-shared -fPIC -Wl,-soname,libregfi.so.%s " % REGFI_VERSION
linkflags += os.environ.get('LDFLAGS','-z relro -z now')

lib_src = ['lib/regfi.c',
           'lib/winsec.c',
           'lib/range_list.c',
           'lib/lru_cache.c',
           'lib/void_stack.c']

cc=os.environ.get('CC', 'gcc')
env = Environment(ENV=os.environ,
                  CC=cc,
                  CFLAGS=cflags,
                  CPPPATH=['include', '/usr/local/include'],
                  LIBPATH=['lib', '/usr/local/lib'],
                  LIBS=['m', 'pthread', 'regfi', 'talloc'])


# Libraries
libregfi_static = env.Library(lib_src)
libregfi = env.SharedLibrary(lib_src, LIBS=['m','pthread', 'talloc'], 
                             LINKFLAGS=linkflags)


# Executables
reglookup = env.Program(['src/reglookup.c'])
reglookup_recover = env.Program(['src/reglookup-recover.c'])


# Documentation
#  This only needs to be run during the release/packaging process
man_fixup = "|sed 's/.SH DESCRIPTION/\\n.SH DESCRIPTION/'"
man_builder = Builder(action='docbook2x-man --to-stdout $SOURCE'
                      + man_fixup + '| gzip -9 > $TARGET',
                      suffix = '.gz',
                      src_suffix = '.docbook')
env['BUILDERS']['ManPage'] = man_builder

man_reglookup = env.ManPage('doc/reglookup.1.docbook')
man_reglookup_recover = env.ManPage('doc/reglookup-recover.1.docbook')
man_reglookup_timeline = env.ManPage('doc/reglookup-timeline.1.docbook')

# Installation
prefix     = os.environ.get('PREFIX','/usr/local')+'/'
destdir    = os.environ.get('DESTDIR','')
bindir     = os.environ.get('BINDIR', prefix + 'bin')
libdir     = os.environ.get('LIBDIR', prefix + 'lib')
includedir = os.environ.get('INCLUDEDIR', prefix + 'include')
mandir     = os.environ.get('MANDIR', prefix + 'man')

install_items = [destdir + bindir,
                 destdir + libdir,
                 destdir + includedir + '/regfi',
                 destdir + mandir]


env.Install(destdir+bindir, [reglookup, reglookup_recover, 'bin/reglookup-timeline'])
libinstall = env.Install(destdir+libdir, [libregfi, libregfi_static])
env.Install(destdir+includedir+'/regfi', Glob('include/*.h'))
env.Install(destdir+mandir+'/man1', [man_reglookup, man_reglookup_recover,
                                     man_reglookup_timeline])

if os.getuid() == 0 and destdir == '':
   env.AddPostAction(libinstall, 'ldconfig')

if sys.version_info[0] == 2:
   install_items.append('pyregfi2-install.log')
   env.Command('pyregfi2-install.log', ['python/pyregfi/__init__.py', 
                                        'python/pyregfi/structures.py', 
                                        'python/pyregfi/winsec.py'],
               "python setup.py install --root=/%s | tee pyregfi2-install.log" % destdir)

python_path = os.popen('which python3').read()
if python_path != '':
   install_items.append('pyregfi3-install.log')
   env.Command('pyregfi3-install.log', ['python/pyregfi/__init__.py', 
                                        'python/pyregfi/structures.py', 
                                        'python/pyregfi/winsec.py'], 
               "python3 setup.py install --root=/%s | tee pyregfi3-install.log" % destdir)

# API documentation
regfi_doc = env.Command('doc/devel/regfi/index.html', 
                        Glob('lib/*.c')+Glob('include/*.h')+['doc/devel/Doxyfile.regfi'],
                        'doxygen doc/devel/Doxyfile.regfi')
pyregfi_doc = env.Command('doc/devel/pyregfi/index.html', 
                          Glob('python/pyregfi/*.py')+['doc/devel/Doxyfile.pyregfi', regfi_doc],
                          'doxygen doc/devel/Doxyfile.pyregfi')


# User Friendly Targets
env.Alias('libregfi', libregfi)
env.Alias('reglookup', reglookup)
env.Alias('reglookup-recover', reglookup_recover)
env.Alias('bin', [reglookup_recover, reglookup])
env.Alias('doc', [man_reglookup,man_reglookup_recover,man_reglookup_timeline])
env.Alias('doc-devel', [regfi_doc, pyregfi_doc])
env.Alias('install', install_items)

Default('bin', libregfi)
