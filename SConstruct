import sys
import os

cflags = '-std=gnu99 -pedantic -Wall -D_FILE_OFFSET_BITS=64 -DREGFI_WIN32'

libiconv_path='.export/win32/libiconv/'
libpthreads_path='.export/win32/libpthreads/'
libpthread_name='pthreadGC2'
libtalloc_path='.export/win32/libtalloc/'

source_targets=('src-trunk', 'src-0.99.0', 'src-1.0.0', 'src-1.0.1')
win32_targets=('win32-trunk', 'win32-0.99.0', 'win32-1.0.0', 'win32-1.0.1')
all_targets = source_targets+win32_targets


def parse_target(target):
    chunks = target.split('-')
    if len(chunks) != 2:
        return None
    return chunks

def version2input(version):
    if version == 'trunk':
        return 'trunk/'
    else:
        return 'releases/%s/' % version


export_cmds='''
rm -rf .export
svn export --depth files svn+ssh://%(user)s@sentinelchicken.org/home/projects/subversion/reglookup .export
svn export svn+ssh://%(user)s@sentinelchicken.org/home/projects/subversion/reglookup/win32 .export/win32
svn export svn+ssh://%(user)s@sentinelchicken.org/home/projects/subversion/reglookup/%(path)s .export/%(path)s
'''

version_cmds='''
echo 'REGFI_VERSION="%(version)s"' > .export/%(path)s/regfi_version.py
'''

svnversion_cmds='''
svn info svn+ssh://%(user)s@sentinelchicken.org/home/projects/subversion/reglookup\
  | grep "Last Changed Rev:" | cut -d' ' -f 4 \
  | sed 's/^/REGFI_VERSION="svn-/' | sed 's/$/"/' > .export/%(path)s/regfi_version.py
'''

cleanup_cmds='''
rm -rf .export
'''

source_cmds='''
mv %s .export/%s
cd .export/%s && scons doc
cd .export && tar cf %s.tar %s && gzip -9 %s.tar
mv .export/%s.tar.gz .
'''+cleanup_cmds

win32_cmds='''
mkdir -p .release/%(base)s/python/pyregfi
cp %(path)s/src/*.exe .release/%(base)s
cp %(path)s/LICENSE .release/%(base)s

cp %(path)s/pyregfi-distutils.py .release/%(base)s/setup.py
cp %(path)s/python/pyregfi/*.py .release/%(base)s/python/pyregfi

cp -r -L .export/win32/doc .release/%(base)s
cp .export/win32/libiconv/bin/*.dll .export/win32/libpthreads/bin/*.dll\
     .export/win32/libtalloc/bin/*.dll %(path)s/lib/*.dll .release/%(base)s

cd .release && zip -r %(base)s.zip %(base)s
mv .release/%(base)s.zip . && rm -rf .release
'''+cleanup_cmds


def generate_cmds(source, target, env, for_signature):
    ret_val = ''
    input_prefix = str(source[0])+'/'

    for t in target:
        ttype,version = parse_target(str(t))
        t_base = 'reglookup-%s-%s' % (ttype, version)

        if ttype == 'src':
            ret_val += source_cmds % (input_prefix, t_base, t_base, t_base,
                                      t_base, t_base, t_base)
        elif ttype == 'win32':
            env['platform']='cygwin'
            env['CC']='i586-mingw32msvc-cc'
            env['AR']='i586-mingw32msvc-ar'
            env['RANLIB']='i586-mingw32msvc-ranlib'
            
            env['CFLAGS']="""%s -DREGFI_VERSION='"%s"'""" % (cflags, version)
            env['CPPPATH']=[input_prefix+'include', 
                            libiconv_path+'include',
                            libpthreads_path+'include',
                            libtalloc_path+'include']
            env['LIBPATH']=[input_prefix+'lib',
                            libiconv_path+'lib',
                            libpthreads_path+'lib',
                            libtalloc_path+'lib']
            env['LIBS']=['m', libpthread_name, 'iconv', 'regfi', 'talloc']
            
            # Third-party dependencies
            extra_obj=['%s/lib/lib%s.a' % (libpthreads_path, libpthread_name),
                       libiconv_path+'/lib/libiconv.dll.a',
                       libtalloc_path+'/lib/libtalloc.dll.a']

            # Build libregfi.dll
            #   Core regfi source
            lib_src = [input_prefix+'lib/regfi.c',
                       input_prefix+'lib/winsec.c',
                       input_prefix+'lib/range_list.c',
                       input_prefix+'lib/lru_cache.c',
                       input_prefix+'lib/void_stack.c']
            regfi_o = env.Object(lib_src)

            regfi_obj = []
            for s in lib_src:
                regfi_obj.append(s[0:-1]+'o')

            # XXX: Several options here may not be necessary.  
            #      Need to investigate why stdcall interfaces don't seem to be 
            #      working on Windows.
            env.Command(input_prefix+'lib/libregfi.o', regfi_o+extra_obj,
                        'i586-mingw32msvc-dlltool --export-all-symbols'
                        +' --add-stdcall-alias  --dllname libregfi.dll -e $TARGET'
                        +' -l %slib/libregfi.dll.a %s' 
                        % (input_prefix, ' '.join(regfi_obj)))

            env.Command(input_prefix+'lib/libregfi.dll',
                        input_prefix+'lib/libregfi.o',
                        'i586-mingw32msvc-gcc ' + cflags 
                        + ' --shared -Wl,--out-implib -add-stdcall-alias -o $TARGET $SOURCE %s'
                        % ' '.join(regfi_obj+extra_obj))

            # Executables
            reglookup = env.Program(input_prefix+'src/reglookup.exe',
                                    [input_prefix+'src/reglookup.c']+extra_obj)
            reglookup_recover = env.Program(input_prefix+'src/reglookup-recover.exe',
                                            [input_prefix+'src/reglookup-recover.c']+extra_obj)

            params = {'path':input_prefix, 'base':t_base}
            ret_val += win32_cmds % params

    return ret_val


release_builder = Builder(generator = generate_cmds,
                          suffix = '',
                          src_suffix = '',
                          prefix='')

env = Environment()
env['ENV']['SSH_AGENT_PID'] = os.environ['SSH_AGENT_PID']
env['ENV']['SSH_AUTH_SOCK'] = os.environ['SSH_AUTH_SOCK']
env['BUILDERS']['Release'] = release_builder

if len(COMMAND_LINE_TARGETS) == 0:
    print('Acceptable targets: %s' % repr(all_targets))

for target in COMMAND_LINE_TARGETS:
    if target not in all_targets:
        print('ERROR: cannot build "%s".  Acceptable targets: %s'
              % (target, repr(all_targets)))
        sys.exit(1)
    AlwaysBuild(target)
    ttype,version = parse_target(target)

    params = {'user':os.environ['USER'], 
              'path':version2input(version), 
              'version':version}
    env.Execute(export_cmds % params)
    if version == 'trunk':
        print env.Execute(svnversion_cmds % params)
    else:
        env.Execute(version_cmds % params)
    env.Release(target, Dir('.export/'+params['path']))

Default(None)
