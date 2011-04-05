cflags = '-std=gnu99 -pedantic -Wall'

libiconv_path='win32/libiconv/'
libpthreads_path='win32/libpthreads/'
libpthread_name='pthreadGC2'
libtalloc_path='win32/libtalloc/'

source_targets=('reglookup-src-trunk.tar.gz',)
win32_targets=('reglookup-win32-trunk.zip',)
doc_targets=('reglookup-doc-trunk.tar.gz',)
all_targets = source_targets+win32_targets+doc_targets 

def target2version(target):
    chunks = target.split('-')
    if len(chunks) != 3:
        return None
    return chunks[2].split('.')[0]

def version2input(version):
    if version == 'trunk':
        return 'trunk/'
    else:
        return 'releases/%s/' % version


source_cmds='''
rm -rf .release;
svn export svn+ssh://sentinelchicken.org/home/projects/subversion/reglookup/$SOURCE .release/%s;
cd .release/%s && scons doc
cd .release && tar cf %s.tar %s && gzip -9 %s.tar;
mv .release/%s.tar.gz . && rm -rf .release
'''

win32_cmds='''
rm -rf .release && mkdir -p .release/%s/python/pyregfi
cp %s/src/*.exe .release/%s

cp %s/pyregfi-distutils.py .release/%s/setup.py
cp %s/python/pyregfi/*.py .release/%s/python/pyregfi

cp win32/libiconv/bin/*.dll win32/libpthreads/bin/*.dll win32/libtalloc/bin/*.dll trunk/lib/*.dll .release/%s
cd .release && zip -r %s.zip %s
mv .release/%s.zip . && rm -rf .release
'''

doc_cmds='''
rm -rf .release;
svn export svn+ssh://sentinelchicken.org/home/projects/subversion/reglookup/ .release;
cd .release && doxygen Doxyfile.regfi
cd .release && doxygen Doxyfile.pyregfi
mv .release/doc .release/%s
cd .release && tar cf %s.tar %s && gzip -9 %s.tar;
mv .release/%s.tar.gz . && rm -rf .release
'''

def generate_cmds(source, target, env, for_signature):
    ret_val = ''
    for t in target:
        t = str(t)
        t_base = t.split('.tar.gz')[0].split('.zip')[0]
        if t in source_targets:
            ret_val += source_cmds % (t_base,t_base,t_base,
                                      t_base,t_base,t_base)
        elif t in win32_targets:
            version = target2version(t)
            input_prefix = version2input(version)

            env['platform']='cygwin'
            env['CC']='i586-mingw32msvc-cc'
            env['AR']='i586-mingw32msvc-ar'
            env['RANLIB']='i586-mingw32msvc-ranlib'
            
            env['CFLAGS']=cflags
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

            env.Command(input_prefix+'lib/libregfi.o', regfi_o+extra_obj,
                        'i586-mingw32msvc-dlltool --export-all-symbols'
                        +' --dllname libregfi.dll -e $TARGET'
                        +' -l %slib/libregfi.dll.a %s' 
                        % (input_prefix, ' '.join(regfi_obj)))

            env.Command(input_prefix+'lib/libregfi.dll',
                        input_prefix+'lib/libregfi.o',
                        'i586-mingw32msvc-gcc --shared -o $TARGET $SOURCE %s'
                        % ' '.join(regfi_obj+extra_obj))

            # Executables
            reglookup = env.Program(input_prefix+'src/reglookup.exe',
                                    [input_prefix+'src/reglookup.c']+extra_obj)
            reglookup_recover = env.Program(input_prefix+'src/reglookup-recover.exe',
                                            [input_prefix+'src/reglookup-recover.c']+extra_obj)

            ret_val += win32_cmds % (t_base,input_prefix,t_base,input_prefix,
                                     t_base,input_prefix,
                                     t_base,t_base,t_base,t_base,t_base)

        elif t in doc_targets:
            ret_val += doc_cmds % (t_base,t_base,t_base,t_base,t_base)
        
    return ret_val



release_builder = Builder(generator = generate_cmds,
                          suffix = '.tar.gz',
                          src_suffix = '',
                          prefix='reglookup-')


env = Environment()
env['BUILDERS']['Release'] = release_builder

if len(COMMAND_LINE_TARGETS) == 0:
    print('Acceptable targets: %s' % repr(all_targets))

for target in COMMAND_LINE_TARGETS:
    AlwaysBuild(target)
    if target not in all_targets:
        print('ERROR: cannot build "%s".  Acceptable targets: %s'
              % (target, repr(all_targets)))
        break
    env.Release(target, Dir(version2input(target2version(target))))

Default(None)
