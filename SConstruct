#cflags = '-std=gnu99 -pedantic -Wall'
cflags = '-std=gnu99 -pedantic -Wall -ggdb'


lib_src = ['lib/regfi.c',
           'lib/talloc.c',
           'lib/winsec.c',
           'lib/range_list.c',
           'lib/lru_cache.c',
           'lib/void_stack.c']

env = Environment(CFLAGS=cflags,
                  CPPPATH=['include', '/usr/local/include'],
                  LIBPATH=['lib', '/usr/local/lib'],
                  LIBS=['m', 'pthread', 'regfi'])


# Libraries
libregfi_static = env.Library(lib_src)
libregfi = env.SharedLibrary(lib_src, LIBS=['m','pthread'])


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
prefix='/usr/local/'
env.Install(prefix+'bin', [reglookup, reglookup_recover, 'bin/reglookup-timeline'])
env.Install(prefix+'lib', [libregfi, libregfi_static])
env.Install(prefix+'include/regfi', Glob('include/*.h'))
env.Install(prefix+'man/man1', [man_reglookup, man_reglookup_recover,
                                man_reglookup_timeline])


# User Friendly Targets
env.Alias('libregfi', libregfi)
env.Alias('reglookup', reglookup)
env.Alias('reglookup-recover', reglookup_recover)
env.Alias('bin', [reglookup_recover, reglookup])
env.Alias('doc', [man_reglookup,man_reglookup_recover,man_reglookup_timeline])
env.Alias('install', [prefix+'bin',
                      prefix+'lib', 
                      prefix+'include/regfi',
                      prefix+'man'])

Default('bin', libregfi)
