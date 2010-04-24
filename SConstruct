
build_cmds='''
rm -rf .release;
svn export svn+ssh://sentinelchicken.org/home/projects/subversion/reglookup/$SOURCE .release/%s;
#XXX: Can this be less of a hack?
cd .release/%s && scons doc
cd .release && tar cf %s.tar %s && gzip -9 %s.tar;
mv .release/%s.tar.gz . && rm -rf .release
'''

buildable_files=('reglookup-trunk.tar.gz',)

def generate_cmds(source, target, env, for_signature):
    ret_val = ''
    for t in target:
        if str(t) in buildable_files:
            t_base = str(t).split('.')[0]
            ret_val += build_cmds % (t_base,t_base,t_base,
                                     t_base,t_base,t_base)
        else:
            return '#ERROR: cannot build "%s".  Acceptable targets: %s' % (t, repr(buildable_files))

    return ret_val


release_builder = Builder(generator = generate_cmds,
                          suffix = '.tar.gz',
                          src_suffix = '',
                          prefix='reglookup-')

env = Environment()
env['BUILDERS']['Release'] = release_builder


env.Release(Dir('trunk'))
#env.Release('reglookup-0.13.0.tar.gz', Dir('releases/0.13.0'))

Default(None)
