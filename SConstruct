build_cmds='''
rm -rf .release;
mkdir -p `dirname .release/$SOURCE`;
svn export svn+ssh://sentinelchicken.org/home/projects/subversion/reglookup/$SOURCE .release/$SOURCE;
#XXX: Can this be less of a hack?
cd .release/$SOURCE && scons doc && cd ..;
cd .release && tar cf $SOURCE.tar $SOURCE && gzip -9 $SOURCE.tar;
mv .release/$SOURCE.tar.gz ..
'''
release_builder = Builder(action=build_cmds)
env['BUILDERS']['Release'] = man_builder


env = Environment()
env.Release('trunk')

Default(None)
