# $Id: Makefile 20 2005-06-07 23:54:16Z tim $

# This Makefile is used only for packaging releases out of Subversion.
################################################################################

SVN_URL=svn+ssh://sentinelchicken.org/home/projects/subversion/reglookup
SUB_DIRS=$(wildcard releases/release-*) trunk

FILES=$(REGLOOKUP)
.PHONY: all $(SUB_DIRS) clean
export


RELEASE_NAME=reglookup-test
RELEASE_DEST=.

all:
	@echo "Please choose one target out of: $(SUB_DIRS)."


$(SUB_DIRS):
	rm -rf .release
	mkdir .release
	svn export $(SVN_URL)/$@/ .release/$(RELEASE_NAME)
	#XXX: Can this be less of a hack?
	cd .release/$(RELEASE_NAME)/doc && make generate
	cd .release\
		&& tar cf $(RELEASE_NAME).tar $(RELEASE_NAME)\
		&& gzip -9 $(RELEASE_NAME).tar
	mv .release/$(RELEASE_NAME).tar.gz $(RELEASE_DEST)


clean:
	rm -rf .release