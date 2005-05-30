# $Id: Makefile 3 2005-02-18 03:59:23Z tim $

default:
	cp -r man $(BUILD_DOC)	

generate:
	txt2tags --mask-email -t man -o man/man1/reglookup.1 reglookup.txt

build: generate default
