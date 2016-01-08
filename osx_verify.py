#!/usr/bin/env python
##
## osx_verify - OSX Installer Verifier
## (C) 2016 SektionEins GmbH / Ben Fuhrmannek
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##  http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

__version__ = "0.1rc1"

import hashlib, os, sys
import fnmatch
import json
from glob import glob

def puts(msg, prefix='+'):
	print "[%s] %s" % (prefix, msg)

def dputs(msg, prefix='-'):
	global args
	if args.verbose:
		puts(msg, prefix)

def fhash(fn):
	m = hashlib.sha256()
	with open(fn, 'rb') as f:
		while 1:
			data = f.read(65536)
			if not data:
				break
			m.update(data)
	return m.hexdigest()

def isignored(fn, ignorelist):
	if not ignorelist:
		return False
	for pat in ignorelist:
		if fnmatch.fnmatch(fn, pat):
			return True
	return False

def traverse(travroot, ignorelist=[]):
	path = os.path.normpath(travroot)
	pathlen = len(path.split(os.path.sep))
	result = []
	for root, dirs, files in os.walk(path):
		## TODO: dirs ?
		for fn in files:
			fullfn = os.path.join(root, fn)
			relfn = os.path.join(*fullfn.split(os.path.sep)[pathlen:])
			
			if isignored(relfn, ignorelist):
				dputs("<-- %s -> ignored" % (relfn,))
				continue
			
			dputs("<-- %s" % (relfn,))
			if os.path.islink(fullfn):
				(typ, data) = ('l', os.readlink(fullfn))
			elif os.path.isfile(fullfn):
				(typ, data) = ('f', fhash(fullfn))
			else: ## e.g. device files
				(typ, data) = ('o', None)
		
			result.append([unicode(typ), unicode(data), unicode(relfn)])
	return result

def find_by_filename(fn, files):
	for entry in files:
		if fn == entry[2]:
			return entry
	return None

# def find_by_hash(hash, files):
# 	for entry in files:
# 		if hash == entry[1]:
# 			return entry
# 	return None

## parse arguments
dbdir = os.path.dirname(__file__) + '/db'

import argparse
parser = argparse.ArgumentParser(
	description="""\
         OSX file integrity verification tool
       https://github.com/sektioneins/osx_verify
     
       (c) 2016 SektionEins GmbH | Ben Fuhrmannek
                https://sektioneins.de/
""",
	formatter_class=argparse.RawDescriptionHelpFormatter,
	epilog="""\
examples:

  * compare installer app to current database
    %(prog)s --scan /Applications/Install\ OS\ X\ El\ Capitan.app

  * add new hash set to database
    %(prog)s --scan /Applications/Install\ OS\ X\ El\ Capitan.app \\
        --store 'Install OS X El Capitan.10.11.2.app.json' \\
        --description 'Install OS X El Capitan.10.11.2.app'
""")
parser.add_argument('-s', '--scan', help="scan file or directory to be stored or campared", metavar="<app-bundle>")
parser.add_argument('-l', '--load', help="load previously stored scan for comparison", metavar="<json-file>")
parser.add_argument('-i', '--ignore', action='append', default=['Contents/_MASReceipt/*'],
	help="ignore wildcard pattern, e.g. '*.txt' (can be used more than once)", metavar="<file-pattern>")
parser.add_argument('-D', '--db', action='append', default=['*.json'],
	help="load db files, e.g. 'db/*.json' (can be used more than once)", metavar="<file-pattern>")
parser.add_argument('-c', '--compare', action='store_true',
	help="compare scan to db. default if --store is not given")
parser.add_argument('-S', '--store', help="store scan", metavar="<file>")
parser.add_argument('-d', '--description', help="provide description for scan", metavar="<text>")
parser.add_argument('-v', '--verbose', action='store_true', help="more output")
parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
args = parser.parse_args()

if len(args.ignore) > 1:
	args.ignore.pop(0)

if len(args.db) > 1:
	args.db.pop(0)

if args.db:
	for i in range(len(args.db)):
		if not os.path.isabs(args.db[i]):
			args.db[i] = os.path.join(dbdir, args.db[i])

if args.scan and args.load:
	parser.error("--scan and --load are mutually exclusive")

if not args.scan and not args.load:
	parser.error("either --scan or --load are required")

if args.store and not args.scan:
	parser.error("--store needs --scan")

if args.store and not args.description:
	parser.error("--store needs --description")

if not args.store:
	args.compare = True

if args.compare and not args.scan and not args.load:
	parser.error("--compare needs either --scan or --load")

if args.store and not os.path.isabs(args.store):
	args.store = os.path.join(dbdir, args.store)

# print args

##

db = {}
if args.db:
	puts("loading database")
	for globpattern in args.db:
		for fn in glob(globpattern):
			if db.has_key(fn): continue
			dputs("loading %s" % (fn,))
			db[fn] = json.load(open(fn))

if args.scan:
	puts("scanning files in %s... (this may take a while)" % (args.scan,))
	trdata = traverse(args.scan, ignorelist=args.ignore)
	trdata = sorted(trdata, key=lambda entry: entry[2])
	trdata = {'description': args.description, 'files': trdata, 'ignore': args.ignore}
	
if args.load:
	trdata = json.load(open(args.load, 'rb'))

if args.store:
	puts("storing to %s" % (args.store,))
	if args.store == '-':
		fh = sys.stdout
	else:
		fh = open(args.store, 'wb')
	json.dump(trdata, fh, indent=2)
	fh.close()

if args.compare:
	puts("comparing...")
	## NOTE: Algorithm is rather crude/redundant/slow, yet trivial and not much of
	## a performance impact with so little data.
	result = {}
	for dbkey, dbentry in db.iteritems():
		dputs("checking scanned files against %s / %s" % (dbkey, dbentry['description']))
		result[dbkey] = []
		for dbfile in dbentry['files']:
			# (typ, data, fn) = dbfile
			if isignored(dbfile[2], trdata['ignore']): ## apply tr ignore list to db file
				continue
			if not dbfile in trdata['files']:
				if find_by_filename(dbfile[2], trdata['files']):
					msg = "%s: %s is different" % (dbkey, dbfile[2])
				else:
					msg = "%s: %s not found in scanned files" % (dbkey, dbfile[2])
				result[dbkey].append(msg)
		
		for trfile in trdata['files']:
			# (typ, data, fn) = trfile
			if isignored(trfile[2], dbentry['ignore']): ## apply db ignore list to tr file
				continue
			if not trfile in dbentry['files']:
				if find_by_filename(trfile[2], dbentry['files']):
					continue ## ignore. already found in previous run.
				msg = "%s not found in %s" % (trfile[2], dbkey)
				result[dbkey].append(msg)
	
	puts("-----------")
	for k, v in sorted(result.items(), key=lambda e: len(e[1]), reverse=True):
		puts("Results for %s (%s):" % (db[k]['description'], k))
		if len(v) == 0:
			puts("  perfect match")
		else:
			if args.verbose:
				puts("  %d files are different" % (len(v),))
				for msg in v:
					dputs("  " + msg)
			else:
				puts("  %d files are different. use --verbose to see details" % (len(v),))

puts("bye.")
