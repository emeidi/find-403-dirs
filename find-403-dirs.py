#!/usr/bin/python

import os
import sys

import subprocess

import re

import argparse

#debug = False

parser = argparse.ArgumentParser(description='Create a list of protected URLs on the local web server based on the Apache VirtualHost configuration and .htaccess files')
parser.add_argument('--debug',action='store_true')
args = parser.parse_args()

if args.debug:
	debug = True
else:
	debug = False

vhostspath='/etc/apache2/sites-enabled'
params = ['ServerName','DocumentRoot']
protections = ['AuthType','Deny from','Require ip']

def extractVhostConfig(path):
	config = {}
		
	for line in open(path).readlines():
		for param in params:
			pattern = param + '\s+([^\s]+)'
			values = re.findall(pattern,line,re.I)
			
			if len(values) > 1:
				if debug: print 'ERROR: Multiple values for parameter ' + param + ' found in file ' + path
			
			if len(values) == 1:
				if debug: print values
				config[param] = values[0]
	
	for param in params:
		if not param in config:
			if debug: print 'ERROR: ' + param + ' not found in ' + path
			return False
	
	return config
			
def scanDocRootForAuthType(config):
	path = config['DocumentRoot']

	if debug: print 'Calling retrieveFilesInDirectory()'	
	files = retrieveFilesInDirectory(path,'.htaccess')
	if debug: print 'retrieveFilesInDirectory() called.'	

	if files == False:
		if debug: print 'ERROR: retrieveFilesInDirectory() returned false for path ' + path
		return False
	
	if files == None:
		if debug: print 'files=None'
		return None

	if debug: print 'files is not empty'
	if debug: print files
	
	protectedUrls = []
	for file in files:
		if debug: print 'Examining ' + file
		
		if isProtectedDir(file):
			if debug: print '=== Yes ==='
			
			url = 'http://' + config['ServerName'] + file.replace('.htaccess','').replace(config['DocumentRoot'],'')
			if debug: print url

			protectedUrls.append(url)

	return protectedUrls

def isProtectedDir(file):
	if debug: print 'Reading in file ' + file

	for line in open(file).readlines():
		lineClean = line.strip()
		
		if len(lineClean) < 1:
			continue

		if lineClean[0] == '#':
			if debug: print 'Skipping line "' + lineClean + '"'
			continue
		
		for protection in protections:
			matches = re.findall(protection,lineClean,re.I)
			if len(matches) > 0:
				if debug: print 'Line "' + lineClean + '" matches "' + protection + '"'
				return True

	return False

def retrieveFilesInDirectory(path,filename):
	if not os.path.isdir(path):
		if debug: print 'ERROR: ' + path + ' could not be found'
		return False

	if debug: print 'Scanning path ' + path + ' for .htaccess files'
	
	cmd = 'find "' + path + '" -name ' + filename
	if debug: print 'Executing command ' + cmd

	out = subprocess.check_output(cmd,stderr=subprocess.STDOUT,shell=True)
	
	if debug: print 'Command returned:'
	if debug: print out
	
	lines = []
	tmp = out.splitlines()
	for line in tmp:
		if len(line.strip()) > 0:
			lines.append(line)

	if debug: print lines
	
	if len(lines) < 1:
		if debug: 'Returning None because no files were found'
		return None
	
	if debug: print str(len(lines)) + ' files found in ' + path

	return lines

for filename in os.listdir(vhostspath):
	path = vhostspath + '/' + filename
	
	if debug: print 'Looking at ' + path	

	config = extractVhostConfig(path)

	if config == False:
		if debug: print 'ERROR: config=False. Skipping.'
		if debug: print ''
		continue
	
	if debug: print config
	if debug: print ''

	out = scanDocRootForAuthType(config)
	
	if out == False:
		if debug: 'out=False. Skipping.'
		continue
	
	if out == None:
		if debug: 'out=None. Skipping.'
		continue
		
	if len(out) < 1:
		if debug: 'len(out) < 1. Skipping.'
		continue
	
	print "\n".join(out)

sys.exit(0)
