#!/usr/bin/env python
from __future__ import print_function
import re

active_databases = "active_dbs"
mysql_schema_file = "mysql_schema.sql"

db_users = []
db_filters = []
with open(active_databases) as filter_file:
	db_filters = filter_file.read().splitlines()

with open(mysql_schema_file) as sql_file:
	exp = re.compile("INSERT INTO `db` VALUES \('[%\d\w.-]+','([\d\w_\\\\-]+)','([\d\w\_\\\\-]+)',.*")

	for line in sql_file:
		if 'INSERT INTO `db`' in line:
			result = exp.match(line)

			if result:
				if result.group(1).replace('\\', '') in db_filters:
					db_users.append(result.group(2))
				result = None
			else:
				print("ERROR, NO MATCH: " + line)

with open(mysql_schema_file) as sql_file:
	for line in sql_file:
		p = True
		if 'INSERT INTO `db`' in line:
			found_db = False
			for filt in db_filters:
				if "'" + filt + "'" in line:
					found_db = True

			if not found_db:
				p = False

		if 'INSERT INTO `user`' in line:
			found_user = False
			for filt in db_users:
				#print("Looking for: " + filt)
				if "'" + filt + "'" in line:
					found_user = True

			if not found_user:
				p = False

		if p == True:
			pass
			print(line, end="")
			
