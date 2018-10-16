#!/usr/bin/env python

import base64
from binascii import hexlify
import sys


class JWT(object):

	def tojohn(self, jwt):
		alg, data, sign = jwt.split('.')
		return "%s.%s#%s" % (alg, data, hexlify(self.decode(sign)))

	def decode(self, value):
		try:
			return base64.urlsafe_b64decode(value)
		except TypeError:
			try:
				return base64.urlsafe_b64decode(value + '=')
			except TypeError:
				try:
					return base64.urlsafe_b64decode(value + '==')
				except Exception:
					pass


if __name__ == "__main__":
	if len(sys.argv) != 2:
		print 'Usage : %s <jwt-token>' % sys.argv[0]
		sys.exit(0)
	else:
		jwt = JWT()
		print jwt.tojohn(sys.argv[1])
