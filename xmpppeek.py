#!/usr/bin/env python

# xmpppeek.py
# Version 0.1
# Ben Lincoln, 2013-06-25
# Based on xmppmitm.py by iamultra (https://github.com/iamultra/xmppmitm)

import sys, socket, thread, ssl, re, base64, os
from datetime import datetime, date, time, tzinfo, timedelta
from dateutil import tz

HOST = '0.0.0.0'
PORT = 5222
BUFSIZE = 4096

logFilePath = 'xmpppeek-log.txt'
writeToLog = 1

stripTLSRequest = 0

closeChannelOnEmptyMessage = 0
closeChannelOn0x20 = 1

#socketTimeoutPlain = 30.0
socketTimeoutPlain = 3.0
#socketTimeoutSSL = 60.0
#socketTimeoutSSL = 30.0
socketTimeoutSSL = 3.0

messageDelimiterStart = '}}}'
messageDelimiterEnd = '{{{'

to_zone = tz.tzlocal()

runServer = 1

def astimezone(self, tz):
	if self.tzinfo is tz:
		return self
	# Convert self to UTC, and attach the new time zone object.
	utc = (self - self.utcoffset()).replace(tzinfo=tz)
	# Convert from UTC to tz's local time.
	return tz.fromutc(utc)

def outputMessage(m):
	dt = datetime.now().replace(tzinfo=to_zone).isoformat(' ')
	logMessage = "[{0}] {1}".format(dt, m)
	print logMessage
	if writeToLog == 1:
		try:
			f = open(logFilePath, 'a+b')
			f.write(logMessage)
			f.write(os.linesep)
			#f.write('\n')
		except Exception as e:
			print '[Exception writing to log file ''{0}'': {1}]'.format(logFilePath, e)


def child(clientsock, clientAddr, target, certfile='', keyfile=''):
	clientReqSSL = 0
	serverReqSSL = 0
	sslEnabled = 0
	sslBridgeUp = 0
	formattedServerAddress = '{0}:{1}'.format(target, PORT)
	targetsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	targetsock.settimeout(socketTimeoutPlain)		
	clientsock.settimeout(socketTimeoutPlain)
	closeConnections = 0
	runChildLoop = 1
	try:
		outputMessage('[Server connect to {0}]'.format(target))
		targetsock.connect((target,PORT))
		while runChildLoop == 1:

			try:
				if sslEnabled == 0:
					p = clientsock.recv(BUFSIZE)
				else:
					p = sslclientsock.recv(BUFSIZE)
				if not p:
					outputMessage('[Client closed channel]')
					runChildLoop = 0
					closeConnections = 1
				if closeChannelOn0x20 == 1:
					if p == ' ':
						outputMessage('[Client sent a single space - closing this channel]')
						runChildLoop = 0
						closeConnections = 1
				if closeChannelOnEmptyMessage == 1:
					if p.strip() == '':
						outputMessage('[Client sent an empty message - closing this channel]')
						runChildLoop = 0
						closeConnections = 1
				strP = str(p)
				matches = re.findall(r'starttls', strP)
				if len(matches) > 0:
					if stripTLSRequest == 0:
						outputMessage('[Client initiated TLS negotiation]')
						clientReqSSL = 1
					else:
						outputMessage('[Client attempted to initiate TLS negotiation - stripping this request]')
						outputMessage('[Original data: {0}]'.format(p))
						strippedP = strP.replace('<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>', '')
						strippedP = strippedP.replace('<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"></starttls>', '')
						outputMessage('[Modified data: {0}]'.format(strippedP))
						p = strippedP
						
				outputMessage('[(C2S) {0} -> {1}] {2}{3}{4}'.format(clientAddr, formattedServerAddress, messageDelimiterStart, p, messageDelimiterEnd))
				if sslEnabled == 0:
					targetsock.send(p)
				else:
					ssltargetsock.send(p)


			except socket.error as e:
				if "timed out" not in str(e):
					raise e	

			if sslBridgeUp == 0:
				if serverReqSSL == 1:
					if clientReqSSL == 1:
						outputMessage('[Client and server have agreed to an encrypted channel]')
						raisedBridge = 1
						try:
							outputMessage('[Creating SSL-wrapped socket to client]')
							sslclientsock = ssl.wrap_socket(clientsock,server_side=True,do_handshake_on_connect=True,suppress_ragged_eofs=True,certfile=certfile,keyfile=keyfile)
							try:
								sslclientsock.settimeout(socketTimeoutSSL)
							except Exception as e:
								outputMessage('[Exception setting SSL client tocket timeout: {0}]'.format(e))
							sslEnabled = 1
							outputMessage('[SSL-wrapped socket to client created]')
						except Exception as e:
						#	if "timed out" not in str(e):
						#		outputMessage('[Exception creating SSL bridge (to client): {0}]'.format(e))
						#		raisedBridge = 0
							outputMessage('[Exception creating SSL bridge (to client): {0}]'.format(e))
							raisedBridge = 0
						if raisedBridge == 1:
							try:
								outputMessage('[Creating SSL-wrapped socket to server]')
								ssltargetsock = ssl.wrap_socket(targetsock,do_handshake_on_connect=True,suppress_ragged_eofs=True)
								try:
									ssltargetsock.settimeout(socketTimeoutSSL)
								except Exception as e:
									outputMessage('[Exception setting SSL target tocket timeout: {0}]'.format(e))
								sslBridgeUp = 1
								outputMessage('[SSL-wrapped socket to server created]')
							except Exception as e:
							#	if "timed out" not in str(e):
							#		outputMessage('[Exception creating SSL bridge (to server): {0}]'.format(e))
							#		raisedBridge = 0
								outputMessage('[Exception creating SSL bridge (to server): {0}]'.format(e))
								raisedBridge = 0
						if raisedBridge == 0:
							sslEnabled = 0
							sslBridgeUp = 0
						else:
							outputMessage('[Successfully created SSL bridge]')
							serverReqSSL = 0
							clientReqSSL = 0
						#serverReqSSL = 0
						#clientReqSSL = 0


			try:
				if sslEnabled == 0:
					p = targetsock.recv(BUFSIZE)
				else:
					p = ssltargetsock.recv(BUFSIZE)
				if not p:
					outputMessage('[Server closed channel]')
					runChildLoop = 0
					closeConnections = 1
				if closeChannelOn0x20 == 1:
					if p == ' ':
						outputMessage('[Server sent a single space - closing this channel]')
						runChildLoop = 0
						closeConnections = 1
				if closeChannelOnEmptyMessage == 1:
					if p.strip() == '':
						outputMessage('[Server sent an empty message - closing this channel]')
						runChildLoop = 0
						closeConnections = 1
				strP = str(p)
				matches1 = re.findall(r'proceed', strP)
				if len(matches1) > 0:
					matches2 = re.findall(r'xmpp-tls', strP)
					if len(matches2) > 0:
						outputMessage('[Server agreed to TLS]')
						serverReqSSL = 1
				else:
					matches = re.findall(r'starttls', strP)
					if len(matches) > 0:
						if stripTLSRequest == 0:
							outputMessage('[Server initiated TLS negotiation]')
						else:
							outputMessage('[Server attempted to initiate TLS negotiation - stripping this request]')
							outputMessage('[Original data: {0}]'.format(p))
							strippedP = strP.replace('<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>', '')
							strippedP = strippedP.replace('<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"></starttls>', '')
							outputMessage('[Modified data: {0}]'.format(strippedP))
							p = strippedP
				outputMessage('[(S2C) {0} -> {1}] {2}{3}{4}'.format(formattedServerAddress, clientAddr, messageDelimiterStart, p, messageDelimiterEnd))
				if sslEnabled == 0:
					clientsock.send(p)
				else:
					sslclientsock.send(p)
				
			except socket.error as e:
				if "timed out" not in str(e):
					raise e

			if sslBridgeUp == 0:
				if serverReqSSL == 1:
					if clientReqSSL == 1:
						outputMessage('[Client and server have agreed to an encrypted channel]')
						raisedBridge = 1
						try:
							outputMessage('[Creating SSL-wrapped socket to client]')
							sslclientsock = ssl.wrap_socket(clientsock,server_side=True,do_handshake_on_connect=True,suppress_ragged_eofs=True,certfile=certfile,keyfile=keyfile)
							try:
								sslclientsock.settimeout(socketTimeoutSSL)
							except Exception as e:
								outputMessage('[Exception setting SSL client tocket timeout: {0}]'.format(e))
							sslEnabled = 1
							outputMessage('[SSL-wrapped socket to client created]')
						except Exception as e:
						#	if "timed out" not in str(e):
						#		outputMessage('[Exception creating SSL bridge (to client): {0}]'.format(e))
						#		raisedBridge = 0
							outputMessage('[Exception creating SSL bridge (to client): {0}]'.format(e))
							raisedBridge = 0
						if raisedBridge == 1:
							try:
								outputMessage('[Creating SSL-wrapped socket to server]')
								ssltargetsock = ssl.wrap_socket(targetsock,do_handshake_on_connect=True,suppress_ragged_eofs=True)
								try:
									ssltargetsock.settimeout(socketTimeoutSSL)
								except Exception as e:
									outputMessage('[Exception setting SSL target tocket timeout: {0}]'.format(e))
								sslBridgeUp = 1
								outputMessage('[SSL-wrapped socket to server created]')
							except Exception as e:
							#	if "timed out" not in str(e):
							#		outputMessage('[Exception creating SSL bridge (to server): {0}]'.format(e))
							#		raisedBridge = 0
								outputMessage('[Exception creating SSL bridge (to server): {0}]'.format(e))
								raisedBridge = 0
						if raisedBridge == 0:
							sslEnabled = 0
							sslBridgeUp = 0
						else:
							outputMessage('[Successfully created SSL bridge]')
							serverReqSSL = 0
							clientReqSSL = 0
						#serverReqSSL = 0
						#clientReqSSL = 0

			if runServer == 0:
				runChildLoop = 0
				closeConnections = 1
				break

	except Exception as e:
		outputMessage('[Connection-level exception: {0}  in thread for bridge ({1} -> {2})]'.format(e, clientAddr, formattedServerAddress))
		closeConnections = 1
		runChildLoop = 0
	if closeConnections == 1:
		outputMessage('[Disengaging bridge ({0} -> {1})]'.format(clientAddr, formattedServerAddress))
		outputMessage('[Closing client socket (non-SSL) ({0} -> {1})]'.format(clientAddr, formattedServerAddress))
		try:
			clientsock.shutdown(1)
			clientsock.close()
		except Exception as e2:
			outputMessage('[Exception while closing client socket (non-SSL): {0}'.format(e2))
		outputMessage('[Closing target socket (non-SSL) ({0} -> {1})]'.format(clientAddr, formattedServerAddress))
		try:
			targetsock.shutdown(1)
			targetsock.close()
		except Exception as e2:
			outputMessage('[Exception while closing target socket (non-SSL): {0}'.format(e2))
		outputMessage('[Closing client socket (SSL) ({0} -> {1})]'.format(clientAddr, formattedServerAddress))
		try:
			sslclientsock.shutdown(1)
			sslclientsock.close()
		except Exception as e2:
			outputMessage('[Exception while closing client socket (SSL): {0}'.format(e2))
		outputMessage('[Closing target socket (SSL) ({0} -> {1})]'.format(clientAddr, formattedServerAddress))
		try:
			ssltargetsock.shutdown(1)
			ssltargetsock.close()
		except Exception as e2:
			outputMessage('[Exception while closing target socket (SSL): {0}'.format(e2))
		#raise Exception("Closing connections")


if __name__=='__main__': 
	keyfile = ''
	certfile = ''
	if len(sys.argv) < 4:
		sys.exit('Usage: %s TARGETHOST CERTFILE KEYFILE\nExample: %s jabber.yourcompany.org\nExample: %s jabber.yourcompany.org cert.pem key.pem' % sys.argv[0], sys.argv[0], sys.argv[0])
	target = sys.argv[1]
	if len(sys.argv) == 4:
		certfile = sys.argv[2]
		keyfile = sys.argv[3]
	myserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	myserver.bind((HOST, PORT))
	myserver.listen(2)
	outputMessage('[Server started]')
	outputMessage('[Listener ready on port {0}]'.format(PORT))
	try:
		while 1:
			try:
				outputMessage('[Main thread waiting for client connection]')
				client, addr = myserver.accept()
				formattedAddress = '{0}:{1}'.format(addr[0], addr[1])
				outputMessage('[Client connect from {0}]'.format(formattedAddress))
				thread.start_new_thread(child, (client, formattedAddress, target, certfile, keyfile))
			except Exception as e:
				if "Closing connections" not in str(e):
					raise e
	except KeyboardInterrupt:
		outputMessage('[Console operator terminated server]')
		runServer = 0
		myserver.close()

	outputMessage('[Server shutdown]')

