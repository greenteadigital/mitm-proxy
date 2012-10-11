import subprocess
pipe = ()
stdout = ''
def sudo(command):
	global pipe, std_out
	pipe = subprocess.Popen(['su','-c','/system/bin/sh'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout = pipe.communicate(input=command)	#use std_out[0] as shell response if running with sl4a
	#print std_out[0]