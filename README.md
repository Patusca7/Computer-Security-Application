# Computer Security Application

In this project, my goal is to create a computer security application built with Python, implementing the following tools:

1. Detect and list which network ports are available on one or more remote machines.  
2. Generate a UDP flood (DoS) attack against a remote IP address.
3. Generate a SYN flood.  
4. Analyze and process log files from at least two services, listing the source of invalid accesses and/or access attempts. 
   The output of the processing should include:
   - Lists of countries of origin;
   - The dates of the attempts and/or accesses.  
5. Develop a basic service for secure message exchange between a client and a server, using symmetric and/or asymmetric keys.  
6. Develop a port-knocking client to establish an SSH login connection to a Linux machine.  
7. Develop a simple “password manager”—this application must store 3 fields (URL / user / pass).
   It must allow users to create, update, delete, and view records.  
   It must use asymmetric keys to encrypt the respective records.  
   Two-factor authentication (2FA) must be implemented to access and view passwords.

---

In addition to these features, there are some extra features that can be explored, such as:

8. A multi-user messaging service, with archiving of secure messages exchanged among all participants.  
   These messages must be stored in text files encrypted with asymmetric keys.  
   Messages must be stored only on the server side.
   It must be possible to view all messages using the corresponding private key.  

10. At the request of any client of the messaging system, it must be possible to list, delete, and download all archived messages stored on the server in which the client was a participant.  

11. It must be possible to back up or export—using symmetric or asymmetric keys—all messages exchanged in the basic messaging service or the multi-user messaging service to an encrypted file, which can be decrypted with the correct credentials.

## ⚠️ Legal Notice
This work was developed exclusively in an academic context. Any use of this project outside of that scope is the sole responsibility of the user; the author cannot be held liable for any improper, incorrect, or unauthorized use.
