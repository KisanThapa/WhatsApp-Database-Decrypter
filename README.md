# WhatsApp-Database-Decrypter
An application which can decypt WhatsApp database (i.e crypt12)

**WhatsApp Database Decrypter**
-

- **Introduction :** WhatsApp is the most secure messaging application available right now. They store their database by most secure encryption technology i.e. crypt12.  WhatsApp used to backup its messages in an SQLite3 database and used to store it in the WhatsApp folder of your phone. With an increasing public awareness related to data privacy, WhatsApp introduced an encryption algorithm named CRYPT12 which is used to encrypt its SQLite database. The CRYPT12 algorithm is based on Advance encryption standards(AES) having a key size of 256 bits and block size of 128 bits.

- **Procedure :** 
1. _Extract Encryption Key :_ WhatsApp stores encryption key in its system file which can be located by other applications like file managers. So to extract encryption key we have to enable root permission of our android phone. Then we can backup system files of WhatsApp by "ES File Explorer" application. Encryption Key is located in `com.whatsapp/file/key`.

2. _Get Database :_ WhatsApp used to backup its messages, call logs, friend list in an SQLite3 database in encrypted by crypt12 and used to store it in the WhatsApp folder of your phone of path `root/WhatsApp/Databases/`.

3. _Passing Arguments :_ This program takes two arguments first argument is encrypted SQLite3 database file and second argument encryption key file. e.g. `msgstore-2018-11-12.1.db.crypt12` and `key`. 

This program decrypt database and saves as a `msgstore.db` which can be opened in any database browser application.

