# Donapi
Malicious NPM Packages Detector using Behavior Sequence Knowledge Mapping

## Some details

Some of the details about the **Donapi** will be briefly described here.

### Features

The paper involves a part of the machine learning model, so we propose corresponding features to help complete the task, as follows.


#### Obfuscation features

| Feature | Description |
| :----:  |    :----:   |
 |line_compression_ratio |	Code line compression ratio, which is the ratio of the number of lines of compressed code functions to the number of lines of original code
 |space_compression_ratio |	Space compression ratio, the ratio of the number of spaces in the compressed code to the number of spaces in the original code
 |prototype_count |	Number of prototype method calls
 |string_function_count |	Number of string function calls, e.g. "subString", "charAt"
 |encoding_function_count |	Number of encoding function calls, such as "escape", "String", "encodeURI"
 |symbol_count |	Number of occurrences of special characters, such as "%", "$"
 |white_space_count |	Number of white spaces
 |special_number_count| 	Number of special numbers, such as hexadecimal numbers and unicode encoding
 |average_identifier_length |	Average length of identifier
 |identifier_entropy |	Identifier Information Entropy
 |max_string_length |	Maximum string length
 |string_length_exceeded |	Number of strings over a certain length
 |lines_of_code |	Number of lines of code
 |kw_if_frequency| 	Frequency of the keyword 'if'
 |kw_else_frequency |	Frequency of the keyword 'else'
 |kw_while_frequency |	Frequency of the keyword 'while'
 |kw_for_frequency |	Frequency of the keyword 'for'
 |kw_switch_frequency |	Frequency of the keyword 'switch'
 |kw_case_frequency |	Frequency of the keyword 'case'
 |kw_default_frequency |	Frequency of the keyword 'default'
 |kw_continue_frequency |	Frequency of the keyword 'continue'
 |kw_break_frequency |	Frequency of the keyword 'break'
 |kw_true_frequency |	Frequency of the keyword 'true'
 |kw_false_frequency |	Frequency of the keyword 'false'
 |kw_function_frequency |	Frequency of the keyword 'function'


#### URL features
| Feature | Description |
| :----:  |    :----:   |
|entropy|	Longest subdomain entropy|
|length|	Maximum subdomain length|
|vowel_rate|	Percentage of vowel letters in the longest subdomain|
|consonant_rate	|Percentage of consonant letters in the longest subdomains|
|continue_char_rate|	Percentage of consecutive letters in the longest subdomain|
|duplicate_char_rate|	Percentage of repeated letters in the longest subdomain|
|no_char_rate|	Percentage of numeric characters in the longest subdomain|
|gibberish|	gibberish detection for determining the readability of the longest subdomains|
|top_domain|	Top-level domain types, including: xyz, br, us, etc.|

#### API sequence features

| Feature | Description |
| :----:  |    :----:   |
|send_sensitive_info|	Sending sensitive information to the outside
|query_environment_variables|	Query system environment variables
|network2stringExecution|	Download the content and execute it as a string
|fileWriteOperation2fileExecution|	Write to file and execute
|fileReadOperation2stringExecution|	Read the contents of the file and execute
|fileReadOperation2code	|Read files and execute code dynamically
|network2code|	Download content and execute code dynamically
|change_permission|	Modify file permissions and create processes
|identify_os_platform|	Identify operating system platforms
|modify_command_stream|	Modify the data flow of system command execution results
|command_execution|	Execute system commands
|sensitive_file_operation|	Performing sensitive file operations


#### Sensitive Behavior Types
| Sensitive Behavior Name | Description |
| :----:  |    :----:   |
|	NETWORK_OUT | Call the API for the network output, including multiple protocols, DNS takeaway and other methods.       
| NETWORK_IN | Call the API for network download, including various protocols and methods.   
| FILE_READ | Call the API for file reading or directory reading, and some APIs need to specify the second parameter as "r". 
| FILE_DELETE | Call the API for file deletion.   
| FILE_MODIFY | Call the API for file modification, and some APIs need to specify the second parameter as "w" or "a".
| FILE_CREATE | Call the API for file creation, and some APIs need to specify the second parameter as "w".   
| CODE_GENERATION | The calling code executes the API execution string. 
| SYSTEM_MESSAGE | Including user information, network interface, user directory, operating system platform, etc. 
| PROCESS_MESSAGE | Including the version, environment, platform, etc. of the current process. 
| PROCESS_COMMAND_EXECUTION | Call the command execution API to execute system commands.
| PROCESS_FILE_EXECUTION | Call file execution API to execute external program.
| SERIALIZATION | Call serialization API.


#### The key APIs we monitor and their implementation files
| Sensitive Behavior Name | Description |
| :----:  |    :----:   |
|./lib/fs.js | fs.access, fs.accessSync, fs.appendFile, fs.appendFileSync, fs.chmod, fs.chmodSync, fs.chown, fs.chownSync, fs.createReadStream, fs.copyFile, fs.copyFileSync, fs.cp, fs.cpSync, fs.createWriteStream, fs.exists, fs.existsSync, fs.fchmod, fs.fchmodSync, fs.fchown, fs.fchownSync, fs.ftruncate, fs.ftruncateSync, fs.lchown, fs.lchownSync, fs.link, fs.linkSync, fs.mkdir, fs.mkdirSync, fs.mkdtemp, fs.mkdtempSync, fs.open, fs.openSync, fs.opendir, fs.opendirSync, fs.read, fs.readFile, fs.readFileSync, fs.readSync, fs.readdir, fs.readdirSync, fs.readlink, fs.readlinkSync, fs.readv, fs.readvSync, fs.rename, fs.renameSync, fs.rm, fs.rmSync, fs.rmdir, fs.rmdirSync, fs.symlink, fs.symlinkSync, fs.truncate, fs.truncateSync, fs.unlink, fs.unlinkSync, fs.write, fs.writeFile, fs.writeFileSync, fs.writeSync, fs.writev, fs.writevSync
|./lib/internal/fs/promises.js | filehandle.appendFile, filehandle.chmod, filehandle.chown, filehandle.read, filehandle.createReadStream, filehandle.datasync, filehandle.createWriteStream,  filehandle.readableWebStream, filehandle.readv, filehandle.truncate, filehandle.write, filehandle.writeFile, filehandle.writev, promises.access, promises.appendFile, promises.chmod, promises.chown, promises.copyFile, promises.cp, promises.link, promises.mkdtemp, promises.mkdir, promises.open, promises.readFile, promises.readdir, promises.readlink, promises.realpath, promises.rename, promises.rm, promises.rmdir, promises.symlink, promises.truncate, promises.unlink, promises.writeFile
|./lib/child_process.js | child_process.exec, child_process.spawnSync, child_process.execFile, child_process.spawn,  child_process.execFileSync, child_process.execSync, child_process.fork
|./lib/internal/dns/callback_resolver.js | dns.resolve, dns.resolve6, dns.resolveCname, dns.resolveMx, dns.resolveNs, dns.resolveSrv, dns.resolveTxt, dns.reverse
|./lib/os.js | os.homedir, os.hostname, os.networkInterfaces, os.platform, os.userInfo
|./lib/http.js | http.get, http.request
|./lib/https.js | https.get, https.request
|./lib/net.js | net.connect, net.write
|./lib/dgram.js| dgram.connect, dgram.send
|./lib/_http_outgoing.js | request.end, request.write
|./lib/dns.js | dns.lookup
|./lib/internal/fs/dir.js | promises.opendir
|~ | process.arch, process.env, process.platform, process.versions


