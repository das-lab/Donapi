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
