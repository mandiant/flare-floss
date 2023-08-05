## Go String Extraction
Programs compiled by the Go compiler use a string representation that is difficult to interpret by humans. Although they are UTF-8 encoded, and therefore show up in the output of `strings.exe`, program strings are not NULL-terminated. This means separate strings within the binary may appear as a large chunk of indistinguishable string data.

FLOSS implements an algorithm to handle the unusual characteristics of strings in Go binaries. This approach analyzes instances of the `struct String` type to identify candidate strings and reasons about the length-sorted order to avoid false positives. Crucially, FLOSS automatically handles the complexities of Go strings and displays strings as written in the program's source code.

It's important to mention that there are other types of strings, such as runtime strings, which are not derived from the program strings. 

### Algorithm:

1. Analyze the string instances within the binary.
    - In Go, strings are encoded as structs (see source code links below) containing two fields: a pointer to the string's underlying data and the length of the string.
    - By examining these instances, we can identify the strings and their locations within the binary.
2. Identify the longest continuous sequence of monotonically increasing string lengths to find the string blob.
3. Use the byte sequence `00 00 00 00` as a delimiter to accurately mark the boundaries of the string blob.
4. Extract the string blob located between the identified boundaries.
5. Split the identified string blob, based on the cross-references available in the binary to separate the individual strings.

Please note that while FLOSS handles many scenarios effectively, there are certain optimizations, such as inlined constants, that may not be fully supported yet. 
For more information on Go strings, you can refer to the Go project's documentation and the source code of the struct String layout.

Learn more:

    Go Project: [Go Project](https://github.com/golang/go)
    Blog post: [Unveiling Go Strings: A Google Summer of Code Journey](https://medium.com/p/92f6d9fee97c)
    Source code: 
    - https://github.com/golang/go/blob/36ea4f9680f8296f1c7d0cf7dbb1b3a9d572754a/src/builtin/builtin.go#L70-L73
    - https://github.com/golang/go/blob/38e2376f35907ebbb98419f1f4b8f28125bf6aaf/src/go/types/builtins.go#L824-L825