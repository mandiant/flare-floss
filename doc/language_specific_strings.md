## Go String Extraction
Programs compiled by the Go compiler use a string representation that is difficult to interpret by humans. Although they are UTF-8 encoded, and therefore show up in the output of `strings.exe`, program strings are not NULL-terminated. This means separate strings within the binary may appear as a large chunk of indistinguishable string data.

FLOSS implements an algorithm to handle the unusual characteristics of strings in Go binaries. This approach analyzes instances of the `struct String` type to identify candidate strings and reasons about the length-sorted order to avoid false positives. Crucially, FLOSS automatically handles the complexities of Go strings and displays strings as written in the program's source code.

 It's important to mention that there are other types of strings, such as runtime strings, which are not derived from the program strings. While FLOSS may not handle these types directly, it provides valuable insights into the strings originated within the program.

### Algorithm:-

1. Analyze the struct string instances within the binary.
    - In Go, a struct string represents a string value. It consists of two components: a pointer to the string's underlying data and the length of the string.
    - By examining these instances, we can identify the characteristics of the strings and their locations within the binary.
2. Identify the longest continuous sequence of monotonically increasing string lengths.
3. This longest sequence denotes the string blob.
4. Examine the surrounding bytes to detect the occurrence of the byte sequence 00 00 00 00.
5. Use the byte sequence as a delimiter to accurately mark the boundaries of the extracted string.
6. Extract the string blob located between the identified boundaries.
7. Split the identified string blob, based on the cross-references available in the binary, effectively separating the individual strings.

By implementing this algorithm, the FLOSS tool is capable of efficiently locating and extracting Go strings from binaries.

Please note that while FLOSS handles many scenarios effectively, there are certain optimizations, such as inlining constants, that may not be fully supported yet. 
For more information on Go strings, you can refer to the Go project's documentation and the source code of the struct String layout. Feel free to explore these resources to expand your understanding of this fascinating topic.

Learn more:

    Go Project: [Go Project](https://github.com/golang/go)
    Blogpost: [Blog](https://medium.com/p/92f6d9fee97c)
    Resources: 
    - https://github.com/golang/go/blob/36ea4f9680f8296f1c7d0cf7dbb1b3a9d572754a/src/builtin/builtin.go#L70-L73
    - https://github.com/golang/go/blob/38e2376f35907ebbb98419f1f4b8f28125bf6aaf/src/go/types/builtins.go#L824-L825