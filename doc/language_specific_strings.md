## Go String Extraction
Programs compiled by the Go compiler use a string representation that is difficult to interpret by humans. Although they are UTF-8 encoded, and therefore show up in the output of `strings.exe`, program strings are not NULL-terminated. This means separate strings within the binary may appear as a large chunk of indistinguishable string data.

FLOSS implements an algorithm to handle the unusual characteristics of strings in Go binaries. This approach analyzes instances of the `struct String` type to identify candidate strings and reasons about the length-sorted order to avoid false positives. Crucially, FLOSS automatically handles the complexities of Go strings and displays strings as written in the program's source code.

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