/*
 * Thanks to Michael Bailey for the idea and source code
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

char *key = "dRSTzVefgHIhUJK2tjpLqru.y0is1vwOPxEF3l4kcWXn/o7Ym9BCD5MN6GQa8AbZ";

void __cdecl substitution_cipher(char * encoded, int len)
{
	int i;
	int keyoffset;
	char *pEncodedChar;
	int c;

	for ( i = 0; i < len; i++)
	{
		keyoffset = 0;
		pEncodedChar = &encoded[i];
		c = encoded[i];

		keyoffset = ((char *)memchr(key, c, 64) - (char *)key);

		if ( keyoffset >= 26 )
		{
			if ( keyoffset >= 52 )
			{
				if ( keyoffset < 64 )
					c = (keyoffset - 6);
			}
			else
			{
				c = (keyoffset + 39);
			}
		}
		else
		{
			c = (keyoffset + 97);
		}

		*pEncodedChar = c;
	}
}

int main(int argc, char **argv)
{
    char in_out[] = "xzhhKDmKjhT";

	substitution_cipher(in_out, strlen(in_out));

	printf("%s\n", in_out);

	return 0;
}

