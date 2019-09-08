#include <stdio.h>

int main(int argc, char* argv[])
{
	char flag[10] = {'S', 'E', 'C', 'R', 'E', 'T', 'F', 'L', 'A', 'G'};
	char digits[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
	int index = 0;

	while (1) {
		printf("Give me an index and I'll tell you what's there!\n");
		scanf("%d", &index);
		printf("Okay, here you go: %p %c\n", &digits[index], digits[index]);
	}
	return 0;
}
