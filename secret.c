/*
 *  Introduction to Software Security Assignment (Laboratory) 1
 *  Hijacked application target program
 *  Copyright (C) 2023  Roy Simanovich
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>

/*
 * @brief A program that asks the user for a password and then does
 *          super secret stuff.
 *
 * @param void No arguments are passed to the program.
 *
 * @return 0 always.
 *
 * @note This program is the target of the hijacking attack.
 * @note This program must be run after the server program.
 */
int main(void){
	char password[1000];

	printf("Please enter password\n");
	scanf("%s\n", password);
	printf("Doing super secret stuff\n");

	while (1);

	return 0;
}
