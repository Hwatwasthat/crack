// crack takes a password hash from the crypt function and tries to find the matching
// password. Can take variable length passwords. Must be composed of alphabetical
// characters only
#define _XOPEN_SOURCE       /* See feature_test_macros(7) */
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <cs50.h>

// Define constants related to arguments, can re-use arg system by changing these.
#define MIN_ARGS 2
#define MAX_ARGS 3
#define OPTIONAL_ARGS 1

// Function prototypes.
int verify_input(int);
int process_input(int, char **, char *, int *);
void output(bool, char *);
char *get_salt(char *);
bool crack(char *, char *, char *, int);

// Character set, all upper and lower characters. Null character at front to simplify
// finding shorter passwords as loop initialises all values to null.
const char charset[] = "\0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";


// Does sanity checks on inputs and runs main loop.
int main(int argc, char *argv[])
{
    int max_length, err;
    char hash[13];
    bool result;
    max_length = 5;

    err = verify_input(argc);
    if (err)
    {
        return 1;
    }

    err = process_input(argc, argv, hash, &max_length);
    if (err)
    {
        return 1;
    }

    char *salt = get_salt(hash);

    char password[max_length + 1];
    password[max_length] = '\0';

    result = crack(hash, salt, password, max_length - 1);
    output(result, password);
}

// Verifies that the input is within expected bounds, returns help text if incorrect.
int verify_input(int argc)
{
    if (argc < MIN_ARGS)
    {
        printf("%d required, %d optional arguments\n", MIN_ARGS, OPTIONAL_ARGS);
        return 1;
    }
    else if (argc > MAX_ARGS)
    {
        printf("Crack only takes %d argument max\n", MAX_ARGS);
        return 1;
    }

    return 0;
}

// Process input takes the provided args and extracts the max_length (if given) and the
// provided hash. Returns a pointer to the hash character array.
int process_input(int argc, char *argv[],char *hash, int *maxLenPtr)
{
    if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "help"))
    {
        printf("Usage: crack-rec (length - optional) (hash - 13 characters from crypt)\n");
        printf("Recommended no longer than 8 characters.\n");
        return 1;
    }
    else if (argc == MAX_ARGS)
    {
        *maxLenPtr = atoi(argv[1]);
        memcpy(hash, argv[2], 13);
    }
    else
    {
        // Easy way to copy array over
        memcpy(hash, argv[1], 13);
    }
    return 0;
}

// Outputs the result of the crack. presents if the password was found or search
// space was exhausted.
void output(bool result, char *password)
{
    printf("\a");
    if (result)
    {
        printf("Found: ");
        int i = 0;
        while (password[i] != '\0')
        {
            printf("%c", password[i]);
            i++;
        }
        printf("\n");
    }
    else
    {
        printf("Not Found\n");
    }
}


// Extracts the salt from the hashed password provided by the crypt function.
char *get_salt(char *hash)
{
    static char salt[2];
    // Salt is stated as being stored as the first two characters in the output hash
    memcpy(salt, hash, 2);
    return salt;
}

// crack recursively works through solutions with the given character set.
// works to the length provided (as position). Returns a bool to signal complete.
bool crack(char *hash, char *salt, char*password, int position)
{
    bool solved = false;
    for (int i = 0; i < 53; i++)
    {
        password[position] = charset[i];
        if (position == 0)
        {
            // strcmp returns 0 if a match, therefore, invert to match true.
            if (!strcmp(hash, crypt(password, salt)))
            {
                solved = true;
                return solved;
            }
        }
        else
        {
            // Recursively call function to lower indices.
            solved = crack(hash, salt, password, position - 1);
            if (solved)
            {
                return solved;
            }
        }
    }
    return solved;
}
