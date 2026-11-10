This is the repository for our IT355 Group Project 2.

POSSIBLE ISSUES
1. Terminal output: "BANK_PEPPER is not set. See setup notes"
   
   then you must do these steps to run the program. Firstly, in the
   terminal run the command: $env:BANK_PEPPER="aString", but replace
   'aString' with a random string of your choosing. This creates an environment variable
   that is used as a Pepper, meaning the string is added to the password
   hash to make the stored password has more random. Doing this requires
   you to run the code in the same terminal as where the environment variable
   was set up. This also means that any accounts created under this environment
   variable will require that same environment variable to access those accounts
   again
