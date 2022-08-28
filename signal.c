#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

void my_signal_handler(int signum)
{
}

int register_signal_handling()
{
    struct sigaction new_action;
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_handler = my_signal_handler; // Assign the new sinal handler, overwrite default behavior for ctrl+c
    // new_action.sa_handler = SIG_IGN; // Just ignore  ctrl+c
    sigaction(SIGUSR1, &new_action, NULL); // Regirter the new signal handler
}
