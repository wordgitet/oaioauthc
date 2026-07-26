/*
** Process entry point.
**
** Command parsing and all application behavior live in app_main.  Keeping
** main as this thin wrapper makes that behavior callable by tests or another
** embedding layer without duplicating process startup policy.
*/

#include "app.h"

/* Preserve app_main's return value as the process exit status. */
int
main(int argc, char **argv)
{
	return app_main(argc, argv);
}
