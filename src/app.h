/*
** Command-line application interface.
**
** app_main is separated from process main so tests and future embedding code
** can run the same option parsing and command dispatch with an explicit argv.
*/

#ifndef OAIOAUTHC_APP_H
#define OAIOAUTHC_APP_H

/* Return a conventional process status after handling one complete command. */
int	app_main(int, char **);

#endif
