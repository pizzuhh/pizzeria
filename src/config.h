#pragma once
/*
This file will be used to easily configure versions, authors, etc.
*/

#define AUTHOR "pizzuhh"
#define RELEASE_URL "https://api.github.com/repos/pizzuhh/pizzeria/releases"
#define VERSION "3.2"

// TODO (0): Make these to use server-cfg.json file:
#define FILTER 0 // profanity filter status

/* FILTER_ACTION sets the action to be performed when someone sends message containing blocked word
### NOTE: 
Private messages will not be checked for privacy reasons!

* `0o000` - Do nothing.

* `0o001` - Do not send the message to other clients and warn the sender.
* `0o010` - Do not send the message to other clients and kick the sender
* `0o100` - Do not send the message to other clients and ban the sender
Combined:
* `0o011` - Do not send the message to other clients, warn the sender and kick them with reason "FILTER_TRIGGERED".
* `0o101` - Do not send the message to other clients, warn the sender and ban them.

* `0o111` - Is pointless since the sender will be kicked when banned.

*/
#define FILTER_ACTION 0o000
#define FILET_CFG NULL // profanity list. Bad words for the server to block
