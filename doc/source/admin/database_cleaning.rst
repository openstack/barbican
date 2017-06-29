Database Cleaning
=================

Entries in the Barbican database are soft deleted and can build up over time.
These entries can be cleaned up with the clean up command. The command
can be used with a cron job to clean the database automatically on intervals.


Commands
--------

The command ```barbican-manage db clean``` can be used to clean up the database.
By default, it will remove soft deletions that are at least 90 days old since
deletion

```barbican-manage db clean --min-days 180``` (```-m```) will go
through the database and remove soft deleted entries that are at least 90 days
old since deletion. The default value is 90 days. Passing a value of
```--min-days 0``` will delete all soft-deleted entries up to today.

```barbican-manage db clean --clean-unassociated-projects``` (```-p```) will go
through the database and remove projects that have no associated resources.
The default value is False.

```barbican-manage db clean --soft-delete-expired-secrets``` (```-e```) will go
through the database and soft delete any secrets that are past
their expiration date. The default value is False. If ```-e``` is used along
with ```---min-days 0``` then all the expired secrets will be hard deleted.

```barbican-manage db clean --verbose``` (```-V```) will print more information
out into the terminal.

```barbican-manage db clean --log-file``` (```-L```) will set the log file
location. The creation of the log may fail if the user running the command
does not have access to the log file location or if the target directory
does not exist. The default value for log_file can be found in
```/etc/barbican/barbican.conf``` The log will contain the verbose
output from the command.

Cron Job
--------

A cron job can be created on linux systems to run at a given interval to
clean the barbican database.

Crontab
'''''''

1. Start the crontab editor ```crontab -e``` with the user that runs the clean up
command
2. Edit the crontab section to run the command at a given interval.
```<minute 0-59> <hour 0-23,0=midnight> <day 1-31> <month 1-12> <weekday 0-6, 0=Sunday> clean up command```

Crontab Examples
''''''''''''''''

```00 00 * * * barbican-manage db clean  -p -e``` -Runs a job everyday at midnight
which will remove soft deleted entries that  90 days old since soft deletion,
will clean unassociated projects, and will soft delete secrets that are
expired.

```00 03 01 * * barbican-manage db clean -m 30``` -Runs a job every month at 3AM
which will remove soft deleted entries that are at least 30 days old since
deletion.

```05 01 07 * 6 barbican-manage db clean -m 180 -p -e -L /tmp/barbican-clean-command.log```
-Runs a job every month at 1:05AM on the 7th day of the month and every Saturday.
Entries that are 180 days old since soft deletion will be removed from the
database. Unassociated projects will be removed. Expired secrets will be
soft deleted. The log file will be saved to ```/tmp/barbican-clean-command.log```
