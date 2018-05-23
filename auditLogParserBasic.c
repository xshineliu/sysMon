/* gcc -o auditLogParser auditLogParser.c -lauparse -laudit */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include "libaudit.h"
#include "auparse.h"

/* Global Data */
static volatile int stop = 0;
static volatile int hup = 0;
static auparse_state_t *au = NULL;
char *logPath = "/tmp/auditlog_reparse.log";
FILE * fp = NULL;

/* Local declarations */
static void handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type,
		void *user_data);

/*
 * SIGTERM handler
 */
static void term_handler(int sig) {
	stop = 1;
}

/*
 * SIGHUP handler: re-read config
 */
static void hup_handler(int sig) {
	hup = 1;
}

static void reload_config(void) {
	hup = 0;
}

int main(int argc, char *argv[]) {
	char tmp[MAX_AUDIT_MESSAGE_LENGTH + 1];
	struct sigaction sa;

	/* Register sighandlers */
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	/* Set handler for the ones we care about */
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

	FILE *aufile = stdin;

	if (argc > 1 && strcmp(argv[1], "-") && (!(aufile = fopen(argv[1], "r")))) {
		errx(EXIT_FAILURE, "failed fopen");
	}

	if ((au = auparse_init(AUSOURCE_FILE_POINTER, aufile)) == NULL) {
		errx(EXIT_FAILURE, "failed auparse_init");
	}

	auparse_add_callback(au, handle_event, NULL, NULL);

	fp = fopen(logPath, "w+");
	if (fp == NULL) {
		printf("ERROR %d\n", errno);
	}

	do {
		/* Load configuration */
		if (hup) {
			reload_config();
		}

		/* Now the event loop, fgets_unlocked _GNU_SOURCE only */
		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, aufile) && hup == 0
				&& stop == 0) {
			auparse_feed( au, tmp, strnlen( tmp, MAX_AUDIT_MESSAGE_LENGTH));
		}

		if (feof(aufile))
			break;

	} while (stop == 0);

	/* Flush any accumulated events from queue */
	auparse_flush_feed(au);
	auparse_destroy(au);
	if (stop)
		printf("audisp-example is exiting on stop request\n");
	else
		printf("audisp-example is exiting on file EOF\n");

	fclose(fp);
	return 0;
}

/* This function shows how to dump a whole event by iterating over records */
static void dump_whole_event(auparse_state_t *au) {
	auparse_first_record(au);
	do {
		fprintf(fp, "%s %s\n", __func__, auparse_get_record_text(au));
	} while (auparse_next_record(au) > 0);
	fprintf(fp, "\n");
}

/* This function shows how to dump a whole record's text */
static void dump_whole_record(auparse_state_t *au) {
	fprintf(fp, "%s: %s\n", audit_msg_type_to_name(auparse_get_type(au)),
			auparse_get_record_text(au));
	fprintf(fp, "\n");
}

static void dump_execv_details(auparse_state_t *au) {
	;
}

/* This function shows how to iterate through the fields of a record
 * and print its name and raw value and interpretted value. */
static void dump_fields_of_record(auparse_state_t *au) {
	fprintf(fp, "record type %d(%s) has %d fields\n", auparse_get_type(au),
			audit_msg_type_to_name(auparse_get_type(au)),
			auparse_get_num_fields(au));

	fprintf(fp, "line=%d file=%s\n", auparse_get_line_number(au),
			auparse_get_filename(au) ? auparse_get_filename(au) : "stdin");

	const au_event_t *e = auparse_get_timestamp(au);
	if (e == NULL) {
		fprintf(fp, "Error getting timestamp - aborting\n");
		return;
	}
	/* Note that e->sec can be treated as time_t data if you want
	 * something a little more readable */
	fprintf(fp, "event time: %u.%u:%lu, host=%s\n", (unsigned) e->sec, e->milli,
			e->serial, e->host ? e->host : "?");
	auparse_first_field(au);

	do {
		fprintf(fp, "field: %s=%s (%s)\n", auparse_get_field_name(au),
				auparse_get_field_str(au), auparse_interpret_field(au));
	} while (auparse_next_field(au) > 0);
	fprintf(fp, "\n");
}

/* This function receives a single complete event at a time from the auparse
 * library. This is where the main analysis code would be added. */
static void handle_event(auparse_state_t *au, auparse_cb_event_t cb_event_type,
		void *user_data) {
	int type, num = 0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	fprintf(fp, "^---> Enter %s\n", __func__);
	/* Loop through the records in the event looking for one to process.
	 We use physical record number because we may search around and
	 move the cursor accidentally skipping a record. */
	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		fprintf(fp, " --- %d\n", num);
		/* Now we can branch based on what record type we find.
		 This is just a few suggestions, but it could be anything. */
		switch (type) {
		case AUDIT_AVC:
			dump_fields_of_record(au);
			break;
		case AUDIT_SYSCALL:
			dump_whole_record(au);
			//dump_fields_of_record(au);
			break;
		case AUDIT_EXECVE:
			dump_whole_record(au);
			dump_fields_of_record(au);
			break;
		//case AUDIT_PROCTITLE:
		//	dump_fields_of_record(au);
		//	break;
		case AUDIT_USER_LOGIN:
			break;
		case AUDIT_ANOM_ABEND:
			break;
		case AUDIT_MAC_STATUS:
			dump_whole_event(au);
			break;
		default:
			//dump_whole_event(au);
			dump_whole_record(au);
			break;
		}
		num++;
	}
	fprintf(fp, "v--> TOTAL %d EVENTS HANDLED\n\n", num);
}
