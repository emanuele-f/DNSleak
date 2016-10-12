/*
 * ----------------------------------------------------------------------------
 * DNSleak - A tool to locally detect DNS leaks
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2016 - Emanuele Faranda
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */

#define _GNU_SOURCE
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <stdbool.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <libgen.h>
#include <errno.h>

#include "ndpi_util.h"
#include "names_count.h"

/******************************************************************************/

#define PCAP_SNAPLEN 1536
#define PCAP_PROMISC 0
#define PCAP_READ_TIMEOUT_MS 250

struct dnsleak_config {
  char * device_name;
  u_int dns_request_count;
  u_int dns_request_interval_ms;
  u_int capture_extra_time_ms;
  u_int stop_after_n_leaks;
  u_int8_t verbose;
};

static struct dnsleak_config default_config = {
  .device_name = NULL,
  .dns_request_count = 10,
  .dns_request_interval_ms = 200,
  .capture_extra_time_ms = 1000,
  .stop_after_n_leaks = 1,
  .verbose = 0
};

static u_int32_t total_packets = 0;
static sig_atomic_t dns_sent = 0;
static struct ndpi_workflow * workflow = NULL;
static struct dnsleak_config config;
static sig_atomic_t running = 1;

/******************************************************************************/

static void * capture_routine(void * arg);

/******************************************************************************/

static void on_protocol_discovered(struct ndpi_workflow * workflow,
        struct ndpi_flow_info * flow,
        void * udata) {
  const char * hostname = (const char *)flow->ndpi_flow->host_server_name;
  
  total_packets++;
  int marked = names_mark(hostname);
  
  if (config.verbose)
    printf("%sDNS '%s' [#%u]\n", marked ? "< " : "", hostname, total_packets);
}

static void pcap_packet_callback(u_char *args,
				 const struct pcap_pkthdr *header,
				 const u_char *packet) {
  ndpi_workflow_process_packet((struct ndpi_workflow *)args, header, packet);
}

static void exit_callback() {
  if (config.verbose)
    printf("%u packets captured, %u leaks / %u DNS requests\n",
            total_packets, names_get_marked(), dns_sent);

  if (workflow) {
    pcap_close(workflow->pcap_handle);
    ndpi_workflow_free(workflow);
    workflow = NULL;
  }
  
  names_end();
}

static void signals_handler (int signo) {
  if (running) {
    fprintf(stderr, "\nTerminating...\n");
    running = 0;
    if (workflow)
      pcap_breakloop(workflow->pcap_handle);
  } else {
    fprintf(stderr, "\nOk, I'm leaving now!\n");
    exit(1);
  }
}

/******************************************************************************/

static void usage(char * arg0) {
  fprintf(stderr, "Usage: %s [options] device\n\n"
          "Options:\n"
          " -c count      number of DNS requests to send (default %u)\n"
          " -i interval   millis between DNS requests send (default %u)\n"
          " -t time       extra millis to wait for a DNS packet to show up (default %u)\n"
          " -l leaks      maximum number of leaks to exit program (default %u)\n"
          " -v            print debug messages\n"
          "\nCopyright Emanuele Faranda <black.silver@hotmail.it>\n",
          basename(arg0),
          default_config.dns_request_count,
          default_config.dns_request_interval_ms,
          default_config.capture_extra_time_ms,
          default_config.stop_after_n_leaks);
}

static int read_config(int argc, char **argv, struct dnsleak_config * config) {
  *config = default_config;
  int opt;
  int valid = 1;

  while (valid && (opt = getopt(argc, argv, "c:i:t:l:v")) != EOF) {
    switch (opt) {
    case 'c':
      config->dns_request_count = atoi(optarg);
      break;

    case 'i':
      config->dns_request_interval_ms = atoi(optarg);
      break;

    case 't':
      config->capture_extra_time_ms = atoi(optarg);
      break;

    case 'l':
      config->stop_after_n_leaks = atoi(optarg);
      break;

    case 'v':
      config->verbose = 1;
      break;

    default:
      valid = 0;
    }
  }

  if (argc-1 == optind)
    config->device_name = argv[optind];
  else
    valid = 0;
  
  if (! valid) {
    usage(argv[0]);
    return 1;
  }

  return 0;
}

static struct timespec millis_to_timespec(u_int millis) {
  struct timespec tspec = {
    .tv_sec = millis / 1000,
    .tv_nsec = (millis % 1000) * 1000000L
  };

  return tspec;
};

static pcap_t * open_device_live(const char * dev) {
  char pcap_error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t * pcap_handle = NULL;

  pcap_handle = pcap_open_live(dev, PCAP_SNAPLEN, PCAP_PROMISC,
          PCAP_READ_TIMEOUT_MS, pcap_error_buffer);

  if(pcap_handle == NULL) {
    fprintf(stderr, "ERROR: could not open device '%s' for capture: %s\n", dev,
            pcap_error_buffer);
    return NULL;
  }
  
  return pcap_handle;
}

static struct ndpi_workflow * init_workflow(pcap_t * device) {
  NDPI_PROTOCOL_BITMASK to_dissect;
  struct ndpi_workflow_prefs prefs;
  struct ndpi_workflow * workflow;
  
  memset(&prefs, 0, sizeof(prefs));
  prefs.decode_tunnels = false;
  prefs.num_roots = 10;
  prefs.max_ndpi_flows = 1000;
  prefs.quiet_mode = true;

  workflow = ndpi_workflow_init(&prefs, device);
  ndpi_workflow_set_flow_detected_callback(workflow, on_protocol_discovered,
          NULL);
  NDPI_BITMASK_RESET(to_dissect);
  NDPI_BITMASK_ADD(to_dissect, NDPI_PROTOCOL_DNS);
  ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &to_dissect);

  return workflow;
}

static int start_capture_thread (struct ndpi_workflow * workflow,
        pthread_t * out) {
  pthread_attr_t attr;
  pthread_t thread_id;
  int rv;
  
  if ((rv = pthread_attr_init(&attr)) != 0) {
    fprintf(stderr, "pthread_attr_init failure with code %d\n", rv);
    return 1;
  }

    
  if ((rv = pthread_create(&thread_id, &attr, &capture_routine,
          workflow)) != 0) {
    fprintf(stderr, "pthread_create failure with code %d\n", rv);
    return 1;
  }

  if (out) *out = thread_id;
  
  return 0;
}

static int setup_signal_handlers(sigset_t * oldmask) {
  struct sigaction sa;
  int rv;

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signals_handler;
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGINT);
  sigaddset(&sa.sa_mask, SIGTERM);
  sigaddset(&sa.sa_mask, SIGHUP);

  // mask signals on main thread
  if ((rv = pthread_sigmask(SIG_BLOCK, &sa.sa_mask, oldmask)) != 0) {
    fprintf(stderr, "pthread_sigmask(SIG_BLOCK) failure with code %d\n", rv);
    return 1;
  }

  if (sigaction(SIGINT, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction(SIGINT) failure: %s\n", strerror(errno));
    return 1;
  }
  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction(SIGTERM) failure: %s\n", strerror(errno));
    return 1;
  }
  if (sigaction(SIGHUP, &sa, NULL) < 0) {
    fprintf(stderr, "sigaction(SIGHUP) failure: %s\n", strerror(errno));
    return 1;
  }

  return 0;
}

/******************************************************************************/

static void * capture_routine(void * arg) {  
  if (running) {  
    // main loop
    if (config.verbose) printf("Capturing packets...\n");
    
    if(workflow->pcap_handle != NULL) {
      pcap_loop(workflow->pcap_handle, -1, &pcap_packet_callback,
              (u_char *)workflow);
    }
  }

  return NULL;
}

int main(int argc, char **argv) {
  pcap_t * device;
  sigset_t oldmask;
  int rv;

  if (read_config(argc, argv, &config) != 0)
    return EXIT_FAILURE;

  if (setup_signal_handlers(&oldmask) != 0)
    return EXIT_FAILURE;

  device = open_device_live(config.device_name);
  if (device == NULL) return EXIT_FAILURE;
  workflow = init_workflow(device);
  if (workflow == NULL) return EXIT_FAILURE;

  srand(time(0));
  names_generate(config.dns_request_count);
  
  if ((rv = atexit(exit_callback)) != 0) {
    fprintf(stderr, "atexit failure with code %d\n", rv);
    return EXIT_FAILURE;
  }

  // capture thread with signals masked
  pthread_t capture_thread;
  if (start_capture_thread(workflow, &capture_thread) != 0)
    return EXIT_FAILURE;

  // main thread with signals enabled
  // We could miss a signal interrupt step here...this should be done in a sigwait loop
  if ((rv = pthread_sigmask(SIG_SETMASK, &oldmask, NULL)) != 0) {
    fprintf(stderr, "pthread_sigmask(SIG_SETMASK) failure with code %d\n", rv);
    return EXIT_FAILURE;
  }
  
  const struct timespec const_time = millis_to_timespec(config.dns_request_interval_ms);

  for (int i=0; i<config.dns_request_count &&
            running &&
            names_get_marked() < config.stop_after_n_leaks;
            i++) {
    struct sigevent sevp;
    memset(&sevp, 0, sizeof(sevp));
    sevp.sigev_notify = SIGEV_NONE;
    struct gaicb resolve_rec;
    struct gaicb * resolve_list = &resolve_rec;
    memset(&resolve_rec, 0, sizeof(resolve_rec));
    resolve_rec.ar_name = names_get_nth(i);

    if (config.verbose) printf("> DNS '%s'\n", names_get_nth(i));

    if ((rv = getaddrinfo_a(GAI_NOWAIT, &resolve_list, 1, &sevp)) != 0) {
      if (rv != EAI_INTR) {
        fprintf(stderr, "getaddrinfo_a failure with code %d\n", rv);
        return EXIT_FAILURE;
      }
    }
    
    dns_sent++;

    if (running && i != config.dns_request_count-1) {
      struct timespec sleep_time = const_time;
      if ((rv = nanosleep(&sleep_time, NULL)) != 0) {
        if (errno != EINTR) {
          fprintf(stderr, "nanosleep failure: %s\n", strerror(errno));
          return EXIT_FAILURE;
        }
      }
    }
  }

  if (names_get_marked() < config.stop_after_n_leaks) {
    // wait extra time
    struct timespec extra_time = millis_to_timespec(config.capture_extra_time_ms);
    if ((rv = nanosleep(&extra_time, NULL)) != 0) {
      if (errno != EINTR) {
        fprintf(stderr, "nanosleep failure: %s\n", strerror(errno));
        return EXIT_FAILURE;
      }
    }
  }

  // terminate
  pcap_breakloop(workflow->pcap_handle);
  
  void *retval;
  if ((rv = pthread_join(capture_thread, &retval)) != 0) {
    fprintf(stderr, "pthread_create failure with code %d\n", rv);
    return EXIT_FAILURE;
  }

  // result
  if (names_get_marked() != 0)
    printf("=== Leaks detected ===\n");
  else
    printf("No leak detected\n");
  
  return EXIT_SUCCESS;
}
