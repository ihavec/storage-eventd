#define _GNU_SOURCE
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <linux/btrfs.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <mntent.h>

#include <libudev.h>
#include <glib.h>
#include <uuid.h>

#include "uevent.h"
#include "common.h"
#include "config.h"
#include "list.h"
#include "subst.h"
#include "filter.h"
#include "util.h"

GAsyncQueue *uevent_queue;
static pthread_t uevent_listener_thread;
static pthread_t uevent_servicer_thread;

#define USEC_PER_MSEC   1000L

static int
match_event(config_t *config, struct event *event, struct udev_device *uevent)
{
	if (event_filter(event, uevent))
		return event_action(event, uevent);

	return -ESRCH;
}

static void *
uevent_servicer(void *ignored)
{
	while (1) {
		struct udev_device *uevent;
		config_t *config;
		int ret;

		uevent = g_async_queue_pop(uevent_queue);
		g_assert(uevent != NULL);

		/* Service uevent */
		config = config_get();
		ret = config_for_each_event(config, match_event, uevent);
		if (ret > 0)
			log_debug("successfully executed %d action%s",
				  ret, ret == 1 ? "" : "s");
		config_put(config);
		udev_device_unref(uevent);
	}
	return NULL;
}

void *
uevent_listener_loop(void *data)
{
	int fd;
	struct udev_monitor *monitor = data;
	sigset_t mask;
	int ret;

	fd = udev_monitor_get_fd(monitor);

	pthread_sigmask(SIG_SETMASK, NULL, &mask);
	while (1) {
		struct udev_device *uevent;
		struct pollfd ev_poll;
		struct timespec poll_timeout;
		time_t timeout = 30;
		int fdcount;

		ev_poll = (struct pollfd) { .fd = fd, .events = POLLIN, };
		poll_timeout = (struct timespec) { .tv_sec = timeout, };

		errno = 0;
		fdcount = ppoll(&ev_poll, 1, &poll_timeout, &mask);
		if (fdcount && ev_poll.revents & POLLIN) {
			timeout = 0;
			uevent = udev_monitor_receive_device(monitor);
			if (!uevent) {
				log_warn("failed getting udev device");
				continue;
			}

			g_async_queue_push(uevent_queue, uevent);
			timeout = 0;
			continue;
		}
		if (fdcount < 0) {
			if (errno == EINTR) {
				timeout = 30;
				continue;
			}

			log_warn("error receiving uevent message: %s",
				 strerror(errno));

			ret = -errno;
			break;
		}
		timeout = 30;
	}

	return ERR_PTR(ret);
}

struct udev_monitor *
uevent_setup_monitor(void)
{
	struct udev *udev;
	struct udev_monitor *monitor = NULL;
	int ret;
	int fd;
	int socket_flags;

	udev = udev_new();
	if (!udev) {
		log_err("couldn't create udev context");
		ret = -ENOMEM;
		goto free_udev;
	}

	monitor = udev_monitor_new_from_netlink(udev, "udev");
	if (!monitor) {
		ret = -errno;
		log_err("failed to create udev monitor.");
		goto free_monitor;
	}

#ifdef LIBUDEV_API_RECVBUF
	ret = udev_monitor_set_receive_buffer_size(monitor, 128 * 1024 * 1024);
	if (ret) {
		log_err("failed to increase buffer size");
		goto free_monitor;
	}
#endif

	fd = udev_monitor_get_fd(monitor);
	if (fd < 0) {
		ret = -EINVAL;
		log_err("failed to get monitor_fd");
		goto free_monitor;
	}
	socket_flags = fcntl(fd, F_GETFL);
	if (socket_flags < 0) {
		ret = -errno;
		log_err("failed to get monitor socket flags: %s",
			strerror(errno));
		goto free_monitor;
	}
	ret = fcntl(fd, F_SETFL, socket_flags & ~O_NONBLOCK);
	if (ret < 0) {
		log_err("failed to set monitor socket flags: %s",
			strerror(errno));
		goto free_monitor;
	}

	ret = udev_monitor_filter_add_match_subsystem_devtype(monitor, "block",
							      NULL);
	if (ret < 0) {
		log_err("failed to add filter for block subsys: %s",
			strerror(-ret));
		goto free_monitor;
	}

#if 0
	ret = udev_monitor_filter_add_match_subsystem_devtype(monitor, "fs",
							      NULL);
	if (ret < 0) {
		log_err("failed to add filter for fs subsys: %s",
			strerror(-ret));
		goto out;
	}
#endif

	ret = udev_monitor_enable_receiving(monitor);
	if (ret) {
		log_err("failed to enable receiving: %s", strerror(-ret));
		goto free_monitor;
	}

	return monitor;

free_monitor:
	udev_monitor_unref(monitor);
free_udev:
	udev_unref(udev);
	return NULL;
}

struct stupidqueue
{
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  GQueue queue;
  GDestroyNotify item_free_func;
  guint waiting_threads;
  gint ref_count;
};

int
uevent_stop_threads(void)
{
	void *ret;
	if (uevent_listener_thread) {
		pthread_cancel(uevent_listener_thread);
		pthread_join(uevent_listener_thread, &ret);
	}
	if (uevent_servicer_thread) {
		pthread_cancel(uevent_servicer_thread);
#if 0
		/*
		 * TODO: cancelable queue implementation
		 */
		pthread_join(uevent_servicer_thread, &ret);
		g_async_queue_unref(uevent_queue);
#endif
	}

	return 0;
}

int
uevent_start_threads(struct udev_monitor *monitor)
{
	int ret;
	struct udev *udev;

	uevent_queue = g_async_queue_new();
	if (!uevent_queue) {
		log_err("couldn't create uevent queue");
		ret = -ENOMEM;
		goto free_monitor;
	}

	ret = pthread_create(&uevent_listener_thread, NULL,
			     uevent_listener_loop, monitor);
	if (ret) {
		log_err("failed to create uevent listener thread: %s",
			strerror(errno));
		goto free_queue;
	}

	ret = pthread_create(&uevent_servicer_thread, NULL,
			     uevent_servicer, NULL);
	if (ret) {
		log_err("failed to create uevent servicer thread: %s",
			strerror(errno));
		goto stop_listener;
	}

	return 0;

stop_listener:
	pthread_cancel(uevent_listener_thread);
free_queue:
	g_async_queue_unref(uevent_queue);
free_monitor:
	udev = udev_monitor_get_udev(monitor);
	udev_monitor_unref(monitor);
	udev_unref(udev);
	return ret;
}

const char *uevent_get_property(const char *key, struct udev_device *uevent,
				bool *needs_free)
{
	const char *value;
	*needs_free = false;

	value = udev_device_get_property_value(uevent, key);
	if (value == NULL) {
		if (!strcmp(key, "SYSPATH"))
			value = udev_device_get_syspath(uevent);
		else if (!strcmp(key, "DEVPATH"))
			value = udev_device_get_devpath(uevent);
		else if (!strcmp(key, "MOUNTPOINT")) {
			dev_t devno = udev_device_get_devnum(uevent);
			value = util_get_any_mountpoint_devno(devno);
			if (value)
				*needs_free = true;
#ifdef DEBUG
		} else if (!strcmp(key, "SDEV_UA")) {
			value = "THIN_PROVISIONING_SOFT_THRESHOLD_REACHED";
#endif
		} else
			value = config_lookup_fn(key, NULL, needs_free);
	}

	return value;
}

static const char *uevent_lookup_fn(const char *key, void *data,
				    bool *needs_free)
{
	struct udev_device *uevent = data;

	return uevent_get_property(key, uevent, needs_free);
}

const char *uevent_subst(const struct subst_vec *vec,
			 struct udev_device *uevent)
{
	return subst_replace(vec, uevent_lookup_fn, uevent);
}
