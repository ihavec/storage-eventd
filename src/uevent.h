#ifndef _UEVENT_H_
#define _UEVENT_H_
#include <stdbool.h>

struct udev_monitor *uevent_setup_monitor(void);
int uevent_start_threads(struct udev_monitor *monitor);
int uevent_stop_threads(void);

struct subst_vec;
struct udev_device;

const char *uevent_subst(const struct subst_vec *vec,
			 struct udev_device *uevent);
const char *uevent_get_property(const char *key, struct udev_device *uevent,
				bool *needs_free);

#endif /* _UEVENT_H_ */
