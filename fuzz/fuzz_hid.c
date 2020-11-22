/*
 * Copyright (c) 2020 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifdef __linux__
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/uhid.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#endif

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dummy.h"
#include "mutator_aux.h"
#include "fido.h"

#include "../openbsd-compat/openbsd-compat.h"

extern int fido_hid_get_usage(const uint8_t *, size_t, uint32_t *);
extern int fido_hid_get_report_len(const uint8_t *, size_t, size_t *, size_t *);

struct param {
	int seed;
	struct blob report_descriptor;
	uint8_t device_count;
	char device_name[MAXSTR];
	int device_bus;
	int device_vendor;
	int device_product;
	uint8_t list_size;
};

#ifdef __linux__
#define UHID_MAX	10
#define UHID_PATH	"/dev/uhid"

static bool uhid_ok = false;
static int uhid_fd[UHID_MAX];

static void
uhid_init(void)
{
	if (uhid_ok)
		return;

	for (size_t i = 0; i < UHID_MAX; i++)
		if ((uhid_fd[i] = open(UHID_PATH, O_RDWR | O_CLOEXEC)) == -1)
			err(1, "%s: open %s", __func__, UHID_PATH);

	drop_privs();
	uhid_ok = true;
}

static int
uhid_read(int fd, struct uhid_event *ev)
{
	ssize_t n;

	memset(ev, 0, sizeof(*ev));

	if ((n = read(fd, ev, sizeof(*ev))) < 0 || (size_t)n != sizeof(*ev)) {
		warn("%s: read: %zd", __func__, n);
		return (-1);
	}

	return (0);
}

static int
uhid_write(int fd, const struct uhid_event *ev)
{
	ssize_t n;

	if ((n = write(fd, ev, sizeof(*ev))) < 0 || (size_t)n != sizeof(*ev)) {
		warn("%s: write: %zd", __func__, n);
		return (-1);
	}

	return (0);
}

static int
uhid_wait(int fd, uint32_t event)
{
	struct uhid_event ev;
	struct pollfd pfd;
	int r;

	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN;
	pfd.fd = fd;

	for (;;) {
		if ((r = poll(&pfd, 1, -1)) > 0) {
			if (uhid_read(fd, &ev) < 0) {
				warn("%s: read", __func__);
				break;
			}
			if (ev.type != event)
				continue;
			return (0);
		} else if (r == 0)
			break;
		else if (errno != EINTR) {
			warn("%s: poll", __func__);
			break;
		}
	}

	return (-1);
}

static int
uhid_create(int fd, const struct param *p)
{
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));

	ev.type = UHID_CREATE2;
	strlcpy((char *)ev.u.create2.name, p->device_name,
	    sizeof(ev.u.create2.name));
	assert(sizeof(dummy_report_descriptor) <= sizeof(ev.u.create2.rd_data));
	memcpy(ev.u.create2.rd_data, dummy_report_descriptor,
	    sizeof(dummy_report_descriptor));
	ev.u.create2.rd_size = sizeof(dummy_report_descriptor);
	ev.u.create2.bus = p->device_bus & 1 ? BUS_USB : BUS_BLUETOOTH;
	ev.u.create2.vendor = p->device_vendor;
	ev.u.create2.product = p->device_product;

	return (uhid_write(fd, &ev));
}

static int
uhid_destroy(int fd)
{
	struct uhid_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;

	return (uhid_write(fd, &ev));
}

static int
uhid_create_wait(int fd, const struct param *p)
{
	if (uhid_create(fd, p) < 0 || uhid_wait(fd, UHID_START) < 0)
		return (-1);

	return (0);
}

static int
uhid_destroy_wait(int fd)
{
	if (uhid_destroy(fd) < 0 || uhid_wait(fd, UHID_STOP) < 0)
		return (-1);

	return (0);
}
#endif /* __linux__ */

struct param *
unpack(const uint8_t *ptr, size_t len)
{
	cbor_item_t *item = NULL, **v;
	struct cbor_load_result cbor;
	struct param *p;
	int ok = -1;

	if ((p = calloc(1, sizeof(*p))) == NULL ||
	    (item = cbor_load(ptr, len, &cbor)) == NULL ||
	    cbor.read != len ||
	    cbor_isa_array(item) == false ||
	    cbor_array_is_definite(item) == false ||
	    cbor_array_size(item) != 8 ||
	    (v = cbor_array_handle(item)) == NULL)
		goto fail;

	if (unpack_int(v[0], &p->seed) < 0 ||
	    unpack_blob(v[1], &p->report_descriptor) < 0 ||
	    unpack_byte(v[2], &p->device_count) < 0 ||
	    unpack_string(v[3], p->device_name) < 0 ||
	    unpack_int(v[4], &p->device_bus) < 0 ||
	    unpack_int(v[5], &p->device_vendor) < 0 ||
	    unpack_int(v[6], &p->device_product) < 0 ||
	    unpack_byte(v[7], &p->list_size) < 0)
		goto fail;

	ok = 0;
fail:
	if (ok < 0) {
		free(p);
		p = NULL;
	}

	if (item)
		cbor_decref(&item);

	return p;
}

size_t
pack(uint8_t *ptr, size_t len, const struct param *p)
{
	cbor_item_t *argv[8], *array = NULL;
	size_t cbor_alloc_len, cbor_len = 0;
	unsigned char *cbor = NULL;

	memset(argv, 0, sizeof(argv));

	if ((array = cbor_new_definite_array(8)) == NULL ||
	    (argv[0] = pack_int(p->seed)) == NULL ||
	    (argv[1] = pack_blob(&p->report_descriptor)) == NULL ||
	    (argv[2] = pack_byte(p->device_count)) == NULL ||
	    (argv[3] = pack_string(p->device_name)) == NULL ||
	    (argv[4] = pack_int(p->device_bus)) == NULL ||
	    (argv[5] = pack_int(p->device_vendor)) == NULL ||
	    (argv[6] = pack_int(p->device_product)) == NULL ||
	    (argv[7] = pack_byte(p->list_size)) == NULL)
		goto fail;

	for (size_t i = 0; i < 8; i++)
		if (cbor_array_push(array, argv[i]) == false)
			goto fail;

	if ((cbor_len = cbor_serialize_alloc(array, &cbor,
	    &cbor_alloc_len)) > len) {
		cbor_len = 0;
		goto fail;
	}

	memcpy(ptr, cbor, cbor_len);
fail:
	for (size_t i = 0; i < 8; i++)
		if (argv[i])
			cbor_decref(&argv[i]);

	if (array)
		cbor_decref(&array);

	free(cbor);

	return cbor_len;
}

size_t
pack_dummy(uint8_t *ptr, size_t len)
{
	struct param dummy;
	uint8_t	blob[4096];
	size_t blob_len;

	memset(&dummy, 0, sizeof(dummy));

	dummy.device_count = 1;
	dummy.device_bus = BUS_USB;
	dummy.device_vendor = 0x1050;
	dummy.device_product = 0x0407;
	dummy.list_size = 64;

	strlcpy(dummy.device_name, "device", sizeof(dummy.device_name));

	dummy.report_descriptor.len = sizeof(dummy_report_descriptor);
	memcpy(&dummy.report_descriptor.body, &dummy_report_descriptor,
	    dummy.report_descriptor.len);

	assert((blob_len = pack(blob, sizeof(blob), &dummy)) != 0);

	if (blob_len > len) {
		memcpy(ptr, blob, len);
		return len;
	}

	memcpy(ptr, blob, blob_len);

	return blob_len;
}

static void
get_usage(const struct param *p)
{
	uint32_t usage_page = 0;

	fido_hid_get_usage(p->report_descriptor.body, p->report_descriptor.len,
	    &usage_page);
	consume(&usage_page, sizeof(usage_page));
}

static void
get_report_len(const struct param *p)
{
	size_t report_in_len = 0;
	size_t report_out_len = 0;

	fido_hid_get_report_len(p->report_descriptor.body,
	    p->report_descriptor.len, &report_in_len, &report_out_len);
	consume(&report_in_len, sizeof(report_in_len));
	consume(&report_out_len, sizeof(report_out_len));
}

#ifdef __linux__
static void
dev_info_manifest(const struct param *p)
{
	fido_dev_info_t *devlist;
	const fido_dev_info_t *devinfo;
	size_t ndevs;
	int16_t x;
	int r;

	if ((devlist = fido_dev_info_new(p->list_size)) == NULL)
		return;

	r = fido_dev_info_manifest(devlist, p->list_size, &ndevs);
	consume_str(fido_strerr(r));

	for (size_t i = 0; i < ndevs; i++) {
		devinfo = fido_dev_info_ptr(devlist, i);

		consume(fido_dev_info_path(devinfo),
		    xstrlen(fido_dev_info_path(devinfo)));
		consume(fido_dev_info_manufacturer_string(devinfo),
		    xstrlen(fido_dev_info_manufacturer_string(devinfo)));
		consume(fido_dev_info_product_string(devinfo),
		    xstrlen(fido_dev_info_product_string(devinfo)));

		x = fido_dev_info_vendor(devinfo);
		consume(&x, sizeof(x));
		x = fido_dev_info_product(devinfo);
		consume(&x, sizeof(x));
	}

	fido_dev_info_free(&devlist, ndevs);
}
#endif /* __linux__ */

void
test(const struct param *p)
{
	prng_init((unsigned int)p->seed);
	fido_init(FIDO_DEBUG);
	fido_set_log_handler(consume_str);

#ifdef __linux__
	uhid_init();

	/* limit the number of virtual devices created */
	if (p->device_count > UHID_MAX)
		return;

	for (uint8_t i = 0; i < p->device_count; i++)
		assert(uhid_create_wait(uhid_fd[i], p) == 0);

	dev_info_manifest(p);

	for (uint8_t i = 0; i < p->device_count; i++)
		assert(uhid_destroy_wait(uhid_fd[i]) == 0);
#endif

	get_usage(p);
	get_report_len(p);
}

void
mutate(struct param *p, unsigned int seed, unsigned int flags) NO_MSAN
{
	if (flags & MUTATE_SEED)
		p->seed = (int)seed;

	if (flags & MUTATE_PARAM) {
		mutate_blob(&p->report_descriptor);
		mutate_byte(&p->device_count);
		mutate_string(p->device_name);
		mutate_int(&p->device_bus);
		mutate_int(&p->device_vendor);
		mutate_int(&p->device_product);
		mutate_byte(&p->list_size);
	}
}
