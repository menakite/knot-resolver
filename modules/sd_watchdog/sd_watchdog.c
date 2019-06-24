/* Copyright (C) Knot Resolver contributors. Licensed under GNU GPLv3 or
 * (at your option) any later version. See COPYING for text of the license.
 *
 * sd_watchdog module implements support for systemd watchdog supervision */

#include <systemd/sd-daemon.h>
#include <uv.h>

#include "lib/module.h"

struct watchdog_config {
	bool enabled;
	uint64_t timeout_usec;
	uv_timer_t timer;
};

static void keepalive_ping(uv_timer_t *timer)
{
	// NOTE: in the future, some sanity checks could be used here
	sd_notify(0, "WATCHDOG=1");
}

KR_EXPORT
int sd_watchdog_init(struct kr_module *module)
{
	struct watchdog_config *conf = calloc(1, sizeof(*conf));
	if (!conf) {
		return kr_error(ENOMEM);
	}
	module->data = conf;

	/* Check if watchdog is enabled */
	int ret = sd_watchdog_enabled(1, &conf->timeout_usec);
	if (ret < 0) {
		kr_log_error("[sd_watchdog] error: %s\n", strerror(abs(ret)));
		return kr_error(ret);
	}
	conf->enabled = ret > 0;
	if (!conf->enabled) {
		kr_log_verbose("[sd_watchdog] disabled (not required)\n");
		return kr_ok();
	}

	uint64_t delay_ms = (conf->timeout_usec / 1000) / 2;
	if (delay_ms == 0) {
		kr_log_error("[sd_watchdog] error: WatchdogSec= must be at least 2ms!\n");
		return kr_error(ENOTSUP);
	}

	uv_loop_t *loop = uv_default_loop();
	uv_timer_init(loop, &conf->timer);
	ret = uv_timer_start(&conf->timer, keepalive_ping, delay_ms, delay_ms);
	if (ret != 0) {
		kr_log_error("[sd_watchdog] error: failed to start uv_timer!\n");
		return kr_error(ret);
	}

	kr_log_verbose("[sd_watchdog] enabled (repeat: %ld ms, timeout: %ld ms)\n",
		delay_ms, conf->timeout_usec / 1000);

	return kr_ok();
}

KR_EXPORT
int sd_watchdog_deinit(struct kr_module *module)
{
	struct stat_data *conf = module->data;
	if (conf) {
		free(conf);
	}
	return kr_ok();
}

KR_MODULE_EXPORT(sd_watchdog)
