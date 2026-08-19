// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

const jobs = [];
let now = 0;

global.clock = function(monotonic) {
	return [ int(now / 1000), (now % 1000) * 1000000 ];
};

export function timer(delay, callback) {
	const job = { deadline: now + delay, callback, active: true };

	job.cancel = () => { job.active = false; };
	push(jobs, job);
	return job;
};

export function interval(delay, callback) {
	return { cancel: () => true };
};

export function advance(delay) {
	const end = now + delay;
	let count = 0;

	while (true) {
		const ready = sort(filter(jobs, job => job.active && job.deadline <= end),
			(a, b) => a.deadline - b.deadline);
		if (!length(ready))
			break;

		const job = ready[0];
		job.active = false;
		now = job.deadline;
		job.callback();
		if (++count > 10000)
			die('timer spin');
	}
	now = end;
};
