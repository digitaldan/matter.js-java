/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Time, Timer, TimerCallback } from "@project-chip/matter.js/time";
import { Logger } from "@project-chip/matter.js/log";

declare const Java: any;  // Declare the Java global provided by GraalVM
declare const Globals: any;

const Instant = Java.type('java.time.Instant');
const logger = Logger.get("TimerNode");

class TimerNode implements Timer {
    private timerTask: any | undefined;
    isRunning = false;

    constructor(
        private readonly intervalMs: number,
        private readonly callback: TimerCallback,
        private readonly periodic: boolean,
    ) {
    }

    start() {
        if (this.isRunning) this.stop();
        this.isRunning = true;

        if (this.periodic) {
            this.timerTask = Globals.executorService.scheduleAtFixedRateJS((arg: string) => {
                this.callback();
            }, 0, this.intervalMs);
        } else {
            this.timerTask = Globals.executorService.scheduleJS((arg: string) => {
                this.callback();
            }, this.intervalMs);
        }
        return this;
    }

    stop() {
        if (this.timerTask) {
            this.timerTask.cancel(false);
        }
        this.isRunning = false;
        return this;
    }
}

export class TimeNode extends Time {
    now(): Date {
        const instant = Instant.now();
        return new Date(instant.toEpochMilli());
    }

    nowMs(): number {
        return Instant.now().toEpochMilli();
    }

    getTimer(durationMs: number, callback: TimerCallback): Timer {
        return new TimerNode(durationMs, callback, false);
    }

    getPeriodicTimer(intervalMs: number, callback: TimerCallback): Timer {
        return new TimerNode(intervalMs, callback, true);
    }
}
