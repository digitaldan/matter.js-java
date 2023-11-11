/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import "../time/register";
import "../crypto/register";
import "../net/register";
import { Format, Level, Logger } from "@project-chip/matter.js/log";
import { MatterNode } from "./MatterNode";
import { Shell } from "./shell/Shell";
declare const Globals: any;
declare const globalThis: any;
declare const process: any;
const PROMPT = "matter-node> ";
const logger = Logger.get("Shell");
Logger.format = Format.ANSI;
Logger.defaultLogLevel = Level.DEBUG;
let theNode: MatterNode;

export function setLogLevel(level: string): void {
    let logLevel = Level.INFO;
    switch (level) {
        case "fatal":
            logLevel = Level.FATAL;
            break;
        case "error":
            logLevel = Level.ERROR;
            break;
        case "warn":
            logLevel = Level.WARN;
            break;
        case "debug":
            logLevel = Level.DEBUG;
            break;
    }
    Logger.defaultLogLevel = logLevel;
}

/**
 * @file Top level application for Matter Node.
 */
async function main(nodeNum = 0, factoryReset = false) {
    theNode = new MatterNode(nodeNum);
    await theNode.initialize(factoryReset);
    const theShell = new Shell(theNode, PROMPT);
    setLogLevel(theNode.Store.get<string>("LogLevel", "info"));
    console.log(`Started Node #${nodeNum}`);
    theShell.start();
}

export async function exit(code = 0) {
    await theNode?.close();
    process.exit(code);
}

process.on("SIGINT", () => {
    // Pragmatic way to make sure the storage is correctly closed before the process ends.
    exit().catch(error => logger.error(error));
});

globalThis.startApp = function () {
    main().catch(error => logger.error(error));
} 
