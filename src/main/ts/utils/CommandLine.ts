/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ValidationError } from "@project-chip/matter.js/common";
import { Logger } from "@project-chip/matter.js/log";

//const commandArguments = process.argv.slice(2);
//declare const commandArguments: string;
declare const Globals: any;
const commandArguments = Globals.commandArguments;
const logger = Logger.get("CommandLine");

export function getParameter(name: string) {
    //logger.debug(`getParameter ${name} from ${commandArguments}`);
    const markerIndex = commandArguments.indexOf(`-${name}`);
    if (markerIndex === -1 || markerIndex + 1 === commandArguments.length) return undefined;
    return commandArguments[markerIndex + 1];
}

export function hasParameter(name: string) {
    //logger.debug(`hasParameter ${name} from ${commandArguments}`);
    return commandArguments.includes(`-${name}`);
}

export function getIntParameter(name: string) {
    //logger.debug(`getIntParameter ${name} from ${commandArguments}`);
    const value = getParameter(name);
    if (value === undefined) return undefined;
    const intValue = parseInt(value, 10);
    if (isNaN(intValue)) throw new ValidationError(`Invalid value for parameter ${name}: ${value} is not a number`);
    return intValue;
}