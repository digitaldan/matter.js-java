/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { MatterError } from "@project-chip/matter.js/common";
// import readline from "./readline";
import type { Argv } from "yargs";
import yargs from "yargs/yargs";
import { MatterNode } from "../MatterNode";
import { exit } from "../app";
import cmdCommission from "./cmd_commission";
import cmdConfig from "./cmd_config";
import cmdDiscover from "./cmd_discover";
import cmdIdentify from "./cmd_identify";
import cmdLock from "./cmd_lock";
import cmdNodes from "./cmd_nodes";
import cmdOnOff from "./cmd_onoff";
import cmdSession from "./cmd_session";
import cmdSubscribe from "./cmd_subscribe";

declare const Globals: any;
declare const process: any;
const Console = Globals.console;


function exitCommand() {
    return {
        command: "exit",
        describe: "Exit",
        builder: {},
        handler: async () => {
            console.log("Goodbye.");
            await exit();
        },
    };
}

/**
 * Class to process and dispatch shell commands.
 */
export class Shell {
    configExecPassthrough = false;
    readline?: any;
    yargsInstance?: Argv;
    buffer: string;
    process: any = process;
    /**
     * Construct a new Shell object.
     *
     * @param {MatterNode} theNode MatterNode object to use for all commands.
     * @param {string} prompt Prompt string to use for each command line.
     */
    constructor(
        public theNode: MatterNode,
        public prompt: string
    ) {
        this.buffer = '';
    }

    start() {

        // this.process.on('message', (line: string) => {
        //     this.onReadLine(line.trim()).catch(e => {
        //         this.process.stderr.write(`Read error: ${e}\n`);
        //         this.process.exit(1);
        //     });
        // });

        Console.startConsole(this.prompt, async (input:string) => {
            try {
                await this.onReadLine(input.trim());
            } catch (e) {
                this.process.stderr.write(`Read error: ${e}\n`);
                this.process.exit(1);
            }
            // this.onReadLine(input.trim()).catch(e => {
            //     this.process.stderr.write(`Read error: ${e}\n`);
            //     this.process.exit(1);
            // });
        });
        this.promptUser();
    }
    private promptUser(): void {
        //this.process.stdout.write(this.prompt);
        //Console.prompt(this.prompt);
    }

    /**
     * Method to process a line of raw cli text input.
     *
     * @param {string} line
     */
    async onReadLine(line: string) {
        //console.log(`onReadLine: ${line}`);
        if (line) {
            const args = line.split(/\s+/);
            const yargsInstance = yargs(args)
                .command([
                    cmdCommission(this.theNode),
                    cmdConfig(this.theNode),
                    cmdLock(this.theNode),
                    cmdSession(this.theNode),
                    cmdNodes(this.theNode),
                    cmdOnOff(this.theNode),
                    cmdSubscribe(this.theNode),
                    cmdIdentify(this.theNode),
                    cmdDiscover(this.theNode),
                    exitCommand(),
                ])
                .command({
                    command: "*",
                    handler: argv => {
                        argv.unhandled = true;
                    },
                })
                .exitProcess(false)
                .version(false)
                .help("help")
                .scriptName("")
                .strictCommands(false)
                .strictOptions(false)
                .fail(false)
                .strict(false);
            try {
                const argv = await yargsInstance.wrap(yargsInstance.terminalWidth()).parseAsync();

                if (argv.unhandled) {
                    this.process.stderr.write(`Unknown command: ${line}\n`);
                    yargsInstance.showHelp();
                } else {
                    //console.log("Done.");
                }
            } catch (error) {
                this.process.stderr.write(`Error happened during command: ${error}\n`);
                if (error instanceof Error && error.stack) {
                    this.process.stderr.write(error.stack.toString());
                    this.process.stderr.write("\n");
                }
                if (!(error instanceof MatterError)) {
                    yargsInstance.showHelp();
                }
            }
        }
        this.promptUser();
    }
}
