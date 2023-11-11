/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { VendorId } from "@project-chip/matter.js/datatype";
import { Logger } from "@project-chip/matter.js/log";
import { ManualPairingCodeCodec } from "@project-chip/matter.js/schema";
import { CommissionableDeviceIdentifiers } from "@project-chip/matter.js/common";
import type { Argv } from "yargs";
import { MatterNode } from "../MatterNode";

export default function commands(theNode: MatterNode) {
    return {
        command: "discover",
        describe: "Handle device discovery",
        builder: (yargs: Argv) =>
            yargs
                // Pair
                .command(
                    "commissionable [timeout-seconds]",
                    "Discover commissionable devices",
                    () => {
                        return yargs
                            .positional("timeout-seconds", {
                                describe: "Discovery timeout in seconds",
                                default: 900,
                                type: "number",
                            })
                            .options({
                                pairingCode: {
                                    describe: "pairing code",
                                    default: undefined,
                                    type: "string",
                                },
                                discriminator: {
                                    alias: "d",
                                    description: "Long discriminator",
                                    default: undefined,
                                    type: "number",
                                },
                                shortDiscriminator: {
                                    alias: "s",
                                    description: "Short discriminator",
                                    default: undefined,
                                    type: "number",
                                },
                                vendorId: {
                                    alias: "v",
                                    description: "Vendor ID",
                                    default: undefined,
                                    type: "number",
                                },
                                productId: {
                                    alias: "p",
                                    description: "Product ID",
                                    default: undefined,
                                    type: "number",
                                },
                                deviceType: {
                                    alias: "t",
                                    description: "Device Type",
                                    default: undefined,
                                    type: "number",
                                },
                                ble: {
                                    alias: "b",
                                    description: "Also discover over BLE",
                                    default: false,
                                    type: "boolean",
                                },
                            });
                    },
                    async argv => {
                        const { ble = false, pairingCode, vendorId, productId, deviceType, timeoutSeconds } = argv;
                        let { discriminator, shortDiscriminator } = argv;

                        if (typeof pairingCode === "string") {
                            const { shortDiscriminator: pairingCodeShortDiscriminator } =
                                ManualPairingCodeCodec.decode(pairingCode);
                            shortDiscriminator = pairingCodeShortDiscriminator;
                            discriminator = undefined;
                        }

                        await theNode.start();
                        if (theNode.commissioningController === undefined) {
                            throw new Error("CommissioningController not initialized");
                        }

                        const identifierData: CommissionableDeviceIdentifiers =
                            discriminator !== undefined
                                ? { longDiscriminator: discriminator }
                                : shortDiscriminator !== undefined
                                ? { shortDiscriminator }
                                : vendorId !== undefined
                                ? { vendorId: VendorId(vendorId) }
                                : productId !== undefined
                                ? { productId }
                                : deviceType !== undefined
                                ? { deviceType }
                                : {};

                        console.log(
                            `Discover devices with identifier ${Logger.toJSON(
                                identifierData,
                            )} for ${timeoutSeconds} seconds.`,
                        );

                        const results = await theNode.commissioningController.discoverCommissionableDevices(
                            identifierData,
                            {
                                ble,
                                onIpNetwork: true,
                            },
                            device => console.log(`Discovered device ${Logger.toJSON(device)}`),
                            timeoutSeconds,
                        );

                        console.log(`Discovered ${results.length} devices`, results);
                    },
                ),
        handler: async (argv: any) => {
            argv.unhandled = true;
        },
    };
}
