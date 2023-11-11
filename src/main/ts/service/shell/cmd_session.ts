/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { MatterNode } from "../MatterNode";

export default function commands(theNode: MatterNode) {
    return {
        command: "session",
        describe: "Manage session",
        builder: {},
        handler: async () => {
            if (!theNode.commissioningController) {
                throw new Error("CommissioningController not initialized");
            }

            const sessions = theNode.commissioningController?.getActiveSessionInformation();
            console.log(sessions);
        },
    };
}
