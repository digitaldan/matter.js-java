/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

// Include this first to auto-register Crypto, Network and Time Node.js implementations
import { CommissioningController, MatterServer } from "@project-chip/matter.js";

import { NodeId } from "@project-chip/matter.js/datatype";
import { Endpoint, PairedNode } from "@project-chip/matter.js/device";
import { Logger } from "@project-chip/matter.js/log";
import { StorageContext, StorageManager } from "@project-chip/matter.js/storage";
import { StorageBackendFile } from "../storage/StorageBackendFile";

const logger = Logger.get("Node");

export class MatterNode {
    private storageLocation?: string;
    private storage?: StorageBackendFile;
    private storageManager?: StorageManager;
    private storageContext?: StorageContext;

    commissioningController?: CommissioningController;
    private matterController?: MatterServer;

    constructor(
        private readonly nodeNum: number,
        private readonly netInterface?: string,
    ) {}

    async initialize(resetStorage: boolean) {
        /**
         * Initialize the storage system.
         *
         * The storage manager is then also used by the Matter server, so this code block in general is required,
         * but you can choose a different storage backend as long as it implements the required API.
         */

        this.storageLocation = `.matter-shell-${this.nodeNum}`;
        this.storage = new StorageBackendFile(this.storageLocation, false);
        logger.info(`Storage location: ${this.storageLocation} (Directory)`);
        this.storageManager = new StorageManager(this.storage);
        await this.storageManager.initialize();
        this.storageContext = this.storageManager.createContext("Node");
        if (resetStorage) {
            this.storage.clearAll([]);
        }
    }

    get Store() {
        if (!this.storageContext) {
            throw new Error("Storage uninitialized");
        }
        return this.storageContext;
    }

    async close() {
        await this.matterController?.close();
        this.closeStorage();
    }

    closeStorage() {
        // this.storage
        //     ?.close()
        //     .then(() => process.exit(0))
        //     .catch(() => process.exit(1));
    }

    async start() {
        if (this.storageManager === undefined) {
            throw new Error("StorageManager not initialized"); // Should never happen
        }
        if (this.matterController !== undefined) {
            return;
        }
        logger.info(`matter.js shell controller started for node ${this.nodeNum}`);

        /**
         * Create Matter Server and Controller Node
         *
         * To allow the device to be announced, found, paired and operated we need a MatterServer instance and add a
         * CommissioningController to it and add the just created device instance to it.
         * The Controller node defines the port where the server listens for the UDP packages of the Matter protocol
         * and initializes deice specific certificates and such.
         *
         * The below logic also adds command handlers for commands of clusters that normally are handled internally
         * like testEventTrigger (General Diagnostic Cluster) that can be implemented with the logic when these commands
         * are called.
         */

        this.matterController = new MatterServer(this.storageManager, { mdnsInterface: this.netInterface });
        this.commissioningController = new CommissioningController({
            autoConnect: false,
        });
        this.matterController.addCommissioningController(this.commissioningController);

        /**
         * Start the Matter Server
         *
         * After everything was plugged together we can start the server. When not delayed announcement is set for the
         * CommissioningServer node then this command also starts the announcement of the device into the network.
         */

        await this.matterController.start();
    }

    async connectAndGetNodes(nodeIdStr?: string) {
        await this.start();
        const nodeId = nodeIdStr !== undefined ? NodeId(BigInt(nodeIdStr)) : undefined;

        if (this.commissioningController === undefined) {
            throw new Error("CommissioningController not initialized");
        }
        let nodes: PairedNode[];
        if (nodeId === undefined) {
            nodes = await this.commissioningController.connect();
        } else {
            nodes = [await this.commissioningController.connectNode(NodeId(nodeId))];
        }
        return nodes;
    }

    async iterateNodeDevices(
        nodes: PairedNode[],
        callback: (device: Endpoint, node: PairedNode) => Promise<void>,
        endpointId?: number,
    ) {
        for (const node of nodes) {
            let devices = node.getDevices();
            if (endpointId !== undefined) {
                devices = devices.filter(device => device.id === endpointId);
            }

            for (const device of devices) {
                await callback(device, node);
            }
        }
    }
}
