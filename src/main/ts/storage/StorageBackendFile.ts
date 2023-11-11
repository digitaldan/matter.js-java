/**
 * @license
 * Copyright 2022-2023 Project CHIP Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Storage, StorageError, SupportedStorageTypes, StorageBackendMemory, toJson, fromJson } from "@project-chip/matter.js/storage";
declare const Java: any;
const FileStorage = Java.type("com.matterjs.storage.Storage")

export class StorageBackendFile extends StorageBackendMemory {
    constructor(protected path: string, clear = false) {
        super();
        if (!clear) {
            const data = FileStorage.read(path);
            if (data.length > 0) {
                this.store = fromJson(data);
            }
        }
    }

    private sync() {
        FileStorage.write(this.path, toJson(this.store));
    }

    override clear(): void {
        this.store = {};
    }

    override set<T extends SupportedStorageTypes>(contexts: string[], key: string, value: T): void {
        super.set(contexts, key, value);
        this.sync();
    }

    override delete(contexts: string[], key: string): void {
        super.delete(contexts, key);
        this.sync();
    }

    override clearAll(contexts: string[]): void {
        super.clearAll(contexts);
        this.sync();
    }
}
