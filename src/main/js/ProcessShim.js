const System = Java.type('java.lang.System');

class ProcessShim {
    constructor(argv) {
        this.eventListeners = {};
        this.queue = [];
        this.draining = false;
        this.currentQueue = null;
        this.queueIndex = -1;
        this.title = 'browser';
        this.browser = true;
        this.env = {};
        this.argv = argv || Globals.commandArguments || [];
        this.version = ''; // empty string to avoid regexp issues
        this.versions = {};

        this.cachedSetTimeout = null;
        this.cachedClearTimeout = null;
        this.init();
    }

    init() {

        // this.JavaProcess.startReadingInput((input) => {
        //     this.emit('message', input);
        // });

        try {
            if (typeof setTimeout === 'function') {
                this.cachedSetTimeout = setTimeout;
            } else {
                this.cachedSetTimeout = this.defaultSetTimeout;
            }
        } catch (e) {
            this.cachedSetTimeout = this.defaultSetTimeout;
        }
        try {
            if (typeof clearTimeout === 'function') {
                this.cachedClearTimeout = clearTimeout;
            } else {
                this.cachedClearTimeout = this.defaultClearTimeout;
            }
        } catch (e) {
            this.cachedClearTimeout = this.defaultClearTimeout;
        }
    }

    defaultSetTimeout() {
        throw new Error('setTimeout has not been defined');
    }

    defaultClearTimeout() {
        throw new Error('clearTimeout has not been defined');
    }

    runTimeout(fun) {
        if (cachedSetTimeout === setTimeout) {
            //normal enviroments in sane situations
            return setTimeout(fun, 0);
        }
        // if setTimeout wasn't available but was latter defined
        if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
            cachedSetTimeout = setTimeout;
            return setTimeout(fun, 0);
        }
        try {
            // when when somebody has screwed with setTimeout but no I.E. maddness
            return cachedSetTimeout(fun, 0);
        } catch (e) {
            try {
                // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
                return cachedSetTimeout.call(null, fun, 0);
            } catch (e) {
                // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
                return cachedSetTimeout.call(this, fun, 0);
            }
        }
    }

    runClearTimeout(marker) {
        if (cachedClearTimeout === clearTimeout) {
            //normal enviroments in sane situations
            return clearTimeout(marker);
        }
        // if clearTimeout wasn't available but was latter defined
        if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
            cachedClearTimeout = clearTimeout;
            return clearTimeout(marker);
        }
        try {
            // when when somebody has screwed with setTimeout but no I.E. maddness
            return cachedClearTimeout(marker);
        } catch (e) {
            try {
                // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
                return cachedClearTimeout.call(null, marker);
            } catch (e) {
                // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
                // Some versions of I.E. have different rules for clearTimeout vs setTimeout
                return cachedClearTimeout.call(this, marker);
            }
        }
    }

    cleanUpNextTick() {
        if (!draining || !currentQueue) {
            return;
        }
        draining = false;
        if (currentQueue.length) {
            queue = currentQueue.concat(queue);
        } else {
            queueIndex = -1;
        }
        if (queue.length) {
            drainQueue();
        }
    }

    drainQueue() {
        if (draining) {
            return;
        }
        var timeout = runTimeout(cleanUpNextTick);
        draining = true;

        var len = queue.length;
        while (len) {
            currentQueue = queue;
            queue = [];
            while (++queueIndex < len) {
                if (currentQueue) {
                    currentQueue[queueIndex].run();
                }
            }
            queueIndex = -1;
            len = queue.length;
        }
        currentQueue = null;
        draining = false;
        runClearTimeout(timeout);
    }

    nextTick(fun, ...args) {
        var args = new Array(arguments.length - 1);
        if (arguments.length > 1) {
            for (var i = 1; i < arguments.length; i++) {
                args[i - 1] = arguments[i];
            }
        }
        this.queue.push(new Item(fun, args));
        if (this.queue.length === 1 && !this.draining) {
            this.runTimeout(() => this.drainQueue());
        }
    }

    // ... (rest of the process functions like on, addListener, etc.)

    cwd() {
        return '/';
    }

    chdir(dir) {
        throw new Error('process.chdir is not supported');
    }

    umask() {
        return 0;
    }

    emit(event, ...args) {
        if (this.eventListeners[event]) {
            this.eventListeners[event].forEach(listener => listener(...args));
        }
    }

    exit(code = 0) {
        System.exit(code);
    }

    get stdin() {
        return {
            on: (event, callback) => {
                if (event === 'data') {
                    this.addListener('message', callback);
                }
            },
        };
    }

    get stdout() {
        return {
            write: (message) => {
                //this.JavaProcess.writeToStdout(message);
            },
        };
    }

    get stderr() {
        return {
            write: (message) => {
                console.error(message);
            },
        };
    }

    on(event, listener) {
        this.addListener(event, listener);
        return this;
    }

    addListener(event, listener) {
        if (!this.eventListeners[event]) {
            this.eventListeners[event] = [];
        }
        this.eventListeners[event].push(listener);
    }
}

class Item {
    constructor(fun, array) {
        this.fun = fun;
        this.array = array;
    }

    run() {
        this.fun.apply(null, this.array);
    }
}

// Exporting the class
module.exports = ProcessShim;
