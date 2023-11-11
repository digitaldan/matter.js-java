const ProcessShim = require("./ProcessShim");

(function (global) {
  'use strict';

  const defaultIdentifier = "matter.js";
  const System = Java.type('java.lang.System');
  const formatRegExp = /%[sdj%]/g;
  // Pass the defaultIdentifier to ThreadsafeTimers to enable naming of scheduled jobs

  function createLogger(name = defaultIdentifier) {
    return Java.type('org.slf4j.LoggerFactory').getLogger(name);
  }

  // User configurable
  let log = createLogger();

  function stringify(value) {
    try {
      if (typeof value === 'string') return value;
      // special cases
      if (value === undefined) {
        return 'undefined';
      }
      if (value === null) {
        return 'null';
      }
      // JSON.stringify all objects that do not polyfill toString()
      const str = value.toString();
      if (typeof value === 'object' && (str === '[object Object]' || str === '[object Java]')) {
        return JSON.stringify(value, null, 2);
      }
      return str;
    } catch (e) {
      return 'Error: failed to format log message: ' + e;
    }
  }

  function format(f) {
    try {
      const args = arguments;

      // If there is only one argument, stringify and return it
      if (args.length === 1) return stringify(f);

      // Else if the first arg is string, do regex string formatting
      // the number of args after the formatted string must match the number of % placeholder
      let str;
      let i = 1;
      if (typeof f === 'string') {
        str = String(f).replace(formatRegExp, function (x) {
          if (x === '%%') return '%';
          if (i >= args.length) return x;
          switch (x) {
            case '%s': return String(args[i++]);
            case '%d': return Number(args[i++]);
            case '%j':
              try {
                return stringify(args[i++]);
              } catch (e) {
                return '[Circular]';
              }
            // falls through
            default:
              return x;
          }
        });
      }
      // Else stringify and join all args
      for (let x = args[i]; i < args.length; x = args[++i]) {
        str += ' ' + stringify(x);
      }
      return str;
    } catch (e) {
      return 'Error: failed to format log message: ' + e;
    }
  }

  const counters = {};
  const timers = {};

  // Polyfills for common NodeJS functions

  const console = {
    assert: function (expression, message) {
      if (!expression) {
        log.error(message);
      }
    },

    count: function (label) {
      let counter;

      if (label) {
        if (counters.hasOwnProperty(label)) {
          counter = counters[label];
        } else {
          counter = 0;
        }

        // update
        counters[label] = ++counter;
        log.debug(format.apply(null, [label + ':', counter]));
      }
    },

    debug: function () {
      log.debug(format.apply(null, arguments));
    },

    info: function () {
      log.info(format.apply(null, arguments));
    },

    log: function () {
      log.info(format.apply(null, arguments));
    },

    warn: function () {
      log.warn(format.apply(null, arguments));
    },

    error: function () {
      log.error(format.apply(null, arguments));
    },

    trace: function () {
      log.trace(new Error(format.apply(null, arguments)).stack.replace(/^Error: /, ''));
    },

    time: function (label) {
      if (label) {
        timers[label] = System.currentTimeMillis();
      }
    },

    timeEnd: function (label) {
      if (label) {
        const now = System.currentTimeMillis();
        if (timers.hasOwnProperty(label)) {
          log.info(format.apply(null, [label + ':', (now - timers[label]) + 'ms']));
          delete timers[label];
        } else {
          log.info(format.apply(null, [label + ':', '<no timer>']));
        }
      }
    },

    // Allow user customizable logging names
    // Be aware that a log4j2 required a logger defined for the logger name, otherwise messages won't be logged!
    set loggerName(name) {
      log = createLogger(name);
      this._loggerName = name;
    },

    get loggerName() {
      return this._loggerName || defaultIdentifier;
    }
  };

  // Polyfill common NodeJS functions onto the global object
  globalThis.console = console;

  // Support legacy NodeJS libraries

  const JSFunction = Java.type('com.matterjs.util.JSFunction');
  const Proxy = Java.type('java.lang.reflect.Proxy');

  globalThis.setTimeout = (callback, delay) => {
    let jsFunction = Proxy.newProxyInstance(
      JSFunction.class.getClassLoader(),
      [JSFunction.class],
      {
        invoke: function (proxy, method, args) {
          callback();
        }
      }
    );
    return Globals.timerManager.setTimeout(jsFunction, delay);
  };


  globalThis.clearTimeout = (id) => {
    Globals.timerManager.clearTimeout(id);
  };

  globalThis.setInterval = (callback, interval, ...args) => {
    let runnable = Java.to(() => callback(...args), "java.lang.Runnable");
    return Globals.timerManager.setInterval(runnable, interval);
  };

  globalThis.clearInterval = (id) => {
    Globals.timerManager.clearInterval(id);
  };

  globalThis.global = globalThis;
  //globalThis.process = { env: { NODE_ENV: '' } };
  globalThis.process = new ProcessShim()

  const enc = require("./encoding.js");
  
})(this);