import { createRequire } from "module"; const require = createRequire(import.meta.url);
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __commonJS = (cb, mod) => function __require2() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/util.js
var require_util = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/util.js"(exports) {
    "use strict";
    exports.getValueAsString = function getValueString(value) {
      if (Number.isNaN(value)) {
        return "Nan";
      } else if (!Number.isFinite(value)) {
        if (value < 0) {
          return "-Inf";
        } else {
          return "+Inf";
        }
      } else {
        return `${value}`;
      }
    };
    exports.removeLabels = function removeLabels(hashMap, labels, sortedLabelNames) {
      const hash = hashObject(labels, sortedLabelNames);
      delete hashMap[hash];
    };
    exports.setValue = function setValue(hashMap, value, labels) {
      const hash = hashObject(labels);
      hashMap[hash] = {
        value: typeof value === "number" ? value : 0,
        labels: labels || {}
      };
      return hashMap;
    };
    exports.setValueDelta = function setValueDelta(hashMap, deltaValue, labels, hash = "") {
      const value = typeof deltaValue === "number" ? deltaValue : 0;
      if (hashMap[hash]) {
        hashMap[hash].value += value;
      } else {
        hashMap[hash] = { value, labels };
      }
      return hashMap;
    };
    exports.getLabels = function(labelNames, args) {
      if (typeof args[0] === "object") {
        return args[0];
      }
      if (labelNames.length !== args.length) {
        throw new Error(
          `Invalid number of arguments (${args.length}): "${args.join(
            ", "
          )}" for label names (${labelNames.length}): "${labelNames.join(", ")}".`
        );
      }
      const acc = {};
      for (let i = 0; i < labelNames.length; i++) {
        acc[labelNames[i]] = args[i];
      }
      return acc;
    };
    function fastHashObject(keys, labels) {
      if (keys.length === 0) {
        return "";
      }
      let hash = "";
      for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const value = labels[key];
        if (value === void 0) continue;
        hash += `${key}:${value},`;
      }
      return hash;
    }
    function hashObject(labels, labelNames) {
      if (labelNames) {
        return fastHashObject(labelNames, labels);
      }
      const keys = Object.keys(labels);
      if (keys.length > 1) {
        keys.sort();
      }
      return fastHashObject(keys, labels);
    }
    exports.hashObject = hashObject;
    exports.isObject = function isObject(obj) {
      return obj !== null && typeof obj === "object";
    };
    exports.nowTimestamp = function nowTimestamp() {
      return Date.now() / 1e3;
    };
    var Grouper = class extends Map {
      /**
       * Adds the `value` to the `key`'s array of values.
       * @param {*} key Key to set.
       * @param {*} value Value to add to `key`'s array.
       * @returns {undefined} undefined.
       */
      add(key, value) {
        if (this.has(key)) {
          this.get(key).push(value);
        } else {
          this.set(key, [value]);
        }
      }
    };
    exports.Grouper = Grouper;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/registry.js
var require_registry = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/registry.js"(exports, module) {
    "use strict";
    var { getValueAsString } = require_util();
    var Registry = class _Registry {
      static get PROMETHEUS_CONTENT_TYPE() {
        return "text/plain; version=0.0.4; charset=utf-8";
      }
      static get OPENMETRICS_CONTENT_TYPE() {
        return "application/openmetrics-text; version=1.0.0; charset=utf-8";
      }
      constructor(regContentType = _Registry.PROMETHEUS_CONTENT_TYPE) {
        this._metrics = {};
        this._collectors = [];
        this._defaultLabels = {};
        if (regContentType !== _Registry.PROMETHEUS_CONTENT_TYPE && regContentType !== _Registry.OPENMETRICS_CONTENT_TYPE) {
          throw new TypeError(`Content type ${regContentType} is unsupported`);
        }
        this._contentType = regContentType;
      }
      getMetricsAsArray() {
        return Object.values(this._metrics);
      }
      async getMetricsAsString(metrics2) {
        const metric = typeof metrics2.getForPromString === "function" ? await metrics2.getForPromString() : await metrics2.get();
        const name = escapeString(metric.name);
        const help = `# HELP ${name} ${escapeString(metric.help)}`;
        const type = `# TYPE ${name} ${metric.type}`;
        const values = [help, type];
        const defaultLabels = Object.keys(this._defaultLabels).length > 0 ? this._defaultLabels : null;
        const isOpenMetrics = this.contentType === _Registry.OPENMETRICS_CONTENT_TYPE;
        for (const val of metric.values || []) {
          let { metricName = name, labels = {} } = val;
          const { sharedLabels = {} } = val;
          if (isOpenMetrics && metric.type === "counter") {
            metricName = `${metricName}_total`;
          }
          if (defaultLabels) {
            labels = { ...labels, ...defaultLabels, ...labels };
          }
          const formattedLabels = formatLabels(labels, sharedLabels);
          const flattenedShared = flattenSharedLabels(sharedLabels);
          const labelParts = [...formattedLabels, flattenedShared].filter(Boolean);
          const labelsString = labelParts.length ? `{${labelParts.join(",")}}` : "";
          let fullMetricLine = `${metricName}${labelsString} ${getValueAsString(
            val.value
          )}`;
          const { exemplar } = val;
          if (exemplar && isOpenMetrics) {
            const formattedExemplars = formatLabels(exemplar.labelSet);
            fullMetricLine += ` # {${formattedExemplars.join(
              ","
            )}} ${getValueAsString(exemplar.value)} ${exemplar.timestamp}`;
          }
          values.push(fullMetricLine);
        }
        return values.join("\n");
      }
      async metrics() {
        const isOpenMetrics = this.contentType === _Registry.OPENMETRICS_CONTENT_TYPE;
        const promises = this.getMetricsAsArray().map((metric) => {
          if (isOpenMetrics && metric.type === "counter") {
            metric.name = standardizeCounterName(metric.name);
          }
          return this.getMetricsAsString(metric);
        });
        const resolves = await Promise.all(promises);
        return isOpenMetrics ? `${resolves.join("\n")}
# EOF
` : `${resolves.join("\n\n")}
`;
      }
      registerMetric(metric) {
        if (this._metrics[metric.name] && this._metrics[metric.name] !== metric) {
          throw new Error(
            `A metric with the name ${metric.name} has already been registered.`
          );
        }
        this._metrics[metric.name] = metric;
      }
      clear() {
        this._metrics = {};
        this._defaultLabels = {};
      }
      async getMetricsAsJSON() {
        const metrics2 = [];
        const defaultLabelNames = Object.keys(this._defaultLabels);
        const promises = [];
        for (const metric of this.getMetricsAsArray()) {
          promises.push(metric.get());
        }
        const resolves = await Promise.all(promises);
        for (const item of resolves) {
          if (item.values && defaultLabelNames.length > 0) {
            for (const val of item.values) {
              val.labels = Object.assign({}, val.labels);
              for (const labelName of defaultLabelNames) {
                val.labels[labelName] = val.labels[labelName] || this._defaultLabels[labelName];
              }
            }
          }
          metrics2.push(item);
        }
        return metrics2;
      }
      removeSingleMetric(name) {
        delete this._metrics[name];
      }
      getSingleMetricAsString(name) {
        return this.getMetricsAsString(this._metrics[name]);
      }
      getSingleMetric(name) {
        return this._metrics[name];
      }
      setDefaultLabels(labels) {
        this._defaultLabels = labels;
      }
      resetMetrics() {
        for (const metric in this._metrics) {
          this._metrics[metric].reset();
        }
      }
      get contentType() {
        return this._contentType;
      }
      setContentType(metricsContentType) {
        if (metricsContentType === _Registry.OPENMETRICS_CONTENT_TYPE || metricsContentType === _Registry.PROMETHEUS_CONTENT_TYPE) {
          this._contentType = metricsContentType;
        } else {
          throw new Error(`Content type ${metricsContentType} is unsupported`);
        }
      }
      static merge(registers) {
        const regType = registers[0].contentType;
        for (const reg of registers) {
          if (reg.contentType !== regType) {
            throw new Error(
              "Registers can only be merged if they have the same content type"
            );
          }
        }
        const mergedRegistry = new _Registry(regType);
        const metricsToMerge = registers.reduce(
          (acc, reg) => acc.concat(reg.getMetricsAsArray()),
          []
        );
        metricsToMerge.forEach(mergedRegistry.registerMetric, mergedRegistry);
        return mergedRegistry;
      }
    };
    function formatLabels(labels, exclude) {
      const { hasOwnProperty } = Object.prototype;
      const formatted = [];
      for (const [name, value] of Object.entries(labels)) {
        if (!exclude || !hasOwnProperty.call(exclude, name)) {
          formatted.push(`${name}="${escapeLabelValue(value)}"`);
        }
      }
      return formatted;
    }
    var sharedLabelCache = /* @__PURE__ */ new WeakMap();
    function flattenSharedLabels(labels) {
      const cached = sharedLabelCache.get(labels);
      if (cached) {
        return cached;
      }
      const formattedLabels = formatLabels(labels);
      const flattened = formattedLabels.join(",");
      sharedLabelCache.set(labels, flattened);
      return flattened;
    }
    function escapeLabelValue(str) {
      if (typeof str !== "string") {
        return str;
      }
      return escapeString(str).replace(/"/g, '\\"');
    }
    function escapeString(str) {
      return str.replace(/\\/g, "\\\\").replace(/\n/g, "\\n");
    }
    function standardizeCounterName(name) {
      return name.replace(/_total$/, "");
    }
    module.exports = Registry;
    module.exports.globalRegistry = new Registry();
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/validation.js
var require_validation = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/validation.js"(exports) {
    "use strict";
    var util2 = __require("util");
    var metricRegexp = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
    var labelRegexp = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
    exports.validateMetricName = function(name) {
      return metricRegexp.test(name);
    };
    exports.validateLabelName = function(names = []) {
      return names.every((name) => labelRegexp.test(name));
    };
    exports.validateLabel = function validateLabel(savedLabels, labels) {
      for (const label in labels) {
        if (!savedLabels.includes(label)) {
          throw new Error(
            `Added label "${label}" is not included in initial labelset: ${util2.inspect(
              savedLabels
            )}`
          );
        }
      }
    };
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metric.js
var require_metric = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metric.js"(exports, module) {
    "use strict";
    var Registry = require_registry();
    var { isObject } = require_util();
    var { validateMetricName, validateLabelName } = require_validation();
    var Metric = class {
      constructor(config, defaults = {}) {
        if (!isObject(config)) {
          throw new TypeError("constructor expected a config object");
        }
        Object.assign(
          this,
          {
            labelNames: [],
            registers: [Registry.globalRegistry],
            aggregator: "sum",
            enableExemplars: false
          },
          defaults,
          config
        );
        if (!this.registers) {
          this.registers = [Registry.globalRegistry];
        }
        if (!this.help) {
          throw new Error("Missing mandatory help parameter");
        }
        if (!this.name) {
          throw new Error("Missing mandatory name parameter");
        }
        if (!validateMetricName(this.name)) {
          throw new Error("Invalid metric name");
        }
        if (!validateLabelName(this.labelNames)) {
          throw new Error("Invalid label name");
        }
        if (this.collect && typeof this.collect !== "function") {
          throw new Error('Optional "collect" parameter must be a function');
        }
        if (this.labelNames) {
          this.sortedLabelNames = [...this.labelNames].sort();
        } else {
          this.sortedLabelNames = [];
        }
        this.reset();
        for (const register of this.registers) {
          if (this.enableExemplars && register.contentType === Registry.PROMETHEUS_CONTENT_TYPE) {
            throw new TypeError(
              "Exemplars are supported only on OpenMetrics registries"
            );
          }
          register.registerMetric(this);
        }
      }
      reset() {
      }
    };
    module.exports = { Metric };
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/exemplar.js
var require_exemplar = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/exemplar.js"(exports, module) {
    "use strict";
    var Exemplar = class {
      constructor(labelSet = {}, value = null) {
        this.labelSet = labelSet;
        this.value = value;
      }
      /**
       * Validation for the label set format.
       * https://github.com/OpenObservability/OpenMetrics/blob/d99b705f611b75fec8f450b05e344e02eea6921d/specification/OpenMetrics.md#exemplars
       *
       * @param {object} labelSet - Exemplar labels.
       * @throws {RangeError}
       * @return {void}
       */
      validateExemplarLabelSet(labelSet) {
        let res = "";
        for (const [labelName, labelValue] of Object.entries(labelSet)) {
          res += `${labelName}${labelValue}`;
        }
        if (res.length > 128) {
          throw new RangeError(
            "Label set size must be smaller than 128 UTF-8 chars"
          );
        }
      }
    };
    module.exports = Exemplar;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/counter.js
var require_counter = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/counter.js"(exports, module) {
    "use strict";
    var util2 = __require("util");
    var {
      hashObject,
      isObject,
      getLabels,
      removeLabels,
      nowTimestamp
    } = require_util();
    var { validateLabel } = require_validation();
    var { Metric } = require_metric();
    var Exemplar = require_exemplar();
    var Counter = class extends Metric {
      constructor(config) {
        super(config);
        this.type = "counter";
        this.defaultLabels = {};
        this.defaultValue = 1;
        this.defaultExemplarLabelSet = {};
        if (config.enableExemplars) {
          this.enableExemplars = true;
          this.inc = this.incWithExemplar;
        } else {
          this.inc = this.incWithoutExemplar;
        }
      }
      /**
       * Increment counter
       * @param {object} labels - What label you want to be incremented
       * @param {Number} value - Value to increment, if omitted increment with 1
       * @returns {object} results - object with information about the inc operation
       * @returns {string} results.labelHash - hash representation of the labels
       */
      incWithoutExemplar(labels, value) {
        let hash = "";
        if (isObject(labels)) {
          hash = hashObject(labels, this.sortedLabelNames);
          validateLabel(this.labelNames, labels);
        } else {
          value = labels;
          labels = {};
        }
        if (value && !Number.isFinite(value)) {
          throw new TypeError(`Value is not a valid number: ${util2.format(value)}`);
        }
        if (value < 0) {
          throw new Error("It is not possible to decrease a counter");
        }
        if (value === null || value === void 0) value = 1;
        setValue(this.hashMap, value, labels, hash);
        return { labelHash: hash };
      }
      /**
       * Increment counter with exemplar, same as inc but accepts labels for an
       * exemplar.
       * If no label is provided the current exemplar labels are kept unchanged
       * (defaults to empty set).
       *
       * @param {object} incOpts - Object with options about what metric to increase
       * @param {object} incOpts.labels - What label you want to be incremented,
       *                                  defaults to null (metric with no labels)
       * @param {Number} incOpts.value - Value to increment, defaults to 1
       * @param {object} incOpts.exemplarLabels - Key-value  labels for the
       *                                          exemplar, defaults to empty set {}
       * @returns {void}
       */
      incWithExemplar({
        labels = this.defaultLabels,
        value = this.defaultValue,
        exemplarLabels = this.defaultExemplarLabelSet
      } = {}) {
        const res = this.incWithoutExemplar(labels, value);
        this.updateExemplar(exemplarLabels, value, res.labelHash);
      }
      updateExemplar(exemplarLabels, value, hash) {
        if (exemplarLabels === this.defaultExemplarLabelSet) return;
        if (!isObject(this.hashMap[hash].exemplar)) {
          this.hashMap[hash].exemplar = new Exemplar();
        }
        this.hashMap[hash].exemplar.validateExemplarLabelSet(exemplarLabels);
        this.hashMap[hash].exemplar.labelSet = exemplarLabels;
        this.hashMap[hash].exemplar.value = value ? value : 1;
        this.hashMap[hash].exemplar.timestamp = nowTimestamp();
      }
      /**
       * Reset counter
       * @returns {void}
       */
      reset() {
        this.hashMap = {};
        if (this.labelNames.length === 0) {
          setValue(this.hashMap, 0);
        }
      }
      async get() {
        if (this.collect) {
          const v = this.collect();
          if (v instanceof Promise) await v;
        }
        return {
          help: this.help,
          name: this.name,
          type: this.type,
          values: Object.values(this.hashMap),
          aggregator: this.aggregator
        };
      }
      labels(...args) {
        const labels = getLabels(this.labelNames, args) || {};
        return {
          inc: this.inc.bind(this, labels)
        };
      }
      remove(...args) {
        const labels = getLabels(this.labelNames, args) || {};
        validateLabel(this.labelNames, labels);
        return removeLabels.call(this, this.hashMap, labels, this.sortedLabelNames);
      }
    };
    function setValue(hashMap, value, labels = {}, hash = "") {
      if (hashMap[hash]) {
        hashMap[hash].value += value;
      } else {
        hashMap[hash] = { value, labels };
      }
      return hashMap;
    }
    module.exports = Counter;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/gauge.js
var require_gauge = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/gauge.js"(exports, module) {
    "use strict";
    var util2 = __require("util");
    var {
      setValue,
      setValueDelta,
      getLabels,
      hashObject,
      isObject,
      removeLabels
    } = require_util();
    var { validateLabel } = require_validation();
    var { Metric } = require_metric();
    var Gauge = class extends Metric {
      constructor(config) {
        super(config);
        this.type = "gauge";
      }
      /**
       * Set a gauge to a value
       * @param {object} labels - Object with labels and their values
       * @param {Number} value - Value to set the gauge to, must be positive
       * @returns {void}
       */
      set(labels, value) {
        value = getValueArg(labels, value);
        labels = getLabelArg(labels);
        set(this, labels, value);
      }
      /**
       * Reset gauge
       * @returns {void}
       */
      reset() {
        this.hashMap = {};
        if (this.labelNames.length === 0) {
          setValue(this.hashMap, 0, {});
        }
      }
      /**
       * Increment a gauge value
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @param {Number} value - Value to increment - if omitted, increment with 1
       * @returns {void}
       */
      inc(labels, value) {
        value = getValueArg(labels, value);
        labels = getLabelArg(labels);
        if (value === void 0) value = 1;
        setDelta(this, labels, value);
      }
      /**
       * Decrement a gauge value
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @param {Number} value - Value to decrement - if omitted, decrement with 1
       * @returns {void}
       */
      dec(labels, value) {
        value = getValueArg(labels, value);
        labels = getLabelArg(labels);
        if (value === void 0) value = 1;
        setDelta(this, labels, -value);
      }
      /**
       * Set the gauge to current unix epoch
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @returns {void}
       */
      setToCurrentTime(labels) {
        const now = Date.now() / 1e3;
        if (labels === void 0) {
          this.set(now);
        } else {
          this.set(labels, now);
        }
      }
      /**
       * Start a timer
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @returns {function} - Invoke this function to set the duration in seconds since you started the timer.
       * @example
       * var done = gauge.startTimer();
       * makeXHRRequest(function(err, response) {
       *	done(); //Duration of the request will be saved
       * });
       */
      startTimer(labels) {
        const start = process.hrtime();
        return (endLabels) => {
          const delta = process.hrtime(start);
          const value = delta[0] + delta[1] / 1e9;
          this.set(Object.assign({}, labels, endLabels), value);
          return value;
        };
      }
      async get() {
        if (this.collect) {
          const v = this.collect();
          if (v instanceof Promise) await v;
        }
        return {
          help: this.help,
          name: this.name,
          type: this.type,
          values: Object.values(this.hashMap),
          aggregator: this.aggregator
        };
      }
      _getValue(labels) {
        const hash = hashObject(labels || {}, this.sortedLabelNames);
        return this.hashMap[hash] ? this.hashMap[hash].value : 0;
      }
      labels(...args) {
        const labels = getLabels(this.labelNames, args);
        validateLabel(this.labelNames, labels);
        return {
          inc: this.inc.bind(this, labels),
          dec: this.dec.bind(this, labels),
          set: this.set.bind(this, labels),
          setToCurrentTime: this.setToCurrentTime.bind(this, labels),
          startTimer: this.startTimer.bind(this, labels)
        };
      }
      remove(...args) {
        const labels = getLabels(this.labelNames, args);
        validateLabel(this.labelNames, labels);
        removeLabels.call(this, this.hashMap, labels, this.sortedLabelNames);
      }
    };
    function set(gauge, labels, value) {
      if (typeof value !== "number") {
        throw new TypeError(`Value is not a valid number: ${util2.format(value)}`);
      }
      validateLabel(gauge.labelNames, labels);
      setValue(gauge.hashMap, value, labels);
    }
    function setDelta(gauge, labels, delta) {
      if (typeof delta !== "number") {
        throw new TypeError(`Delta is not a valid number: ${util2.format(delta)}`);
      }
      validateLabel(gauge.labelNames, labels);
      const hash = hashObject(labels, gauge.sortedLabelNames);
      setValueDelta(gauge.hashMap, delta, labels, hash);
    }
    function getLabelArg(labels) {
      return isObject(labels) ? labels : {};
    }
    function getValueArg(labels, value) {
      return isObject(labels) ? value : labels;
    }
    module.exports = Gauge;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/histogram.js
var require_histogram = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/histogram.js"(exports, module) {
    "use strict";
    var util2 = __require("util");
    var {
      getLabels,
      hashObject,
      isObject,
      removeLabels,
      nowTimestamp
    } = require_util();
    var { validateLabel } = require_validation();
    var { Metric } = require_metric();
    var Exemplar = require_exemplar();
    var Histogram = class extends Metric {
      constructor(config) {
        super(config, {
          buckets: [5e-3, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
        });
        this.type = "histogram";
        this.defaultLabels = {};
        this.defaultExemplarLabelSet = {};
        this.enableExemplars = false;
        for (const label of this.labelNames) {
          if (label === "le") {
            throw new Error("le is a reserved label keyword");
          }
        }
        this.upperBounds = this.buckets;
        this.bucketValues = this.upperBounds.reduce((acc, upperBound) => {
          acc[upperBound] = 0;
          return acc;
        }, {});
        if (config.enableExemplars) {
          this.enableExemplars = true;
          this.bucketExemplars = this.upperBounds.reduce((acc, upperBound) => {
            acc[upperBound] = null;
            return acc;
          }, {});
          Object.freeze(this.bucketExemplars);
          this.observe = this.observeWithExemplar;
        } else {
          this.observe = this.observeWithoutExemplar;
        }
        Object.freeze(this.bucketValues);
        Object.freeze(this.upperBounds);
        if (this.labelNames.length === 0) {
          this.hashMap = {
            [hashObject({})]: createBaseValues(
              {},
              this.bucketValues,
              this.bucketExemplars
            )
          };
        }
      }
      /**
       * Observe a value in histogram
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @param {Number} value - Value to observe in the histogram
       * @returns {void}
       */
      observeWithoutExemplar(labels, value) {
        observe.call(this, labels === 0 ? 0 : labels || {})(value);
      }
      observeWithExemplar({
        labels = this.defaultLabels,
        value,
        exemplarLabels = this.defaultExemplarLabelSet
      } = {}) {
        observe.call(this, labels === 0 ? 0 : labels || {})(value);
        this.updateExemplar(labels, value, exemplarLabels);
      }
      updateExemplar(labels, value, exemplarLabels) {
        if (Object.keys(exemplarLabels).length === 0) return;
        const hash = hashObject(labels, this.sortedLabelNames);
        const bound = findBound(this.upperBounds, value);
        const { bucketExemplars } = this.hashMap[hash];
        let exemplar = bucketExemplars[bound];
        if (!isObject(exemplar)) {
          exemplar = new Exemplar();
          bucketExemplars[bound] = exemplar;
        }
        exemplar.validateExemplarLabelSet(exemplarLabels);
        exemplar.labelSet = exemplarLabels;
        exemplar.value = value;
        exemplar.timestamp = nowTimestamp();
      }
      async get() {
        const data = await this.getForPromString();
        data.values = data.values.map(splayLabels);
        return data;
      }
      async getForPromString() {
        if (this.collect) {
          const v = this.collect();
          if (v instanceof Promise) await v;
        }
        const data = Object.values(this.hashMap);
        const values = data.map(extractBucketValuesForExport(this)).reduce(addSumAndCountForExport(this), []);
        return {
          name: this.name,
          help: this.help,
          type: this.type,
          values,
          aggregator: this.aggregator
        };
      }
      reset() {
        this.hashMap = {};
      }
      /**
       * Initialize the metrics for the given combination of labels to zero
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @returns {void}
       */
      zero(labels) {
        const hash = hashObject(labels, this.sortedLabelNames);
        this.hashMap[hash] = createBaseValues(
          labels,
          this.bucketValues,
          this.bucketExemplars
        );
      }
      /**
       * Start a timer that could be used to logging durations
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @param {object} exemplarLabels - Object with labels for exemplar where key is the label key and value is label value. Can only be one level deep
       * @returns {function} - Function to invoke when you want to stop the timer and observe the duration in seconds
       * @example
       * var end = histogram.startTimer();
       * makeExpensiveXHRRequest(function(err, res) {
       * 	const duration = end(); //Observe the duration of expensiveXHRRequest and returns duration in seconds
       * 	console.log('Duration', duration);
       * });
       */
      startTimer(labels, exemplarLabels) {
        return this.enableExemplars ? startTimerWithExemplar.call(this, labels, exemplarLabels)() : startTimer.call(this, labels)();
      }
      labels(...args) {
        const labels = getLabels(this.labelNames, args);
        validateLabel(this.labelNames, labels);
        return {
          observe: observe.call(this, labels),
          startTimer: startTimer.call(this, labels)
        };
      }
      remove(...args) {
        const labels = getLabels(this.labelNames, args);
        validateLabel(this.labelNames, labels);
        removeLabels.call(this, this.hashMap, labels, this.sortedLabelNames);
      }
    };
    function startTimer(startLabels) {
      return () => {
        const start = process.hrtime();
        return (endLabels) => {
          const delta = process.hrtime(start);
          const value = delta[0] + delta[1] / 1e9;
          this.observe(Object.assign({}, startLabels, endLabels), value);
          return value;
        };
      };
    }
    function startTimerWithExemplar(startLabels, startExemplarLabels) {
      return () => {
        const start = process.hrtime();
        return (endLabels, endExemplarLabels) => {
          const delta = process.hrtime(start);
          const value = delta[0] + delta[1] / 1e9;
          this.observe({
            labels: Object.assign({}, startLabels, endLabels),
            value,
            exemplarLabels: Object.assign(
              {},
              startExemplarLabels,
              endExemplarLabels
            )
          });
          return value;
        };
      };
    }
    function setValuePair(labels, value, metricName, exemplar, sharedLabels = {}) {
      return {
        labels,
        sharedLabels,
        value,
        metricName,
        exemplar
      };
    }
    function findBound(upperBounds, value) {
      for (let i = 0; i < upperBounds.length; i++) {
        const bound = upperBounds[i];
        if (value <= bound) {
          return bound;
        }
      }
      return -1;
    }
    function observe(labels) {
      return (value) => {
        const labelValuePair = convertLabelsAndValues(labels, value);
        validateLabel(this.labelNames, labelValuePair.labels);
        if (!Number.isFinite(labelValuePair.value)) {
          throw new TypeError(
            `Value is not a valid number: ${util2.format(labelValuePair.value)}`
          );
        }
        const hash = hashObject(labelValuePair.labels, this.sortedLabelNames);
        let valueFromMap = this.hashMap[hash];
        if (!valueFromMap) {
          valueFromMap = createBaseValues(
            labelValuePair.labels,
            this.bucketValues,
            this.bucketExemplars
          );
        }
        const b = findBound(this.upperBounds, labelValuePair.value);
        valueFromMap.sum += labelValuePair.value;
        valueFromMap.count += 1;
        if (Object.prototype.hasOwnProperty.call(valueFromMap.bucketValues, b)) {
          valueFromMap.bucketValues[b] += 1;
        }
        this.hashMap[hash] = valueFromMap;
      };
    }
    function createBaseValues(labels, bucketValues, bucketExemplars) {
      const result = {
        labels,
        bucketValues: { ...bucketValues },
        sum: 0,
        count: 0
      };
      if (bucketExemplars) {
        result.bucketExemplars = { ...bucketExemplars };
      }
      return result;
    }
    function convertLabelsAndValues(labels, value) {
      return isObject(labels) ? {
        labels,
        value
      } : {
        value: labels,
        labels: {}
      };
    }
    function extractBucketValuesForExport(histogram) {
      const name = `${histogram.name}_bucket`;
      return (bucketData) => {
        let acc = 0;
        const buckets = histogram.upperBounds.map((upperBound) => {
          acc += bucketData.bucketValues[upperBound];
          return setValuePair(
            { le: upperBound },
            acc,
            name,
            bucketData.bucketExemplars ? bucketData.bucketExemplars[upperBound] : null,
            bucketData.labels
          );
        });
        return { buckets, data: bucketData };
      };
    }
    function addSumAndCountForExport(histogram) {
      return (acc, d) => {
        acc.push(...d.buckets);
        const infLabel = { le: "+Inf" };
        acc.push(
          setValuePair(
            infLabel,
            d.data.count,
            `${histogram.name}_bucket`,
            d.data.bucketExemplars ? d.data.bucketExemplars["-1"] : null,
            d.data.labels
          ),
          setValuePair(
            {},
            d.data.sum,
            `${histogram.name}_sum`,
            void 0,
            d.data.labels
          ),
          setValuePair(
            {},
            d.data.count,
            `${histogram.name}_count`,
            void 0,
            d.data.labels
          )
        );
        return acc;
      };
    }
    function splayLabels(bucket) {
      const { sharedLabels, labels, ...newBucket } = bucket;
      for (const label of Object.keys(sharedLabels)) {
        labels[label] = sharedLabels[label];
      }
      newBucket.labels = labels;
      return newBucket;
    }
    module.exports = Histogram;
  }
});

// ../../node_modules/.pnpm/bintrees@1.0.2/node_modules/bintrees/lib/treebase.js
var require_treebase = __commonJS({
  "../../node_modules/.pnpm/bintrees@1.0.2/node_modules/bintrees/lib/treebase.js"(exports, module) {
    function TreeBase() {
    }
    TreeBase.prototype.clear = function() {
      this._root = null;
      this.size = 0;
    };
    TreeBase.prototype.find = function(data) {
      var res = this._root;
      while (res !== null) {
        var c = this._comparator(data, res.data);
        if (c === 0) {
          return res.data;
        } else {
          res = res.get_child(c > 0);
        }
      }
      return null;
    };
    TreeBase.prototype.findIter = function(data) {
      var res = this._root;
      var iter = this.iterator();
      while (res !== null) {
        var c = this._comparator(data, res.data);
        if (c === 0) {
          iter._cursor = res;
          return iter;
        } else {
          iter._ancestors.push(res);
          res = res.get_child(c > 0);
        }
      }
      return null;
    };
    TreeBase.prototype.lowerBound = function(item) {
      var cur = this._root;
      var iter = this.iterator();
      var cmp = this._comparator;
      while (cur !== null) {
        var c = cmp(item, cur.data);
        if (c === 0) {
          iter._cursor = cur;
          return iter;
        }
        iter._ancestors.push(cur);
        cur = cur.get_child(c > 0);
      }
      for (var i = iter._ancestors.length - 1; i >= 0; --i) {
        cur = iter._ancestors[i];
        if (cmp(item, cur.data) < 0) {
          iter._cursor = cur;
          iter._ancestors.length = i;
          return iter;
        }
      }
      iter._ancestors.length = 0;
      return iter;
    };
    TreeBase.prototype.upperBound = function(item) {
      var iter = this.lowerBound(item);
      var cmp = this._comparator;
      while (iter.data() !== null && cmp(iter.data(), item) === 0) {
        iter.next();
      }
      return iter;
    };
    TreeBase.prototype.min = function() {
      var res = this._root;
      if (res === null) {
        return null;
      }
      while (res.left !== null) {
        res = res.left;
      }
      return res.data;
    };
    TreeBase.prototype.max = function() {
      var res = this._root;
      if (res === null) {
        return null;
      }
      while (res.right !== null) {
        res = res.right;
      }
      return res.data;
    };
    TreeBase.prototype.iterator = function() {
      return new Iterator(this);
    };
    TreeBase.prototype.each = function(cb) {
      var it = this.iterator(), data;
      while ((data = it.next()) !== null) {
        if (cb(data) === false) {
          return;
        }
      }
    };
    TreeBase.prototype.reach = function(cb) {
      var it = this.iterator(), data;
      while ((data = it.prev()) !== null) {
        if (cb(data) === false) {
          return;
        }
      }
    };
    function Iterator(tree) {
      this._tree = tree;
      this._ancestors = [];
      this._cursor = null;
    }
    Iterator.prototype.data = function() {
      return this._cursor !== null ? this._cursor.data : null;
    };
    Iterator.prototype.next = function() {
      if (this._cursor === null) {
        var root = this._tree._root;
        if (root !== null) {
          this._minNode(root);
        }
      } else {
        if (this._cursor.right === null) {
          var save;
          do {
            save = this._cursor;
            if (this._ancestors.length) {
              this._cursor = this._ancestors.pop();
            } else {
              this._cursor = null;
              break;
            }
          } while (this._cursor.right === save);
        } else {
          this._ancestors.push(this._cursor);
          this._minNode(this._cursor.right);
        }
      }
      return this._cursor !== null ? this._cursor.data : null;
    };
    Iterator.prototype.prev = function() {
      if (this._cursor === null) {
        var root = this._tree._root;
        if (root !== null) {
          this._maxNode(root);
        }
      } else {
        if (this._cursor.left === null) {
          var save;
          do {
            save = this._cursor;
            if (this._ancestors.length) {
              this._cursor = this._ancestors.pop();
            } else {
              this._cursor = null;
              break;
            }
          } while (this._cursor.left === save);
        } else {
          this._ancestors.push(this._cursor);
          this._maxNode(this._cursor.left);
        }
      }
      return this._cursor !== null ? this._cursor.data : null;
    };
    Iterator.prototype._minNode = function(start) {
      while (start.left !== null) {
        this._ancestors.push(start);
        start = start.left;
      }
      this._cursor = start;
    };
    Iterator.prototype._maxNode = function(start) {
      while (start.right !== null) {
        this._ancestors.push(start);
        start = start.right;
      }
      this._cursor = start;
    };
    module.exports = TreeBase;
  }
});

// ../../node_modules/.pnpm/bintrees@1.0.2/node_modules/bintrees/lib/rbtree.js
var require_rbtree = __commonJS({
  "../../node_modules/.pnpm/bintrees@1.0.2/node_modules/bintrees/lib/rbtree.js"(exports, module) {
    var TreeBase = require_treebase();
    function Node(data) {
      this.data = data;
      this.left = null;
      this.right = null;
      this.red = true;
    }
    Node.prototype.get_child = function(dir) {
      return dir ? this.right : this.left;
    };
    Node.prototype.set_child = function(dir, val) {
      if (dir) {
        this.right = val;
      } else {
        this.left = val;
      }
    };
    function RBTree(comparator) {
      this._root = null;
      this._comparator = comparator;
      this.size = 0;
    }
    RBTree.prototype = new TreeBase();
    RBTree.prototype.insert = function(data) {
      var ret2 = false;
      if (this._root === null) {
        this._root = new Node(data);
        ret2 = true;
        this.size++;
      } else {
        var head = new Node(void 0);
        var dir = 0;
        var last = 0;
        var gp = null;
        var ggp = head;
        var p = null;
        var node = this._root;
        ggp.right = this._root;
        while (true) {
          if (node === null) {
            node = new Node(data);
            p.set_child(dir, node);
            ret2 = true;
            this.size++;
          } else if (is_red(node.left) && is_red(node.right)) {
            node.red = true;
            node.left.red = false;
            node.right.red = false;
          }
          if (is_red(node) && is_red(p)) {
            var dir2 = ggp.right === gp;
            if (node === p.get_child(last)) {
              ggp.set_child(dir2, single_rotate(gp, !last));
            } else {
              ggp.set_child(dir2, double_rotate(gp, !last));
            }
          }
          var cmp = this._comparator(node.data, data);
          if (cmp === 0) {
            break;
          }
          last = dir;
          dir = cmp < 0;
          if (gp !== null) {
            ggp = gp;
          }
          gp = p;
          p = node;
          node = node.get_child(dir);
        }
        this._root = head.right;
      }
      this._root.red = false;
      return ret2;
    };
    RBTree.prototype.remove = function(data) {
      if (this._root === null) {
        return false;
      }
      var head = new Node(void 0);
      var node = head;
      node.right = this._root;
      var p = null;
      var gp = null;
      var found = null;
      var dir = 1;
      while (node.get_child(dir) !== null) {
        var last = dir;
        gp = p;
        p = node;
        node = node.get_child(dir);
        var cmp = this._comparator(data, node.data);
        dir = cmp > 0;
        if (cmp === 0) {
          found = node;
        }
        if (!is_red(node) && !is_red(node.get_child(dir))) {
          if (is_red(node.get_child(!dir))) {
            var sr = single_rotate(node, dir);
            p.set_child(last, sr);
            p = sr;
          } else if (!is_red(node.get_child(!dir))) {
            var sibling = p.get_child(!last);
            if (sibling !== null) {
              if (!is_red(sibling.get_child(!last)) && !is_red(sibling.get_child(last))) {
                p.red = false;
                sibling.red = true;
                node.red = true;
              } else {
                var dir2 = gp.right === p;
                if (is_red(sibling.get_child(last))) {
                  gp.set_child(dir2, double_rotate(p, last));
                } else if (is_red(sibling.get_child(!last))) {
                  gp.set_child(dir2, single_rotate(p, last));
                }
                var gpc = gp.get_child(dir2);
                gpc.red = true;
                node.red = true;
                gpc.left.red = false;
                gpc.right.red = false;
              }
            }
          }
        }
      }
      if (found !== null) {
        found.data = node.data;
        p.set_child(p.right === node, node.get_child(node.left === null));
        this.size--;
      }
      this._root = head.right;
      if (this._root !== null) {
        this._root.red = false;
      }
      return found !== null;
    };
    function is_red(node) {
      return node !== null && node.red;
    }
    function single_rotate(root, dir) {
      var save = root.get_child(!dir);
      root.set_child(!dir, save.get_child(dir));
      save.set_child(dir, root);
      root.red = true;
      save.red = false;
      return save;
    }
    function double_rotate(root, dir) {
      root.set_child(!dir, single_rotate(root.get_child(!dir), !dir));
      return single_rotate(root, dir);
    }
    module.exports = RBTree;
  }
});

// ../../node_modules/.pnpm/bintrees@1.0.2/node_modules/bintrees/lib/bintree.js
var require_bintree = __commonJS({
  "../../node_modules/.pnpm/bintrees@1.0.2/node_modules/bintrees/lib/bintree.js"(exports, module) {
    var TreeBase = require_treebase();
    function Node(data) {
      this.data = data;
      this.left = null;
      this.right = null;
    }
    Node.prototype.get_child = function(dir) {
      return dir ? this.right : this.left;
    };
    Node.prototype.set_child = function(dir, val) {
      if (dir) {
        this.right = val;
      } else {
        this.left = val;
      }
    };
    function BinTree(comparator) {
      this._root = null;
      this._comparator = comparator;
      this.size = 0;
    }
    BinTree.prototype = new TreeBase();
    BinTree.prototype.insert = function(data) {
      if (this._root === null) {
        this._root = new Node(data);
        this.size++;
        return true;
      }
      var dir = 0;
      var p = null;
      var node = this._root;
      while (true) {
        if (node === null) {
          node = new Node(data);
          p.set_child(dir, node);
          ret = true;
          this.size++;
          return true;
        }
        if (this._comparator(node.data, data) === 0) {
          return false;
        }
        dir = this._comparator(node.data, data) < 0;
        p = node;
        node = node.get_child(dir);
      }
    };
    BinTree.prototype.remove = function(data) {
      if (this._root === null) {
        return false;
      }
      var head = new Node(void 0);
      var node = head;
      node.right = this._root;
      var p = null;
      var found = null;
      var dir = 1;
      while (node.get_child(dir) !== null) {
        p = node;
        node = node.get_child(dir);
        var cmp = this._comparator(data, node.data);
        dir = cmp > 0;
        if (cmp === 0) {
          found = node;
        }
      }
      if (found !== null) {
        found.data = node.data;
        p.set_child(p.right === node, node.get_child(node.left === null));
        this._root = head.right;
        this.size--;
        return true;
      } else {
        return false;
      }
    };
    module.exports = BinTree;
  }
});

// ../../node_modules/.pnpm/bintrees@1.0.2/node_modules/bintrees/index.js
var require_bintrees = __commonJS({
  "../../node_modules/.pnpm/bintrees@1.0.2/node_modules/bintrees/index.js"(exports, module) {
    module.exports = {
      RBTree: require_rbtree(),
      BinTree: require_bintree()
    };
  }
});

// ../../node_modules/.pnpm/tdigest@0.1.3/node_modules/tdigest/tdigest.js
var require_tdigest = __commonJS({
  "../../node_modules/.pnpm/tdigest@0.1.3/node_modules/tdigest/tdigest.js"(exports, module) {
    var RBTree = require_bintrees().RBTree;
    function TDigest(delta, K, CX) {
      this.discrete = delta === false;
      this.delta = delta || 0.01;
      this.K = K === void 0 ? 25 : K;
      this.CX = CX === void 0 ? 1.1 : CX;
      this.centroids = new RBTree(compare_centroid_means);
      this.nreset = 0;
      this.reset();
    }
    TDigest.prototype.reset = function() {
      this.centroids.clear();
      this.n = 0;
      this.nreset += 1;
      this.last_cumulate = 0;
    };
    TDigest.prototype.size = function() {
      return this.centroids.size;
    };
    TDigest.prototype.toArray = function(everything) {
      var result = [];
      if (everything) {
        this._cumulate(true);
        this.centroids.each(function(c) {
          result.push(c);
        });
      } else {
        this.centroids.each(function(c) {
          result.push({ mean: c.mean, n: c.n });
        });
      }
      return result;
    };
    TDigest.prototype.summary = function() {
      var approx = this.discrete ? "exact " : "approximating ";
      var s = [
        approx + this.n + " samples using " + this.size() + " centroids",
        "min = " + this.percentile(0),
        "Q1  = " + this.percentile(0.25),
        "Q2  = " + this.percentile(0.5),
        "Q3  = " + this.percentile(0.75),
        "max = " + this.percentile(1)
      ];
      return s.join("\n");
    };
    function compare_centroid_means(a, b) {
      return a.mean > b.mean ? 1 : a.mean < b.mean ? -1 : 0;
    }
    function compare_centroid_mean_cumns(a, b) {
      return a.mean_cumn - b.mean_cumn;
    }
    TDigest.prototype.push = function(x, n) {
      n = n || 1;
      x = Array.isArray(x) ? x : [x];
      for (var i = 0; i < x.length; i++) {
        this._digest(x[i], n);
      }
    };
    TDigest.prototype.push_centroid = function(c) {
      c = Array.isArray(c) ? c : [c];
      for (var i = 0; i < c.length; i++) {
        this._digest(c[i].mean, c[i].n);
      }
    };
    TDigest.prototype._cumulate = function(exact) {
      if (this.n === this.last_cumulate || !exact && this.CX && this.CX > this.n / this.last_cumulate) {
        return;
      }
      var cumn = 0;
      this.centroids.each(function(c) {
        c.mean_cumn = cumn + c.n / 2;
        cumn = c.cumn = cumn + c.n;
      });
      this.n = this.last_cumulate = cumn;
    };
    TDigest.prototype.find_nearest = function(x) {
      if (this.size() === 0) {
        return null;
      }
      var iter = this.centroids.lowerBound({ mean: x });
      var c = iter.data() === null ? iter.prev() : iter.data();
      if (c.mean === x || this.discrete) {
        return c;
      }
      var prev = iter.prev();
      if (prev && Math.abs(prev.mean - x) < Math.abs(c.mean - x)) {
        return prev;
      } else {
        return c;
      }
    };
    TDigest.prototype._new_centroid = function(x, n, cumn) {
      var c = { mean: x, n, cumn };
      this.centroids.insert(c);
      this.n += n;
      return c;
    };
    TDigest.prototype._addweight = function(nearest, x, n) {
      if (x !== nearest.mean) {
        nearest.mean += n * (x - nearest.mean) / (nearest.n + n);
      }
      nearest.cumn += n;
      nearest.mean_cumn += n / 2;
      nearest.n += n;
      this.n += n;
    };
    TDigest.prototype._digest = function(x, n) {
      var min = this.centroids.min();
      var max = this.centroids.max();
      var nearest = this.find_nearest(x);
      if (nearest && nearest.mean === x) {
        this._addweight(nearest, x, n);
      } else if (nearest === min) {
        this._new_centroid(x, n, 0);
      } else if (nearest === max) {
        this._new_centroid(x, n, this.n);
      } else if (this.discrete) {
        this._new_centroid(x, n, nearest.cumn);
      } else {
        var p = nearest.mean_cumn / this.n;
        var max_n = Math.floor(4 * this.n * this.delta * p * (1 - p));
        if (max_n - nearest.n >= n) {
          this._addweight(nearest, x, n);
        } else {
          this._new_centroid(x, n, nearest.cumn);
        }
      }
      this._cumulate(false);
      if (!this.discrete && this.K && this.size() > this.K / this.delta) {
        this.compress();
      }
    };
    TDigest.prototype.bound_mean = function(x) {
      var iter = this.centroids.upperBound({ mean: x });
      var lower = iter.prev();
      var upper = lower.mean === x ? lower : iter.next();
      return [lower, upper];
    };
    TDigest.prototype.p_rank = function(x_or_xlist) {
      var xs = Array.isArray(x_or_xlist) ? x_or_xlist : [x_or_xlist];
      var ps = xs.map(this._p_rank, this);
      return Array.isArray(x_or_xlist) ? ps : ps[0];
    };
    TDigest.prototype._p_rank = function(x) {
      if (this.size() === 0) {
        return void 0;
      } else if (x < this.centroids.min().mean) {
        return 0;
      } else if (x > this.centroids.max().mean) {
        return 1;
      }
      this._cumulate(true);
      var bound = this.bound_mean(x);
      var lower = bound[0], upper = bound[1];
      if (this.discrete) {
        return lower.cumn / this.n;
      } else {
        var cumn = lower.mean_cumn;
        if (lower !== upper) {
          cumn += (x - lower.mean) * (upper.mean_cumn - lower.mean_cumn) / (upper.mean - lower.mean);
        }
        return cumn / this.n;
      }
    };
    TDigest.prototype.bound_mean_cumn = function(cumn) {
      this.centroids._comparator = compare_centroid_mean_cumns;
      var iter = this.centroids.upperBound({ mean_cumn: cumn });
      this.centroids._comparator = compare_centroid_means;
      var lower = iter.prev();
      var upper = lower && lower.mean_cumn === cumn ? lower : iter.next();
      return [lower, upper];
    };
    TDigest.prototype.percentile = function(p_or_plist) {
      var ps = Array.isArray(p_or_plist) ? p_or_plist : [p_or_plist];
      var qs = ps.map(this._percentile, this);
      return Array.isArray(p_or_plist) ? qs : qs[0];
    };
    TDigest.prototype._percentile = function(p) {
      if (this.size() === 0) {
        return void 0;
      }
      this._cumulate(true);
      var h = this.n * p;
      var bound = this.bound_mean_cumn(h);
      var lower = bound[0], upper = bound[1];
      if (upper === lower || lower === null || upper === null) {
        return (lower || upper).mean;
      } else if (!this.discrete) {
        return lower.mean + (h - lower.mean_cumn) * (upper.mean - lower.mean) / (upper.mean_cumn - lower.mean_cumn);
      } else if (h <= lower.cumn) {
        return lower.mean;
      } else {
        return upper.mean;
      }
    };
    function pop_random(choices) {
      var idx = Math.floor(Math.random() * choices.length);
      return choices.splice(idx, 1)[0];
    }
    TDigest.prototype.compress = function() {
      if (this.compressing) {
        return;
      }
      var points = this.toArray();
      this.reset();
      this.compressing = true;
      while (points.length > 0) {
        this.push_centroid(pop_random(points));
      }
      this._cumulate(true);
      this.compressing = false;
    };
    function Digest(config) {
      this.config = config || {};
      this.mode = this.config.mode || "auto";
      TDigest.call(this, this.mode === "cont" ? config.delta : false);
      this.digest_ratio = this.config.ratio || 0.9;
      this.digest_thresh = this.config.thresh || 1e3;
      this.n_unique = 0;
    }
    Digest.prototype = Object.create(TDigest.prototype);
    Digest.prototype.constructor = Digest;
    Digest.prototype.push = function(x_or_xlist) {
      TDigest.prototype.push.call(this, x_or_xlist);
      this.check_continuous();
    };
    Digest.prototype._new_centroid = function(x, n, cumn) {
      this.n_unique += 1;
      TDigest.prototype._new_centroid.call(this, x, n, cumn);
    };
    Digest.prototype._addweight = function(nearest, x, n) {
      if (nearest.n === 1) {
        this.n_unique -= 1;
      }
      TDigest.prototype._addweight.call(this, nearest, x, n);
    };
    Digest.prototype.check_continuous = function() {
      if (this.mode !== "auto" || this.size() < this.digest_thresh) {
        return false;
      }
      if (this.n_unique / this.size() > this.digest_ratio) {
        this.mode = "cont";
        this.discrete = false;
        this.delta = this.config.delta || 0.01;
        this.compress();
        return true;
      }
      return false;
    };
    module.exports = {
      "TDigest": TDigest,
      "Digest": Digest
    };
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/timeWindowQuantiles.js
var require_timeWindowQuantiles = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/timeWindowQuantiles.js"(exports, module) {
    "use strict";
    var { TDigest } = require_tdigest();
    var TimeWindowQuantiles = class {
      constructor(maxAgeSeconds, ageBuckets) {
        this.maxAgeSeconds = maxAgeSeconds || 0;
        this.ageBuckets = ageBuckets || 0;
        this.shouldRotate = maxAgeSeconds && ageBuckets;
        this.ringBuffer = Array(ageBuckets).fill(new TDigest());
        this.currentBuffer = 0;
        this.lastRotateTimestampMillis = Date.now();
        this.durationBetweenRotatesMillis = maxAgeSeconds * 1e3 / ageBuckets || Infinity;
      }
      size() {
        const bucket = rotate.call(this);
        return bucket.size();
      }
      percentile(quantile) {
        const bucket = rotate.call(this);
        return bucket.percentile(quantile);
      }
      push(value) {
        rotate.call(this);
        this.ringBuffer.forEach((bucket) => {
          bucket.push(value);
        });
      }
      reset() {
        this.ringBuffer.forEach((bucket) => {
          bucket.reset();
        });
      }
      compress() {
        this.ringBuffer.forEach((bucket) => {
          bucket.compress();
        });
      }
    };
    function rotate() {
      let timeSinceLastRotateMillis = Date.now() - this.lastRotateTimestampMillis;
      while (timeSinceLastRotateMillis > this.durationBetweenRotatesMillis && this.shouldRotate) {
        this.ringBuffer[this.currentBuffer] = new TDigest();
        if (++this.currentBuffer >= this.ringBuffer.length) {
          this.currentBuffer = 0;
        }
        timeSinceLastRotateMillis -= this.durationBetweenRotatesMillis;
        this.lastRotateTimestampMillis += this.durationBetweenRotatesMillis;
      }
      return this.ringBuffer[this.currentBuffer];
    }
    module.exports = TimeWindowQuantiles;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/summary.js
var require_summary = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/summary.js"(exports, module) {
    "use strict";
    var util2 = __require("util");
    var { getLabels, hashObject, removeLabels } = require_util();
    var { validateLabel } = require_validation();
    var { Metric } = require_metric();
    var timeWindowQuantiles = require_timeWindowQuantiles();
    var DEFAULT_COMPRESS_COUNT = 1e3;
    var Summary = class extends Metric {
      constructor(config) {
        super(config, {
          percentiles: [0.01, 0.05, 0.5, 0.9, 0.95, 0.99, 0.999],
          compressCount: DEFAULT_COMPRESS_COUNT,
          hashMap: {}
        });
        this.type = "summary";
        for (const label of this.labelNames) {
          if (label === "quantile")
            throw new Error("quantile is a reserved label keyword");
        }
        if (this.labelNames.length === 0) {
          this.hashMap = {
            [hashObject({})]: {
              labels: {},
              td: new timeWindowQuantiles(this.maxAgeSeconds, this.ageBuckets),
              count: 0,
              sum: 0
            }
          };
        }
      }
      /**
       * Observe a value
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @param {Number} value - Value to observe
       * @returns {void}
       */
      observe(labels, value) {
        observe.call(this, labels === 0 ? 0 : labels || {})(value);
      }
      async get() {
        if (this.collect) {
          const v = this.collect();
          if (v instanceof Promise) await v;
        }
        const hashKeys = Object.keys(this.hashMap);
        const values = [];
        hashKeys.forEach((hashKey) => {
          const s = this.hashMap[hashKey];
          if (s) {
            if (this.pruneAgedBuckets && s.td.size() === 0) {
              delete this.hashMap[hashKey];
            } else {
              extractSummariesForExport(s, this.percentiles).forEach((v) => {
                values.push(v);
              });
              values.push(getSumForExport(s, this));
              values.push(getCountForExport(s, this));
            }
          }
        });
        return {
          name: this.name,
          help: this.help,
          type: this.type,
          values,
          aggregator: this.aggregator
        };
      }
      reset() {
        const data = Object.values(this.hashMap);
        data.forEach((s) => {
          s.td.reset();
          s.count = 0;
          s.sum = 0;
        });
      }
      /**
       * Start a timer that could be used to logging durations
       * @param {object} labels - Object with labels where key is the label key and value is label value. Can only be one level deep
       * @returns {function} - Function to invoke when you want to stop the timer and observe the duration in seconds
       * @example
       * var end = summary.startTimer();
       * makeExpensiveXHRRequest(function(err, res) {
       *	end(); //Observe the duration of expensiveXHRRequest
       * });
       */
      startTimer(labels) {
        return startTimer.call(this, labels)();
      }
      labels(...args) {
        const labels = getLabels(this.labelNames, args);
        validateLabel(this.labelNames, labels);
        return {
          observe: observe.call(this, labels),
          startTimer: startTimer.call(this, labels)
        };
      }
      remove(...args) {
        const labels = getLabels(this.labelNames, args);
        validateLabel(this.labelNames, labels);
        removeLabels.call(this, this.hashMap, labels, this.sortedLabelNames);
      }
    };
    function extractSummariesForExport(summaryOfLabels, percentiles) {
      summaryOfLabels.td.compress();
      return percentiles.map((percentile) => {
        const percentileValue = summaryOfLabels.td.percentile(percentile);
        return {
          labels: Object.assign({ quantile: percentile }, summaryOfLabels.labels),
          value: percentileValue ? percentileValue : 0
        };
      });
    }
    function getCountForExport(value, summary) {
      return {
        metricName: `${summary.name}_count`,
        labels: value.labels,
        value: value.count
      };
    }
    function getSumForExport(value, summary) {
      return {
        metricName: `${summary.name}_sum`,
        labels: value.labels,
        value: value.sum
      };
    }
    function startTimer(startLabels) {
      return () => {
        const start = process.hrtime();
        return (endLabels) => {
          const delta = process.hrtime(start);
          const value = delta[0] + delta[1] / 1e9;
          this.observe(Object.assign({}, startLabels, endLabels), value);
          return value;
        };
      };
    }
    function observe(labels) {
      return (value) => {
        const labelValuePair = convertLabelsAndValues(labels, value);
        validateLabel(this.labelNames, labels);
        if (!Number.isFinite(labelValuePair.value)) {
          throw new TypeError(
            `Value is not a valid number: ${util2.format(labelValuePair.value)}`
          );
        }
        const hash = hashObject(labelValuePair.labels, this.sortedLabelNames);
        let summaryOfLabel = this.hashMap[hash];
        if (!summaryOfLabel) {
          summaryOfLabel = {
            labels: labelValuePair.labels,
            td: new timeWindowQuantiles(this.maxAgeSeconds, this.ageBuckets),
            count: 0,
            sum: 0
          };
        }
        summaryOfLabel.td.push(labelValuePair.value);
        summaryOfLabel.count++;
        if (summaryOfLabel.count % this.compressCount === 0) {
          summaryOfLabel.td.compress();
        }
        summaryOfLabel.sum += labelValuePair.value;
        this.hashMap[hash] = summaryOfLabel;
      };
    }
    function convertLabelsAndValues(labels, value) {
      if (value === void 0) {
        return {
          value: labels,
          labels: {}
        };
      }
      return {
        labels,
        value
      };
    }
    module.exports = Summary;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/pushgateway.js
var require_pushgateway = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/pushgateway.js"(exports, module) {
    "use strict";
    var url = __require("url");
    var http3 = __require("http");
    var https2 = __require("https");
    var { gzipSync } = __require("zlib");
    var { globalRegistry } = require_registry();
    var Pushgateway = class {
      constructor(gatewayUrl, options, registry) {
        if (!registry) {
          registry = globalRegistry;
        }
        this.registry = registry;
        this.gatewayUrl = gatewayUrl;
        const { requireJobName, ...requestOptions } = {
          requireJobName: true,
          ...options
        };
        this.requireJobName = requireJobName;
        this.requestOptions = requestOptions;
      }
      pushAdd(params = {}) {
        if (this.requireJobName && !params.jobName) {
          throw new Error("Missing jobName parameter");
        }
        return useGateway.call(this, "POST", params.jobName, params.groupings);
      }
      push(params = {}) {
        if (this.requireJobName && !params.jobName) {
          throw new Error("Missing jobName parameter");
        }
        return useGateway.call(this, "PUT", params.jobName, params.groupings);
      }
      delete(params = {}) {
        if (this.requireJobName && !params.jobName) {
          throw new Error("Missing jobName parameter");
        }
        return useGateway.call(this, "DELETE", params.jobName, params.groupings);
      }
    };
    async function useGateway(method, job, groupings) {
      const gatewayUrlParsed = url.parse(this.gatewayUrl);
      const gatewayUrlPath = gatewayUrlParsed.pathname && gatewayUrlParsed.pathname !== "/" ? gatewayUrlParsed.pathname : "";
      const jobPath = job ? `/job/${encodeURIComponent(job)}${generateGroupings(groupings)}` : "";
      const path = `${gatewayUrlPath}/metrics${jobPath}`;
      const target = url.resolve(this.gatewayUrl, path);
      const requestParams = url.parse(target);
      const httpModule = isHttps(requestParams.href) ? https2 : http3;
      const options = Object.assign(requestParams, this.requestOptions, {
        method
      });
      return new Promise((resolve, reject) => {
        if (method === "DELETE" && options.headers) {
          delete options.headers["Content-Encoding"];
        }
        const req = httpModule.request(options, (resp) => {
          let body = "";
          resp.setEncoding("utf8");
          resp.on("data", (chunk) => {
            body += chunk;
          });
          resp.on("end", () => {
            if (resp.statusCode >= 400) {
              reject(
                new Error(`push failed with status ${resp.statusCode}, ${body}`)
              );
            } else {
              resolve({ resp, body });
            }
          });
        });
        req.on("error", (err) => {
          reject(err);
        });
        req.on("timeout", () => {
          req.destroy(new Error("Pushgateway request timed out"));
        });
        if (method !== "DELETE") {
          this.registry.metrics().then((metrics2) => {
            if (options.headers && options.headers["Content-Encoding"] === "gzip") {
              metrics2 = gzipSync(metrics2);
            }
            req.write(metrics2);
            req.end();
          }).catch((err) => {
            reject(err);
          });
        } else {
          req.end();
        }
      });
    }
    function generateGroupings(groupings) {
      if (!groupings) {
        return "";
      }
      return Object.keys(groupings).map(
        (key) => `/${encodeURIComponent(key)}/${encodeURIComponent(groupings[key])}`
      ).join("");
    }
    function isHttps(href) {
      return href.search(/^https/) !== -1;
    }
    module.exports = Pushgateway;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/bucketGenerators.js
var require_bucketGenerators = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/bucketGenerators.js"(exports) {
    "use strict";
    exports.linearBuckets = (start, width, count) => {
      if (count < 1) {
        throw new Error("Linear buckets needs a positive count");
      }
      const buckets = new Array(count);
      for (let i = 0; i < count; i++) {
        buckets[i] = start + i * width;
      }
      return buckets;
    };
    exports.exponentialBuckets = (start, factor, count) => {
      if (start <= 0) {
        throw new Error("Exponential buckets needs a positive start");
      }
      if (count < 1) {
        throw new Error("Exponential buckets needs a positive count");
      }
      if (factor <= 1) {
        throw new Error("Exponential buckets needs a factor greater than 1");
      }
      const buckets = new Array(count);
      for (let i = 0; i < count; i++) {
        buckets[i] = start;
        start *= factor;
      }
      return buckets;
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/version.js
var VERSION;
var init_version = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/version.js"() {
    VERSION = "1.9.1";
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/internal/semver.js
function _makeCompatibilityCheck(ownVersion) {
  const acceptedVersions = /* @__PURE__ */ new Set([ownVersion]);
  const rejectedVersions = /* @__PURE__ */ new Set();
  const myVersionMatch = ownVersion.match(re);
  if (!myVersionMatch) {
    return () => false;
  }
  const ownVersionParsed = {
    major: +myVersionMatch[1],
    minor: +myVersionMatch[2],
    patch: +myVersionMatch[3],
    prerelease: myVersionMatch[4]
  };
  if (ownVersionParsed.prerelease != null) {
    return function isExactmatch(globalVersion) {
      return globalVersion === ownVersion;
    };
  }
  function _reject(v) {
    rejectedVersions.add(v);
    return false;
  }
  function _accept(v) {
    acceptedVersions.add(v);
    return true;
  }
  return function isCompatible2(globalVersion) {
    if (acceptedVersions.has(globalVersion)) {
      return true;
    }
    if (rejectedVersions.has(globalVersion)) {
      return false;
    }
    const globalVersionMatch = globalVersion.match(re);
    if (!globalVersionMatch) {
      return _reject(globalVersion);
    }
    const globalVersionParsed = {
      major: +globalVersionMatch[1],
      minor: +globalVersionMatch[2],
      patch: +globalVersionMatch[3],
      prerelease: globalVersionMatch[4]
    };
    if (globalVersionParsed.prerelease != null) {
      return _reject(globalVersion);
    }
    if (ownVersionParsed.major !== globalVersionParsed.major) {
      return _reject(globalVersion);
    }
    if (ownVersionParsed.major === 0) {
      if (ownVersionParsed.minor === globalVersionParsed.minor && ownVersionParsed.patch <= globalVersionParsed.patch) {
        return _accept(globalVersion);
      }
      return _reject(globalVersion);
    }
    if (ownVersionParsed.minor <= globalVersionParsed.minor) {
      return _accept(globalVersion);
    }
    return _reject(globalVersion);
  };
}
var re, isCompatible;
var init_semver = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/internal/semver.js"() {
    init_version();
    re = /^(\d+)\.(\d+)\.(\d+)(-(.+))?$/;
    isCompatible = _makeCompatibilityCheck(VERSION);
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/internal/global-utils.js
function registerGlobal(type, instance, diag3, allowOverride = false) {
  var _a;
  const api = _global[GLOBAL_OPENTELEMETRY_API_KEY] = (_a = _global[GLOBAL_OPENTELEMETRY_API_KEY]) !== null && _a !== void 0 ? _a : {
    version: VERSION
  };
  if (!allowOverride && api[type]) {
    const err = new Error(`@opentelemetry/api: Attempted duplicate registration of API: ${type}`);
    diag3.error(err.stack || err.message);
    return false;
  }
  if (api.version !== VERSION) {
    const err = new Error(`@opentelemetry/api: Registration of version v${api.version} for ${type} does not match previously registered API v${VERSION}`);
    diag3.error(err.stack || err.message);
    return false;
  }
  api[type] = instance;
  diag3.debug(`@opentelemetry/api: Registered a global for ${type} v${VERSION}.`);
  return true;
}
function getGlobal(type) {
  var _a, _b;
  const globalVersion = (_a = _global[GLOBAL_OPENTELEMETRY_API_KEY]) === null || _a === void 0 ? void 0 : _a.version;
  if (!globalVersion || !isCompatible(globalVersion)) {
    return;
  }
  return (_b = _global[GLOBAL_OPENTELEMETRY_API_KEY]) === null || _b === void 0 ? void 0 : _b[type];
}
function unregisterGlobal(type, diag3) {
  diag3.debug(`@opentelemetry/api: Unregistering a global for ${type} v${VERSION}.`);
  const api = _global[GLOBAL_OPENTELEMETRY_API_KEY];
  if (api) {
    delete api[type];
  }
}
var major, GLOBAL_OPENTELEMETRY_API_KEY, _global;
var init_global_utils = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/internal/global-utils.js"() {
    init_version();
    init_semver();
    major = VERSION.split(".")[0];
    GLOBAL_OPENTELEMETRY_API_KEY = /* @__PURE__ */ Symbol.for(`opentelemetry.js.api.${major}`);
    _global = typeof globalThis === "object" ? globalThis : typeof self === "object" ? self : typeof window === "object" ? window : typeof global === "object" ? global : {};
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag/ComponentLogger.js
function logProxy(funcName, namespace, args) {
  const logger = getGlobal("diag");
  if (!logger) {
    return;
  }
  return logger[funcName](namespace, ...args);
}
var DiagComponentLogger;
var init_ComponentLogger = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag/ComponentLogger.js"() {
    init_global_utils();
    DiagComponentLogger = class {
      constructor(props) {
        this._namespace = props.namespace || "DiagComponentLogger";
      }
      debug(...args) {
        return logProxy("debug", this._namespace, args);
      }
      error(...args) {
        return logProxy("error", this._namespace, args);
      }
      info(...args) {
        return logProxy("info", this._namespace, args);
      }
      warn(...args) {
        return logProxy("warn", this._namespace, args);
      }
      verbose(...args) {
        return logProxy("verbose", this._namespace, args);
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag/types.js
var DiagLogLevel;
var init_types = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag/types.js"() {
    (function(DiagLogLevel2) {
      DiagLogLevel2[DiagLogLevel2["NONE"] = 0] = "NONE";
      DiagLogLevel2[DiagLogLevel2["ERROR"] = 30] = "ERROR";
      DiagLogLevel2[DiagLogLevel2["WARN"] = 50] = "WARN";
      DiagLogLevel2[DiagLogLevel2["INFO"] = 60] = "INFO";
      DiagLogLevel2[DiagLogLevel2["DEBUG"] = 70] = "DEBUG";
      DiagLogLevel2[DiagLogLevel2["VERBOSE"] = 80] = "VERBOSE";
      DiagLogLevel2[DiagLogLevel2["ALL"] = 9999] = "ALL";
    })(DiagLogLevel || (DiagLogLevel = {}));
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag/internal/logLevelLogger.js
function createLogLevelDiagLogger(maxLevel, logger) {
  if (maxLevel < DiagLogLevel.NONE) {
    maxLevel = DiagLogLevel.NONE;
  } else if (maxLevel > DiagLogLevel.ALL) {
    maxLevel = DiagLogLevel.ALL;
  }
  logger = logger || {};
  function _filterFunc(funcName, theLevel) {
    const theFunc = logger[funcName];
    if (typeof theFunc === "function" && maxLevel >= theLevel) {
      return theFunc.bind(logger);
    }
    return function() {
    };
  }
  return {
    error: _filterFunc("error", DiagLogLevel.ERROR),
    warn: _filterFunc("warn", DiagLogLevel.WARN),
    info: _filterFunc("info", DiagLogLevel.INFO),
    debug: _filterFunc("debug", DiagLogLevel.DEBUG),
    verbose: _filterFunc("verbose", DiagLogLevel.VERBOSE)
  };
}
var init_logLevelLogger = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag/internal/logLevelLogger.js"() {
    init_types();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/diag.js
var API_NAME, DiagAPI;
var init_diag = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/diag.js"() {
    init_ComponentLogger();
    init_logLevelLogger();
    init_types();
    init_global_utils();
    API_NAME = "diag";
    DiagAPI = class _DiagAPI {
      /** Get the singleton instance of the DiagAPI API */
      static instance() {
        if (!this._instance) {
          this._instance = new _DiagAPI();
        }
        return this._instance;
      }
      /**
       * Private internal constructor
       * @private
       */
      constructor() {
        function _logProxy(funcName) {
          return function(...args) {
            const logger = getGlobal("diag");
            if (!logger)
              return;
            return logger[funcName](...args);
          };
        }
        const self2 = this;
        const setLogger = (logger, optionsOrLogLevel = { logLevel: DiagLogLevel.INFO }) => {
          var _a, _b, _c;
          if (logger === self2) {
            const err = new Error("Cannot use diag as the logger for itself. Please use a DiagLogger implementation like ConsoleDiagLogger or a custom implementation");
            self2.error((_a = err.stack) !== null && _a !== void 0 ? _a : err.message);
            return false;
          }
          if (typeof optionsOrLogLevel === "number") {
            optionsOrLogLevel = {
              logLevel: optionsOrLogLevel
            };
          }
          const oldLogger = getGlobal("diag");
          const newLogger = createLogLevelDiagLogger((_b = optionsOrLogLevel.logLevel) !== null && _b !== void 0 ? _b : DiagLogLevel.INFO, logger);
          if (oldLogger && !optionsOrLogLevel.suppressOverrideMessage) {
            const stack = (_c = new Error().stack) !== null && _c !== void 0 ? _c : "<failed to generate stacktrace>";
            oldLogger.warn(`Current logger will be overwritten from ${stack}`);
            newLogger.warn(`Current logger will overwrite one already registered from ${stack}`);
          }
          return registerGlobal("diag", newLogger, self2, true);
        };
        self2.setLogger = setLogger;
        self2.disable = () => {
          unregisterGlobal(API_NAME, self2);
        };
        self2.createComponentLogger = (options) => {
          return new DiagComponentLogger(options);
        };
        self2.verbose = _logProxy("verbose");
        self2.debug = _logProxy("debug");
        self2.info = _logProxy("info");
        self2.warn = _logProxy("warn");
        self2.error = _logProxy("error");
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/baggage/internal/baggage-impl.js
var BaggageImpl;
var init_baggage_impl = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/baggage/internal/baggage-impl.js"() {
    BaggageImpl = class _BaggageImpl {
      constructor(entries) {
        this._entries = entries ? new Map(entries) : /* @__PURE__ */ new Map();
      }
      getEntry(key) {
        const entry = this._entries.get(key);
        if (!entry) {
          return void 0;
        }
        return Object.assign({}, entry);
      }
      getAllEntries() {
        return Array.from(this._entries.entries());
      }
      setEntry(key, entry) {
        const newBaggage = new _BaggageImpl(this._entries);
        newBaggage._entries.set(key, entry);
        return newBaggage;
      }
      removeEntry(key) {
        const newBaggage = new _BaggageImpl(this._entries);
        newBaggage._entries.delete(key);
        return newBaggage;
      }
      removeEntries(...keys) {
        const newBaggage = new _BaggageImpl(this._entries);
        for (const key of keys) {
          newBaggage._entries.delete(key);
        }
        return newBaggage;
      }
      clear() {
        return new _BaggageImpl();
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/baggage/internal/symbol.js
var baggageEntryMetadataSymbol;
var init_symbol = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/baggage/internal/symbol.js"() {
    baggageEntryMetadataSymbol = /* @__PURE__ */ Symbol("BaggageEntryMetadata");
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/baggage/utils.js
function createBaggage(entries = {}) {
  return new BaggageImpl(new Map(Object.entries(entries)));
}
function baggageEntryMetadataFromString(str) {
  if (typeof str !== "string") {
    diag.error(`Cannot create baggage metadata from unknown type: ${typeof str}`);
    str = "";
  }
  return {
    __TYPE__: baggageEntryMetadataSymbol,
    toString() {
      return str;
    }
  };
}
var diag;
var init_utils = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/baggage/utils.js"() {
    init_diag();
    init_baggage_impl();
    init_symbol();
    diag = DiagAPI.instance();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/context/context.js
function createContextKey(description) {
  return Symbol.for(description);
}
var BaseContext, ROOT_CONTEXT;
var init_context = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/context/context.js"() {
    BaseContext = class _BaseContext {
      /**
       * Construct a new context which inherits values from an optional parent context.
       *
       * @param parentContext a context from which to inherit values
       */
      constructor(parentContext) {
        const self2 = this;
        self2._currentContext = parentContext ? new Map(parentContext) : /* @__PURE__ */ new Map();
        self2.getValue = (key) => self2._currentContext.get(key);
        self2.setValue = (key, value) => {
          const context2 = new _BaseContext(self2._currentContext);
          context2._currentContext.set(key, value);
          return context2;
        };
        self2.deleteValue = (key) => {
          const context2 = new _BaseContext(self2._currentContext);
          context2._currentContext.delete(key);
          return context2;
        };
      }
    };
    ROOT_CONTEXT = new BaseContext();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag/consoleLogger.js
var consoleMap, _originalConsoleMethods, DiagConsoleLogger;
var init_consoleLogger = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag/consoleLogger.js"() {
    consoleMap = [
      { n: "error", c: "error" },
      { n: "warn", c: "warn" },
      { n: "info", c: "info" },
      { n: "debug", c: "debug" },
      { n: "verbose", c: "trace" }
    ];
    _originalConsoleMethods = {};
    if (typeof console !== "undefined") {
      const keys = [
        "error",
        "warn",
        "info",
        "debug",
        "trace",
        "log"
      ];
      for (const key of keys) {
        if (typeof console[key] === "function") {
          _originalConsoleMethods[key] = console[key];
        }
      }
    }
    DiagConsoleLogger = class {
      constructor() {
        function _consoleFunc(funcName) {
          return function(...args) {
            let theFunc = _originalConsoleMethods[funcName];
            if (typeof theFunc !== "function") {
              theFunc = _originalConsoleMethods["log"];
            }
            if (typeof theFunc !== "function" && console) {
              theFunc = console[funcName];
              if (typeof theFunc !== "function") {
                theFunc = console.log;
              }
            }
            if (typeof theFunc === "function") {
              return theFunc.apply(console, args);
            }
          };
        }
        for (let i = 0; i < consoleMap.length; i++) {
          this[consoleMap[i].n] = _consoleFunc(consoleMap[i].c);
        }
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/metrics/NoopMeter.js
function createNoopMeter() {
  return NOOP_METER;
}
var NoopMeter, NoopMetric, NoopCounterMetric, NoopUpDownCounterMetric, NoopGaugeMetric, NoopHistogramMetric, NoopObservableMetric, NoopObservableCounterMetric, NoopObservableGaugeMetric, NoopObservableUpDownCounterMetric, NOOP_METER, NOOP_COUNTER_METRIC, NOOP_GAUGE_METRIC, NOOP_HISTOGRAM_METRIC, NOOP_UP_DOWN_COUNTER_METRIC, NOOP_OBSERVABLE_COUNTER_METRIC, NOOP_OBSERVABLE_GAUGE_METRIC, NOOP_OBSERVABLE_UP_DOWN_COUNTER_METRIC;
var init_NoopMeter = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/metrics/NoopMeter.js"() {
    NoopMeter = class {
      constructor() {
      }
      /**
       * @see {@link Meter.createGauge}
       */
      createGauge(_name, _options) {
        return NOOP_GAUGE_METRIC;
      }
      /**
       * @see {@link Meter.createHistogram}
       */
      createHistogram(_name, _options) {
        return NOOP_HISTOGRAM_METRIC;
      }
      /**
       * @see {@link Meter.createCounter}
       */
      createCounter(_name, _options) {
        return NOOP_COUNTER_METRIC;
      }
      /**
       * @see {@link Meter.createUpDownCounter}
       */
      createUpDownCounter(_name, _options) {
        return NOOP_UP_DOWN_COUNTER_METRIC;
      }
      /**
       * @see {@link Meter.createObservableGauge}
       */
      createObservableGauge(_name, _options) {
        return NOOP_OBSERVABLE_GAUGE_METRIC;
      }
      /**
       * @see {@link Meter.createObservableCounter}
       */
      createObservableCounter(_name, _options) {
        return NOOP_OBSERVABLE_COUNTER_METRIC;
      }
      /**
       * @see {@link Meter.createObservableUpDownCounter}
       */
      createObservableUpDownCounter(_name, _options) {
        return NOOP_OBSERVABLE_UP_DOWN_COUNTER_METRIC;
      }
      /**
       * @see {@link Meter.addBatchObservableCallback}
       */
      addBatchObservableCallback(_callback, _observables) {
      }
      /**
       * @see {@link Meter.removeBatchObservableCallback}
       */
      removeBatchObservableCallback(_callback) {
      }
    };
    NoopMetric = class {
    };
    NoopCounterMetric = class extends NoopMetric {
      add(_value, _attributes) {
      }
    };
    NoopUpDownCounterMetric = class extends NoopMetric {
      add(_value, _attributes) {
      }
    };
    NoopGaugeMetric = class extends NoopMetric {
      record(_value, _attributes) {
      }
    };
    NoopHistogramMetric = class extends NoopMetric {
      record(_value, _attributes) {
      }
    };
    NoopObservableMetric = class {
      addCallback(_callback) {
      }
      removeCallback(_callback) {
      }
    };
    NoopObservableCounterMetric = class extends NoopObservableMetric {
    };
    NoopObservableGaugeMetric = class extends NoopObservableMetric {
    };
    NoopObservableUpDownCounterMetric = class extends NoopObservableMetric {
    };
    NOOP_METER = new NoopMeter();
    NOOP_COUNTER_METRIC = new NoopCounterMetric();
    NOOP_GAUGE_METRIC = new NoopGaugeMetric();
    NOOP_HISTOGRAM_METRIC = new NoopHistogramMetric();
    NOOP_UP_DOWN_COUNTER_METRIC = new NoopUpDownCounterMetric();
    NOOP_OBSERVABLE_COUNTER_METRIC = new NoopObservableCounterMetric();
    NOOP_OBSERVABLE_GAUGE_METRIC = new NoopObservableGaugeMetric();
    NOOP_OBSERVABLE_UP_DOWN_COUNTER_METRIC = new NoopObservableUpDownCounterMetric();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/metrics/Metric.js
var ValueType;
var init_Metric = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/metrics/Metric.js"() {
    (function(ValueType2) {
      ValueType2[ValueType2["INT"] = 0] = "INT";
      ValueType2[ValueType2["DOUBLE"] = 1] = "DOUBLE";
    })(ValueType || (ValueType = {}));
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/propagation/TextMapPropagator.js
var defaultTextMapGetter, defaultTextMapSetter;
var init_TextMapPropagator = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/propagation/TextMapPropagator.js"() {
    defaultTextMapGetter = {
      get(carrier, key) {
        if (carrier == null) {
          return void 0;
        }
        return carrier[key];
      },
      keys(carrier) {
        if (carrier == null) {
          return [];
        }
        return Object.keys(carrier);
      }
    };
    defaultTextMapSetter = {
      set(carrier, key, value) {
        if (carrier == null) {
          return;
        }
        carrier[key] = value;
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/context/NoopContextManager.js
var NoopContextManager;
var init_NoopContextManager = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/context/NoopContextManager.js"() {
    init_context();
    NoopContextManager = class {
      active() {
        return ROOT_CONTEXT;
      }
      with(_context, fn, thisArg, ...args) {
        return fn.call(thisArg, ...args);
      }
      bind(_context, target) {
        return target;
      }
      enable() {
        return this;
      }
      disable() {
        return this;
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/context.js
var API_NAME2, NOOP_CONTEXT_MANAGER, ContextAPI;
var init_context2 = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/context.js"() {
    init_NoopContextManager();
    init_global_utils();
    init_diag();
    API_NAME2 = "context";
    NOOP_CONTEXT_MANAGER = new NoopContextManager();
    ContextAPI = class _ContextAPI {
      /** Empty private constructor prevents end users from constructing a new instance of the API */
      constructor() {
      }
      /** Get the singleton instance of the Context API */
      static getInstance() {
        if (!this._instance) {
          this._instance = new _ContextAPI();
        }
        return this._instance;
      }
      /**
       * Set the current context manager.
       *
       * @returns true if the context manager was successfully registered, else false
       */
      setGlobalContextManager(contextManager) {
        return registerGlobal(API_NAME2, contextManager, DiagAPI.instance());
      }
      /**
       * Get the currently active context
       */
      active() {
        return this._getContextManager().active();
      }
      /**
       * Execute a function with an active context
       *
       * @param context context to be active during function execution
       * @param fn function to execute in a context
       * @param thisArg optional receiver to be used for calling fn
       * @param args optional arguments forwarded to fn
       */
      with(context2, fn, thisArg, ...args) {
        return this._getContextManager().with(context2, fn, thisArg, ...args);
      }
      /**
       * Bind a context to a target function or event emitter
       *
       * @param context context to bind to the event emitter or function. Defaults to the currently active context
       * @param target function or event emitter to bind
       */
      bind(context2, target) {
        return this._getContextManager().bind(context2, target);
      }
      _getContextManager() {
        return getGlobal(API_NAME2) || NOOP_CONTEXT_MANAGER;
      }
      /** Disable and remove the global context manager */
      disable() {
        this._getContextManager().disable();
        unregisterGlobal(API_NAME2, DiagAPI.instance());
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/trace_flags.js
var TraceFlags;
var init_trace_flags = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/trace_flags.js"() {
    (function(TraceFlags2) {
      TraceFlags2[TraceFlags2["NONE"] = 0] = "NONE";
      TraceFlags2[TraceFlags2["SAMPLED"] = 1] = "SAMPLED";
    })(TraceFlags || (TraceFlags = {}));
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/invalid-span-constants.js
var INVALID_SPANID, INVALID_TRACEID, INVALID_SPAN_CONTEXT;
var init_invalid_span_constants = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/invalid-span-constants.js"() {
    init_trace_flags();
    INVALID_SPANID = "0000000000000000";
    INVALID_TRACEID = "00000000000000000000000000000000";
    INVALID_SPAN_CONTEXT = {
      traceId: INVALID_TRACEID,
      spanId: INVALID_SPANID,
      traceFlags: TraceFlags.NONE
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/NonRecordingSpan.js
var NonRecordingSpan;
var init_NonRecordingSpan = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/NonRecordingSpan.js"() {
    init_invalid_span_constants();
    NonRecordingSpan = class {
      constructor(spanContext = INVALID_SPAN_CONTEXT) {
        this._spanContext = spanContext;
      }
      // Returns a SpanContext.
      spanContext() {
        return this._spanContext;
      }
      // By default does nothing
      setAttribute(_key, _value) {
        return this;
      }
      // By default does nothing
      setAttributes(_attributes) {
        return this;
      }
      // By default does nothing
      addEvent(_name, _attributes) {
        return this;
      }
      addLink(_link) {
        return this;
      }
      addLinks(_links) {
        return this;
      }
      // By default does nothing
      setStatus(_status) {
        return this;
      }
      // By default does nothing
      updateName(_name) {
        return this;
      }
      // By default does nothing
      end(_endTime) {
      }
      // isRecording always returns false for NonRecordingSpan.
      isRecording() {
        return false;
      }
      // By default does nothing
      recordException(_exception, _time) {
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/context-utils.js
function getSpan(context2) {
  return context2.getValue(SPAN_KEY) || void 0;
}
function getActiveSpan() {
  return getSpan(ContextAPI.getInstance().active());
}
function setSpan(context2, span) {
  return context2.setValue(SPAN_KEY, span);
}
function deleteSpan(context2) {
  return context2.deleteValue(SPAN_KEY);
}
function setSpanContext(context2, spanContext) {
  return setSpan(context2, new NonRecordingSpan(spanContext));
}
function getSpanContext(context2) {
  var _a;
  return (_a = getSpan(context2)) === null || _a === void 0 ? void 0 : _a.spanContext();
}
var SPAN_KEY;
var init_context_utils = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/context-utils.js"() {
    init_context();
    init_NonRecordingSpan();
    init_context2();
    SPAN_KEY = createContextKey("OpenTelemetry Context Key SPAN");
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/spancontext-utils.js
function isValidHex(id, length) {
  if (typeof id !== "string" || id.length !== length)
    return false;
  let r = 0;
  for (let i = 0; i < id.length; i += 4) {
    r += (isHex[id.charCodeAt(i)] | 0) + (isHex[id.charCodeAt(i + 1)] | 0) + (isHex[id.charCodeAt(i + 2)] | 0) + (isHex[id.charCodeAt(i + 3)] | 0);
  }
  return r === length;
}
function isValidTraceId(traceId) {
  return isValidHex(traceId, 32) && traceId !== INVALID_TRACEID;
}
function isValidSpanId(spanId) {
  return isValidHex(spanId, 16) && spanId !== INVALID_SPANID;
}
function isSpanContextValid(spanContext) {
  return isValidTraceId(spanContext.traceId) && isValidSpanId(spanContext.spanId);
}
function wrapSpanContext(spanContext) {
  return new NonRecordingSpan(spanContext);
}
var isHex;
var init_spancontext_utils = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/spancontext-utils.js"() {
    init_invalid_span_constants();
    init_NonRecordingSpan();
    isHex = new Uint8Array([
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      1,
      1,
      1,
      1,
      1
    ]);
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/NoopTracer.js
function isSpanContext(spanContext) {
  return spanContext !== null && typeof spanContext === "object" && "spanId" in spanContext && typeof spanContext["spanId"] === "string" && "traceId" in spanContext && typeof spanContext["traceId"] === "string" && "traceFlags" in spanContext && typeof spanContext["traceFlags"] === "number";
}
var contextApi, NoopTracer;
var init_NoopTracer = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/NoopTracer.js"() {
    init_context2();
    init_context_utils();
    init_NonRecordingSpan();
    init_spancontext_utils();
    contextApi = ContextAPI.getInstance();
    NoopTracer = class {
      // startSpan starts a noop span.
      startSpan(name, options, context2 = contextApi.active()) {
        const root = Boolean(options === null || options === void 0 ? void 0 : options.root);
        if (root) {
          return new NonRecordingSpan();
        }
        const parentFromContext = context2 && getSpanContext(context2);
        if (isSpanContext(parentFromContext) && isSpanContextValid(parentFromContext)) {
          return new NonRecordingSpan(parentFromContext);
        } else {
          return new NonRecordingSpan();
        }
      }
      startActiveSpan(name, arg2, arg3, arg4) {
        let opts;
        let ctx;
        let fn;
        if (arguments.length < 2) {
          return;
        } else if (arguments.length === 2) {
          fn = arg2;
        } else if (arguments.length === 3) {
          opts = arg2;
          fn = arg3;
        } else {
          opts = arg2;
          ctx = arg3;
          fn = arg4;
        }
        const parentContext = ctx !== null && ctx !== void 0 ? ctx : contextApi.active();
        const span = this.startSpan(name, opts, parentContext);
        const contextWithSpanSet = setSpan(parentContext, span);
        return contextApi.with(contextWithSpanSet, fn, void 0, span);
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/ProxyTracer.js
var NOOP_TRACER, ProxyTracer;
var init_ProxyTracer = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/ProxyTracer.js"() {
    init_NoopTracer();
    NOOP_TRACER = new NoopTracer();
    ProxyTracer = class {
      constructor(provider, name, version, options) {
        this._provider = provider;
        this.name = name;
        this.version = version;
        this.options = options;
      }
      startSpan(name, options, context2) {
        return this._getTracer().startSpan(name, options, context2);
      }
      startActiveSpan(_name, _options, _context, _fn) {
        const tracer = this._getTracer();
        return Reflect.apply(tracer.startActiveSpan, tracer, arguments);
      }
      /**
       * Try to get a tracer from the proxy tracer provider.
       * If the proxy tracer provider has no delegate, return a noop tracer.
       */
      _getTracer() {
        if (this._delegate) {
          return this._delegate;
        }
        const tracer = this._provider.getDelegateTracer(this.name, this.version, this.options);
        if (!tracer) {
          return NOOP_TRACER;
        }
        this._delegate = tracer;
        return this._delegate;
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/NoopTracerProvider.js
var NoopTracerProvider;
var init_NoopTracerProvider = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/NoopTracerProvider.js"() {
    init_NoopTracer();
    NoopTracerProvider = class {
      getTracer(_name, _version, _options) {
        return new NoopTracer();
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/ProxyTracerProvider.js
var NOOP_TRACER_PROVIDER, ProxyTracerProvider;
var init_ProxyTracerProvider = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/ProxyTracerProvider.js"() {
    init_ProxyTracer();
    init_NoopTracerProvider();
    NOOP_TRACER_PROVIDER = new NoopTracerProvider();
    ProxyTracerProvider = class {
      /**
       * Get a {@link ProxyTracer}
       */
      getTracer(name, version, options) {
        var _a;
        return (_a = this.getDelegateTracer(name, version, options)) !== null && _a !== void 0 ? _a : new ProxyTracer(this, name, version, options);
      }
      getDelegate() {
        var _a;
        return (_a = this._delegate) !== null && _a !== void 0 ? _a : NOOP_TRACER_PROVIDER;
      }
      /**
       * Set the delegate tracer provider
       */
      setDelegate(delegate) {
        this._delegate = delegate;
      }
      getDelegateTracer(name, version, options) {
        var _a;
        return (_a = this._delegate) === null || _a === void 0 ? void 0 : _a.getTracer(name, version, options);
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/SamplingResult.js
var SamplingDecision;
var init_SamplingResult = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/SamplingResult.js"() {
    (function(SamplingDecision2) {
      SamplingDecision2[SamplingDecision2["NOT_RECORD"] = 0] = "NOT_RECORD";
      SamplingDecision2[SamplingDecision2["RECORD"] = 1] = "RECORD";
      SamplingDecision2[SamplingDecision2["RECORD_AND_SAMPLED"] = 2] = "RECORD_AND_SAMPLED";
    })(SamplingDecision || (SamplingDecision = {}));
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/span_kind.js
var SpanKind;
var init_span_kind = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/span_kind.js"() {
    (function(SpanKind2) {
      SpanKind2[SpanKind2["INTERNAL"] = 0] = "INTERNAL";
      SpanKind2[SpanKind2["SERVER"] = 1] = "SERVER";
      SpanKind2[SpanKind2["CLIENT"] = 2] = "CLIENT";
      SpanKind2[SpanKind2["PRODUCER"] = 3] = "PRODUCER";
      SpanKind2[SpanKind2["CONSUMER"] = 4] = "CONSUMER";
    })(SpanKind || (SpanKind = {}));
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/status.js
var SpanStatusCode;
var init_status = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/status.js"() {
    (function(SpanStatusCode2) {
      SpanStatusCode2[SpanStatusCode2["UNSET"] = 0] = "UNSET";
      SpanStatusCode2[SpanStatusCode2["OK"] = 1] = "OK";
      SpanStatusCode2[SpanStatusCode2["ERROR"] = 2] = "ERROR";
    })(SpanStatusCode || (SpanStatusCode = {}));
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/internal/tracestate-validators.js
function validateKey(key) {
  return VALID_KEY_REGEX.test(key);
}
function validateValue(value) {
  return VALID_VALUE_BASE_REGEX.test(value) && !INVALID_VALUE_COMMA_EQUAL_REGEX.test(value);
}
var VALID_KEY_CHAR_RANGE, VALID_KEY, VALID_VENDOR_KEY, VALID_KEY_REGEX, VALID_VALUE_BASE_REGEX, INVALID_VALUE_COMMA_EQUAL_REGEX;
var init_tracestate_validators = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/internal/tracestate-validators.js"() {
    VALID_KEY_CHAR_RANGE = "[_0-9a-z-*/]";
    VALID_KEY = `[a-z]${VALID_KEY_CHAR_RANGE}{0,255}`;
    VALID_VENDOR_KEY = `[a-z0-9]${VALID_KEY_CHAR_RANGE}{0,240}@[a-z]${VALID_KEY_CHAR_RANGE}{0,13}`;
    VALID_KEY_REGEX = new RegExp(`^(?:${VALID_KEY}|${VALID_VENDOR_KEY})$`);
    VALID_VALUE_BASE_REGEX = /^[ -~]{0,255}[!-~]$/;
    INVALID_VALUE_COMMA_EQUAL_REGEX = /,|=/;
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/internal/tracestate-impl.js
var MAX_TRACE_STATE_ITEMS, MAX_TRACE_STATE_LEN, LIST_MEMBERS_SEPARATOR, LIST_MEMBER_KEY_VALUE_SPLITTER, TraceStateImpl;
var init_tracestate_impl = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/internal/tracestate-impl.js"() {
    init_tracestate_validators();
    MAX_TRACE_STATE_ITEMS = 32;
    MAX_TRACE_STATE_LEN = 512;
    LIST_MEMBERS_SEPARATOR = ",";
    LIST_MEMBER_KEY_VALUE_SPLITTER = "=";
    TraceStateImpl = class _TraceStateImpl {
      constructor(rawTraceState) {
        this._internalState = /* @__PURE__ */ new Map();
        if (rawTraceState)
          this._parse(rawTraceState);
      }
      set(key, value) {
        const traceState = this._clone();
        if (traceState._internalState.has(key)) {
          traceState._internalState.delete(key);
        }
        traceState._internalState.set(key, value);
        return traceState;
      }
      unset(key) {
        const traceState = this._clone();
        traceState._internalState.delete(key);
        return traceState;
      }
      get(key) {
        return this._internalState.get(key);
      }
      serialize() {
        return Array.from(this._internalState.keys()).reduceRight((agg, key) => {
          agg.push(key + LIST_MEMBER_KEY_VALUE_SPLITTER + this.get(key));
          return agg;
        }, []).join(LIST_MEMBERS_SEPARATOR);
      }
      _parse(rawTraceState) {
        if (rawTraceState.length > MAX_TRACE_STATE_LEN)
          return;
        this._internalState = rawTraceState.split(LIST_MEMBERS_SEPARATOR).reduceRight((agg, part) => {
          const listMember = part.trim();
          const i = listMember.indexOf(LIST_MEMBER_KEY_VALUE_SPLITTER);
          if (i !== -1) {
            const key = listMember.slice(0, i);
            const value = listMember.slice(i + 1, part.length);
            if (validateKey(key) && validateValue(value)) {
              agg.set(key, value);
            } else {
            }
          }
          return agg;
        }, /* @__PURE__ */ new Map());
        if (this._internalState.size > MAX_TRACE_STATE_ITEMS) {
          this._internalState = new Map(Array.from(this._internalState.entries()).reverse().slice(0, MAX_TRACE_STATE_ITEMS));
        }
      }
      // @ts-expect-error TS6133 Accessed in tests only.
      _keys() {
        return Array.from(this._internalState.keys()).reverse();
      }
      _clone() {
        const traceState = new _TraceStateImpl();
        traceState._internalState = new Map(this._internalState);
        return traceState;
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/internal/utils.js
function createTraceState(rawTraceState) {
  return new TraceStateImpl(rawTraceState);
}
var init_utils2 = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace/internal/utils.js"() {
    init_tracestate_impl();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/context-api.js
var context;
var init_context_api = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/context-api.js"() {
    init_context2();
    context = ContextAPI.getInstance();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag-api.js
var diag2;
var init_diag_api = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/diag-api.js"() {
    init_diag();
    diag2 = DiagAPI.instance();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/metrics/NoopMeterProvider.js
var NoopMeterProvider, NOOP_METER_PROVIDER;
var init_NoopMeterProvider = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/metrics/NoopMeterProvider.js"() {
    init_NoopMeter();
    NoopMeterProvider = class {
      getMeter(_name, _version, _options) {
        return NOOP_METER;
      }
    };
    NOOP_METER_PROVIDER = new NoopMeterProvider();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/metrics.js
var API_NAME3, MetricsAPI;
var init_metrics = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/metrics.js"() {
    init_NoopMeterProvider();
    init_global_utils();
    init_diag();
    API_NAME3 = "metrics";
    MetricsAPI = class _MetricsAPI {
      /** Empty private constructor prevents end users from constructing a new instance of the API */
      constructor() {
      }
      /** Get the singleton instance of the Metrics API */
      static getInstance() {
        if (!this._instance) {
          this._instance = new _MetricsAPI();
        }
        return this._instance;
      }
      /**
       * Set the current global meter provider.
       * Returns true if the meter provider was successfully registered, else false.
       */
      setGlobalMeterProvider(provider) {
        return registerGlobal(API_NAME3, provider, DiagAPI.instance());
      }
      /**
       * Returns the global meter provider.
       */
      getMeterProvider() {
        return getGlobal(API_NAME3) || NOOP_METER_PROVIDER;
      }
      /**
       * Returns a meter from the global meter provider.
       */
      getMeter(name, version, options) {
        return this.getMeterProvider().getMeter(name, version, options);
      }
      /** Remove the global meter provider */
      disable() {
        unregisterGlobal(API_NAME3, DiagAPI.instance());
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/metrics-api.js
var metrics;
var init_metrics_api = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/metrics-api.js"() {
    init_metrics();
    metrics = MetricsAPI.getInstance();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/propagation/NoopTextMapPropagator.js
var NoopTextMapPropagator;
var init_NoopTextMapPropagator = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/propagation/NoopTextMapPropagator.js"() {
    NoopTextMapPropagator = class {
      /** Noop inject function does nothing */
      inject(_context, _carrier) {
      }
      /** Noop extract function does nothing and returns the input context */
      extract(context2, _carrier) {
        return context2;
      }
      fields() {
        return [];
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/baggage/context-helpers.js
function getBaggage(context2) {
  return context2.getValue(BAGGAGE_KEY) || void 0;
}
function getActiveBaggage() {
  return getBaggage(ContextAPI.getInstance().active());
}
function setBaggage(context2, baggage) {
  return context2.setValue(BAGGAGE_KEY, baggage);
}
function deleteBaggage(context2) {
  return context2.deleteValue(BAGGAGE_KEY);
}
var BAGGAGE_KEY;
var init_context_helpers = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/baggage/context-helpers.js"() {
    init_context2();
    init_context();
    BAGGAGE_KEY = createContextKey("OpenTelemetry Baggage Key");
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/propagation.js
var API_NAME4, NOOP_TEXT_MAP_PROPAGATOR, PropagationAPI;
var init_propagation = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/propagation.js"() {
    init_global_utils();
    init_NoopTextMapPropagator();
    init_TextMapPropagator();
    init_context_helpers();
    init_utils();
    init_diag();
    API_NAME4 = "propagation";
    NOOP_TEXT_MAP_PROPAGATOR = new NoopTextMapPropagator();
    PropagationAPI = class _PropagationAPI {
      /** Empty private constructor prevents end users from constructing a new instance of the API */
      constructor() {
        this.createBaggage = createBaggage;
        this.getBaggage = getBaggage;
        this.getActiveBaggage = getActiveBaggage;
        this.setBaggage = setBaggage;
        this.deleteBaggage = deleteBaggage;
      }
      /** Get the singleton instance of the Propagator API */
      static getInstance() {
        if (!this._instance) {
          this._instance = new _PropagationAPI();
        }
        return this._instance;
      }
      /**
       * Set the current propagator.
       *
       * @returns true if the propagator was successfully registered, else false
       */
      setGlobalPropagator(propagator) {
        return registerGlobal(API_NAME4, propagator, DiagAPI.instance());
      }
      /**
       * Inject context into a carrier to be propagated inter-process
       *
       * @param context Context carrying tracing data to inject
       * @param carrier carrier to inject context into
       * @param setter Function used to set values on the carrier
       */
      inject(context2, carrier, setter = defaultTextMapSetter) {
        return this._getGlobalPropagator().inject(context2, carrier, setter);
      }
      /**
       * Extract context from a carrier
       *
       * @param context Context which the newly created context will inherit from
       * @param carrier Carrier to extract context from
       * @param getter Function used to extract keys from a carrier
       */
      extract(context2, carrier, getter = defaultTextMapGetter) {
        return this._getGlobalPropagator().extract(context2, carrier, getter);
      }
      /**
       * Return a list of all fields which may be used by the propagator.
       */
      fields() {
        return this._getGlobalPropagator().fields();
      }
      /** Remove the global propagator */
      disable() {
        unregisterGlobal(API_NAME4, DiagAPI.instance());
      }
      _getGlobalPropagator() {
        return getGlobal(API_NAME4) || NOOP_TEXT_MAP_PROPAGATOR;
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/propagation-api.js
var propagation;
var init_propagation_api = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/propagation-api.js"() {
    init_propagation();
    propagation = PropagationAPI.getInstance();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/trace.js
var API_NAME5, TraceAPI;
var init_trace = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/api/trace.js"() {
    init_global_utils();
    init_ProxyTracerProvider();
    init_spancontext_utils();
    init_context_utils();
    init_diag();
    API_NAME5 = "trace";
    TraceAPI = class _TraceAPI {
      /** Empty private constructor prevents end users from constructing a new instance of the API */
      constructor() {
        this._proxyTracerProvider = new ProxyTracerProvider();
        this.wrapSpanContext = wrapSpanContext;
        this.isSpanContextValid = isSpanContextValid;
        this.deleteSpan = deleteSpan;
        this.getSpan = getSpan;
        this.getActiveSpan = getActiveSpan;
        this.getSpanContext = getSpanContext;
        this.setSpan = setSpan;
        this.setSpanContext = setSpanContext;
      }
      /** Get the singleton instance of the Trace API */
      static getInstance() {
        if (!this._instance) {
          this._instance = new _TraceAPI();
        }
        return this._instance;
      }
      /**
       * Set the current global tracer.
       *
       * @returns true if the tracer provider was successfully registered, else false
       */
      setGlobalTracerProvider(provider) {
        const success = registerGlobal(API_NAME5, this._proxyTracerProvider, DiagAPI.instance());
        if (success) {
          this._proxyTracerProvider.setDelegate(provider);
        }
        return success;
      }
      /**
       * Returns the global tracer provider.
       */
      getTracerProvider() {
        return getGlobal(API_NAME5) || this._proxyTracerProvider;
      }
      /**
       * Returns a tracer from the global tracer provider.
       */
      getTracer(name, version) {
        return this.getTracerProvider().getTracer(name, version);
      }
      /** Remove the global tracer provider */
      disable() {
        unregisterGlobal(API_NAME5, DiagAPI.instance());
        this._proxyTracerProvider = new ProxyTracerProvider();
      }
    };
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace-api.js
var trace;
var init_trace_api = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/trace-api.js"() {
    init_trace();
    trace = TraceAPI.getInstance();
  }
});

// ../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/index.js
var esm_exports = {};
__export(esm_exports, {
  DiagConsoleLogger: () => DiagConsoleLogger,
  DiagLogLevel: () => DiagLogLevel,
  INVALID_SPANID: () => INVALID_SPANID,
  INVALID_SPAN_CONTEXT: () => INVALID_SPAN_CONTEXT,
  INVALID_TRACEID: () => INVALID_TRACEID,
  ProxyTracer: () => ProxyTracer,
  ProxyTracerProvider: () => ProxyTracerProvider,
  ROOT_CONTEXT: () => ROOT_CONTEXT,
  SamplingDecision: () => SamplingDecision,
  SpanKind: () => SpanKind,
  SpanStatusCode: () => SpanStatusCode,
  TraceFlags: () => TraceFlags,
  ValueType: () => ValueType,
  baggageEntryMetadataFromString: () => baggageEntryMetadataFromString,
  context: () => context,
  createContextKey: () => createContextKey,
  createNoopMeter: () => createNoopMeter,
  createTraceState: () => createTraceState,
  default: () => esm_default,
  defaultTextMapGetter: () => defaultTextMapGetter,
  defaultTextMapSetter: () => defaultTextMapSetter,
  diag: () => diag2,
  isSpanContextValid: () => isSpanContextValid,
  isValidSpanId: () => isValidSpanId,
  isValidTraceId: () => isValidTraceId,
  metrics: () => metrics,
  propagation: () => propagation,
  trace: () => trace
});
var esm_default;
var init_esm = __esm({
  "../../node_modules/.pnpm/@opentelemetry+api@1.9.1/node_modules/@opentelemetry/api/build/esm/index.js"() {
    init_utils();
    init_context();
    init_consoleLogger();
    init_types();
    init_NoopMeter();
    init_Metric();
    init_TextMapPropagator();
    init_ProxyTracer();
    init_ProxyTracerProvider();
    init_SamplingResult();
    init_span_kind();
    init_status();
    init_trace_flags();
    init_utils2();
    init_spancontext_utils();
    init_invalid_span_constants();
    init_context_api();
    init_diag_api();
    init_metrics_api();
    init_propagation_api();
    init_trace_api();
    esm_default = {
      context,
      diag: diag2,
      metrics,
      propagation,
      trace
    };
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processCpuTotal.js
var require_processCpuTotal = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processCpuTotal.js"(exports, module) {
    "use strict";
    var OtelApi = (init_esm(), __toCommonJS(esm_exports));
    var Counter = require_counter();
    var PROCESS_CPU_USER_SECONDS = "process_cpu_user_seconds_total";
    var PROCESS_CPU_SYSTEM_SECONDS = "process_cpu_system_seconds_total";
    var PROCESS_CPU_SECONDS = "process_cpu_seconds_total";
    module.exports = (registry, config = {}) => {
      const registers = registry ? [registry] : void 0;
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const exemplars = config.enableExemplars ? config.enableExemplars : false;
      const labelNames = Object.keys(labels);
      let lastCpuUsage = process.cpuUsage();
      const cpuUserUsageCounter = new Counter({
        name: namePrefix + PROCESS_CPU_USER_SECONDS,
        help: "Total user CPU time spent in seconds.",
        enableExemplars: exemplars,
        registers,
        labelNames,
        // Use this one metric's `collect` to set all metrics' values.
        collect() {
          const cpuUsage = process.cpuUsage();
          const userUsageMicros = cpuUsage.user - lastCpuUsage.user;
          const systemUsageMicros = cpuUsage.system - lastCpuUsage.system;
          lastCpuUsage = cpuUsage;
          if (this.enableExemplars) {
            let exemplarLabels = {};
            const currentSpan = OtelApi.trace.getSpan(OtelApi.context.active());
            if (currentSpan) {
              exemplarLabels = {
                traceId: currentSpan.spanContext().traceId,
                spanId: currentSpan.spanContext().spanId
              };
            }
            cpuUserUsageCounter.inc({
              labels,
              value: userUsageMicros / 1e6,
              exemplarLabels
            });
            cpuSystemUsageCounter.inc({
              labels,
              value: systemUsageMicros / 1e6,
              exemplarLabels
            });
            cpuUsageCounter.inc({
              labels,
              value: (userUsageMicros + systemUsageMicros) / 1e6,
              exemplarLabels
            });
          } else {
            cpuUserUsageCounter.inc(labels, userUsageMicros / 1e6);
            cpuSystemUsageCounter.inc(labels, systemUsageMicros / 1e6);
            cpuUsageCounter.inc(
              labels,
              (userUsageMicros + systemUsageMicros) / 1e6
            );
          }
        }
      });
      const cpuSystemUsageCounter = new Counter({
        name: namePrefix + PROCESS_CPU_SYSTEM_SECONDS,
        help: "Total system CPU time spent in seconds.",
        enableExemplars: exemplars,
        registers,
        labelNames
      });
      const cpuUsageCounter = new Counter({
        name: namePrefix + PROCESS_CPU_SECONDS,
        help: "Total user and system CPU time spent in seconds.",
        enableExemplars: exemplars,
        registers,
        labelNames
      });
    };
    module.exports.metricNames = [
      PROCESS_CPU_USER_SECONDS,
      PROCESS_CPU_SYSTEM_SECONDS,
      PROCESS_CPU_SECONDS
    ];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processStartTime.js
var require_processStartTime = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processStartTime.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var startInSeconds = Math.round(Date.now() / 1e3 - process.uptime());
    var PROCESS_START_TIME = "process_start_time_seconds";
    module.exports = (registry, config = {}) => {
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      new Gauge({
        name: namePrefix + PROCESS_START_TIME,
        help: "Start time of the process since unix epoch in seconds.",
        registers: registry ? [registry] : void 0,
        labelNames,
        aggregator: "omit",
        collect() {
          this.set(labels, startInSeconds);
        }
      });
    };
    module.exports.metricNames = [PROCESS_START_TIME];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/osMemoryHeapLinux.js
var require_osMemoryHeapLinux = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/osMemoryHeapLinux.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var fs2 = __require("fs");
    var values = ["VmSize", "VmRSS", "VmData"];
    var PROCESS_RESIDENT_MEMORY = "process_resident_memory_bytes";
    var PROCESS_VIRTUAL_MEMORY = "process_virtual_memory_bytes";
    var PROCESS_HEAP = "process_heap_bytes";
    function structureOutput(input) {
      return input.split("\n").reduce((acc, string) => {
        if (!values.some((value2) => string.startsWith(value2))) {
          return acc;
        }
        const split = string.split(":");
        let value = split[1].trim();
        value = value.substr(0, value.length - 3);
        value = Number(value) * 1024;
        acc[split[0]] = value;
        return acc;
      }, {});
    }
    module.exports = (registry, config = {}) => {
      const registers = registry ? [registry] : void 0;
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      const residentMemGauge = new Gauge({
        name: namePrefix + PROCESS_RESIDENT_MEMORY,
        help: "Resident memory size in bytes.",
        registers,
        labelNames,
        // Use this one metric's `collect` to set all metrics' values.
        collect() {
          try {
            const stat = fs2.readFileSync("/proc/self/status", "utf8");
            const structuredOutput = structureOutput(stat);
            residentMemGauge.set(labels, structuredOutput.VmRSS);
            virtualMemGauge.set(labels, structuredOutput.VmSize);
            heapSizeMemGauge.set(labels, structuredOutput.VmData);
          } catch {
          }
        }
      });
      const virtualMemGauge = new Gauge({
        name: namePrefix + PROCESS_VIRTUAL_MEMORY,
        help: "Virtual memory size in bytes.",
        registers,
        labelNames
      });
      const heapSizeMemGauge = new Gauge({
        name: namePrefix + PROCESS_HEAP,
        help: "Process heap size in bytes.",
        registers,
        labelNames
      });
    };
    module.exports.metricNames = [
      PROCESS_RESIDENT_MEMORY,
      PROCESS_VIRTUAL_MEMORY,
      PROCESS_HEAP
    ];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/helpers/safeMemoryUsage.js
var require_safeMemoryUsage = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/helpers/safeMemoryUsage.js"(exports, module) {
    "use strict";
    function safeMemoryUsage() {
      try {
        return process.memoryUsage();
      } catch {
        return;
      }
    }
    module.exports = safeMemoryUsage;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/osMemoryHeap.js
var require_osMemoryHeap = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/osMemoryHeap.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var linuxVariant = require_osMemoryHeapLinux();
    var safeMemoryUsage = require_safeMemoryUsage();
    var PROCESS_RESIDENT_MEMORY = "process_resident_memory_bytes";
    function notLinuxVariant(registry, config = {}) {
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      new Gauge({
        name: namePrefix + PROCESS_RESIDENT_MEMORY,
        help: "Resident memory size in bytes.",
        registers: registry ? [registry] : void 0,
        labelNames,
        collect() {
          const memUsage = safeMemoryUsage();
          if (memUsage) {
            this.set(labels, memUsage.rss);
          }
        }
      });
    }
    module.exports = (registry, config) => process.platform === "linux" ? linuxVariant(registry, config) : notLinuxVariant(registry, config);
    module.exports.metricNames = process.platform === "linux" ? linuxVariant.metricNames : [PROCESS_RESIDENT_MEMORY];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processOpenFileDescriptors.js
var require_processOpenFileDescriptors = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processOpenFileDescriptors.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var fs2 = __require("fs");
    var process2 = __require("process");
    var PROCESS_OPEN_FDS = "process_open_fds";
    module.exports = (registry, config = {}) => {
      if (process2.platform !== "linux") {
        return;
      }
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      new Gauge({
        name: namePrefix + PROCESS_OPEN_FDS,
        help: "Number of open file descriptors.",
        registers: registry ? [registry] : void 0,
        labelNames,
        collect() {
          try {
            const fds = fs2.readdirSync("/proc/self/fd");
            this.set(labels, fds.length - 1);
          } catch {
          }
        }
      });
    };
    module.exports.metricNames = [PROCESS_OPEN_FDS];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processMaxFileDescriptors.js
var require_processMaxFileDescriptors = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processMaxFileDescriptors.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var fs2 = __require("fs");
    var PROCESS_MAX_FDS = "process_max_fds";
    var maxFds;
    module.exports = (registry, config = {}) => {
      if (maxFds === void 0) {
        try {
          const limits = fs2.readFileSync("/proc/self/limits", "utf8");
          const lines = limits.split("\n");
          for (const line of lines) {
            if (line.startsWith("Max open files")) {
              const parts = line.split(/  +/);
              maxFds = Number(parts[1]);
              break;
            }
          }
        } catch {
          return;
        }
      }
      if (maxFds === void 0) return;
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      new Gauge({
        name: namePrefix + PROCESS_MAX_FDS,
        help: "Maximum number of open file descriptors.",
        registers: registry ? [registry] : void 0,
        labelNames,
        collect() {
          if (maxFds !== void 0) this.set(labels, maxFds);
        }
      });
    };
    module.exports.metricNames = [PROCESS_MAX_FDS];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/eventLoopLag.js
var require_eventLoopLag = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/eventLoopLag.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var perf_hooks;
    try {
      perf_hooks = __require("perf_hooks");
    } catch {
    }
    var NODEJS_EVENTLOOP_LAG = "nodejs_eventloop_lag_seconds";
    var NODEJS_EVENTLOOP_LAG_MIN = "nodejs_eventloop_lag_min_seconds";
    var NODEJS_EVENTLOOP_LAG_MAX = "nodejs_eventloop_lag_max_seconds";
    var NODEJS_EVENTLOOP_LAG_MEAN = "nodejs_eventloop_lag_mean_seconds";
    var NODEJS_EVENTLOOP_LAG_STDDEV = "nodejs_eventloop_lag_stddev_seconds";
    var NODEJS_EVENTLOOP_LAG_P50 = "nodejs_eventloop_lag_p50_seconds";
    var NODEJS_EVENTLOOP_LAG_P90 = "nodejs_eventloop_lag_p90_seconds";
    var NODEJS_EVENTLOOP_LAG_P99 = "nodejs_eventloop_lag_p99_seconds";
    function reportEventloopLag(start, gauge, labels) {
      const delta = process.hrtime(start);
      const nanosec = delta[0] * 1e9 + delta[1];
      const seconds = nanosec / 1e9;
      gauge.set(labels, seconds);
    }
    module.exports = (registry, config = {}) => {
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      const registers = registry ? [registry] : void 0;
      let collect = () => {
        const start = process.hrtime();
        setImmediate(reportEventloopLag, start, lag, labels);
      };
      if (perf_hooks && perf_hooks.monitorEventLoopDelay) {
        try {
          const histogram = perf_hooks.monitorEventLoopDelay({
            resolution: config.eventLoopMonitoringPrecision
          });
          histogram.enable();
          collect = () => {
            const start = process.hrtime();
            setImmediate(reportEventloopLag, start, lag, labels);
            lagMin.set(labels, histogram.min / 1e9);
            lagMax.set(labels, histogram.max / 1e9);
            lagMean.set(labels, histogram.mean / 1e9);
            lagStddev.set(labels, histogram.stddev / 1e9);
            lagP50.set(labels, histogram.percentile(50) / 1e9);
            lagP90.set(labels, histogram.percentile(90) / 1e9);
            lagP99.set(labels, histogram.percentile(99) / 1e9);
            histogram.reset();
          };
        } catch (e) {
          if (e.code === "ERR_NOT_IMPLEMENTED") {
            return;
          }
          throw e;
        }
      }
      const lag = new Gauge({
        name: namePrefix + NODEJS_EVENTLOOP_LAG,
        help: "Lag of event loop in seconds.",
        registers,
        labelNames,
        aggregator: "average",
        // Use this one metric's `collect` to set all metrics' values.
        collect
      });
      const lagMin = new Gauge({
        name: namePrefix + NODEJS_EVENTLOOP_LAG_MIN,
        help: "The minimum recorded event loop delay.",
        registers,
        labelNames,
        aggregator: "min"
      });
      const lagMax = new Gauge({
        name: namePrefix + NODEJS_EVENTLOOP_LAG_MAX,
        help: "The maximum recorded event loop delay.",
        registers,
        labelNames,
        aggregator: "max"
      });
      const lagMean = new Gauge({
        name: namePrefix + NODEJS_EVENTLOOP_LAG_MEAN,
        help: "The mean of the recorded event loop delays.",
        registers,
        labelNames,
        aggregator: "average"
      });
      const lagStddev = new Gauge({
        name: namePrefix + NODEJS_EVENTLOOP_LAG_STDDEV,
        help: "The standard deviation of the recorded event loop delays.",
        registers,
        labelNames,
        aggregator: "average"
      });
      const lagP50 = new Gauge({
        name: namePrefix + NODEJS_EVENTLOOP_LAG_P50,
        help: "The 50th percentile of the recorded event loop delays.",
        registers,
        labelNames,
        aggregator: "average"
      });
      const lagP90 = new Gauge({
        name: namePrefix + NODEJS_EVENTLOOP_LAG_P90,
        help: "The 90th percentile of the recorded event loop delays.",
        registers,
        labelNames,
        aggregator: "average"
      });
      const lagP99 = new Gauge({
        name: namePrefix + NODEJS_EVENTLOOP_LAG_P99,
        help: "The 99th percentile of the recorded event loop delays.",
        registers,
        labelNames,
        aggregator: "average"
      });
    };
    module.exports.metricNames = [
      NODEJS_EVENTLOOP_LAG,
      NODEJS_EVENTLOOP_LAG_MIN,
      NODEJS_EVENTLOOP_LAG_MAX,
      NODEJS_EVENTLOOP_LAG_MEAN,
      NODEJS_EVENTLOOP_LAG_STDDEV,
      NODEJS_EVENTLOOP_LAG_P50,
      NODEJS_EVENTLOOP_LAG_P90,
      NODEJS_EVENTLOOP_LAG_P99
    ];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/helpers/processMetricsHelpers.js
var require_processMetricsHelpers = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/helpers/processMetricsHelpers.js"(exports, module) {
    "use strict";
    function aggregateByObjectName(list) {
      const data = {};
      for (let i = 0; i < list.length; i++) {
        const listElement = list[i];
        if (!listElement || typeof listElement.constructor === "undefined") {
          continue;
        }
        if (Object.hasOwnProperty.call(data, listElement.constructor.name)) {
          data[listElement.constructor.name] += 1;
        } else {
          data[listElement.constructor.name] = 1;
        }
      }
      return data;
    }
    function updateMetrics(gauge, data, labels) {
      gauge.reset();
      for (const key in data) {
        gauge.set(Object.assign({ type: key }, labels || {}), data[key]);
      }
    }
    module.exports = {
      aggregateByObjectName,
      updateMetrics
    };
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processHandles.js
var require_processHandles = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processHandles.js"(exports, module) {
    "use strict";
    var { aggregateByObjectName } = require_processMetricsHelpers();
    var { updateMetrics } = require_processMetricsHelpers();
    var Gauge = require_gauge();
    var NODEJS_ACTIVE_HANDLES = "nodejs_active_handles";
    var NODEJS_ACTIVE_HANDLES_TOTAL = "nodejs_active_handles_total";
    module.exports = (registry, config = {}) => {
      if (typeof process._getActiveHandles !== "function") {
        return;
      }
      const registers = registry ? [registry] : void 0;
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      new Gauge({
        name: namePrefix + NODEJS_ACTIVE_HANDLES,
        help: "Number of active libuv handles grouped by handle type. Every handle type is C++ class name.",
        labelNames: ["type", ...labelNames],
        registers,
        collect() {
          const handles = process._getActiveHandles();
          updateMetrics(this, aggregateByObjectName(handles), labels);
        }
      });
      new Gauge({
        name: namePrefix + NODEJS_ACTIVE_HANDLES_TOTAL,
        help: "Total number of active handles.",
        registers,
        labelNames,
        collect() {
          const handles = process._getActiveHandles();
          this.set(labels, handles.length);
        }
      });
    };
    module.exports.metricNames = [
      NODEJS_ACTIVE_HANDLES,
      NODEJS_ACTIVE_HANDLES_TOTAL
    ];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processRequests.js
var require_processRequests = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processRequests.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var { aggregateByObjectName } = require_processMetricsHelpers();
    var { updateMetrics } = require_processMetricsHelpers();
    var NODEJS_ACTIVE_REQUESTS = "nodejs_active_requests";
    var NODEJS_ACTIVE_REQUESTS_TOTAL = "nodejs_active_requests_total";
    module.exports = (registry, config = {}) => {
      if (typeof process._getActiveRequests !== "function") {
        return;
      }
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      new Gauge({
        name: namePrefix + NODEJS_ACTIVE_REQUESTS,
        help: "Number of active libuv requests grouped by request type. Every request type is C++ class name.",
        labelNames: ["type", ...labelNames],
        registers: registry ? [registry] : void 0,
        collect() {
          const requests = process._getActiveRequests();
          updateMetrics(this, aggregateByObjectName(requests), labels);
        }
      });
      new Gauge({
        name: namePrefix + NODEJS_ACTIVE_REQUESTS_TOTAL,
        help: "Total number of active requests.",
        registers: registry ? [registry] : void 0,
        labelNames,
        collect() {
          const requests = process._getActiveRequests();
          this.set(labels, requests.length);
        }
      });
    };
    module.exports.metricNames = [
      NODEJS_ACTIVE_REQUESTS,
      NODEJS_ACTIVE_REQUESTS_TOTAL
    ];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processResources.js
var require_processResources = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/processResources.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var { updateMetrics } = require_processMetricsHelpers();
    var NODEJS_ACTIVE_RESOURCES = "nodejs_active_resources";
    var NODEJS_ACTIVE_RESOURCES_TOTAL = "nodejs_active_resources_total";
    module.exports = (registry, config = {}) => {
      if (typeof process.getActiveResourcesInfo !== "function") {
        return;
      }
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      new Gauge({
        name: namePrefix + NODEJS_ACTIVE_RESOURCES,
        help: "Number of active resources that are currently keeping the event loop alive, grouped by async resource type.",
        labelNames: ["type", ...labelNames],
        registers: registry ? [registry] : void 0,
        collect() {
          const resources = process.getActiveResourcesInfo();
          const data = {};
          for (let i = 0; i < resources.length; i++) {
            const resource = resources[i];
            if (Object.hasOwn(data, resource)) {
              data[resource] += 1;
            } else {
              data[resource] = 1;
            }
          }
          updateMetrics(this, data, labels);
        }
      });
      new Gauge({
        name: namePrefix + NODEJS_ACTIVE_RESOURCES_TOTAL,
        help: "Total number of active resources.",
        registers: registry ? [registry] : void 0,
        labelNames,
        collect() {
          const resources = process.getActiveResourcesInfo();
          this.set(labels, resources.length);
        }
      });
    };
    module.exports.metricNames = [
      NODEJS_ACTIVE_RESOURCES,
      NODEJS_ACTIVE_RESOURCES_TOTAL
    ];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/heapSizeAndUsed.js
var require_heapSizeAndUsed = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/heapSizeAndUsed.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var safeMemoryUsage = require_safeMemoryUsage();
    var NODEJS_HEAP_SIZE_TOTAL = "nodejs_heap_size_total_bytes";
    var NODEJS_HEAP_SIZE_USED = "nodejs_heap_size_used_bytes";
    var NODEJS_EXTERNAL_MEMORY = "nodejs_external_memory_bytes";
    module.exports = (registry, config = {}) => {
      if (typeof process.memoryUsage !== "function") {
        return;
      }
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      const registers = registry ? [registry] : void 0;
      const namePrefix = config.prefix ? config.prefix : "";
      const collect = () => {
        const memUsage = safeMemoryUsage();
        if (memUsage) {
          heapSizeTotal.set(labels, memUsage.heapTotal);
          heapSizeUsed.set(labels, memUsage.heapUsed);
          if (memUsage.external !== void 0) {
            externalMemUsed.set(labels, memUsage.external);
          }
        }
      };
      const heapSizeTotal = new Gauge({
        name: namePrefix + NODEJS_HEAP_SIZE_TOTAL,
        help: "Process heap size from Node.js in bytes.",
        registers,
        labelNames,
        // Use this one metric's `collect` to set all metrics' values.
        collect
      });
      const heapSizeUsed = new Gauge({
        name: namePrefix + NODEJS_HEAP_SIZE_USED,
        help: "Process heap size used from Node.js in bytes.",
        registers,
        labelNames
      });
      const externalMemUsed = new Gauge({
        name: namePrefix + NODEJS_EXTERNAL_MEMORY,
        help: "Node.js external memory size in bytes.",
        registers,
        labelNames
      });
    };
    module.exports.metricNames = [
      NODEJS_HEAP_SIZE_TOTAL,
      NODEJS_HEAP_SIZE_USED,
      NODEJS_EXTERNAL_MEMORY
    ];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/heapSpacesSizeAndUsed.js
var require_heapSpacesSizeAndUsed = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/heapSpacesSizeAndUsed.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var v8 = __require("v8");
    var METRICS = ["total", "used", "available"];
    var NODEJS_HEAP_SIZE = {};
    METRICS.forEach((metricType) => {
      NODEJS_HEAP_SIZE[metricType] = `nodejs_heap_space_size_${metricType}_bytes`;
    });
    module.exports = (registry, config = {}) => {
      try {
        v8.getHeapSpaceStatistics();
      } catch (e) {
        if (e.code === "ERR_NOT_IMPLEMENTED") {
          return;
        }
        throw e;
      }
      const registers = registry ? [registry] : void 0;
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = ["space", ...Object.keys(labels)];
      const gauges = {};
      METRICS.forEach((metricType) => {
        gauges[metricType] = new Gauge({
          name: namePrefix + NODEJS_HEAP_SIZE[metricType],
          help: `Process heap space size ${metricType} from Node.js in bytes.`,
          labelNames,
          registers
        });
      });
      gauges.total.collect = () => {
        for (const space of v8.getHeapSpaceStatistics()) {
          const spaceName = space.space_name.substr(
            0,
            space.space_name.indexOf("_space")
          );
          gauges.total.set({ space: spaceName, ...labels }, space.space_size);
          gauges.used.set({ space: spaceName, ...labels }, space.space_used_size);
          gauges.available.set(
            { space: spaceName, ...labels },
            space.space_available_size
          );
        }
      };
    };
    module.exports.metricNames = Object.values(NODEJS_HEAP_SIZE);
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/version.js
var require_version = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/version.js"(exports, module) {
    "use strict";
    var Gauge = require_gauge();
    var version = process.version;
    var versionSegments = version.slice(1).split(".").map(Number);
    var NODE_VERSION_INFO = "nodejs_version_info";
    module.exports = (registry, config = {}) => {
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      new Gauge({
        name: namePrefix + NODE_VERSION_INFO,
        help: "Node.js version info.",
        labelNames: ["version", "major", "minor", "patch", ...labelNames],
        registers: registry ? [registry] : void 0,
        aggregator: "first",
        collect() {
          this.labels(
            version,
            versionSegments[0],
            versionSegments[1],
            versionSegments[2],
            ...Object.values(labels)
          ).set(1);
        }
      });
    };
    module.exports.metricNames = [NODE_VERSION_INFO];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/gc.js
var require_gc = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metrics/gc.js"(exports, module) {
    "use strict";
    var Histogram = require_histogram();
    var perf_hooks;
    try {
      perf_hooks = __require("perf_hooks");
    } catch {
    }
    var NODEJS_GC_DURATION_SECONDS = "nodejs_gc_duration_seconds";
    var DEFAULT_GC_DURATION_BUCKETS = [1e-3, 0.01, 0.1, 1, 2, 5];
    var kinds = [];
    if (perf_hooks && perf_hooks.constants) {
      kinds[perf_hooks.constants.NODE_PERFORMANCE_GC_MAJOR] = "major";
      kinds[perf_hooks.constants.NODE_PERFORMANCE_GC_MINOR] = "minor";
      kinds[perf_hooks.constants.NODE_PERFORMANCE_GC_INCREMENTAL] = "incremental";
      kinds[perf_hooks.constants.NODE_PERFORMANCE_GC_WEAKCB] = "weakcb";
    }
    module.exports = (registry, config = {}) => {
      if (!perf_hooks) {
        return;
      }
      const namePrefix = config.prefix ? config.prefix : "";
      const labels = config.labels ? config.labels : {};
      const labelNames = Object.keys(labels);
      const buckets = config.gcDurationBuckets ? config.gcDurationBuckets : DEFAULT_GC_DURATION_BUCKETS;
      const gcHistogram = new Histogram({
        name: namePrefix + NODEJS_GC_DURATION_SECONDS,
        help: "Garbage collection duration by kind, one of major, minor, incremental or weakcb.",
        labelNames: ["kind", ...labelNames],
        enableExemplars: false,
        buckets,
        registers: registry ? [registry] : void 0
      });
      const obs = new perf_hooks.PerformanceObserver((list) => {
        const entry = list.getEntries()[0];
        const kind = entry.detail ? kinds[entry.detail.kind] : kinds[entry.kind];
        gcHistogram.observe(Object.assign({ kind }, labels), entry.duration / 1e3);
      });
      obs.observe({ entryTypes: ["gc"] });
    };
    module.exports.metricNames = [NODEJS_GC_DURATION_SECONDS];
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/defaultMetrics.js
var require_defaultMetrics = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/defaultMetrics.js"(exports, module) {
    "use strict";
    var { isObject } = require_util();
    var processCpuTotal = require_processCpuTotal();
    var processStartTime = require_processStartTime();
    var osMemoryHeap = require_osMemoryHeap();
    var processOpenFileDescriptors = require_processOpenFileDescriptors();
    var processMaxFileDescriptors = require_processMaxFileDescriptors();
    var eventLoopLag = require_eventLoopLag();
    var processHandles = require_processHandles();
    var processRequests = require_processRequests();
    var processResources = require_processResources();
    var heapSizeAndUsed = require_heapSizeAndUsed();
    var heapSpacesSizeAndUsed = require_heapSpacesSizeAndUsed();
    var version = require_version();
    var gc = require_gc();
    var metrics2 = {
      processCpuTotal,
      processStartTime,
      osMemoryHeap,
      processOpenFileDescriptors,
      processMaxFileDescriptors,
      eventLoopLag,
      ...typeof process.getActiveResourcesInfo === "function" ? { processResources } : {},
      processHandles,
      processRequests,
      heapSizeAndUsed,
      heapSpacesSizeAndUsed,
      version,
      gc
    };
    var metricsList = Object.keys(metrics2);
    module.exports = function collectDefaultMetrics(config) {
      if (config !== null && config !== void 0 && !isObject(config)) {
        throw new TypeError("config must be null, undefined, or an object");
      }
      config = { eventLoopMonitoringPrecision: 10, ...config };
      for (const metric of Object.values(metrics2)) {
        metric(config.register, config);
      }
    };
    module.exports.metricsList = metricsList;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metricAggregators.js
var require_metricAggregators = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/metricAggregators.js"(exports) {
    "use strict";
    var { Grouper, hashObject } = require_util();
    function AggregatorFactory(aggregatorFn) {
      return (metrics2) => {
        if (metrics2.length === 0) return;
        const result = {
          help: metrics2[0].help,
          name: metrics2[0].name,
          type: metrics2[0].type,
          values: [],
          aggregator: metrics2[0].aggregator
        };
        const byLabels = new Grouper();
        metrics2.forEach((metric) => {
          metric.values.forEach((value) => {
            const key = hashObject(value.labels);
            byLabels.add(`${value.metricName}_${key}`, value);
          });
        });
        byLabels.forEach((values) => {
          if (values.length === 0) return;
          const valObj = {
            value: aggregatorFn(values),
            labels: values[0].labels
          };
          if (values[0].metricName) {
            valObj.metricName = values[0].metricName;
          }
          result.values.push(valObj);
        });
        return result;
      };
    }
    exports.AggregatorFactory = AggregatorFactory;
    exports.aggregators = {
      /**
       * @return The sum of values.
       */
      sum: AggregatorFactory((v) => v.reduce((p, c) => p + c.value, 0)),
      /**
       * @return The first value.
       */
      first: AggregatorFactory((v) => v[0].value),
      /**
       * @return {undefined} Undefined; omits the metric.
       */
      omit: () => {
      },
      /**
       * @return The arithmetic mean of the values.
       */
      average: AggregatorFactory(
        (v) => v.reduce((p, c) => p + c.value, 0) / v.length
      ),
      /**
       * @return The minimum of the values.
       */
      min: AggregatorFactory(
        (v) => v.reduce((p, c) => Math.min(p, c.value), Infinity)
      ),
      /**
       * @return The maximum of the values.
       */
      max: AggregatorFactory(
        (v) => v.reduce((p, c) => Math.max(p, c.value), -Infinity)
      )
    };
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/cluster.js
var require_cluster = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/lib/cluster.js"(exports, module) {
    "use strict";
    var Registry = require_registry();
    var { Grouper } = require_util();
    var { aggregators } = require_metricAggregators();
    var cluster = () => {
      const data = __require("cluster");
      cluster = () => data;
      return data;
    };
    var GET_METRICS_REQ = "prom-client:getMetricsReq";
    var GET_METRICS_RES = "prom-client:getMetricsRes";
    var registries = [Registry.globalRegistry];
    var requestCtr = 0;
    var listenersAdded = false;
    var requests = /* @__PURE__ */ new Map();
    var AggregatorRegistry = class extends Registry {
      constructor(regContentType = Registry.PROMETHEUS_CONTENT_TYPE) {
        super(regContentType);
        addListeners();
      }
      /**
       * Gets aggregated metrics for all workers. The optional callback and
       * returned Promise resolve with the same value; either may be used.
       * @return {Promise<string>} Promise that resolves with the aggregated
       *   metrics.
       */
      clusterMetrics() {
        const requestId = requestCtr++;
        return new Promise((resolve, reject) => {
          let settled = false;
          function done(err, result) {
            if (settled) return;
            settled = true;
            if (err) reject(err);
            else resolve(result);
          }
          const request2 = {
            responses: [],
            pending: 0,
            done,
            errorTimeout: setTimeout(() => {
              const err = new Error("Operation timed out.");
              request2.done(err);
            }, 5e3)
          };
          requests.set(requestId, request2);
          const message = {
            type: GET_METRICS_REQ,
            requestId
          };
          for (const id in cluster().workers) {
            if (cluster().workers[id].isConnected()) {
              cluster().workers[id].send(message);
              request2.pending++;
            }
          }
          if (request2.pending === 0) {
            clearTimeout(request2.errorTimeout);
            process.nextTick(() => done(null, ""));
          }
        });
      }
      get contentType() {
        return super.contentType;
      }
      /**
       * Creates a new Registry instance from an array of metrics that were
       * created by `registry.getMetricsAsJSON()`. Metrics are aggregated using
       * the method specified by their `aggregator` property, or by summation if
       * `aggregator` is undefined.
       * @param {Array} metricsArr Array of metrics, each of which created by
       *   `registry.getMetricsAsJSON()`.
       * @param {string} registryType content type of the new registry. Defaults
       * to PROMETHEUS_CONTENT_TYPE.
       * @return {Registry} aggregated registry.
       */
      static aggregate(metricsArr, registryType = Registry.PROMETHEUS_CONTENT_TYPE) {
        const aggregatedRegistry = new Registry();
        const metricsByName = new Grouper();
        aggregatedRegistry.setContentType(registryType);
        metricsArr.forEach((metrics2) => {
          metrics2.forEach((metric) => {
            metricsByName.add(metric.name, metric);
          });
        });
        metricsByName.forEach((metrics2) => {
          const aggregatorName = metrics2[0].aggregator;
          const aggregatorFn = aggregators[aggregatorName];
          if (typeof aggregatorFn !== "function") {
            throw new Error(`'${aggregatorName}' is not a defined aggregator.`);
          }
          const aggregatedMetric = aggregatorFn(metrics2);
          if (aggregatedMetric) {
            const aggregatedMetricWrapper = Object.assign(
              {
                get: () => aggregatedMetric
              },
              aggregatedMetric
            );
            aggregatedRegistry.registerMetric(aggregatedMetricWrapper);
          }
        });
        return aggregatedRegistry;
      }
      /**
       * Sets the registry or registries to be aggregated. Call from workers to
       * use a registry/registries other than the default global registry.
       * @param {Array<Registry>|Registry} regs Registry or registries to be
       *   aggregated.
       * @return {void}
       */
      static setRegistries(regs) {
        if (!Array.isArray(regs)) regs = [regs];
        regs.forEach((reg) => {
          if (!(reg instanceof Registry)) {
            throw new TypeError(`Expected Registry, got ${typeof reg}`);
          }
        });
        registries = regs;
      }
    };
    function addListeners() {
      if (listenersAdded) return;
      listenersAdded = true;
      if (cluster().isMaster) {
        cluster().on("message", (worker, message) => {
          if (message.type === GET_METRICS_RES) {
            const request2 = requests.get(message.requestId);
            if (message.error) {
              request2.done(new Error(message.error));
              return;
            }
            message.metrics.forEach((registry) => request2.responses.push(registry));
            request2.pending--;
            if (request2.pending === 0) {
              requests.delete(message.requestId);
              clearTimeout(request2.errorTimeout);
              const registry = AggregatorRegistry.aggregate(request2.responses);
              const promString = registry.metrics();
              request2.done(null, promString);
            }
          }
        });
      }
      if (cluster().isWorker) {
        process.on("message", (message) => {
          if (message.type === GET_METRICS_REQ) {
            Promise.all(registries.map((r) => r.getMetricsAsJSON())).then((metrics2) => {
              process.send({
                type: GET_METRICS_RES,
                requestId: message.requestId,
                metrics: metrics2
              });
            }).catch((error) => {
              process.send({
                type: GET_METRICS_RES,
                requestId: message.requestId,
                error: error.message
              });
            });
          }
        });
      }
    }
    module.exports = AggregatorRegistry;
  }
});

// ../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/index.js
var require_prom_client = __commonJS({
  "../../node_modules/.pnpm/prom-client@15.1.3/node_modules/prom-client/index.js"(exports) {
    "use strict";
    exports.register = require_registry().globalRegistry;
    exports.Registry = require_registry();
    Object.defineProperty(exports, "contentType", {
      configurable: false,
      enumerable: true,
      get() {
        return exports.register.contentType;
      },
      set(value) {
        exports.register.setContentType(value);
      }
    });
    exports.prometheusContentType = exports.Registry.PROMETHEUS_CONTENT_TYPE;
    exports.openMetricsContentType = exports.Registry.OPENMETRICS_CONTENT_TYPE;
    exports.validateMetricName = require_validation().validateMetricName;
    exports.Counter = require_counter();
    exports.Gauge = require_gauge();
    exports.Histogram = require_histogram();
    exports.Summary = require_summary();
    exports.Pushgateway = require_pushgateway();
    exports.linearBuckets = require_bucketGenerators().linearBuckets;
    exports.exponentialBuckets = require_bucketGenerators().exponentialBuckets;
    exports.collectDefaultMetrics = require_defaultMetrics();
    exports.aggregators = require_metricAggregators().aggregators;
    exports.AggregatorRegistry = require_cluster();
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/constants.js
var require_constants = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/constants.js"(exports, module) {
    "use strict";
    var BINARY_TYPES = ["nodebuffer", "arraybuffer", "fragments"];
    var hasBlob = typeof Blob !== "undefined";
    if (hasBlob) BINARY_TYPES.push("blob");
    module.exports = {
      BINARY_TYPES,
      CLOSE_TIMEOUT: 3e4,
      EMPTY_BUFFER: Buffer.alloc(0),
      GUID: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
      hasBlob,
      kForOnEventAttribute: /* @__PURE__ */ Symbol("kIsForOnEventAttribute"),
      kListener: /* @__PURE__ */ Symbol("kListener"),
      kStatusCode: /* @__PURE__ */ Symbol("status-code"),
      kWebSocket: /* @__PURE__ */ Symbol("websocket"),
      NOOP: () => {
      }
    };
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/buffer-util.js
var require_buffer_util = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/buffer-util.js"(exports, module) {
    "use strict";
    var { EMPTY_BUFFER } = require_constants();
    var FastBuffer = Buffer[Symbol.species];
    function concat(list, totalLength) {
      if (list.length === 0) return EMPTY_BUFFER;
      if (list.length === 1) return list[0];
      const target = Buffer.allocUnsafe(totalLength);
      let offset = 0;
      for (let i = 0; i < list.length; i++) {
        const buf = list[i];
        target.set(buf, offset);
        offset += buf.length;
      }
      if (offset < totalLength) {
        return new FastBuffer(target.buffer, target.byteOffset, offset);
      }
      return target;
    }
    function _mask(source, mask, output, offset, length) {
      for (let i = 0; i < length; i++) {
        output[offset + i] = source[i] ^ mask[i & 3];
      }
    }
    function _unmask(buffer, mask) {
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] ^= mask[i & 3];
      }
    }
    function toArrayBuffer(buf) {
      if (buf.length === buf.buffer.byteLength) {
        return buf.buffer;
      }
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);
    }
    function toBuffer(data) {
      toBuffer.readOnly = true;
      if (Buffer.isBuffer(data)) return data;
      let buf;
      if (data instanceof ArrayBuffer) {
        buf = new FastBuffer(data);
      } else if (ArrayBuffer.isView(data)) {
        buf = new FastBuffer(data.buffer, data.byteOffset, data.byteLength);
      } else {
        buf = Buffer.from(data);
        toBuffer.readOnly = false;
      }
      return buf;
    }
    module.exports = {
      concat,
      mask: _mask,
      toArrayBuffer,
      toBuffer,
      unmask: _unmask
    };
    if (!process.env.WS_NO_BUFFER_UTIL) {
      try {
        const bufferUtil = __require("bufferutil");
        module.exports.mask = function(source, mask, output, offset, length) {
          if (length < 48) _mask(source, mask, output, offset, length);
          else bufferUtil.mask(source, mask, output, offset, length);
        };
        module.exports.unmask = function(buffer, mask) {
          if (buffer.length < 32) _unmask(buffer, mask);
          else bufferUtil.unmask(buffer, mask);
        };
      } catch (e) {
      }
    }
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/limiter.js
var require_limiter = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/limiter.js"(exports, module) {
    "use strict";
    var kDone = /* @__PURE__ */ Symbol("kDone");
    var kRun = /* @__PURE__ */ Symbol("kRun");
    var Limiter = class {
      /**
       * Creates a new `Limiter`.
       *
       * @param {Number} [concurrency=Infinity] The maximum number of jobs allowed
       *     to run concurrently
       */
      constructor(concurrency) {
        this[kDone] = () => {
          this.pending--;
          this[kRun]();
        };
        this.concurrency = concurrency || Infinity;
        this.jobs = [];
        this.pending = 0;
      }
      /**
       * Adds a job to the queue.
       *
       * @param {Function} job The job to run
       * @public
       */
      add(job) {
        this.jobs.push(job);
        this[kRun]();
      }
      /**
       * Removes a job from the queue and runs it if possible.
       *
       * @private
       */
      [kRun]() {
        if (this.pending === this.concurrency) return;
        if (this.jobs.length) {
          const job = this.jobs.shift();
          this.pending++;
          job(this[kDone]);
        }
      }
    };
    module.exports = Limiter;
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/permessage-deflate.js
var require_permessage_deflate = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/permessage-deflate.js"(exports, module) {
    "use strict";
    var zlib = __require("zlib");
    var bufferUtil = require_buffer_util();
    var Limiter = require_limiter();
    var { kStatusCode } = require_constants();
    var FastBuffer = Buffer[Symbol.species];
    var TRAILER = Buffer.from([0, 0, 255, 255]);
    var kPerMessageDeflate = /* @__PURE__ */ Symbol("permessage-deflate");
    var kTotalLength = /* @__PURE__ */ Symbol("total-length");
    var kCallback = /* @__PURE__ */ Symbol("callback");
    var kBuffers = /* @__PURE__ */ Symbol("buffers");
    var kError = /* @__PURE__ */ Symbol("error");
    var zlibLimiter;
    var PerMessageDeflate2 = class {
      /**
       * Creates a PerMessageDeflate instance.
       *
       * @param {Object} [options] Configuration options
       * @param {(Boolean|Number)} [options.clientMaxWindowBits] Advertise support
       *     for, or request, a custom client window size
       * @param {Boolean} [options.clientNoContextTakeover=false] Advertise/
       *     acknowledge disabling of client context takeover
       * @param {Number} [options.concurrencyLimit=10] The number of concurrent
       *     calls to zlib
       * @param {Boolean} [options.isServer=false] Create the instance in either
       *     server or client mode
       * @param {Number} [options.maxPayload=0] The maximum allowed message length
       * @param {(Boolean|Number)} [options.serverMaxWindowBits] Request/confirm the
       *     use of a custom server window size
       * @param {Boolean} [options.serverNoContextTakeover=false] Request/accept
       *     disabling of server context takeover
       * @param {Number} [options.threshold=1024] Size (in bytes) below which
       *     messages should not be compressed if context takeover is disabled
       * @param {Object} [options.zlibDeflateOptions] Options to pass to zlib on
       *     deflate
       * @param {Object} [options.zlibInflateOptions] Options to pass to zlib on
       *     inflate
       */
      constructor(options) {
        this._options = options || {};
        this._threshold = this._options.threshold !== void 0 ? this._options.threshold : 1024;
        this._maxPayload = this._options.maxPayload | 0;
        this._isServer = !!this._options.isServer;
        this._deflate = null;
        this._inflate = null;
        this.params = null;
        if (!zlibLimiter) {
          const concurrency = this._options.concurrencyLimit !== void 0 ? this._options.concurrencyLimit : 10;
          zlibLimiter = new Limiter(concurrency);
        }
      }
      /**
       * @type {String}
       */
      static get extensionName() {
        return "permessage-deflate";
      }
      /**
       * Create an extension negotiation offer.
       *
       * @return {Object} Extension parameters
       * @public
       */
      offer() {
        const params = {};
        if (this._options.serverNoContextTakeover) {
          params.server_no_context_takeover = true;
        }
        if (this._options.clientNoContextTakeover) {
          params.client_no_context_takeover = true;
        }
        if (this._options.serverMaxWindowBits) {
          params.server_max_window_bits = this._options.serverMaxWindowBits;
        }
        if (this._options.clientMaxWindowBits) {
          params.client_max_window_bits = this._options.clientMaxWindowBits;
        } else if (this._options.clientMaxWindowBits == null) {
          params.client_max_window_bits = true;
        }
        return params;
      }
      /**
       * Accept an extension negotiation offer/response.
       *
       * @param {Array} configurations The extension negotiation offers/reponse
       * @return {Object} Accepted configuration
       * @public
       */
      accept(configurations) {
        configurations = this.normalizeParams(configurations);
        this.params = this._isServer ? this.acceptAsServer(configurations) : this.acceptAsClient(configurations);
        return this.params;
      }
      /**
       * Releases all resources used by the extension.
       *
       * @public
       */
      cleanup() {
        if (this._inflate) {
          this._inflate.close();
          this._inflate = null;
        }
        if (this._deflate) {
          const callback = this._deflate[kCallback];
          this._deflate.close();
          this._deflate = null;
          if (callback) {
            callback(
              new Error(
                "The deflate stream was closed while data was being processed"
              )
            );
          }
        }
      }
      /**
       *  Accept an extension negotiation offer.
       *
       * @param {Array} offers The extension negotiation offers
       * @return {Object} Accepted configuration
       * @private
       */
      acceptAsServer(offers) {
        const opts = this._options;
        const accepted = offers.find((params) => {
          if (opts.serverNoContextTakeover === false && params.server_no_context_takeover || params.server_max_window_bits && (opts.serverMaxWindowBits === false || typeof opts.serverMaxWindowBits === "number" && opts.serverMaxWindowBits > params.server_max_window_bits) || typeof opts.clientMaxWindowBits === "number" && (typeof params.client_max_window_bits === "number" ? opts.clientMaxWindowBits > params.client_max_window_bits : !params.client_max_window_bits)) {
            return false;
          }
          return true;
        });
        if (!accepted) {
          throw new Error("None of the extension offers can be accepted");
        }
        if (opts.serverNoContextTakeover) {
          accepted.server_no_context_takeover = true;
        }
        if (opts.clientNoContextTakeover) {
          accepted.client_no_context_takeover = true;
        }
        if (typeof opts.serverMaxWindowBits === "number") {
          accepted.server_max_window_bits = opts.serverMaxWindowBits;
        }
        if (typeof opts.clientMaxWindowBits === "number") {
          accepted.client_max_window_bits = opts.clientMaxWindowBits;
        } else if (accepted.client_max_window_bits === true || opts.clientMaxWindowBits === false) {
          delete accepted.client_max_window_bits;
        }
        return accepted;
      }
      /**
       * Accept the extension negotiation response.
       *
       * @param {Array} response The extension negotiation response
       * @return {Object} Accepted configuration
       * @private
       */
      acceptAsClient(response) {
        const params = response[0];
        if (this._options.clientNoContextTakeover === false && params.client_no_context_takeover) {
          throw new Error('Unexpected parameter "client_no_context_takeover"');
        }
        if (!params.client_max_window_bits) {
          if (typeof this._options.clientMaxWindowBits === "number") {
            params.client_max_window_bits = this._options.clientMaxWindowBits;
          }
        } else if (this._options.clientMaxWindowBits === false || typeof this._options.clientMaxWindowBits === "number" && params.client_max_window_bits > this._options.clientMaxWindowBits) {
          throw new Error(
            'Unexpected or invalid parameter "client_max_window_bits"'
          );
        }
        return params;
      }
      /**
       * Normalize parameters.
       *
       * @param {Array} configurations The extension negotiation offers/reponse
       * @return {Array} The offers/response with normalized parameters
       * @private
       */
      normalizeParams(configurations) {
        configurations.forEach((params) => {
          Object.keys(params).forEach((key) => {
            let value = params[key];
            if (value.length > 1) {
              throw new Error(`Parameter "${key}" must have only a single value`);
            }
            value = value[0];
            if (key === "client_max_window_bits") {
              if (value !== true) {
                const num = +value;
                if (!Number.isInteger(num) || num < 8 || num > 15) {
                  throw new TypeError(
                    `Invalid value for parameter "${key}": ${value}`
                  );
                }
                value = num;
              } else if (!this._isServer) {
                throw new TypeError(
                  `Invalid value for parameter "${key}": ${value}`
                );
              }
            } else if (key === "server_max_window_bits") {
              const num = +value;
              if (!Number.isInteger(num) || num < 8 || num > 15) {
                throw new TypeError(
                  `Invalid value for parameter "${key}": ${value}`
                );
              }
              value = num;
            } else if (key === "client_no_context_takeover" || key === "server_no_context_takeover") {
              if (value !== true) {
                throw new TypeError(
                  `Invalid value for parameter "${key}": ${value}`
                );
              }
            } else {
              throw new Error(`Unknown parameter "${key}"`);
            }
            params[key] = value;
          });
        });
        return configurations;
      }
      /**
       * Decompress data. Concurrency limited.
       *
       * @param {Buffer} data Compressed data
       * @param {Boolean} fin Specifies whether or not this is the last fragment
       * @param {Function} callback Callback
       * @public
       */
      decompress(data, fin, callback) {
        zlibLimiter.add((done) => {
          this._decompress(data, fin, (err, result) => {
            done();
            callback(err, result);
          });
        });
      }
      /**
       * Compress data. Concurrency limited.
       *
       * @param {(Buffer|String)} data Data to compress
       * @param {Boolean} fin Specifies whether or not this is the last fragment
       * @param {Function} callback Callback
       * @public
       */
      compress(data, fin, callback) {
        zlibLimiter.add((done) => {
          this._compress(data, fin, (err, result) => {
            done();
            callback(err, result);
          });
        });
      }
      /**
       * Decompress data.
       *
       * @param {Buffer} data Compressed data
       * @param {Boolean} fin Specifies whether or not this is the last fragment
       * @param {Function} callback Callback
       * @private
       */
      _decompress(data, fin, callback) {
        const endpoint = this._isServer ? "client" : "server";
        if (!this._inflate) {
          const key = `${endpoint}_max_window_bits`;
          const windowBits = typeof this.params[key] !== "number" ? zlib.Z_DEFAULT_WINDOWBITS : this.params[key];
          this._inflate = zlib.createInflateRaw({
            ...this._options.zlibInflateOptions,
            windowBits
          });
          this._inflate[kPerMessageDeflate] = this;
          this._inflate[kTotalLength] = 0;
          this._inflate[kBuffers] = [];
          this._inflate.on("error", inflateOnError);
          this._inflate.on("data", inflateOnData);
        }
        this._inflate[kCallback] = callback;
        this._inflate.write(data);
        if (fin) this._inflate.write(TRAILER);
        this._inflate.flush(() => {
          const err = this._inflate[kError];
          if (err) {
            this._inflate.close();
            this._inflate = null;
            callback(err);
            return;
          }
          const data2 = bufferUtil.concat(
            this._inflate[kBuffers],
            this._inflate[kTotalLength]
          );
          if (this._inflate._readableState.endEmitted) {
            this._inflate.close();
            this._inflate = null;
          } else {
            this._inflate[kTotalLength] = 0;
            this._inflate[kBuffers] = [];
            if (fin && this.params[`${endpoint}_no_context_takeover`]) {
              this._inflate.reset();
            }
          }
          callback(null, data2);
        });
      }
      /**
       * Compress data.
       *
       * @param {(Buffer|String)} data Data to compress
       * @param {Boolean} fin Specifies whether or not this is the last fragment
       * @param {Function} callback Callback
       * @private
       */
      _compress(data, fin, callback) {
        const endpoint = this._isServer ? "server" : "client";
        if (!this._deflate) {
          const key = `${endpoint}_max_window_bits`;
          const windowBits = typeof this.params[key] !== "number" ? zlib.Z_DEFAULT_WINDOWBITS : this.params[key];
          this._deflate = zlib.createDeflateRaw({
            ...this._options.zlibDeflateOptions,
            windowBits
          });
          this._deflate[kTotalLength] = 0;
          this._deflate[kBuffers] = [];
          this._deflate.on("data", deflateOnData);
        }
        this._deflate[kCallback] = callback;
        this._deflate.write(data);
        this._deflate.flush(zlib.Z_SYNC_FLUSH, () => {
          if (!this._deflate) {
            return;
          }
          let data2 = bufferUtil.concat(
            this._deflate[kBuffers],
            this._deflate[kTotalLength]
          );
          if (fin) {
            data2 = new FastBuffer(data2.buffer, data2.byteOffset, data2.length - 4);
          }
          this._deflate[kCallback] = null;
          this._deflate[kTotalLength] = 0;
          this._deflate[kBuffers] = [];
          if (fin && this.params[`${endpoint}_no_context_takeover`]) {
            this._deflate.reset();
          }
          callback(null, data2);
        });
      }
    };
    module.exports = PerMessageDeflate2;
    function deflateOnData(chunk) {
      this[kBuffers].push(chunk);
      this[kTotalLength] += chunk.length;
    }
    function inflateOnData(chunk) {
      this[kTotalLength] += chunk.length;
      if (this[kPerMessageDeflate]._maxPayload < 1 || this[kTotalLength] <= this[kPerMessageDeflate]._maxPayload) {
        this[kBuffers].push(chunk);
        return;
      }
      this[kError] = new RangeError("Max payload size exceeded");
      this[kError].code = "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH";
      this[kError][kStatusCode] = 1009;
      this.removeListener("data", inflateOnData);
      this.reset();
    }
    function inflateOnError(err) {
      this[kPerMessageDeflate]._inflate = null;
      if (this[kError]) {
        this[kCallback](this[kError]);
        return;
      }
      err[kStatusCode] = 1007;
      this[kCallback](err);
    }
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/validation.js
var require_validation2 = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/validation.js"(exports, module) {
    "use strict";
    var { isUtf8 } = __require("buffer");
    var { hasBlob } = require_constants();
    var tokenChars = [
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      // 0 - 15
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      // 16 - 31
      0,
      1,
      0,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      1,
      1,
      0,
      1,
      1,
      0,
      // 32 - 47
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      // 48 - 63
      0,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      // 64 - 79
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      0,
      1,
      1,
      // 80 - 95
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      // 96 - 111
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      1,
      0,
      1,
      0
      // 112 - 127
    ];
    function isValidStatusCode(code) {
      return code >= 1e3 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006 || code >= 3e3 && code <= 4999;
    }
    function _isValidUTF8(buf) {
      const len = buf.length;
      let i = 0;
      while (i < len) {
        if ((buf[i] & 128) === 0) {
          i++;
        } else if ((buf[i] & 224) === 192) {
          if (i + 1 === len || (buf[i + 1] & 192) !== 128 || (buf[i] & 254) === 192) {
            return false;
          }
          i += 2;
        } else if ((buf[i] & 240) === 224) {
          if (i + 2 >= len || (buf[i + 1] & 192) !== 128 || (buf[i + 2] & 192) !== 128 || buf[i] === 224 && (buf[i + 1] & 224) === 128 || // Overlong
          buf[i] === 237 && (buf[i + 1] & 224) === 160) {
            return false;
          }
          i += 3;
        } else if ((buf[i] & 248) === 240) {
          if (i + 3 >= len || (buf[i + 1] & 192) !== 128 || (buf[i + 2] & 192) !== 128 || (buf[i + 3] & 192) !== 128 || buf[i] === 240 && (buf[i + 1] & 240) === 128 || // Overlong
          buf[i] === 244 && buf[i + 1] > 143 || buf[i] > 244) {
            return false;
          }
          i += 4;
        } else {
          return false;
        }
      }
      return true;
    }
    function isBlob(value) {
      return hasBlob && typeof value === "object" && typeof value.arrayBuffer === "function" && typeof value.type === "string" && typeof value.stream === "function" && (value[Symbol.toStringTag] === "Blob" || value[Symbol.toStringTag] === "File");
    }
    module.exports = {
      isBlob,
      isValidStatusCode,
      isValidUTF8: _isValidUTF8,
      tokenChars
    };
    if (isUtf8) {
      module.exports.isValidUTF8 = function(buf) {
        return buf.length < 24 ? _isValidUTF8(buf) : isUtf8(buf);
      };
    } else if (!process.env.WS_NO_UTF_8_VALIDATE) {
      try {
        const isValidUTF8 = __require("utf-8-validate");
        module.exports.isValidUTF8 = function(buf) {
          return buf.length < 32 ? _isValidUTF8(buf) : isValidUTF8(buf);
        };
      } catch (e) {
      }
    }
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/receiver.js
var require_receiver = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/receiver.js"(exports, module) {
    "use strict";
    var { Writable } = __require("stream");
    var PerMessageDeflate2 = require_permessage_deflate();
    var {
      BINARY_TYPES,
      EMPTY_BUFFER,
      kStatusCode,
      kWebSocket
    } = require_constants();
    var { concat, toArrayBuffer, unmask } = require_buffer_util();
    var { isValidStatusCode, isValidUTF8 } = require_validation2();
    var FastBuffer = Buffer[Symbol.species];
    var GET_INFO = 0;
    var GET_PAYLOAD_LENGTH_16 = 1;
    var GET_PAYLOAD_LENGTH_64 = 2;
    var GET_MASK = 3;
    var GET_DATA = 4;
    var INFLATING = 5;
    var DEFER_EVENT = 6;
    var Receiver2 = class extends Writable {
      /**
       * Creates a Receiver instance.
       *
       * @param {Object} [options] Options object
       * @param {Boolean} [options.allowSynchronousEvents=true] Specifies whether
       *     any of the `'message'`, `'ping'`, and `'pong'` events can be emitted
       *     multiple times in the same tick
       * @param {String} [options.binaryType=nodebuffer] The type for binary data
       * @param {Object} [options.extensions] An object containing the negotiated
       *     extensions
       * @param {Boolean} [options.isServer=false] Specifies whether to operate in
       *     client or server mode
       * @param {Number} [options.maxBufferedChunks=0] The maximum number of
       *     buffered data chunks
       * @param {Number} [options.maxFragments=0] The maximum number of message
       *     fragments
       * @param {Number} [options.maxPayload=0] The maximum allowed message length
       * @param {Boolean} [options.skipUTF8Validation=false] Specifies whether or
       *     not to skip UTF-8 validation for text and close messages
       */
      constructor(options = {}) {
        super();
        this._allowSynchronousEvents = options.allowSynchronousEvents !== void 0 ? options.allowSynchronousEvents : true;
        this._binaryType = options.binaryType || BINARY_TYPES[0];
        this._extensions = options.extensions || {};
        this._isServer = !!options.isServer;
        this._maxBufferedChunks = options.maxBufferedChunks | 0;
        this._maxFragments = options.maxFragments | 0;
        this._maxPayload = options.maxPayload | 0;
        this._skipUTF8Validation = !!options.skipUTF8Validation;
        this[kWebSocket] = void 0;
        this._bufferedBytes = 0;
        this._buffers = [];
        this._compressed = false;
        this._payloadLength = 0;
        this._mask = void 0;
        this._fragmented = 0;
        this._masked = false;
        this._fin = false;
        this._opcode = 0;
        this._totalPayloadLength = 0;
        this._messageLength = 0;
        this._numFragments = 0;
        this._fragments = [];
        this._errored = false;
        this._loop = false;
        this._state = GET_INFO;
      }
      /**
       * Implements `Writable.prototype._write()`.
       *
       * @param {Buffer} chunk The chunk of data to write
       * @param {String} encoding The character encoding of `chunk`
       * @param {Function} cb Callback
       * @private
       */
      _write(chunk, encoding, cb) {
        if (this._opcode === 8 && this._state == GET_INFO) return cb();
        if (this._maxBufferedChunks > 0 && this._buffers.length >= this._maxBufferedChunks) {
          cb(
            this.createError(
              RangeError,
              "Too many buffered chunks",
              false,
              1008,
              "WS_ERR_TOO_MANY_BUFFERED_PARTS"
            )
          );
          return;
        }
        this._bufferedBytes += chunk.length;
        this._buffers.push(chunk);
        this.startLoop(cb);
      }
      /**
       * Consumes `n` bytes from the buffered data.
       *
       * @param {Number} n The number of bytes to consume
       * @return {Buffer} The consumed bytes
       * @private
       */
      consume(n) {
        this._bufferedBytes -= n;
        if (n === this._buffers[0].length) return this._buffers.shift();
        if (n < this._buffers[0].length) {
          const buf = this._buffers[0];
          this._buffers[0] = new FastBuffer(
            buf.buffer,
            buf.byteOffset + n,
            buf.length - n
          );
          return new FastBuffer(buf.buffer, buf.byteOffset, n);
        }
        const dst = Buffer.allocUnsafe(n);
        do {
          const buf = this._buffers[0];
          const offset = dst.length - n;
          if (n >= buf.length) {
            dst.set(this._buffers.shift(), offset);
          } else {
            dst.set(new Uint8Array(buf.buffer, buf.byteOffset, n), offset);
            this._buffers[0] = new FastBuffer(
              buf.buffer,
              buf.byteOffset + n,
              buf.length - n
            );
          }
          n -= buf.length;
        } while (n > 0);
        return dst;
      }
      /**
       * Starts the parsing loop.
       *
       * @param {Function} cb Callback
       * @private
       */
      startLoop(cb) {
        this._loop = true;
        do {
          switch (this._state) {
            case GET_INFO:
              this.getInfo(cb);
              break;
            case GET_PAYLOAD_LENGTH_16:
              this.getPayloadLength16(cb);
              break;
            case GET_PAYLOAD_LENGTH_64:
              this.getPayloadLength64(cb);
              break;
            case GET_MASK:
              this.getMask();
              break;
            case GET_DATA:
              this.getData(cb);
              break;
            case INFLATING:
            case DEFER_EVENT:
              this._loop = false;
              return;
          }
        } while (this._loop);
        if (!this._errored) cb();
      }
      /**
       * Reads the first two bytes of a frame.
       *
       * @param {Function} cb Callback
       * @private
       */
      getInfo(cb) {
        if (this._bufferedBytes < 2) {
          this._loop = false;
          return;
        }
        const buf = this.consume(2);
        if ((buf[0] & 48) !== 0) {
          const error = this.createError(
            RangeError,
            "RSV2 and RSV3 must be clear",
            true,
            1002,
            "WS_ERR_UNEXPECTED_RSV_2_3"
          );
          cb(error);
          return;
        }
        const compressed = (buf[0] & 64) === 64;
        if (compressed && !this._extensions[PerMessageDeflate2.extensionName]) {
          const error = this.createError(
            RangeError,
            "RSV1 must be clear",
            true,
            1002,
            "WS_ERR_UNEXPECTED_RSV_1"
          );
          cb(error);
          return;
        }
        this._fin = (buf[0] & 128) === 128;
        this._opcode = buf[0] & 15;
        this._payloadLength = buf[1] & 127;
        if (this._opcode === 0) {
          if (compressed) {
            const error = this.createError(
              RangeError,
              "RSV1 must be clear",
              true,
              1002,
              "WS_ERR_UNEXPECTED_RSV_1"
            );
            cb(error);
            return;
          }
          if (!this._fragmented) {
            const error = this.createError(
              RangeError,
              "invalid opcode 0",
              true,
              1002,
              "WS_ERR_INVALID_OPCODE"
            );
            cb(error);
            return;
          }
          this._opcode = this._fragmented;
        } else if (this._opcode === 1 || this._opcode === 2) {
          if (this._fragmented) {
            const error = this.createError(
              RangeError,
              `invalid opcode ${this._opcode}`,
              true,
              1002,
              "WS_ERR_INVALID_OPCODE"
            );
            cb(error);
            return;
          }
          this._compressed = compressed;
        } else if (this._opcode > 7 && this._opcode < 11) {
          if (!this._fin) {
            const error = this.createError(
              RangeError,
              "FIN must be set",
              true,
              1002,
              "WS_ERR_EXPECTED_FIN"
            );
            cb(error);
            return;
          }
          if (compressed) {
            const error = this.createError(
              RangeError,
              "RSV1 must be clear",
              true,
              1002,
              "WS_ERR_UNEXPECTED_RSV_1"
            );
            cb(error);
            return;
          }
          if (this._payloadLength > 125 || this._opcode === 8 && this._payloadLength === 1) {
            const error = this.createError(
              RangeError,
              `invalid payload length ${this._payloadLength}`,
              true,
              1002,
              "WS_ERR_INVALID_CONTROL_PAYLOAD_LENGTH"
            );
            cb(error);
            return;
          }
        } else {
          const error = this.createError(
            RangeError,
            `invalid opcode ${this._opcode}`,
            true,
            1002,
            "WS_ERR_INVALID_OPCODE"
          );
          cb(error);
          return;
        }
        if (!this._fin && !this._fragmented) this._fragmented = this._opcode;
        this._masked = (buf[1] & 128) === 128;
        if (this._isServer) {
          if (!this._masked) {
            const error = this.createError(
              RangeError,
              "MASK must be set",
              true,
              1002,
              "WS_ERR_EXPECTED_MASK"
            );
            cb(error);
            return;
          }
        } else if (this._masked) {
          const error = this.createError(
            RangeError,
            "MASK must be clear",
            true,
            1002,
            "WS_ERR_UNEXPECTED_MASK"
          );
          cb(error);
          return;
        }
        if (this._payloadLength === 126) this._state = GET_PAYLOAD_LENGTH_16;
        else if (this._payloadLength === 127) this._state = GET_PAYLOAD_LENGTH_64;
        else this.haveLength(cb);
      }
      /**
       * Gets extended payload length (7+16).
       *
       * @param {Function} cb Callback
       * @private
       */
      getPayloadLength16(cb) {
        if (this._bufferedBytes < 2) {
          this._loop = false;
          return;
        }
        this._payloadLength = this.consume(2).readUInt16BE(0);
        this.haveLength(cb);
      }
      /**
       * Gets extended payload length (7+64).
       *
       * @param {Function} cb Callback
       * @private
       */
      getPayloadLength64(cb) {
        if (this._bufferedBytes < 8) {
          this._loop = false;
          return;
        }
        const buf = this.consume(8);
        const num = buf.readUInt32BE(0);
        if (num > Math.pow(2, 53 - 32) - 1) {
          const error = this.createError(
            RangeError,
            "Unsupported WebSocket frame: payload length > 2^53 - 1",
            false,
            1009,
            "WS_ERR_UNSUPPORTED_DATA_PAYLOAD_LENGTH"
          );
          cb(error);
          return;
        }
        this._payloadLength = num * Math.pow(2, 32) + buf.readUInt32BE(4);
        this.haveLength(cb);
      }
      /**
       * Payload length has been read.
       *
       * @param {Function} cb Callback
       * @private
       */
      haveLength(cb) {
        if (this._payloadLength && this._opcode < 8) {
          this._totalPayloadLength += this._payloadLength;
          if (this._totalPayloadLength > this._maxPayload && this._maxPayload > 0) {
            const error = this.createError(
              RangeError,
              "Max payload size exceeded",
              false,
              1009,
              "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH"
            );
            cb(error);
            return;
          }
        }
        if (this._masked) this._state = GET_MASK;
        else this._state = GET_DATA;
      }
      /**
       * Reads mask bytes.
       *
       * @private
       */
      getMask() {
        if (this._bufferedBytes < 4) {
          this._loop = false;
          return;
        }
        this._mask = this.consume(4);
        this._state = GET_DATA;
      }
      /**
       * Reads data bytes.
       *
       * @param {Function} cb Callback
       * @private
       */
      getData(cb) {
        let data = EMPTY_BUFFER;
        if (this._payloadLength) {
          if (this._bufferedBytes < this._payloadLength) {
            this._loop = false;
            return;
          }
          data = this.consume(this._payloadLength);
          if (this._masked && (this._mask[0] | this._mask[1] | this._mask[2] | this._mask[3]) !== 0) {
            unmask(data, this._mask);
          }
        }
        if (this._opcode > 7) {
          this.controlMessage(data, cb);
          return;
        }
        if (this._maxFragments > 0 && ++this._numFragments > this._maxFragments) {
          const error = this.createError(
            RangeError,
            "Too many message fragments",
            false,
            1008,
            "WS_ERR_TOO_MANY_BUFFERED_PARTS"
          );
          cb(error);
          return;
        }
        if (this._compressed) {
          this._state = INFLATING;
          this.decompress(data, cb);
          return;
        }
        if (data.length) {
          this._messageLength = this._totalPayloadLength;
          this._fragments.push(data);
        }
        this.dataMessage(cb);
      }
      /**
       * Decompresses data.
       *
       * @param {Buffer} data Compressed data
       * @param {Function} cb Callback
       * @private
       */
      decompress(data, cb) {
        const perMessageDeflate = this._extensions[PerMessageDeflate2.extensionName];
        perMessageDeflate.decompress(data, this._fin, (err, buf) => {
          if (err) return cb(err);
          if (buf.length) {
            this._messageLength += buf.length;
            if (this._messageLength > this._maxPayload && this._maxPayload > 0) {
              const error = this.createError(
                RangeError,
                "Max payload size exceeded",
                false,
                1009,
                "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH"
              );
              cb(error);
              return;
            }
            this._fragments.push(buf);
          }
          this.dataMessage(cb);
          if (this._state === GET_INFO) this.startLoop(cb);
        });
      }
      /**
       * Handles a data message.
       *
       * @param {Function} cb Callback
       * @private
       */
      dataMessage(cb) {
        if (!this._fin) {
          this._state = GET_INFO;
          return;
        }
        const messageLength = this._messageLength;
        const fragments = this._fragments;
        this._totalPayloadLength = 0;
        this._messageLength = 0;
        this._fragmented = 0;
        this._numFragments = 0;
        this._fragments = [];
        if (this._opcode === 2) {
          let data;
          if (this._binaryType === "nodebuffer") {
            data = concat(fragments, messageLength);
          } else if (this._binaryType === "arraybuffer") {
            data = toArrayBuffer(concat(fragments, messageLength));
          } else if (this._binaryType === "blob") {
            data = new Blob(fragments);
          } else {
            data = fragments;
          }
          if (this._allowSynchronousEvents) {
            this.emit("message", data, true);
            this._state = GET_INFO;
          } else {
            this._state = DEFER_EVENT;
            setImmediate(() => {
              this.emit("message", data, true);
              this._state = GET_INFO;
              this.startLoop(cb);
            });
          }
        } else {
          const buf = concat(fragments, messageLength);
          if (!this._skipUTF8Validation && !isValidUTF8(buf)) {
            const error = this.createError(
              Error,
              "invalid UTF-8 sequence",
              true,
              1007,
              "WS_ERR_INVALID_UTF8"
            );
            cb(error);
            return;
          }
          if (this._state === INFLATING || this._allowSynchronousEvents) {
            this.emit("message", buf, false);
            this._state = GET_INFO;
          } else {
            this._state = DEFER_EVENT;
            setImmediate(() => {
              this.emit("message", buf, false);
              this._state = GET_INFO;
              this.startLoop(cb);
            });
          }
        }
      }
      /**
       * Handles a control message.
       *
       * @param {Buffer} data Data to handle
       * @return {(Error|RangeError|undefined)} A possible error
       * @private
       */
      controlMessage(data, cb) {
        if (this._opcode === 8) {
          if (data.length === 0) {
            this._loop = false;
            this.emit("conclude", 1005, EMPTY_BUFFER);
            this.end();
          } else {
            const code = data.readUInt16BE(0);
            if (!isValidStatusCode(code)) {
              const error = this.createError(
                RangeError,
                `invalid status code ${code}`,
                true,
                1002,
                "WS_ERR_INVALID_CLOSE_CODE"
              );
              cb(error);
              return;
            }
            const buf = new FastBuffer(
              data.buffer,
              data.byteOffset + 2,
              data.length - 2
            );
            if (!this._skipUTF8Validation && !isValidUTF8(buf)) {
              const error = this.createError(
                Error,
                "invalid UTF-8 sequence",
                true,
                1007,
                "WS_ERR_INVALID_UTF8"
              );
              cb(error);
              return;
            }
            this._loop = false;
            this.emit("conclude", code, buf);
            this.end();
          }
          this._state = GET_INFO;
          return;
        }
        if (this._allowSynchronousEvents) {
          this.emit(this._opcode === 9 ? "ping" : "pong", data);
          this._state = GET_INFO;
        } else {
          this._state = DEFER_EVENT;
          setImmediate(() => {
            this.emit(this._opcode === 9 ? "ping" : "pong", data);
            this._state = GET_INFO;
            this.startLoop(cb);
          });
        }
      }
      /**
       * Builds an error object.
       *
       * @param {function(new:Error|RangeError)} ErrorCtor The error constructor
       * @param {String} message The error message
       * @param {Boolean} prefix Specifies whether or not to add a default prefix to
       *     `message`
       * @param {Number} statusCode The status code
       * @param {String} errorCode The exposed error code
       * @return {(Error|RangeError)} The error
       * @private
       */
      createError(ErrorCtor, message, prefix, statusCode, errorCode) {
        this._loop = false;
        this._errored = true;
        const err = new ErrorCtor(
          prefix ? `Invalid WebSocket frame: ${message}` : message
        );
        Error.captureStackTrace(err, this.createError);
        err.code = errorCode;
        err[kStatusCode] = statusCode;
        return err;
      }
    };
    module.exports = Receiver2;
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/sender.js
var require_sender = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/sender.js"(exports, module) {
    "use strict";
    var { Duplex } = __require("stream");
    var { randomFillSync } = __require("crypto");
    var {
      types: { isUint8Array }
    } = __require("util");
    var PerMessageDeflate2 = require_permessage_deflate();
    var { EMPTY_BUFFER, kWebSocket, NOOP } = require_constants();
    var { isBlob, isValidStatusCode } = require_validation2();
    var { mask: applyMask, toBuffer } = require_buffer_util();
    var kByteLength = /* @__PURE__ */ Symbol("kByteLength");
    var maskBuffer = Buffer.alloc(4);
    var RANDOM_POOL_SIZE = 8 * 1024;
    var randomPool;
    var randomPoolPointer = RANDOM_POOL_SIZE;
    var DEFAULT = 0;
    var DEFLATING = 1;
    var GET_BLOB_DATA = 2;
    var Sender2 = class _Sender {
      /**
       * Creates a Sender instance.
       *
       * @param {Duplex} socket The connection socket
       * @param {Object} [extensions] An object containing the negotiated extensions
       * @param {Function} [generateMask] The function used to generate the masking
       *     key
       */
      constructor(socket, extensions, generateMask) {
        this._extensions = extensions || {};
        if (generateMask) {
          this._generateMask = generateMask;
          this._maskBuffer = Buffer.alloc(4);
        }
        this._socket = socket;
        this._firstFragment = true;
        this._compress = false;
        this._bufferedBytes = 0;
        this._queue = [];
        this._state = DEFAULT;
        this.onerror = NOOP;
        this[kWebSocket] = void 0;
      }
      /**
       * Frames a piece of data according to the HyBi WebSocket protocol.
       *
       * @param {(Buffer|String)} data The data to frame
       * @param {Object} options Options object
       * @param {Boolean} [options.fin=false] Specifies whether or not to set the
       *     FIN bit
       * @param {Function} [options.generateMask] The function used to generate the
       *     masking key
       * @param {Boolean} [options.mask=false] Specifies whether or not to mask
       *     `data`
       * @param {Buffer} [options.maskBuffer] The buffer used to store the masking
       *     key
       * @param {Number} options.opcode The opcode
       * @param {Boolean} [options.readOnly=false] Specifies whether `data` can be
       *     modified
       * @param {Boolean} [options.rsv1=false] Specifies whether or not to set the
       *     RSV1 bit
       * @return {(Buffer|String)[]} The framed data
       * @public
       */
      static frame(data, options) {
        let mask;
        let merge = false;
        let offset = 2;
        let skipMasking = false;
        if (options.mask) {
          mask = options.maskBuffer || maskBuffer;
          if (options.generateMask) {
            options.generateMask(mask);
          } else {
            if (randomPoolPointer === RANDOM_POOL_SIZE) {
              if (randomPool === void 0) {
                randomPool = Buffer.alloc(RANDOM_POOL_SIZE);
              }
              randomFillSync(randomPool, 0, RANDOM_POOL_SIZE);
              randomPoolPointer = 0;
            }
            mask[0] = randomPool[randomPoolPointer++];
            mask[1] = randomPool[randomPoolPointer++];
            mask[2] = randomPool[randomPoolPointer++];
            mask[3] = randomPool[randomPoolPointer++];
          }
          skipMasking = (mask[0] | mask[1] | mask[2] | mask[3]) === 0;
          offset = 6;
        }
        let dataLength;
        if (typeof data === "string") {
          if ((!options.mask || skipMasking) && options[kByteLength] !== void 0) {
            dataLength = options[kByteLength];
          } else {
            data = Buffer.from(data);
            dataLength = data.length;
          }
        } else {
          dataLength = data.length;
          merge = options.mask && options.readOnly && !skipMasking;
        }
        let payloadLength = dataLength;
        if (dataLength >= 65536) {
          offset += 8;
          payloadLength = 127;
        } else if (dataLength > 125) {
          offset += 2;
          payloadLength = 126;
        }
        const target = Buffer.allocUnsafe(merge ? dataLength + offset : offset);
        target[0] = options.fin ? options.opcode | 128 : options.opcode;
        if (options.rsv1) target[0] |= 64;
        target[1] = payloadLength;
        if (payloadLength === 126) {
          target.writeUInt16BE(dataLength, 2);
        } else if (payloadLength === 127) {
          target[2] = target[3] = 0;
          target.writeUIntBE(dataLength, 4, 6);
        }
        if (!options.mask) return [target, data];
        target[1] |= 128;
        target[offset - 4] = mask[0];
        target[offset - 3] = mask[1];
        target[offset - 2] = mask[2];
        target[offset - 1] = mask[3];
        if (skipMasking) return [target, data];
        if (merge) {
          applyMask(data, mask, target, offset, dataLength);
          return [target];
        }
        applyMask(data, mask, data, 0, dataLength);
        return [target, data];
      }
      /**
       * Sends a close message to the other peer.
       *
       * @param {Number} [code] The status code component of the body
       * @param {(String|Buffer)} [data] The message component of the body
       * @param {Boolean} [mask=false] Specifies whether or not to mask the message
       * @param {Function} [cb] Callback
       * @public
       */
      close(code, data, mask, cb) {
        let buf;
        if (code === void 0) {
          buf = EMPTY_BUFFER;
        } else if (typeof code !== "number" || !isValidStatusCode(code)) {
          throw new TypeError("First argument must be a valid error code number");
        } else if (data === void 0 || !data.length) {
          buf = Buffer.allocUnsafe(2);
          buf.writeUInt16BE(code, 0);
        } else {
          const length = Buffer.byteLength(data);
          if (length > 123) {
            throw new RangeError("The message must not be greater than 123 bytes");
          }
          buf = Buffer.allocUnsafe(2 + length);
          buf.writeUInt16BE(code, 0);
          if (typeof data === "string") {
            buf.write(data, 2);
          } else if (isUint8Array(data)) {
            buf.set(data, 2);
          } else {
            throw new TypeError("Second argument must be a string or a Uint8Array");
          }
        }
        const options = {
          [kByteLength]: buf.length,
          fin: true,
          generateMask: this._generateMask,
          mask,
          maskBuffer: this._maskBuffer,
          opcode: 8,
          readOnly: false,
          rsv1: false
        };
        if (this._state !== DEFAULT) {
          this.enqueue([this.dispatch, buf, false, options, cb]);
        } else {
          this.sendFrame(_Sender.frame(buf, options), cb);
        }
      }
      /**
       * Sends a ping message to the other peer.
       *
       * @param {*} data The message to send
       * @param {Boolean} [mask=false] Specifies whether or not to mask `data`
       * @param {Function} [cb] Callback
       * @public
       */
      ping(data, mask, cb) {
        let byteLength;
        let readOnly;
        if (typeof data === "string") {
          byteLength = Buffer.byteLength(data);
          readOnly = false;
        } else if (isBlob(data)) {
          byteLength = data.size;
          readOnly = false;
        } else {
          data = toBuffer(data);
          byteLength = data.length;
          readOnly = toBuffer.readOnly;
        }
        if (byteLength > 125) {
          throw new RangeError("The data size must not be greater than 125 bytes");
        }
        const options = {
          [kByteLength]: byteLength,
          fin: true,
          generateMask: this._generateMask,
          mask,
          maskBuffer: this._maskBuffer,
          opcode: 9,
          readOnly,
          rsv1: false
        };
        if (isBlob(data)) {
          if (this._state !== DEFAULT) {
            this.enqueue([this.getBlobData, data, false, options, cb]);
          } else {
            this.getBlobData(data, false, options, cb);
          }
        } else if (this._state !== DEFAULT) {
          this.enqueue([this.dispatch, data, false, options, cb]);
        } else {
          this.sendFrame(_Sender.frame(data, options), cb);
        }
      }
      /**
       * Sends a pong message to the other peer.
       *
       * @param {*} data The message to send
       * @param {Boolean} [mask=false] Specifies whether or not to mask `data`
       * @param {Function} [cb] Callback
       * @public
       */
      pong(data, mask, cb) {
        let byteLength;
        let readOnly;
        if (typeof data === "string") {
          byteLength = Buffer.byteLength(data);
          readOnly = false;
        } else if (isBlob(data)) {
          byteLength = data.size;
          readOnly = false;
        } else {
          data = toBuffer(data);
          byteLength = data.length;
          readOnly = toBuffer.readOnly;
        }
        if (byteLength > 125) {
          throw new RangeError("The data size must not be greater than 125 bytes");
        }
        const options = {
          [kByteLength]: byteLength,
          fin: true,
          generateMask: this._generateMask,
          mask,
          maskBuffer: this._maskBuffer,
          opcode: 10,
          readOnly,
          rsv1: false
        };
        if (isBlob(data)) {
          if (this._state !== DEFAULT) {
            this.enqueue([this.getBlobData, data, false, options, cb]);
          } else {
            this.getBlobData(data, false, options, cb);
          }
        } else if (this._state !== DEFAULT) {
          this.enqueue([this.dispatch, data, false, options, cb]);
        } else {
          this.sendFrame(_Sender.frame(data, options), cb);
        }
      }
      /**
       * Sends a data message to the other peer.
       *
       * @param {*} data The message to send
       * @param {Object} options Options object
       * @param {Boolean} [options.binary=false] Specifies whether `data` is binary
       *     or text
       * @param {Boolean} [options.compress=false] Specifies whether or not to
       *     compress `data`
       * @param {Boolean} [options.fin=false] Specifies whether the fragment is the
       *     last one
       * @param {Boolean} [options.mask=false] Specifies whether or not to mask
       *     `data`
       * @param {Function} [cb] Callback
       * @public
       */
      send(data, options, cb) {
        const perMessageDeflate = this._extensions[PerMessageDeflate2.extensionName];
        let opcode = options.binary ? 2 : 1;
        let rsv1 = options.compress;
        let byteLength;
        let readOnly;
        if (typeof data === "string") {
          byteLength = Buffer.byteLength(data);
          readOnly = false;
        } else if (isBlob(data)) {
          byteLength = data.size;
          readOnly = false;
        } else {
          data = toBuffer(data);
          byteLength = data.length;
          readOnly = toBuffer.readOnly;
        }
        if (this._firstFragment) {
          this._firstFragment = false;
          if (rsv1 && perMessageDeflate && perMessageDeflate.params[perMessageDeflate._isServer ? "server_no_context_takeover" : "client_no_context_takeover"]) {
            rsv1 = byteLength >= perMessageDeflate._threshold;
          }
          this._compress = rsv1;
        } else {
          rsv1 = false;
          opcode = 0;
        }
        if (options.fin) this._firstFragment = true;
        const opts = {
          [kByteLength]: byteLength,
          fin: options.fin,
          generateMask: this._generateMask,
          mask: options.mask,
          maskBuffer: this._maskBuffer,
          opcode,
          readOnly,
          rsv1
        };
        if (isBlob(data)) {
          if (this._state !== DEFAULT) {
            this.enqueue([this.getBlobData, data, this._compress, opts, cb]);
          } else {
            this.getBlobData(data, this._compress, opts, cb);
          }
        } else if (this._state !== DEFAULT) {
          this.enqueue([this.dispatch, data, this._compress, opts, cb]);
        } else {
          this.dispatch(data, this._compress, opts, cb);
        }
      }
      /**
       * Gets the contents of a blob as binary data.
       *
       * @param {Blob} blob The blob
       * @param {Boolean} [compress=false] Specifies whether or not to compress
       *     the data
       * @param {Object} options Options object
       * @param {Boolean} [options.fin=false] Specifies whether or not to set the
       *     FIN bit
       * @param {Function} [options.generateMask] The function used to generate the
       *     masking key
       * @param {Boolean} [options.mask=false] Specifies whether or not to mask
       *     `data`
       * @param {Buffer} [options.maskBuffer] The buffer used to store the masking
       *     key
       * @param {Number} options.opcode The opcode
       * @param {Boolean} [options.readOnly=false] Specifies whether `data` can be
       *     modified
       * @param {Boolean} [options.rsv1=false] Specifies whether or not to set the
       *     RSV1 bit
       * @param {Function} [cb] Callback
       * @private
       */
      getBlobData(blob, compress, options, cb) {
        this._bufferedBytes += options[kByteLength];
        this._state = GET_BLOB_DATA;
        blob.arrayBuffer().then((arrayBuffer) => {
          if (this._socket.destroyed) {
            const err = new Error(
              "The socket was closed while the blob was being read"
            );
            process.nextTick(callCallbacks, this, err, cb);
            return;
          }
          this._bufferedBytes -= options[kByteLength];
          const data = toBuffer(arrayBuffer);
          if (!compress) {
            this._state = DEFAULT;
            this.sendFrame(_Sender.frame(data, options), cb);
            this.dequeue();
          } else {
            this.dispatch(data, compress, options, cb);
          }
        }).catch((err) => {
          process.nextTick(onError, this, err, cb);
        });
      }
      /**
       * Dispatches a message.
       *
       * @param {(Buffer|String)} data The message to send
       * @param {Boolean} [compress=false] Specifies whether or not to compress
       *     `data`
       * @param {Object} options Options object
       * @param {Boolean} [options.fin=false] Specifies whether or not to set the
       *     FIN bit
       * @param {Function} [options.generateMask] The function used to generate the
       *     masking key
       * @param {Boolean} [options.mask=false] Specifies whether or not to mask
       *     `data`
       * @param {Buffer} [options.maskBuffer] The buffer used to store the masking
       *     key
       * @param {Number} options.opcode The opcode
       * @param {Boolean} [options.readOnly=false] Specifies whether `data` can be
       *     modified
       * @param {Boolean} [options.rsv1=false] Specifies whether or not to set the
       *     RSV1 bit
       * @param {Function} [cb] Callback
       * @private
       */
      dispatch(data, compress, options, cb) {
        if (!compress) {
          this.sendFrame(_Sender.frame(data, options), cb);
          return;
        }
        const perMessageDeflate = this._extensions[PerMessageDeflate2.extensionName];
        this._bufferedBytes += options[kByteLength];
        this._state = DEFLATING;
        perMessageDeflate.compress(data, options.fin, (_, buf) => {
          if (this._socket.destroyed) {
            const err = new Error(
              "The socket was closed while data was being compressed"
            );
            callCallbacks(this, err, cb);
            return;
          }
          this._bufferedBytes -= options[kByteLength];
          this._state = DEFAULT;
          options.readOnly = false;
          this.sendFrame(_Sender.frame(buf, options), cb);
          this.dequeue();
        });
      }
      /**
       * Executes queued send operations.
       *
       * @private
       */
      dequeue() {
        while (this._state === DEFAULT && this._queue.length) {
          const params = this._queue.shift();
          this._bufferedBytes -= params[3][kByteLength];
          Reflect.apply(params[0], this, params.slice(1));
        }
      }
      /**
       * Enqueues a send operation.
       *
       * @param {Array} params Send operation parameters.
       * @private
       */
      enqueue(params) {
        this._bufferedBytes += params[3][kByteLength];
        this._queue.push(params);
      }
      /**
       * Sends a frame.
       *
       * @param {(Buffer | String)[]} list The frame to send
       * @param {Function} [cb] Callback
       * @private
       */
      sendFrame(list, cb) {
        if (list.length === 2) {
          this._socket.cork();
          this._socket.write(list[0]);
          this._socket.write(list[1], cb);
          this._socket.uncork();
        } else {
          this._socket.write(list[0], cb);
        }
      }
    };
    module.exports = Sender2;
    function callCallbacks(sender, err, cb) {
      if (typeof cb === "function") cb(err);
      for (let i = 0; i < sender._queue.length; i++) {
        const params = sender._queue[i];
        const callback = params[params.length - 1];
        if (typeof callback === "function") callback(err);
      }
    }
    function onError(sender, err, cb) {
      callCallbacks(sender, err, cb);
      sender.onerror(err);
    }
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/event-target.js
var require_event_target = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/event-target.js"(exports, module) {
    "use strict";
    var { kForOnEventAttribute, kListener } = require_constants();
    var kCode = /* @__PURE__ */ Symbol("kCode");
    var kData = /* @__PURE__ */ Symbol("kData");
    var kError = /* @__PURE__ */ Symbol("kError");
    var kMessage = /* @__PURE__ */ Symbol("kMessage");
    var kReason = /* @__PURE__ */ Symbol("kReason");
    var kTarget = /* @__PURE__ */ Symbol("kTarget");
    var kType = /* @__PURE__ */ Symbol("kType");
    var kWasClean = /* @__PURE__ */ Symbol("kWasClean");
    var Event = class {
      /**
       * Create a new `Event`.
       *
       * @param {String} type The name of the event
       * @throws {TypeError} If the `type` argument is not specified
       */
      constructor(type) {
        this[kTarget] = null;
        this[kType] = type;
      }
      /**
       * @type {*}
       */
      get target() {
        return this[kTarget];
      }
      /**
       * @type {String}
       */
      get type() {
        return this[kType];
      }
    };
    Object.defineProperty(Event.prototype, "target", { enumerable: true });
    Object.defineProperty(Event.prototype, "type", { enumerable: true });
    var CloseEvent = class extends Event {
      /**
       * Create a new `CloseEvent`.
       *
       * @param {String} type The name of the event
       * @param {Object} [options] A dictionary object that allows for setting
       *     attributes via object members of the same name
       * @param {Number} [options.code=0] The status code explaining why the
       *     connection was closed
       * @param {String} [options.reason=''] A human-readable string explaining why
       *     the connection was closed
       * @param {Boolean} [options.wasClean=false] Indicates whether or not the
       *     connection was cleanly closed
       */
      constructor(type, options = {}) {
        super(type);
        this[kCode] = options.code === void 0 ? 0 : options.code;
        this[kReason] = options.reason === void 0 ? "" : options.reason;
        this[kWasClean] = options.wasClean === void 0 ? false : options.wasClean;
      }
      /**
       * @type {Number}
       */
      get code() {
        return this[kCode];
      }
      /**
       * @type {String}
       */
      get reason() {
        return this[kReason];
      }
      /**
       * @type {Boolean}
       */
      get wasClean() {
        return this[kWasClean];
      }
    };
    Object.defineProperty(CloseEvent.prototype, "code", { enumerable: true });
    Object.defineProperty(CloseEvent.prototype, "reason", { enumerable: true });
    Object.defineProperty(CloseEvent.prototype, "wasClean", { enumerable: true });
    var ErrorEvent = class extends Event {
      /**
       * Create a new `ErrorEvent`.
       *
       * @param {String} type The name of the event
       * @param {Object} [options] A dictionary object that allows for setting
       *     attributes via object members of the same name
       * @param {*} [options.error=null] The error that generated this event
       * @param {String} [options.message=''] The error message
       */
      constructor(type, options = {}) {
        super(type);
        this[kError] = options.error === void 0 ? null : options.error;
        this[kMessage] = options.message === void 0 ? "" : options.message;
      }
      /**
       * @type {*}
       */
      get error() {
        return this[kError];
      }
      /**
       * @type {String}
       */
      get message() {
        return this[kMessage];
      }
    };
    Object.defineProperty(ErrorEvent.prototype, "error", { enumerable: true });
    Object.defineProperty(ErrorEvent.prototype, "message", { enumerable: true });
    var MessageEvent = class extends Event {
      /**
       * Create a new `MessageEvent`.
       *
       * @param {String} type The name of the event
       * @param {Object} [options] A dictionary object that allows for setting
       *     attributes via object members of the same name
       * @param {*} [options.data=null] The message content
       */
      constructor(type, options = {}) {
        super(type);
        this[kData] = options.data === void 0 ? null : options.data;
      }
      /**
       * @type {*}
       */
      get data() {
        return this[kData];
      }
    };
    Object.defineProperty(MessageEvent.prototype, "data", { enumerable: true });
    var EventTarget = {
      /**
       * Register an event listener.
       *
       * @param {String} type A string representing the event type to listen for
       * @param {(Function|Object)} handler The listener to add
       * @param {Object} [options] An options object specifies characteristics about
       *     the event listener
       * @param {Boolean} [options.once=false] A `Boolean` indicating that the
       *     listener should be invoked at most once after being added. If `true`,
       *     the listener would be automatically removed when invoked.
       * @public
       */
      addEventListener(type, handler, options = {}) {
        for (const listener of this.listeners(type)) {
          if (!options[kForOnEventAttribute] && listener[kListener] === handler && !listener[kForOnEventAttribute]) {
            return;
          }
        }
        let wrapper;
        if (type === "message") {
          wrapper = function onMessage(data, isBinary) {
            const event = new MessageEvent("message", {
              data: isBinary ? data : data.toString()
            });
            event[kTarget] = this;
            callListener(handler, this, event);
          };
        } else if (type === "close") {
          wrapper = function onClose(code, message) {
            const event = new CloseEvent("close", {
              code,
              reason: message.toString(),
              wasClean: this._closeFrameReceived && this._closeFrameSent
            });
            event[kTarget] = this;
            callListener(handler, this, event);
          };
        } else if (type === "error") {
          wrapper = function onError(error) {
            const event = new ErrorEvent("error", {
              error,
              message: error.message
            });
            event[kTarget] = this;
            callListener(handler, this, event);
          };
        } else if (type === "open") {
          wrapper = function onOpen() {
            const event = new Event("open");
            event[kTarget] = this;
            callListener(handler, this, event);
          };
        } else {
          return;
        }
        wrapper[kForOnEventAttribute] = !!options[kForOnEventAttribute];
        wrapper[kListener] = handler;
        if (options.once) {
          this.once(type, wrapper);
        } else {
          this.on(type, wrapper);
        }
      },
      /**
       * Remove an event listener.
       *
       * @param {String} type A string representing the event type to remove
       * @param {(Function|Object)} handler The listener to remove
       * @public
       */
      removeEventListener(type, handler) {
        for (const listener of this.listeners(type)) {
          if (listener[kListener] === handler && !listener[kForOnEventAttribute]) {
            this.removeListener(type, listener);
            break;
          }
        }
      }
    };
    module.exports = {
      CloseEvent,
      ErrorEvent,
      Event,
      EventTarget,
      MessageEvent
    };
    function callListener(listener, thisArg, event) {
      if (typeof listener === "object" && listener.handleEvent) {
        listener.handleEvent.call(listener, event);
      } else {
        listener.call(thisArg, event);
      }
    }
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/extension.js
var require_extension = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/extension.js"(exports, module) {
    "use strict";
    var { tokenChars } = require_validation2();
    function push(dest, name, elem) {
      if (dest[name] === void 0) dest[name] = [elem];
      else dest[name].push(elem);
    }
    function parse(header) {
      const offers = /* @__PURE__ */ Object.create(null);
      let params = /* @__PURE__ */ Object.create(null);
      let mustUnescape = false;
      let isEscaping = false;
      let inQuotes = false;
      let extensionName;
      let paramName;
      let start = -1;
      let code = -1;
      let end = -1;
      let i = 0;
      for (; i < header.length; i++) {
        code = header.charCodeAt(i);
        if (extensionName === void 0) {
          if (end === -1 && tokenChars[code] === 1) {
            if (start === -1) start = i;
          } else if (i !== 0 && (code === 32 || code === 9)) {
            if (end === -1 && start !== -1) end = i;
          } else if (code === 59 || code === 44) {
            if (start === -1) {
              throw new SyntaxError(`Unexpected character at index ${i}`);
            }
            if (end === -1) end = i;
            const name = header.slice(start, end);
            if (code === 44) {
              push(offers, name, params);
              params = /* @__PURE__ */ Object.create(null);
            } else {
              extensionName = name;
            }
            start = end = -1;
          } else {
            throw new SyntaxError(`Unexpected character at index ${i}`);
          }
        } else if (paramName === void 0) {
          if (end === -1 && tokenChars[code] === 1) {
            if (start === -1) start = i;
          } else if (code === 32 || code === 9) {
            if (end === -1 && start !== -1) end = i;
          } else if (code === 59 || code === 44) {
            if (start === -1) {
              throw new SyntaxError(`Unexpected character at index ${i}`);
            }
            if (end === -1) end = i;
            push(params, header.slice(start, end), true);
            if (code === 44) {
              push(offers, extensionName, params);
              params = /* @__PURE__ */ Object.create(null);
              extensionName = void 0;
            }
            start = end = -1;
          } else if (code === 61 && start !== -1 && end === -1) {
            paramName = header.slice(start, i);
            start = end = -1;
          } else {
            throw new SyntaxError(`Unexpected character at index ${i}`);
          }
        } else {
          if (isEscaping) {
            if (tokenChars[code] !== 1) {
              throw new SyntaxError(`Unexpected character at index ${i}`);
            }
            if (start === -1) start = i;
            else if (!mustUnescape) mustUnescape = true;
            isEscaping = false;
          } else if (inQuotes) {
            if (tokenChars[code] === 1) {
              if (start === -1) start = i;
            } else if (code === 34 && start !== -1) {
              inQuotes = false;
              end = i;
            } else if (code === 92) {
              isEscaping = true;
            } else {
              throw new SyntaxError(`Unexpected character at index ${i}`);
            }
          } else if (code === 34 && header.charCodeAt(i - 1) === 61) {
            inQuotes = true;
          } else if (end === -1 && tokenChars[code] === 1) {
            if (start === -1) start = i;
          } else if (start !== -1 && (code === 32 || code === 9)) {
            if (end === -1) end = i;
          } else if (code === 59 || code === 44) {
            if (start === -1) {
              throw new SyntaxError(`Unexpected character at index ${i}`);
            }
            if (end === -1) end = i;
            let value = header.slice(start, end);
            if (mustUnescape) {
              value = value.replace(/\\/g, "");
              mustUnescape = false;
            }
            push(params, paramName, value);
            if (code === 44) {
              push(offers, extensionName, params);
              params = /* @__PURE__ */ Object.create(null);
              extensionName = void 0;
            }
            paramName = void 0;
            start = end = -1;
          } else {
            throw new SyntaxError(`Unexpected character at index ${i}`);
          }
        }
      }
      if (start === -1 || inQuotes || code === 32 || code === 9) {
        throw new SyntaxError("Unexpected end of input");
      }
      if (end === -1) end = i;
      const token = header.slice(start, end);
      if (extensionName === void 0) {
        push(offers, token, params);
      } else {
        if (paramName === void 0) {
          push(params, token, true);
        } else if (mustUnescape) {
          push(params, paramName, token.replace(/\\/g, ""));
        } else {
          push(params, paramName, token);
        }
        push(offers, extensionName, params);
      }
      return offers;
    }
    function format(extensions) {
      return Object.keys(extensions).map((extension2) => {
        let configurations = extensions[extension2];
        if (!Array.isArray(configurations)) configurations = [configurations];
        return configurations.map((params) => {
          return [extension2].concat(
            Object.keys(params).map((k) => {
              let values = params[k];
              if (!Array.isArray(values)) values = [values];
              return values.map((v) => v === true ? k : `${k}=${v}`).join("; ");
            })
          ).join("; ");
        }).join(", ");
      }).join(", ");
    }
    module.exports = { format, parse };
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/websocket.js
var require_websocket = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/websocket.js"(exports, module) {
    "use strict";
    var EventEmitter = __require("events");
    var https2 = __require("https");
    var http3 = __require("http");
    var net = __require("net");
    var tls = __require("tls");
    var { randomBytes, createHash: createHash2 } = __require("crypto");
    var { Duplex, Readable } = __require("stream");
    var { URL: URL2 } = __require("url");
    var PerMessageDeflate2 = require_permessage_deflate();
    var Receiver2 = require_receiver();
    var Sender2 = require_sender();
    var { isBlob } = require_validation2();
    var {
      BINARY_TYPES,
      CLOSE_TIMEOUT,
      EMPTY_BUFFER,
      GUID,
      kForOnEventAttribute,
      kListener,
      kStatusCode,
      kWebSocket,
      NOOP
    } = require_constants();
    var {
      EventTarget: { addEventListener, removeEventListener }
    } = require_event_target();
    var { format, parse } = require_extension();
    var { toBuffer } = require_buffer_util();
    var kAborted = /* @__PURE__ */ Symbol("kAborted");
    var protocolVersions = [8, 13];
    var readyStates = ["CONNECTING", "OPEN", "CLOSING", "CLOSED"];
    var subprotocolRegex = /^[!#$%&'*+\-.0-9A-Z^_`|a-z~]+$/;
    var WebSocket2 = class _WebSocket extends EventEmitter {
      /**
       * Create a new `WebSocket`.
       *
       * @param {(String|URL)} address The URL to which to connect
       * @param {(String|String[])} [protocols] The subprotocols
       * @param {Object} [options] Connection options
       */
      constructor(address, protocols, options) {
        super();
        this._binaryType = BINARY_TYPES[0];
        this._closeCode = 1006;
        this._closeFrameReceived = false;
        this._closeFrameSent = false;
        this._closeMessage = EMPTY_BUFFER;
        this._closeTimer = null;
        this._errorEmitted = false;
        this._extensions = {};
        this._paused = false;
        this._protocol = "";
        this._readyState = _WebSocket.CONNECTING;
        this._receiver = null;
        this._sender = null;
        this._socket = null;
        if (address !== null) {
          this._bufferedAmount = 0;
          this._isServer = false;
          this._redirects = 0;
          if (protocols === void 0) {
            if (!options || options.protocols === void 0) {
              protocols = [];
            } else if (Array.isArray(options.protocols)) {
              protocols = options.protocols;
            } else {
              protocols = [options.protocols];
            }
          } else if (!Array.isArray(protocols)) {
            if (typeof protocols === "object" && protocols !== null) {
              options = protocols;
              if (options.protocols === void 0) {
                protocols = [];
              } else if (Array.isArray(options.protocols)) {
                protocols = options.protocols;
              } else {
                protocols = [options.protocols];
              }
            } else {
              protocols = [protocols];
            }
          }
          initAsClient(this, address, protocols, options);
        } else {
          this._autoPong = options.autoPong;
          this._closeTimeout = options.closeTimeout;
          this._isServer = true;
        }
      }
      /**
       * For historical reasons, the custom "nodebuffer" type is used by the default
       * instead of "blob".
       *
       * @type {String}
       */
      get binaryType() {
        return this._binaryType;
      }
      set binaryType(type) {
        if (!BINARY_TYPES.includes(type)) return;
        this._binaryType = type;
        if (this._receiver) this._receiver._binaryType = type;
      }
      /**
       * @type {Number}
       */
      get bufferedAmount() {
        if (!this._socket) return this._bufferedAmount;
        return this._socket._writableState.length + this._sender._bufferedBytes;
      }
      /**
       * @type {String}
       */
      get extensions() {
        return Object.keys(this._extensions).join();
      }
      /**
       * @type {Boolean}
       */
      get isPaused() {
        return this._paused;
      }
      /**
       * @type {Function}
       */
      /* istanbul ignore next */
      get onclose() {
        return null;
      }
      /**
       * @type {Function}
       */
      /* istanbul ignore next */
      get onerror() {
        return null;
      }
      /**
       * @type {Function}
       */
      /* istanbul ignore next */
      get onopen() {
        return null;
      }
      /**
       * @type {Function}
       */
      /* istanbul ignore next */
      get onmessage() {
        return null;
      }
      /**
       * @type {String}
       */
      get protocol() {
        return this._protocol;
      }
      /**
       * @type {Number}
       */
      get readyState() {
        return this._readyState;
      }
      /**
       * @type {String}
       */
      get url() {
        return this._url;
      }
      /**
       * Set up the socket and the internal resources.
       *
       * @param {Duplex} socket The network socket between the server and client
       * @param {Buffer} head The first packet of the upgraded stream
       * @param {Object} options Options object
       * @param {Boolean} [options.allowSynchronousEvents=false] Specifies whether
       *     any of the `'message'`, `'ping'`, and `'pong'` events can be emitted
       *     multiple times in the same tick
       * @param {Function} [options.generateMask] The function used to generate the
       *     masking key
       * @param {Number} [options.maxBufferedChunks=0] The maximum number of
       *     buffered data chunks
       * @param {Number} [options.maxFragments=0] The maximum number of message
       *     fragments
       * @param {Number} [options.maxPayload=0] The maximum allowed message size
       * @param {Boolean} [options.skipUTF8Validation=false] Specifies whether or
       *     not to skip UTF-8 validation for text and close messages
       * @private
       */
      setSocket(socket, head, options) {
        const receiver = new Receiver2({
          allowSynchronousEvents: options.allowSynchronousEvents,
          binaryType: this.binaryType,
          extensions: this._extensions,
          isServer: this._isServer,
          maxBufferedChunks: options.maxBufferedChunks,
          maxFragments: options.maxFragments,
          maxPayload: options.maxPayload,
          skipUTF8Validation: options.skipUTF8Validation
        });
        const sender = new Sender2(socket, this._extensions, options.generateMask);
        this._receiver = receiver;
        this._sender = sender;
        this._socket = socket;
        receiver[kWebSocket] = this;
        sender[kWebSocket] = this;
        socket[kWebSocket] = this;
        receiver.on("conclude", receiverOnConclude);
        receiver.on("drain", receiverOnDrain);
        receiver.on("error", receiverOnError);
        receiver.on("message", receiverOnMessage);
        receiver.on("ping", receiverOnPing);
        receiver.on("pong", receiverOnPong);
        sender.onerror = senderOnError;
        if (socket.setTimeout) socket.setTimeout(0);
        if (socket.setNoDelay) socket.setNoDelay();
        if (head.length > 0) socket.unshift(head);
        socket.on("close", socketOnClose);
        socket.on("data", socketOnData);
        socket.on("end", socketOnEnd);
        socket.on("error", socketOnError);
        this._readyState = _WebSocket.OPEN;
        this.emit("open");
      }
      /**
       * Emit the `'close'` event.
       *
       * @private
       */
      emitClose() {
        if (!this._socket) {
          this._readyState = _WebSocket.CLOSED;
          this.emit("close", this._closeCode, this._closeMessage);
          return;
        }
        if (this._extensions[PerMessageDeflate2.extensionName]) {
          this._extensions[PerMessageDeflate2.extensionName].cleanup();
        }
        this._receiver.removeAllListeners();
        this._readyState = _WebSocket.CLOSED;
        this.emit("close", this._closeCode, this._closeMessage);
      }
      /**
       * Start a closing handshake.
       *
       *          +----------+   +-----------+   +----------+
       *     - - -|ws.close()|-->|close frame|-->|ws.close()|- - -
       *    |     +----------+   +-----------+   +----------+     |
       *          +----------+   +-----------+         |
       * CLOSING  |ws.close()|<--|close frame|<--+-----+       CLOSING
       *          +----------+   +-----------+   |
       *    |           |                        |   +---+        |
       *                +------------------------+-->|fin| - - - -
       *    |         +---+                      |   +---+
       *     - - - - -|fin|<---------------------+
       *              +---+
       *
       * @param {Number} [code] Status code explaining why the connection is closing
       * @param {(String|Buffer)} [data] The reason why the connection is
       *     closing
       * @public
       */
      close(code, data) {
        if (this.readyState === _WebSocket.CLOSED) return;
        if (this.readyState === _WebSocket.CONNECTING) {
          const msg = "WebSocket was closed before the connection was established";
          abortHandshake(this, this._req, msg);
          return;
        }
        if (this.readyState === _WebSocket.CLOSING) {
          if (this._closeFrameSent && (this._closeFrameReceived || this._receiver._writableState.errorEmitted)) {
            this._socket.end();
          }
          return;
        }
        this._sender.close(code, data, !this._isServer, (err) => {
          if (err) return;
          this._closeFrameSent = true;
          if (this._closeFrameReceived || this._receiver._writableState.errorEmitted) {
            this._socket.end();
          }
        });
        this._readyState = _WebSocket.CLOSING;
        setCloseTimer(this);
      }
      /**
       * Pause the socket.
       *
       * @public
       */
      pause() {
        if (this.readyState === _WebSocket.CONNECTING || this.readyState === _WebSocket.CLOSED) {
          return;
        }
        this._paused = true;
        this._socket.pause();
      }
      /**
       * Send a ping.
       *
       * @param {*} [data] The data to send
       * @param {Boolean} [mask] Indicates whether or not to mask `data`
       * @param {Function} [cb] Callback which is executed when the ping is sent
       * @public
       */
      ping(data, mask, cb) {
        if (this.readyState === _WebSocket.CONNECTING) {
          throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
        }
        if (typeof data === "function") {
          cb = data;
          data = mask = void 0;
        } else if (typeof mask === "function") {
          cb = mask;
          mask = void 0;
        }
        if (typeof data === "number") data = data.toString();
        if (this.readyState !== _WebSocket.OPEN) {
          sendAfterClose(this, data, cb);
          return;
        }
        if (mask === void 0) mask = !this._isServer;
        this._sender.ping(data || EMPTY_BUFFER, mask, cb);
      }
      /**
       * Send a pong.
       *
       * @param {*} [data] The data to send
       * @param {Boolean} [mask] Indicates whether or not to mask `data`
       * @param {Function} [cb] Callback which is executed when the pong is sent
       * @public
       */
      pong(data, mask, cb) {
        if (this.readyState === _WebSocket.CONNECTING) {
          throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
        }
        if (typeof data === "function") {
          cb = data;
          data = mask = void 0;
        } else if (typeof mask === "function") {
          cb = mask;
          mask = void 0;
        }
        if (typeof data === "number") data = data.toString();
        if (this.readyState !== _WebSocket.OPEN) {
          sendAfterClose(this, data, cb);
          return;
        }
        if (mask === void 0) mask = !this._isServer;
        this._sender.pong(data || EMPTY_BUFFER, mask, cb);
      }
      /**
       * Resume the socket.
       *
       * @public
       */
      resume() {
        if (this.readyState === _WebSocket.CONNECTING || this.readyState === _WebSocket.CLOSED) {
          return;
        }
        this._paused = false;
        if (!this._receiver._writableState.needDrain) this._socket.resume();
      }
      /**
       * Send a data message.
       *
       * @param {*} data The message to send
       * @param {Object} [options] Options object
       * @param {Boolean} [options.binary] Specifies whether `data` is binary or
       *     text
       * @param {Boolean} [options.compress] Specifies whether or not to compress
       *     `data`
       * @param {Boolean} [options.fin=true] Specifies whether the fragment is the
       *     last one
       * @param {Boolean} [options.mask] Specifies whether or not to mask `data`
       * @param {Function} [cb] Callback which is executed when data is written out
       * @public
       */
      send(data, options, cb) {
        if (this.readyState === _WebSocket.CONNECTING) {
          throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
        }
        if (typeof options === "function") {
          cb = options;
          options = {};
        }
        if (typeof data === "number") data = data.toString();
        if (this.readyState !== _WebSocket.OPEN) {
          sendAfterClose(this, data, cb);
          return;
        }
        const opts = {
          binary: typeof data !== "string",
          mask: !this._isServer,
          compress: true,
          fin: true,
          ...options
        };
        if (!this._extensions[PerMessageDeflate2.extensionName]) {
          opts.compress = false;
        }
        this._sender.send(data || EMPTY_BUFFER, opts, cb);
      }
      /**
       * Forcibly close the connection.
       *
       * @public
       */
      terminate() {
        if (this.readyState === _WebSocket.CLOSED) return;
        if (this.readyState === _WebSocket.CONNECTING) {
          const msg = "WebSocket was closed before the connection was established";
          abortHandshake(this, this._req, msg);
          return;
        }
        if (this._socket) {
          this._readyState = _WebSocket.CLOSING;
          this._socket.destroy();
        }
      }
    };
    Object.defineProperty(WebSocket2, "CONNECTING", {
      enumerable: true,
      value: readyStates.indexOf("CONNECTING")
    });
    Object.defineProperty(WebSocket2.prototype, "CONNECTING", {
      enumerable: true,
      value: readyStates.indexOf("CONNECTING")
    });
    Object.defineProperty(WebSocket2, "OPEN", {
      enumerable: true,
      value: readyStates.indexOf("OPEN")
    });
    Object.defineProperty(WebSocket2.prototype, "OPEN", {
      enumerable: true,
      value: readyStates.indexOf("OPEN")
    });
    Object.defineProperty(WebSocket2, "CLOSING", {
      enumerable: true,
      value: readyStates.indexOf("CLOSING")
    });
    Object.defineProperty(WebSocket2.prototype, "CLOSING", {
      enumerable: true,
      value: readyStates.indexOf("CLOSING")
    });
    Object.defineProperty(WebSocket2, "CLOSED", {
      enumerable: true,
      value: readyStates.indexOf("CLOSED")
    });
    Object.defineProperty(WebSocket2.prototype, "CLOSED", {
      enumerable: true,
      value: readyStates.indexOf("CLOSED")
    });
    [
      "binaryType",
      "bufferedAmount",
      "extensions",
      "isPaused",
      "protocol",
      "readyState",
      "url"
    ].forEach((property) => {
      Object.defineProperty(WebSocket2.prototype, property, { enumerable: true });
    });
    ["open", "error", "close", "message"].forEach((method) => {
      Object.defineProperty(WebSocket2.prototype, `on${method}`, {
        enumerable: true,
        get() {
          for (const listener of this.listeners(method)) {
            if (listener[kForOnEventAttribute]) return listener[kListener];
          }
          return null;
        },
        set(handler) {
          for (const listener of this.listeners(method)) {
            if (listener[kForOnEventAttribute]) {
              this.removeListener(method, listener);
              break;
            }
          }
          if (typeof handler !== "function") return;
          this.addEventListener(method, handler, {
            [kForOnEventAttribute]: true
          });
        }
      });
    });
    WebSocket2.prototype.addEventListener = addEventListener;
    WebSocket2.prototype.removeEventListener = removeEventListener;
    module.exports = WebSocket2;
    function initAsClient(websocket, address, protocols, options) {
      const opts = {
        allowSynchronousEvents: true,
        autoPong: true,
        closeTimeout: CLOSE_TIMEOUT,
        protocolVersion: protocolVersions[1],
        maxBufferedChunks: 256 * 1024,
        maxFragments: 16 * 1024,
        maxPayload: 100 * 1024 * 1024,
        skipUTF8Validation: false,
        perMessageDeflate: true,
        followRedirects: false,
        maxRedirects: 10,
        ...options,
        socketPath: void 0,
        hostname: void 0,
        protocol: void 0,
        protocols: void 0,
        timeout: void 0,
        method: "GET",
        host: void 0,
        path: void 0,
        port: void 0
      };
      websocket._autoPong = opts.autoPong;
      websocket._closeTimeout = opts.closeTimeout;
      if (!protocolVersions.includes(opts.protocolVersion)) {
        throw new RangeError(
          `Unsupported protocol version: ${opts.protocolVersion} (supported versions: ${protocolVersions.join(", ")})`
        );
      }
      let parsedUrl;
      if (address instanceof URL2) {
        parsedUrl = address;
      } else {
        try {
          parsedUrl = new URL2(address);
        } catch {
          throw new SyntaxError(`Invalid URL: ${address}`);
        }
      }
      if (parsedUrl.protocol === "http:") {
        parsedUrl.protocol = "ws:";
      } else if (parsedUrl.protocol === "https:") {
        parsedUrl.protocol = "wss:";
      }
      websocket._url = parsedUrl.href;
      const isSecure = parsedUrl.protocol === "wss:";
      const isIpcUrl = parsedUrl.protocol === "ws+unix:";
      let invalidUrlMessage;
      if (parsedUrl.protocol !== "ws:" && !isSecure && !isIpcUrl) {
        invalidUrlMessage = `The URL's protocol must be one of "ws:", "wss:", "http:", "https:", or "ws+unix:"`;
      } else if (isIpcUrl && !parsedUrl.pathname) {
        invalidUrlMessage = "The URL's pathname is empty";
      } else if (parsedUrl.hash) {
        invalidUrlMessage = "The URL contains a fragment identifier";
      }
      if (invalidUrlMessage) {
        const err = new SyntaxError(invalidUrlMessage);
        if (websocket._redirects === 0) {
          throw err;
        } else {
          emitErrorAndClose(websocket, err);
          return;
        }
      }
      const defaultPort = isSecure ? 443 : 80;
      const key = randomBytes(16).toString("base64");
      const request2 = isSecure ? https2.request : http3.request;
      const protocolSet = /* @__PURE__ */ new Set();
      let perMessageDeflate;
      opts.createConnection = opts.createConnection || (isSecure ? tlsConnect : netConnect);
      opts.defaultPort = opts.defaultPort || defaultPort;
      opts.port = parsedUrl.port || defaultPort;
      opts.host = parsedUrl.hostname.startsWith("[") ? parsedUrl.hostname.slice(1, -1) : parsedUrl.hostname;
      opts.headers = {
        ...opts.headers,
        "Sec-WebSocket-Version": opts.protocolVersion,
        "Sec-WebSocket-Key": key,
        Connection: "Upgrade",
        Upgrade: "websocket"
      };
      opts.path = parsedUrl.pathname + parsedUrl.search;
      opts.timeout = opts.handshakeTimeout;
      if (opts.perMessageDeflate) {
        perMessageDeflate = new PerMessageDeflate2({
          ...opts.perMessageDeflate,
          isServer: false,
          maxPayload: opts.maxPayload
        });
        opts.headers["Sec-WebSocket-Extensions"] = format({
          [PerMessageDeflate2.extensionName]: perMessageDeflate.offer()
        });
      }
      if (protocols.length) {
        for (const protocol of protocols) {
          if (typeof protocol !== "string" || !subprotocolRegex.test(protocol) || protocolSet.has(protocol)) {
            throw new SyntaxError(
              "An invalid or duplicated subprotocol was specified"
            );
          }
          protocolSet.add(protocol);
        }
        opts.headers["Sec-WebSocket-Protocol"] = protocols.join(",");
      }
      if (opts.origin) {
        if (opts.protocolVersion < 13) {
          opts.headers["Sec-WebSocket-Origin"] = opts.origin;
        } else {
          opts.headers.Origin = opts.origin;
        }
      }
      if (parsedUrl.username || parsedUrl.password) {
        opts.auth = `${parsedUrl.username}:${parsedUrl.password}`;
      }
      if (isIpcUrl) {
        const parts = opts.path.split(":");
        opts.socketPath = parts[0];
        opts.path = parts[1];
      }
      let req;
      if (opts.followRedirects) {
        if (websocket._redirects === 0) {
          websocket._originalIpc = isIpcUrl;
          websocket._originalSecure = isSecure;
          websocket._originalHostOrSocketPath = isIpcUrl ? opts.socketPath : parsedUrl.host;
          const headers = options && options.headers;
          options = { ...options, headers: {} };
          if (headers) {
            for (const [key2, value] of Object.entries(headers)) {
              options.headers[key2.toLowerCase()] = value;
            }
          }
        } else if (websocket.listenerCount("redirect") === 0) {
          const isSameHost = isIpcUrl ? websocket._originalIpc ? opts.socketPath === websocket._originalHostOrSocketPath : false : websocket._originalIpc ? false : parsedUrl.host === websocket._originalHostOrSocketPath;
          if (!isSameHost || websocket._originalSecure && !isSecure) {
            delete opts.headers.authorization;
            delete opts.headers.cookie;
            if (!isSameHost) delete opts.headers.host;
            opts.auth = void 0;
          }
        }
        if (opts.auth && !options.headers.authorization) {
          options.headers.authorization = "Basic " + Buffer.from(opts.auth).toString("base64");
        }
        req = websocket._req = request2(opts);
        if (websocket._redirects) {
          websocket.emit("redirect", websocket.url, req);
        }
      } else {
        req = websocket._req = request2(opts);
      }
      if (opts.timeout) {
        req.on("timeout", () => {
          abortHandshake(websocket, req, "Opening handshake has timed out");
        });
      }
      req.on("error", (err) => {
        if (req === null || req[kAborted]) return;
        req = websocket._req = null;
        emitErrorAndClose(websocket, err);
      });
      req.on("response", (res) => {
        const location = res.headers.location;
        const statusCode = res.statusCode;
        if (location && opts.followRedirects && statusCode >= 300 && statusCode < 400) {
          if (++websocket._redirects > opts.maxRedirects) {
            abortHandshake(websocket, req, "Maximum redirects exceeded");
            return;
          }
          req.abort();
          let addr;
          try {
            addr = new URL2(location, address);
          } catch (e) {
            const err = new SyntaxError(`Invalid URL: ${location}`);
            emitErrorAndClose(websocket, err);
            return;
          }
          initAsClient(websocket, addr, protocols, options);
        } else if (!websocket.emit("unexpected-response", req, res)) {
          abortHandshake(
            websocket,
            req,
            `Unexpected server response: ${res.statusCode}`
          );
        }
      });
      req.on("upgrade", (res, socket, head) => {
        websocket.emit("upgrade", res);
        if (websocket.readyState !== WebSocket2.CONNECTING) return;
        req = websocket._req = null;
        const upgrade = res.headers.upgrade;
        if (upgrade === void 0 || upgrade.toLowerCase() !== "websocket") {
          abortHandshake(websocket, socket, "Invalid Upgrade header");
          return;
        }
        const digest = createHash2("sha1").update(key + GUID).digest("base64");
        if (res.headers["sec-websocket-accept"] !== digest) {
          abortHandshake(websocket, socket, "Invalid Sec-WebSocket-Accept header");
          return;
        }
        const serverProt = res.headers["sec-websocket-protocol"];
        let protError;
        if (serverProt !== void 0) {
          if (!protocolSet.size) {
            protError = "Server sent a subprotocol but none was requested";
          } else if (!protocolSet.has(serverProt)) {
            protError = "Server sent an invalid subprotocol";
          }
        } else if (protocolSet.size) {
          protError = "Server sent no subprotocol";
        }
        if (protError) {
          abortHandshake(websocket, socket, protError);
          return;
        }
        if (serverProt) websocket._protocol = serverProt;
        const secWebSocketExtensions = res.headers["sec-websocket-extensions"];
        if (secWebSocketExtensions !== void 0) {
          if (!perMessageDeflate) {
            const message = "Server sent a Sec-WebSocket-Extensions header but no extension was requested";
            abortHandshake(websocket, socket, message);
            return;
          }
          let extensions;
          try {
            extensions = parse(secWebSocketExtensions);
          } catch (err) {
            const message = "Invalid Sec-WebSocket-Extensions header";
            abortHandshake(websocket, socket, message);
            return;
          }
          const extensionNames = Object.keys(extensions);
          if (extensionNames.length !== 1 || extensionNames[0] !== PerMessageDeflate2.extensionName) {
            const message = "Server indicated an extension that was not requested";
            abortHandshake(websocket, socket, message);
            return;
          }
          try {
            perMessageDeflate.accept(extensions[PerMessageDeflate2.extensionName]);
          } catch (err) {
            const message = "Invalid Sec-WebSocket-Extensions header";
            abortHandshake(websocket, socket, message);
            return;
          }
          websocket._extensions[PerMessageDeflate2.extensionName] = perMessageDeflate;
        }
        websocket.setSocket(socket, head, {
          allowSynchronousEvents: opts.allowSynchronousEvents,
          generateMask: opts.generateMask,
          maxBufferedChunks: opts.maxBufferedChunks,
          maxFragments: opts.maxFragments,
          maxPayload: opts.maxPayload,
          skipUTF8Validation: opts.skipUTF8Validation
        });
      });
      if (opts.finishRequest) {
        opts.finishRequest(req, websocket);
      } else {
        req.end();
      }
    }
    function emitErrorAndClose(websocket, err) {
      websocket._readyState = WebSocket2.CLOSING;
      websocket._errorEmitted = true;
      websocket.emit("error", err);
      websocket.emitClose();
    }
    function netConnect(options) {
      options.path = options.socketPath;
      return net.connect(options);
    }
    function tlsConnect(options) {
      options.path = void 0;
      if (!options.servername && options.servername !== "") {
        options.servername = net.isIP(options.host) ? "" : options.host;
      }
      return tls.connect(options);
    }
    function abortHandshake(websocket, stream, message) {
      websocket._readyState = WebSocket2.CLOSING;
      const err = new Error(message);
      Error.captureStackTrace(err, abortHandshake);
      if (stream.setHeader) {
        stream[kAborted] = true;
        stream.abort();
        if (stream.socket && !stream.socket.destroyed) {
          stream.socket.destroy();
        }
        process.nextTick(emitErrorAndClose, websocket, err);
      } else {
        stream.destroy(err);
        stream.once("error", websocket.emit.bind(websocket, "error"));
        stream.once("close", websocket.emitClose.bind(websocket));
      }
    }
    function sendAfterClose(websocket, data, cb) {
      if (data) {
        const length = isBlob(data) ? data.size : toBuffer(data).length;
        if (websocket._socket) websocket._sender._bufferedBytes += length;
        else websocket._bufferedAmount += length;
      }
      if (cb) {
        const err = new Error(
          `WebSocket is not open: readyState ${websocket.readyState} (${readyStates[websocket.readyState]})`
        );
        process.nextTick(cb, err);
      }
    }
    function receiverOnConclude(code, reason) {
      const websocket = this[kWebSocket];
      websocket._closeFrameReceived = true;
      websocket._closeMessage = reason;
      websocket._closeCode = code;
      if (websocket._socket[kWebSocket] === void 0) return;
      websocket._socket.removeListener("data", socketOnData);
      process.nextTick(resume, websocket._socket);
      if (code === 1005) websocket.close();
      else websocket.close(code, reason);
    }
    function receiverOnDrain() {
      const websocket = this[kWebSocket];
      if (!websocket.isPaused) websocket._socket.resume();
    }
    function receiverOnError(err) {
      const websocket = this[kWebSocket];
      if (websocket._socket[kWebSocket] !== void 0) {
        websocket._socket.removeListener("data", socketOnData);
        process.nextTick(resume, websocket._socket);
        websocket.close(err[kStatusCode]);
      }
      if (!websocket._errorEmitted) {
        websocket._errorEmitted = true;
        websocket.emit("error", err);
      }
    }
    function receiverOnFinish() {
      this[kWebSocket].emitClose();
    }
    function receiverOnMessage(data, isBinary) {
      this[kWebSocket].emit("message", data, isBinary);
    }
    function receiverOnPing(data) {
      const websocket = this[kWebSocket];
      if (websocket._autoPong) websocket.pong(data, !this._isServer, NOOP);
      websocket.emit("ping", data);
    }
    function receiverOnPong(data) {
      this[kWebSocket].emit("pong", data);
    }
    function resume(stream) {
      stream.resume();
    }
    function senderOnError(err) {
      const websocket = this[kWebSocket];
      if (websocket.readyState === WebSocket2.CLOSED) return;
      if (websocket.readyState === WebSocket2.OPEN) {
        websocket._readyState = WebSocket2.CLOSING;
        setCloseTimer(websocket);
      }
      this._socket.end();
      if (!websocket._errorEmitted) {
        websocket._errorEmitted = true;
        websocket.emit("error", err);
      }
    }
    function setCloseTimer(websocket) {
      websocket._closeTimer = setTimeout(
        websocket._socket.destroy.bind(websocket._socket),
        websocket._closeTimeout
      );
    }
    function socketOnClose() {
      const websocket = this[kWebSocket];
      this.removeListener("close", socketOnClose);
      this.removeListener("data", socketOnData);
      this.removeListener("end", socketOnEnd);
      websocket._readyState = WebSocket2.CLOSING;
      if (!this._readableState.endEmitted && !websocket._closeFrameReceived && !websocket._receiver._writableState.errorEmitted && this._readableState.length !== 0) {
        const chunk = this.read(this._readableState.length);
        websocket._receiver.write(chunk);
      }
      websocket._receiver.end();
      this[kWebSocket] = void 0;
      clearTimeout(websocket._closeTimer);
      if (websocket._receiver._writableState.finished || websocket._receiver._writableState.errorEmitted) {
        websocket.emitClose();
      } else {
        websocket._receiver.on("error", receiverOnFinish);
        websocket._receiver.on("finish", receiverOnFinish);
      }
    }
    function socketOnData(chunk) {
      if (!this[kWebSocket]._receiver.write(chunk)) {
        this.pause();
      }
    }
    function socketOnEnd() {
      const websocket = this[kWebSocket];
      websocket._readyState = WebSocket2.CLOSING;
      websocket._receiver.end();
      this.end();
    }
    function socketOnError() {
      const websocket = this[kWebSocket];
      this.removeListener("error", socketOnError);
      this.on("error", NOOP);
      if (websocket) {
        websocket._readyState = WebSocket2.CLOSING;
        this.destroy();
      }
    }
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/stream.js
var require_stream = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/stream.js"(exports, module) {
    "use strict";
    var WebSocket2 = require_websocket();
    var { Duplex } = __require("stream");
    function emitClose(stream) {
      stream.emit("close");
    }
    function duplexOnEnd() {
      if (!this.destroyed && this._writableState.finished) {
        this.destroy();
      }
    }
    function duplexOnError(err) {
      this.removeListener("error", duplexOnError);
      this.destroy();
      if (this.listenerCount("error") === 0) {
        this.emit("error", err);
      }
    }
    function createWebSocketStream2(ws, options) {
      let terminateOnDestroy = true;
      const duplex = new Duplex({
        ...options,
        autoDestroy: false,
        emitClose: false,
        objectMode: false,
        writableObjectMode: false
      });
      ws.on("message", function message(msg, isBinary) {
        const data = !isBinary && duplex._readableState.objectMode ? msg.toString() : msg;
        if (!duplex.push(data)) ws.pause();
      });
      ws.once("error", function error(err) {
        if (duplex.destroyed) return;
        terminateOnDestroy = false;
        duplex.destroy(err);
      });
      ws.once("close", function close() {
        if (duplex.destroyed) return;
        duplex.push(null);
      });
      duplex._destroy = function(err, callback) {
        if (ws.readyState === ws.CLOSED) {
          callback(err);
          process.nextTick(emitClose, duplex);
          return;
        }
        let called = false;
        ws.once("error", function error(err2) {
          called = true;
          callback(err2);
        });
        ws.once("close", function close() {
          if (!called) callback(err);
          process.nextTick(emitClose, duplex);
        });
        if (terminateOnDestroy) ws.terminate();
      };
      duplex._final = function(callback) {
        if (ws.readyState === ws.CONNECTING) {
          ws.once("open", function open() {
            duplex._final(callback);
          });
          return;
        }
        if (ws._socket === null) return;
        if (ws._socket._writableState.finished) {
          callback();
          if (duplex._readableState.endEmitted) duplex.destroy();
        } else {
          ws._socket.once("finish", function finish() {
            callback();
          });
          ws.close();
        }
      };
      duplex._read = function() {
        if (ws.isPaused) ws.resume();
      };
      duplex._write = function(chunk, encoding, callback) {
        if (ws.readyState === ws.CONNECTING) {
          ws.once("open", function open() {
            duplex._write(chunk, encoding, callback);
          });
          return;
        }
        ws.send(chunk, callback);
      };
      duplex.on("end", duplexOnEnd);
      duplex.on("error", duplexOnError);
      return duplex;
    }
    module.exports = createWebSocketStream2;
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/subprotocol.js
var require_subprotocol = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/subprotocol.js"(exports, module) {
    "use strict";
    var { tokenChars } = require_validation2();
    function parse(header) {
      const protocols = /* @__PURE__ */ new Set();
      let start = -1;
      let end = -1;
      let i = 0;
      for (i; i < header.length; i++) {
        const code = header.charCodeAt(i);
        if (end === -1 && tokenChars[code] === 1) {
          if (start === -1) start = i;
        } else if (i !== 0 && (code === 32 || code === 9)) {
          if (end === -1 && start !== -1) end = i;
        } else if (code === 44) {
          if (start === -1) {
            throw new SyntaxError(`Unexpected character at index ${i}`);
          }
          if (end === -1) end = i;
          const protocol2 = header.slice(start, end);
          if (protocols.has(protocol2)) {
            throw new SyntaxError(`The "${protocol2}" subprotocol is duplicated`);
          }
          protocols.add(protocol2);
          start = end = -1;
        } else {
          throw new SyntaxError(`Unexpected character at index ${i}`);
        }
      }
      if (start === -1 || end !== -1) {
        throw new SyntaxError("Unexpected end of input");
      }
      const protocol = header.slice(start, i);
      if (protocols.has(protocol)) {
        throw new SyntaxError(`The "${protocol}" subprotocol is duplicated`);
      }
      protocols.add(protocol);
      return protocols;
    }
    module.exports = { parse };
  }
});

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/websocket-server.js
var require_websocket_server = __commonJS({
  "../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/lib/websocket-server.js"(exports, module) {
    "use strict";
    var EventEmitter = __require("events");
    var http3 = __require("http");
    var { Duplex } = __require("stream");
    var { createHash: createHash2 } = __require("crypto");
    var extension2 = require_extension();
    var PerMessageDeflate2 = require_permessage_deflate();
    var subprotocol2 = require_subprotocol();
    var WebSocket2 = require_websocket();
    var { CLOSE_TIMEOUT, GUID, kWebSocket } = require_constants();
    var keyRegex = /^[+/0-9A-Za-z]{22}==$/;
    var RUNNING = 0;
    var CLOSING = 1;
    var CLOSED = 2;
    var WebSocketServer2 = class extends EventEmitter {
      /**
       * Create a `WebSocketServer` instance.
       *
       * @param {Object} options Configuration options
       * @param {Boolean} [options.allowSynchronousEvents=true] Specifies whether
       *     any of the `'message'`, `'ping'`, and `'pong'` events can be emitted
       *     multiple times in the same tick
       * @param {Boolean} [options.autoPong=true] Specifies whether or not to
       *     automatically send a pong in response to a ping
       * @param {Number} [options.backlog=511] The maximum length of the queue of
       *     pending connections
       * @param {Boolean} [options.clientTracking=true] Specifies whether or not to
       *     track clients
       * @param {Number} [options.closeTimeout=30000] Duration in milliseconds to
       *     wait for the closing handshake to finish after `websocket.close()` is
       *     called
       * @param {Function} [options.handleProtocols] A hook to handle protocols
       * @param {String} [options.host] The hostname where to bind the server
       * @param {Number} [options.maxBufferedChunks=262144] The maximum number of
       *     buffered data chunks
       * @param {Number} [options.maxFragments=16384] The maximum number of message
       *     fragments
       * @param {Number} [options.maxPayload=104857600] The maximum allowed message
       *     size
       * @param {Boolean} [options.noServer=false] Enable no server mode
       * @param {String} [options.path] Accept only connections matching this path
       * @param {(Boolean|Object)} [options.perMessageDeflate=false] Enable/disable
       *     permessage-deflate
       * @param {Number} [options.port] The port where to bind the server
       * @param {(http.Server|https.Server)} [options.server] A pre-created HTTP/S
       *     server to use
       * @param {Boolean} [options.skipUTF8Validation=false] Specifies whether or
       *     not to skip UTF-8 validation for text and close messages
       * @param {Function} [options.verifyClient] A hook to reject connections
       * @param {Function} [options.WebSocket=WebSocket] Specifies the `WebSocket`
       *     class to use. It must be the `WebSocket` class or class that extends it
       * @param {Function} [callback] A listener for the `listening` event
       */
      constructor(options, callback) {
        super();
        options = {
          allowSynchronousEvents: true,
          autoPong: true,
          maxBufferedChunks: 256 * 1024,
          maxFragments: 16 * 1024,
          maxPayload: 100 * 1024 * 1024,
          skipUTF8Validation: false,
          perMessageDeflate: false,
          handleProtocols: null,
          clientTracking: true,
          closeTimeout: CLOSE_TIMEOUT,
          verifyClient: null,
          noServer: false,
          backlog: null,
          // use default (511 as implemented in net.js)
          server: null,
          host: null,
          path: null,
          port: null,
          WebSocket: WebSocket2,
          ...options
        };
        if (options.port == null && !options.server && !options.noServer || options.port != null && (options.server || options.noServer) || options.server && options.noServer) {
          throw new TypeError(
            'One and only one of the "port", "server", or "noServer" options must be specified'
          );
        }
        if (options.port != null) {
          this._server = http3.createServer((req, res) => {
            const body = http3.STATUS_CODES[426];
            res.writeHead(426, {
              "Content-Length": body.length,
              "Content-Type": "text/plain"
            });
            res.end(body);
          });
          this._server.listen(
            options.port,
            options.host,
            options.backlog,
            callback
          );
        } else if (options.server) {
          this._server = options.server;
        }
        if (this._server) {
          const emitConnection = this.emit.bind(this, "connection");
          this._removeListeners = addListeners(this._server, {
            listening: this.emit.bind(this, "listening"),
            error: this.emit.bind(this, "error"),
            upgrade: (req, socket, head) => {
              this.handleUpgrade(req, socket, head, emitConnection);
            }
          });
        }
        if (options.perMessageDeflate === true) options.perMessageDeflate = {};
        if (options.clientTracking) {
          this.clients = /* @__PURE__ */ new Set();
          this._shouldEmitClose = false;
        }
        this.options = options;
        this._state = RUNNING;
      }
      /**
       * Returns the bound address, the address family name, and port of the server
       * as reported by the operating system if listening on an IP socket.
       * If the server is listening on a pipe or UNIX domain socket, the name is
       * returned as a string.
       *
       * @return {(Object|String|null)} The address of the server
       * @public
       */
      address() {
        if (this.options.noServer) {
          throw new Error('The server is operating in "noServer" mode');
        }
        if (!this._server) return null;
        return this._server.address();
      }
      /**
       * Stop the server from accepting new connections and emit the `'close'` event
       * when all existing connections are closed.
       *
       * @param {Function} [cb] A one-time listener for the `'close'` event
       * @public
       */
      close(cb) {
        if (this._state === CLOSED) {
          if (cb) {
            this.once("close", () => {
              cb(new Error("The server is not running"));
            });
          }
          process.nextTick(emitClose, this);
          return;
        }
        if (cb) this.once("close", cb);
        if (this._state === CLOSING) return;
        this._state = CLOSING;
        if (this.options.noServer || this.options.server) {
          if (this._server) {
            this._removeListeners();
            this._removeListeners = this._server = null;
          }
          if (this.clients) {
            if (!this.clients.size) {
              process.nextTick(emitClose, this);
            } else {
              this._shouldEmitClose = true;
            }
          } else {
            process.nextTick(emitClose, this);
          }
        } else {
          const server = this._server;
          this._removeListeners();
          this._removeListeners = this._server = null;
          server.close(() => {
            emitClose(this);
          });
        }
      }
      /**
       * See if a given request should be handled by this server instance.
       *
       * @param {http.IncomingMessage} req Request object to inspect
       * @return {Boolean} `true` if the request is valid, else `false`
       * @public
       */
      shouldHandle(req) {
        if (this.options.path) {
          const index = req.url.indexOf("?");
          const pathname = index !== -1 ? req.url.slice(0, index) : req.url;
          if (pathname !== this.options.path) return false;
        }
        return true;
      }
      /**
       * Handle a HTTP Upgrade request.
       *
       * @param {http.IncomingMessage} req The request object
       * @param {Duplex} socket The network socket between the server and client
       * @param {Buffer} head The first packet of the upgraded stream
       * @param {Function} cb Callback
       * @public
       */
      handleUpgrade(req, socket, head, cb) {
        socket.on("error", socketOnError);
        const key = req.headers["sec-websocket-key"];
        const upgrade = req.headers.upgrade;
        const version = +req.headers["sec-websocket-version"];
        if (req.method !== "GET") {
          const message = "Invalid HTTP method";
          abortHandshakeOrEmitwsClientError(this, req, socket, 405, message);
          return;
        }
        if (upgrade === void 0 || upgrade.toLowerCase() !== "websocket") {
          const message = "Invalid Upgrade header";
          abortHandshakeOrEmitwsClientError(this, req, socket, 400, message);
          return;
        }
        if (key === void 0 || !keyRegex.test(key)) {
          const message = "Missing or invalid Sec-WebSocket-Key header";
          abortHandshakeOrEmitwsClientError(this, req, socket, 400, message);
          return;
        }
        if (version !== 13 && version !== 8) {
          const message = "Missing or invalid Sec-WebSocket-Version header";
          abortHandshakeOrEmitwsClientError(this, req, socket, 400, message, {
            "Sec-WebSocket-Version": "13, 8"
          });
          return;
        }
        if (!this.shouldHandle(req)) {
          abortHandshake(socket, 400);
          return;
        }
        const secWebSocketProtocol = req.headers["sec-websocket-protocol"];
        let protocols = /* @__PURE__ */ new Set();
        if (secWebSocketProtocol !== void 0) {
          try {
            protocols = subprotocol2.parse(secWebSocketProtocol);
          } catch (err) {
            const message = "Invalid Sec-WebSocket-Protocol header";
            abortHandshakeOrEmitwsClientError(this, req, socket, 400, message);
            return;
          }
        }
        const secWebSocketExtensions = req.headers["sec-websocket-extensions"];
        const extensions = {};
        if (this.options.perMessageDeflate && secWebSocketExtensions !== void 0) {
          const perMessageDeflate = new PerMessageDeflate2({
            ...this.options.perMessageDeflate,
            isServer: true,
            maxPayload: this.options.maxPayload
          });
          try {
            const offers = extension2.parse(secWebSocketExtensions);
            if (offers[PerMessageDeflate2.extensionName]) {
              perMessageDeflate.accept(offers[PerMessageDeflate2.extensionName]);
              extensions[PerMessageDeflate2.extensionName] = perMessageDeflate;
            }
          } catch (err) {
            const message = "Invalid or unacceptable Sec-WebSocket-Extensions header";
            abortHandshakeOrEmitwsClientError(this, req, socket, 400, message);
            return;
          }
        }
        if (this.options.verifyClient) {
          const info = {
            origin: req.headers[`${version === 8 ? "sec-websocket-origin" : "origin"}`],
            secure: !!(req.socket.authorized || req.socket.encrypted),
            req
          };
          if (this.options.verifyClient.length === 2) {
            this.options.verifyClient(info, (verified, code, message, headers) => {
              if (!verified) {
                return abortHandshake(socket, code || 401, message, headers);
              }
              this.completeUpgrade(
                extensions,
                key,
                protocols,
                req,
                socket,
                head,
                cb
              );
            });
            return;
          }
          if (!this.options.verifyClient(info)) return abortHandshake(socket, 401);
        }
        this.completeUpgrade(extensions, key, protocols, req, socket, head, cb);
      }
      /**
       * Upgrade the connection to WebSocket.
       *
       * @param {Object} extensions The accepted extensions
       * @param {String} key The value of the `Sec-WebSocket-Key` header
       * @param {Set} protocols The subprotocols
       * @param {http.IncomingMessage} req The request object
       * @param {Duplex} socket The network socket between the server and client
       * @param {Buffer} head The first packet of the upgraded stream
       * @param {Function} cb Callback
       * @throws {Error} If called more than once with the same socket
       * @private
       */
      completeUpgrade(extensions, key, protocols, req, socket, head, cb) {
        if (!socket.readable || !socket.writable) return socket.destroy();
        if (socket[kWebSocket]) {
          throw new Error(
            "server.handleUpgrade() was called more than once with the same socket, possibly due to a misconfiguration"
          );
        }
        if (this._state > RUNNING) return abortHandshake(socket, 503);
        const digest = createHash2("sha1").update(key + GUID).digest("base64");
        const headers = [
          "HTTP/1.1 101 Switching Protocols",
          "Upgrade: websocket",
          "Connection: Upgrade",
          `Sec-WebSocket-Accept: ${digest}`
        ];
        const ws = new this.options.WebSocket(null, void 0, this.options);
        if (protocols.size) {
          const protocol = this.options.handleProtocols ? this.options.handleProtocols(protocols, req) : protocols.values().next().value;
          if (protocol) {
            headers.push(`Sec-WebSocket-Protocol: ${protocol}`);
            ws._protocol = protocol;
          }
        }
        if (extensions[PerMessageDeflate2.extensionName]) {
          const params = extensions[PerMessageDeflate2.extensionName].params;
          const value = extension2.format({
            [PerMessageDeflate2.extensionName]: [params]
          });
          headers.push(`Sec-WebSocket-Extensions: ${value}`);
          ws._extensions = extensions;
        }
        this.emit("headers", headers, req);
        socket.write(headers.concat("\r\n").join("\r\n"));
        socket.removeListener("error", socketOnError);
        ws.setSocket(socket, head, {
          allowSynchronousEvents: this.options.allowSynchronousEvents,
          maxBufferedChunks: this.options.maxBufferedChunks,
          maxFragments: this.options.maxFragments,
          maxPayload: this.options.maxPayload,
          skipUTF8Validation: this.options.skipUTF8Validation
        });
        if (this.clients) {
          this.clients.add(ws);
          ws.on("close", () => {
            this.clients.delete(ws);
            if (this._shouldEmitClose && !this.clients.size) {
              process.nextTick(emitClose, this);
            }
          });
        }
        cb(ws, req);
      }
    };
    module.exports = WebSocketServer2;
    function addListeners(server, map) {
      for (const event of Object.keys(map)) server.on(event, map[event]);
      return function removeListeners() {
        for (const event of Object.keys(map)) {
          server.removeListener(event, map[event]);
        }
      };
    }
    function emitClose(server) {
      server._state = CLOSED;
      server.emit("close");
    }
    function socketOnError() {
      this.destroy();
    }
    function abortHandshake(socket, code, message, headers) {
      message = message || http3.STATUS_CODES[code];
      headers = {
        Connection: "close",
        "Content-Type": "text/html",
        "Content-Length": Buffer.byteLength(message),
        ...headers
      };
      socket.once("finish", socket.destroy);
      socket.end(
        `HTTP/1.1 ${code} ${http3.STATUS_CODES[code]}\r
` + Object.keys(headers).map((h) => `${h}: ${headers[h]}`).join("\r\n") + "\r\n\r\n" + message
      );
    }
    function abortHandshakeOrEmitwsClientError(server, req, socket, code, message, headers) {
      if (server.listenerCount("wsClientError")) {
        const err = new Error(message);
        Error.captureStackTrace(err, abortHandshakeOrEmitwsClientError);
        server.emit("wsClientError", err, socket, req);
      } else {
        abortHandshake(socket, code, message, headers);
      }
    }
  }
});

// src/index.ts
var import_prom_client = __toESM(require_prom_client(), 1);

// ../../packages/axonwall_lib/dist/util/index.js
function isValidIPv4(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4)
    return false;
  for (const part of parts) {
    if (!/^\d+$/.test(part))
      return false;
    const num = Number.parseInt(part, 10);
    if (num < 0 || num > 255)
      return false;
    if (part.length > 1 && part.startsWith("0"))
      return false;
  }
  return true;
}
function isValidIPv6(ip) {
  const ipv6Regex2 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
  return ipv6Regex2.test(ip);
}
function isValidCIDR(cidr) {
  const parts = cidr.split("/");
  if (parts.length !== 2)
    return false;
  const [ip, prefix] = parts;
  const prefixNum = Number.parseInt(prefix, 10);
  if (Number.isNaN(prefixNum))
    return false;
  if (isValidIPv4(ip)) {
    return prefixNum >= 0 && prefixNum <= 32;
  }
  if (isValidIPv6(ip)) {
    return prefixNum >= 0 && prefixNum <= 128;
  }
  return false;
}
function isValidPort(port) {
  if (typeof port === "string" && !/^\d+$/.test(port.trim()))
    return false;
  const p = typeof port === "string" ? Number.parseInt(port.trim(), 10) : port;
  return !Number.isNaN(p) && p >= 1 && p <= 65535;
}
function isValidPortRange(range) {
  const items = range.split(",").map((s) => s.trim());
  if (items.length === 0 || items.some((item) => item === ""))
    return false;
  for (const item of items) {
    if (item.includes("-")) {
      const parts = item.split("-");
      if (parts.length !== 2)
        return false;
      const [startStr, endStr] = parts.map((s) => s.trim());
      if (!isValidPort(startStr) || !isValidPort(endStr))
        return false;
      const start = Number.parseInt(startStr, 10);
      const end = Number.parseInt(endStr, 10);
      if (start > end)
        return false;
    } else {
      if (!isValidPort(item))
        return false;
    }
  }
  return true;
}
function isValidMAC(mac) {
  return /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac);
}
function sanitizeIdentifier(name) {
  return name.replace(/[^a-zA-Z0-9_]/g, "_").toLowerCase();
}

// ../../node_modules/.pnpm/zod@3.25.76/node_modules/zod/v3/external.js
var external_exports = {};
__export(external_exports, {
  BRAND: () => BRAND,
  DIRTY: () => DIRTY,
  EMPTY_PATH: () => EMPTY_PATH,
  INVALID: () => INVALID,
  NEVER: () => NEVER,
  OK: () => OK,
  ParseStatus: () => ParseStatus,
  Schema: () => ZodType,
  ZodAny: () => ZodAny,
  ZodArray: () => ZodArray,
  ZodBigInt: () => ZodBigInt,
  ZodBoolean: () => ZodBoolean,
  ZodBranded: () => ZodBranded,
  ZodCatch: () => ZodCatch,
  ZodDate: () => ZodDate,
  ZodDefault: () => ZodDefault,
  ZodDiscriminatedUnion: () => ZodDiscriminatedUnion,
  ZodEffects: () => ZodEffects,
  ZodEnum: () => ZodEnum,
  ZodError: () => ZodError,
  ZodFirstPartyTypeKind: () => ZodFirstPartyTypeKind,
  ZodFunction: () => ZodFunction,
  ZodIntersection: () => ZodIntersection,
  ZodIssueCode: () => ZodIssueCode,
  ZodLazy: () => ZodLazy,
  ZodLiteral: () => ZodLiteral,
  ZodMap: () => ZodMap,
  ZodNaN: () => ZodNaN,
  ZodNativeEnum: () => ZodNativeEnum,
  ZodNever: () => ZodNever,
  ZodNull: () => ZodNull,
  ZodNullable: () => ZodNullable,
  ZodNumber: () => ZodNumber,
  ZodObject: () => ZodObject,
  ZodOptional: () => ZodOptional,
  ZodParsedType: () => ZodParsedType,
  ZodPipeline: () => ZodPipeline,
  ZodPromise: () => ZodPromise,
  ZodReadonly: () => ZodReadonly,
  ZodRecord: () => ZodRecord,
  ZodSchema: () => ZodType,
  ZodSet: () => ZodSet,
  ZodString: () => ZodString,
  ZodSymbol: () => ZodSymbol,
  ZodTransformer: () => ZodEffects,
  ZodTuple: () => ZodTuple,
  ZodType: () => ZodType,
  ZodUndefined: () => ZodUndefined,
  ZodUnion: () => ZodUnion,
  ZodUnknown: () => ZodUnknown,
  ZodVoid: () => ZodVoid,
  addIssueToContext: () => addIssueToContext,
  any: () => anyType,
  array: () => arrayType,
  bigint: () => bigIntType,
  boolean: () => booleanType,
  coerce: () => coerce,
  custom: () => custom,
  date: () => dateType,
  datetimeRegex: () => datetimeRegex,
  defaultErrorMap: () => en_default,
  discriminatedUnion: () => discriminatedUnionType,
  effect: () => effectsType,
  enum: () => enumType,
  function: () => functionType,
  getErrorMap: () => getErrorMap,
  getParsedType: () => getParsedType,
  instanceof: () => instanceOfType,
  intersection: () => intersectionType,
  isAborted: () => isAborted,
  isAsync: () => isAsync,
  isDirty: () => isDirty,
  isValid: () => isValid,
  late: () => late,
  lazy: () => lazyType,
  literal: () => literalType,
  makeIssue: () => makeIssue,
  map: () => mapType,
  nan: () => nanType,
  nativeEnum: () => nativeEnumType,
  never: () => neverType,
  null: () => nullType,
  nullable: () => nullableType,
  number: () => numberType,
  object: () => objectType,
  objectUtil: () => objectUtil,
  oboolean: () => oboolean,
  onumber: () => onumber,
  optional: () => optionalType,
  ostring: () => ostring,
  pipeline: () => pipelineType,
  preprocess: () => preprocessType,
  promise: () => promiseType,
  quotelessJson: () => quotelessJson,
  record: () => recordType,
  set: () => setType,
  setErrorMap: () => setErrorMap,
  strictObject: () => strictObjectType,
  string: () => stringType,
  symbol: () => symbolType,
  transformer: () => effectsType,
  tuple: () => tupleType,
  undefined: () => undefinedType,
  union: () => unionType,
  unknown: () => unknownType,
  util: () => util,
  void: () => voidType
});

// ../../node_modules/.pnpm/zod@3.25.76/node_modules/zod/v3/helpers/util.js
var util;
(function(util2) {
  util2.assertEqual = (_) => {
  };
  function assertIs(_arg) {
  }
  util2.assertIs = assertIs;
  function assertNever(_x) {
    throw new Error();
  }
  util2.assertNever = assertNever;
  util2.arrayToEnum = (items) => {
    const obj = {};
    for (const item of items) {
      obj[item] = item;
    }
    return obj;
  };
  util2.getValidEnumValues = (obj) => {
    const validKeys = util2.objectKeys(obj).filter((k) => typeof obj[obj[k]] !== "number");
    const filtered = {};
    for (const k of validKeys) {
      filtered[k] = obj[k];
    }
    return util2.objectValues(filtered);
  };
  util2.objectValues = (obj) => {
    return util2.objectKeys(obj).map(function(e) {
      return obj[e];
    });
  };
  util2.objectKeys = typeof Object.keys === "function" ? (obj) => Object.keys(obj) : (object) => {
    const keys = [];
    for (const key in object) {
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        keys.push(key);
      }
    }
    return keys;
  };
  util2.find = (arr, checker) => {
    for (const item of arr) {
      if (checker(item))
        return item;
    }
    return void 0;
  };
  util2.isInteger = typeof Number.isInteger === "function" ? (val) => Number.isInteger(val) : (val) => typeof val === "number" && Number.isFinite(val) && Math.floor(val) === val;
  function joinValues(array, separator = " | ") {
    return array.map((val) => typeof val === "string" ? `'${val}'` : val).join(separator);
  }
  util2.joinValues = joinValues;
  util2.jsonStringifyReplacer = (_, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  };
})(util || (util = {}));
var objectUtil;
(function(objectUtil2) {
  objectUtil2.mergeShapes = (first, second) => {
    return {
      ...first,
      ...second
      // second overwrites first
    };
  };
})(objectUtil || (objectUtil = {}));
var ZodParsedType = util.arrayToEnum([
  "string",
  "nan",
  "number",
  "integer",
  "float",
  "boolean",
  "date",
  "bigint",
  "symbol",
  "function",
  "undefined",
  "null",
  "array",
  "object",
  "unknown",
  "promise",
  "void",
  "never",
  "map",
  "set"
]);
var getParsedType = (data) => {
  const t = typeof data;
  switch (t) {
    case "undefined":
      return ZodParsedType.undefined;
    case "string":
      return ZodParsedType.string;
    case "number":
      return Number.isNaN(data) ? ZodParsedType.nan : ZodParsedType.number;
    case "boolean":
      return ZodParsedType.boolean;
    case "function":
      return ZodParsedType.function;
    case "bigint":
      return ZodParsedType.bigint;
    case "symbol":
      return ZodParsedType.symbol;
    case "object":
      if (Array.isArray(data)) {
        return ZodParsedType.array;
      }
      if (data === null) {
        return ZodParsedType.null;
      }
      if (data.then && typeof data.then === "function" && data.catch && typeof data.catch === "function") {
        return ZodParsedType.promise;
      }
      if (typeof Map !== "undefined" && data instanceof Map) {
        return ZodParsedType.map;
      }
      if (typeof Set !== "undefined" && data instanceof Set) {
        return ZodParsedType.set;
      }
      if (typeof Date !== "undefined" && data instanceof Date) {
        return ZodParsedType.date;
      }
      return ZodParsedType.object;
    default:
      return ZodParsedType.unknown;
  }
};

// ../../node_modules/.pnpm/zod@3.25.76/node_modules/zod/v3/ZodError.js
var ZodIssueCode = util.arrayToEnum([
  "invalid_type",
  "invalid_literal",
  "custom",
  "invalid_union",
  "invalid_union_discriminator",
  "invalid_enum_value",
  "unrecognized_keys",
  "invalid_arguments",
  "invalid_return_type",
  "invalid_date",
  "invalid_string",
  "too_small",
  "too_big",
  "invalid_intersection_types",
  "not_multiple_of",
  "not_finite"
]);
var quotelessJson = (obj) => {
  const json = JSON.stringify(obj, null, 2);
  return json.replace(/"([^"]+)":/g, "$1:");
};
var ZodError = class _ZodError extends Error {
  get errors() {
    return this.issues;
  }
  constructor(issues) {
    super();
    this.issues = [];
    this.addIssue = (sub) => {
      this.issues = [...this.issues, sub];
    };
    this.addIssues = (subs = []) => {
      this.issues = [...this.issues, ...subs];
    };
    const actualProto = new.target.prototype;
    if (Object.setPrototypeOf) {
      Object.setPrototypeOf(this, actualProto);
    } else {
      this.__proto__ = actualProto;
    }
    this.name = "ZodError";
    this.issues = issues;
  }
  format(_mapper) {
    const mapper = _mapper || function(issue) {
      return issue.message;
    };
    const fieldErrors = { _errors: [] };
    const processError = (error) => {
      for (const issue of error.issues) {
        if (issue.code === "invalid_union") {
          issue.unionErrors.map(processError);
        } else if (issue.code === "invalid_return_type") {
          processError(issue.returnTypeError);
        } else if (issue.code === "invalid_arguments") {
          processError(issue.argumentsError);
        } else if (issue.path.length === 0) {
          fieldErrors._errors.push(mapper(issue));
        } else {
          let curr = fieldErrors;
          let i = 0;
          while (i < issue.path.length) {
            const el = issue.path[i];
            const terminal = i === issue.path.length - 1;
            if (!terminal) {
              curr[el] = curr[el] || { _errors: [] };
            } else {
              curr[el] = curr[el] || { _errors: [] };
              curr[el]._errors.push(mapper(issue));
            }
            curr = curr[el];
            i++;
          }
        }
      }
    };
    processError(this);
    return fieldErrors;
  }
  static assert(value) {
    if (!(value instanceof _ZodError)) {
      throw new Error(`Not a ZodError: ${value}`);
    }
  }
  toString() {
    return this.message;
  }
  get message() {
    return JSON.stringify(this.issues, util.jsonStringifyReplacer, 2);
  }
  get isEmpty() {
    return this.issues.length === 0;
  }
  flatten(mapper = (issue) => issue.message) {
    const fieldErrors = {};
    const formErrors = [];
    for (const sub of this.issues) {
      if (sub.path.length > 0) {
        const firstEl = sub.path[0];
        fieldErrors[firstEl] = fieldErrors[firstEl] || [];
        fieldErrors[firstEl].push(mapper(sub));
      } else {
        formErrors.push(mapper(sub));
      }
    }
    return { formErrors, fieldErrors };
  }
  get formErrors() {
    return this.flatten();
  }
};
ZodError.create = (issues) => {
  const error = new ZodError(issues);
  return error;
};

// ../../node_modules/.pnpm/zod@3.25.76/node_modules/zod/v3/locales/en.js
var errorMap = (issue, _ctx) => {
  let message;
  switch (issue.code) {
    case ZodIssueCode.invalid_type:
      if (issue.received === ZodParsedType.undefined) {
        message = "Required";
      } else {
        message = `Expected ${issue.expected}, received ${issue.received}`;
      }
      break;
    case ZodIssueCode.invalid_literal:
      message = `Invalid literal value, expected ${JSON.stringify(issue.expected, util.jsonStringifyReplacer)}`;
      break;
    case ZodIssueCode.unrecognized_keys:
      message = `Unrecognized key(s) in object: ${util.joinValues(issue.keys, ", ")}`;
      break;
    case ZodIssueCode.invalid_union:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_union_discriminator:
      message = `Invalid discriminator value. Expected ${util.joinValues(issue.options)}`;
      break;
    case ZodIssueCode.invalid_enum_value:
      message = `Invalid enum value. Expected ${util.joinValues(issue.options)}, received '${issue.received}'`;
      break;
    case ZodIssueCode.invalid_arguments:
      message = `Invalid function arguments`;
      break;
    case ZodIssueCode.invalid_return_type:
      message = `Invalid function return type`;
      break;
    case ZodIssueCode.invalid_date:
      message = `Invalid date`;
      break;
    case ZodIssueCode.invalid_string:
      if (typeof issue.validation === "object") {
        if ("includes" in issue.validation) {
          message = `Invalid input: must include "${issue.validation.includes}"`;
          if (typeof issue.validation.position === "number") {
            message = `${message} at one or more positions greater than or equal to ${issue.validation.position}`;
          }
        } else if ("startsWith" in issue.validation) {
          message = `Invalid input: must start with "${issue.validation.startsWith}"`;
        } else if ("endsWith" in issue.validation) {
          message = `Invalid input: must end with "${issue.validation.endsWith}"`;
        } else {
          util.assertNever(issue.validation);
        }
      } else if (issue.validation !== "regex") {
        message = `Invalid ${issue.validation}`;
      } else {
        message = "Invalid";
      }
      break;
    case ZodIssueCode.too_small:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `more than`} ${issue.minimum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `over`} ${issue.minimum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "bigint")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${new Date(Number(issue.minimum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.too_big:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `less than`} ${issue.maximum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `under`} ${issue.maximum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "bigint")
        message = `BigInt must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly` : issue.inclusive ? `smaller than or equal to` : `smaller than`} ${new Date(Number(issue.maximum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.custom:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_intersection_types:
      message = `Intersection results could not be merged`;
      break;
    case ZodIssueCode.not_multiple_of:
      message = `Number must be a multiple of ${issue.multipleOf}`;
      break;
    case ZodIssueCode.not_finite:
      message = "Number must be finite";
      break;
    default:
      message = _ctx.defaultError;
      util.assertNever(issue);
  }
  return { message };
};
var en_default = errorMap;

// ../../node_modules/.pnpm/zod@3.25.76/node_modules/zod/v3/errors.js
var overrideErrorMap = en_default;
function setErrorMap(map) {
  overrideErrorMap = map;
}
function getErrorMap() {
  return overrideErrorMap;
}

// ../../node_modules/.pnpm/zod@3.25.76/node_modules/zod/v3/helpers/parseUtil.js
var makeIssue = (params) => {
  const { data, path, errorMaps, issueData } = params;
  const fullPath = [...path, ...issueData.path || []];
  const fullIssue = {
    ...issueData,
    path: fullPath
  };
  if (issueData.message !== void 0) {
    return {
      ...issueData,
      path: fullPath,
      message: issueData.message
    };
  }
  let errorMessage = "";
  const maps = errorMaps.filter((m) => !!m).slice().reverse();
  for (const map of maps) {
    errorMessage = map(fullIssue, { data, defaultError: errorMessage }).message;
  }
  return {
    ...issueData,
    path: fullPath,
    message: errorMessage
  };
};
var EMPTY_PATH = [];
function addIssueToContext(ctx, issueData) {
  const overrideMap = getErrorMap();
  const issue = makeIssue({
    issueData,
    data: ctx.data,
    path: ctx.path,
    errorMaps: [
      ctx.common.contextualErrorMap,
      // contextual error map is first priority
      ctx.schemaErrorMap,
      // then schema-bound map if available
      overrideMap,
      // then global override map
      overrideMap === en_default ? void 0 : en_default
      // then global default map
    ].filter((x) => !!x)
  });
  ctx.common.issues.push(issue);
}
var ParseStatus = class _ParseStatus {
  constructor() {
    this.value = "valid";
  }
  dirty() {
    if (this.value === "valid")
      this.value = "dirty";
  }
  abort() {
    if (this.value !== "aborted")
      this.value = "aborted";
  }
  static mergeArray(status, results) {
    const arrayValue = [];
    for (const s of results) {
      if (s.status === "aborted")
        return INVALID;
      if (s.status === "dirty")
        status.dirty();
      arrayValue.push(s.value);
    }
    return { status: status.value, value: arrayValue };
  }
  static async mergeObjectAsync(status, pairs) {
    const syncPairs = [];
    for (const pair of pairs) {
      const key = await pair.key;
      const value = await pair.value;
      syncPairs.push({
        key,
        value
      });
    }
    return _ParseStatus.mergeObjectSync(status, syncPairs);
  }
  static mergeObjectSync(status, pairs) {
    const finalObject = {};
    for (const pair of pairs) {
      const { key, value } = pair;
      if (key.status === "aborted")
        return INVALID;
      if (value.status === "aborted")
        return INVALID;
      if (key.status === "dirty")
        status.dirty();
      if (value.status === "dirty")
        status.dirty();
      if (key.value !== "__proto__" && (typeof value.value !== "undefined" || pair.alwaysSet)) {
        finalObject[key.value] = value.value;
      }
    }
    return { status: status.value, value: finalObject };
  }
};
var INVALID = Object.freeze({
  status: "aborted"
});
var DIRTY = (value) => ({ status: "dirty", value });
var OK = (value) => ({ status: "valid", value });
var isAborted = (x) => x.status === "aborted";
var isDirty = (x) => x.status === "dirty";
var isValid = (x) => x.status === "valid";
var isAsync = (x) => typeof Promise !== "undefined" && x instanceof Promise;

// ../../node_modules/.pnpm/zod@3.25.76/node_modules/zod/v3/helpers/errorUtil.js
var errorUtil;
(function(errorUtil2) {
  errorUtil2.errToObj = (message) => typeof message === "string" ? { message } : message || {};
  errorUtil2.toString = (message) => typeof message === "string" ? message : message?.message;
})(errorUtil || (errorUtil = {}));

// ../../node_modules/.pnpm/zod@3.25.76/node_modules/zod/v3/types.js
var ParseInputLazyPath = class {
  constructor(parent, value, path, key) {
    this._cachedPath = [];
    this.parent = parent;
    this.data = value;
    this._path = path;
    this._key = key;
  }
  get path() {
    if (!this._cachedPath.length) {
      if (Array.isArray(this._key)) {
        this._cachedPath.push(...this._path, ...this._key);
      } else {
        this._cachedPath.push(...this._path, this._key);
      }
    }
    return this._cachedPath;
  }
};
var handleResult = (ctx, result) => {
  if (isValid(result)) {
    return { success: true, data: result.value };
  } else {
    if (!ctx.common.issues.length) {
      throw new Error("Validation failed but no issues detected.");
    }
    return {
      success: false,
      get error() {
        if (this._error)
          return this._error;
        const error = new ZodError(ctx.common.issues);
        this._error = error;
        return this._error;
      }
    };
  }
};
function processCreateParams(params) {
  if (!params)
    return {};
  const { errorMap: errorMap2, invalid_type_error, required_error, description } = params;
  if (errorMap2 && (invalid_type_error || required_error)) {
    throw new Error(`Can't use "invalid_type_error" or "required_error" in conjunction with custom error map.`);
  }
  if (errorMap2)
    return { errorMap: errorMap2, description };
  const customMap = (iss, ctx) => {
    const { message } = params;
    if (iss.code === "invalid_enum_value") {
      return { message: message ?? ctx.defaultError };
    }
    if (typeof ctx.data === "undefined") {
      return { message: message ?? required_error ?? ctx.defaultError };
    }
    if (iss.code !== "invalid_type")
      return { message: ctx.defaultError };
    return { message: message ?? invalid_type_error ?? ctx.defaultError };
  };
  return { errorMap: customMap, description };
}
var ZodType = class {
  get description() {
    return this._def.description;
  }
  _getType(input) {
    return getParsedType(input.data);
  }
  _getOrReturnCtx(input, ctx) {
    return ctx || {
      common: input.parent.common,
      data: input.data,
      parsedType: getParsedType(input.data),
      schemaErrorMap: this._def.errorMap,
      path: input.path,
      parent: input.parent
    };
  }
  _processInputParams(input) {
    return {
      status: new ParseStatus(),
      ctx: {
        common: input.parent.common,
        data: input.data,
        parsedType: getParsedType(input.data),
        schemaErrorMap: this._def.errorMap,
        path: input.path,
        parent: input.parent
      }
    };
  }
  _parseSync(input) {
    const result = this._parse(input);
    if (isAsync(result)) {
      throw new Error("Synchronous parse encountered promise.");
    }
    return result;
  }
  _parseAsync(input) {
    const result = this._parse(input);
    return Promise.resolve(result);
  }
  parse(data, params) {
    const result = this.safeParse(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  safeParse(data, params) {
    const ctx = {
      common: {
        issues: [],
        async: params?.async ?? false,
        contextualErrorMap: params?.errorMap
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const result = this._parseSync({ data, path: ctx.path, parent: ctx });
    return handleResult(ctx, result);
  }
  "~validate"(data) {
    const ctx = {
      common: {
        issues: [],
        async: !!this["~standard"].async
      },
      path: [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    if (!this["~standard"].async) {
      try {
        const result = this._parseSync({ data, path: [], parent: ctx });
        return isValid(result) ? {
          value: result.value
        } : {
          issues: ctx.common.issues
        };
      } catch (err) {
        if (err?.message?.toLowerCase()?.includes("encountered")) {
          this["~standard"].async = true;
        }
        ctx.common = {
          issues: [],
          async: true
        };
      }
    }
    return this._parseAsync({ data, path: [], parent: ctx }).then((result) => isValid(result) ? {
      value: result.value
    } : {
      issues: ctx.common.issues
    });
  }
  async parseAsync(data, params) {
    const result = await this.safeParseAsync(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  async safeParseAsync(data, params) {
    const ctx = {
      common: {
        issues: [],
        contextualErrorMap: params?.errorMap,
        async: true
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const maybeAsyncResult = this._parse({ data, path: ctx.path, parent: ctx });
    const result = await (isAsync(maybeAsyncResult) ? maybeAsyncResult : Promise.resolve(maybeAsyncResult));
    return handleResult(ctx, result);
  }
  refine(check, message) {
    const getIssueProperties = (val) => {
      if (typeof message === "string" || typeof message === "undefined") {
        return { message };
      } else if (typeof message === "function") {
        return message(val);
      } else {
        return message;
      }
    };
    return this._refinement((val, ctx) => {
      const result = check(val);
      const setError = () => ctx.addIssue({
        code: ZodIssueCode.custom,
        ...getIssueProperties(val)
      });
      if (typeof Promise !== "undefined" && result instanceof Promise) {
        return result.then((data) => {
          if (!data) {
            setError();
            return false;
          } else {
            return true;
          }
        });
      }
      if (!result) {
        setError();
        return false;
      } else {
        return true;
      }
    });
  }
  refinement(check, refinementData) {
    return this._refinement((val, ctx) => {
      if (!check(val)) {
        ctx.addIssue(typeof refinementData === "function" ? refinementData(val, ctx) : refinementData);
        return false;
      } else {
        return true;
      }
    });
  }
  _refinement(refinement) {
    return new ZodEffects({
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "refinement", refinement }
    });
  }
  superRefine(refinement) {
    return this._refinement(refinement);
  }
  constructor(def) {
    this.spa = this.safeParseAsync;
    this._def = def;
    this.parse = this.parse.bind(this);
    this.safeParse = this.safeParse.bind(this);
    this.parseAsync = this.parseAsync.bind(this);
    this.safeParseAsync = this.safeParseAsync.bind(this);
    this.spa = this.spa.bind(this);
    this.refine = this.refine.bind(this);
    this.refinement = this.refinement.bind(this);
    this.superRefine = this.superRefine.bind(this);
    this.optional = this.optional.bind(this);
    this.nullable = this.nullable.bind(this);
    this.nullish = this.nullish.bind(this);
    this.array = this.array.bind(this);
    this.promise = this.promise.bind(this);
    this.or = this.or.bind(this);
    this.and = this.and.bind(this);
    this.transform = this.transform.bind(this);
    this.brand = this.brand.bind(this);
    this.default = this.default.bind(this);
    this.catch = this.catch.bind(this);
    this.describe = this.describe.bind(this);
    this.pipe = this.pipe.bind(this);
    this.readonly = this.readonly.bind(this);
    this.isNullable = this.isNullable.bind(this);
    this.isOptional = this.isOptional.bind(this);
    this["~standard"] = {
      version: 1,
      vendor: "zod",
      validate: (data) => this["~validate"](data)
    };
  }
  optional() {
    return ZodOptional.create(this, this._def);
  }
  nullable() {
    return ZodNullable.create(this, this._def);
  }
  nullish() {
    return this.nullable().optional();
  }
  array() {
    return ZodArray.create(this);
  }
  promise() {
    return ZodPromise.create(this, this._def);
  }
  or(option) {
    return ZodUnion.create([this, option], this._def);
  }
  and(incoming) {
    return ZodIntersection.create(this, incoming, this._def);
  }
  transform(transform) {
    return new ZodEffects({
      ...processCreateParams(this._def),
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "transform", transform }
    });
  }
  default(def) {
    const defaultValueFunc = typeof def === "function" ? def : () => def;
    return new ZodDefault({
      ...processCreateParams(this._def),
      innerType: this,
      defaultValue: defaultValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodDefault
    });
  }
  brand() {
    return new ZodBranded({
      typeName: ZodFirstPartyTypeKind.ZodBranded,
      type: this,
      ...processCreateParams(this._def)
    });
  }
  catch(def) {
    const catchValueFunc = typeof def === "function" ? def : () => def;
    return new ZodCatch({
      ...processCreateParams(this._def),
      innerType: this,
      catchValue: catchValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodCatch
    });
  }
  describe(description) {
    const This = this.constructor;
    return new This({
      ...this._def,
      description
    });
  }
  pipe(target) {
    return ZodPipeline.create(this, target);
  }
  readonly() {
    return ZodReadonly.create(this);
  }
  isOptional() {
    return this.safeParse(void 0).success;
  }
  isNullable() {
    return this.safeParse(null).success;
  }
};
var cuidRegex = /^c[^\s-]{8,}$/i;
var cuid2Regex = /^[0-9a-z]+$/;
var ulidRegex = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
var uuidRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i;
var nanoidRegex = /^[a-z0-9_-]{21}$/i;
var jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
var durationRegex = /^[-+]?P(?!$)(?:(?:[-+]?\d+Y)|(?:[-+]?\d+[.,]\d+Y$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:(?:[-+]?\d+W)|(?:[-+]?\d+[.,]\d+W$))?(?:(?:[-+]?\d+D)|(?:[-+]?\d+[.,]\d+D$))?(?:T(?=[\d+-])(?:(?:[-+]?\d+H)|(?:[-+]?\d+[.,]\d+H$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:[-+]?\d+(?:[.,]\d+)?S)?)??$/;
var emailRegex = /^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-\.]*)[A-Z0-9_+-]@([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$/i;
var _emojiRegex = `^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$`;
var emojiRegex;
var ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
var ipv4CidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/(3[0-2]|[12]?[0-9])$/;
var ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
var ipv6CidrRegex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
var base64Regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
var base64urlRegex = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;
var dateRegexSource = `((\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\\d|3[01])|(0[469]|11)-(0[1-9]|[12]\\d|30)|(02)-(0[1-9]|1\\d|2[0-8])))`;
var dateRegex = new RegExp(`^${dateRegexSource}$`);
function timeRegexSource(args) {
  let secondsRegexSource = `[0-5]\\d`;
  if (args.precision) {
    secondsRegexSource = `${secondsRegexSource}\\.\\d{${args.precision}}`;
  } else if (args.precision == null) {
    secondsRegexSource = `${secondsRegexSource}(\\.\\d+)?`;
  }
  const secondsQuantifier = args.precision ? "+" : "?";
  return `([01]\\d|2[0-3]):[0-5]\\d(:${secondsRegexSource})${secondsQuantifier}`;
}
function timeRegex(args) {
  return new RegExp(`^${timeRegexSource(args)}$`);
}
function datetimeRegex(args) {
  let regex = `${dateRegexSource}T${timeRegexSource(args)}`;
  const opts = [];
  opts.push(args.local ? `Z?` : `Z`);
  if (args.offset)
    opts.push(`([+-]\\d{2}:?\\d{2})`);
  regex = `${regex}(${opts.join("|")})`;
  return new RegExp(`^${regex}$`);
}
function isValidIP(ip, version) {
  if ((version === "v4" || !version) && ipv4Regex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6Regex.test(ip)) {
    return true;
  }
  return false;
}
function isValidJWT(jwt, alg) {
  if (!jwtRegex.test(jwt))
    return false;
  try {
    const [header] = jwt.split(".");
    if (!header)
      return false;
    const base64 = header.replace(/-/g, "+").replace(/_/g, "/").padEnd(header.length + (4 - header.length % 4) % 4, "=");
    const decoded = JSON.parse(atob(base64));
    if (typeof decoded !== "object" || decoded === null)
      return false;
    if ("typ" in decoded && decoded?.typ !== "JWT")
      return false;
    if (!decoded.alg)
      return false;
    if (alg && decoded.alg !== alg)
      return false;
    return true;
  } catch {
    return false;
  }
}
function isValidCidr(ip, version) {
  if ((version === "v4" || !version) && ipv4CidrRegex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6CidrRegex.test(ip)) {
    return true;
  }
  return false;
}
var ZodString = class _ZodString extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = String(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.string) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.string,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    const status = new ParseStatus();
    let ctx = void 0;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.length < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.length > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "length") {
        const tooBig = input.data.length > check.value;
        const tooSmall = input.data.length < check.value;
        if (tooBig || tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          if (tooBig) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_big,
              maximum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          } else if (tooSmall) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_small,
              minimum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          }
          status.dirty();
        }
      } else if (check.kind === "email") {
        if (!emailRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "email",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "emoji") {
        if (!emojiRegex) {
          emojiRegex = new RegExp(_emojiRegex, "u");
        }
        if (!emojiRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "emoji",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "uuid") {
        if (!uuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "uuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "nanoid") {
        if (!nanoidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "nanoid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid") {
        if (!cuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid2") {
        if (!cuid2Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid2",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ulid") {
        if (!ulidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ulid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "url") {
        try {
          new URL(input.data);
        } catch {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "regex") {
        check.regex.lastIndex = 0;
        const testResult = check.regex.test(input.data);
        if (!testResult) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "regex",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "trim") {
        input.data = input.data.trim();
      } else if (check.kind === "includes") {
        if (!input.data.includes(check.value, check.position)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { includes: check.value, position: check.position },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "toLowerCase") {
        input.data = input.data.toLowerCase();
      } else if (check.kind === "toUpperCase") {
        input.data = input.data.toUpperCase();
      } else if (check.kind === "startsWith") {
        if (!input.data.startsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { startsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "endsWith") {
        if (!input.data.endsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { endsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "datetime") {
        const regex = datetimeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "datetime",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "date") {
        const regex = dateRegex;
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "date",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "time") {
        const regex = timeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "time",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "duration") {
        if (!durationRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "duration",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ip") {
        if (!isValidIP(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ip",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "jwt") {
        if (!isValidJWT(input.data, check.alg)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "jwt",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cidr") {
        if (!isValidCidr(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cidr",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64") {
        if (!base64Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64url") {
        if (!base64urlRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _regex(regex, validation, message) {
    return this.refinement((data) => regex.test(data), {
      validation,
      code: ZodIssueCode.invalid_string,
      ...errorUtil.errToObj(message)
    });
  }
  _addCheck(check) {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  email(message) {
    return this._addCheck({ kind: "email", ...errorUtil.errToObj(message) });
  }
  url(message) {
    return this._addCheck({ kind: "url", ...errorUtil.errToObj(message) });
  }
  emoji(message) {
    return this._addCheck({ kind: "emoji", ...errorUtil.errToObj(message) });
  }
  uuid(message) {
    return this._addCheck({ kind: "uuid", ...errorUtil.errToObj(message) });
  }
  nanoid(message) {
    return this._addCheck({ kind: "nanoid", ...errorUtil.errToObj(message) });
  }
  cuid(message) {
    return this._addCheck({ kind: "cuid", ...errorUtil.errToObj(message) });
  }
  cuid2(message) {
    return this._addCheck({ kind: "cuid2", ...errorUtil.errToObj(message) });
  }
  ulid(message) {
    return this._addCheck({ kind: "ulid", ...errorUtil.errToObj(message) });
  }
  base64(message) {
    return this._addCheck({ kind: "base64", ...errorUtil.errToObj(message) });
  }
  base64url(message) {
    return this._addCheck({
      kind: "base64url",
      ...errorUtil.errToObj(message)
    });
  }
  jwt(options) {
    return this._addCheck({ kind: "jwt", ...errorUtil.errToObj(options) });
  }
  ip(options) {
    return this._addCheck({ kind: "ip", ...errorUtil.errToObj(options) });
  }
  cidr(options) {
    return this._addCheck({ kind: "cidr", ...errorUtil.errToObj(options) });
  }
  datetime(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "datetime",
        precision: null,
        offset: false,
        local: false,
        message: options
      });
    }
    return this._addCheck({
      kind: "datetime",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      offset: options?.offset ?? false,
      local: options?.local ?? false,
      ...errorUtil.errToObj(options?.message)
    });
  }
  date(message) {
    return this._addCheck({ kind: "date", message });
  }
  time(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "time",
        precision: null,
        message: options
      });
    }
    return this._addCheck({
      kind: "time",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      ...errorUtil.errToObj(options?.message)
    });
  }
  duration(message) {
    return this._addCheck({ kind: "duration", ...errorUtil.errToObj(message) });
  }
  regex(regex, message) {
    return this._addCheck({
      kind: "regex",
      regex,
      ...errorUtil.errToObj(message)
    });
  }
  includes(value, options) {
    return this._addCheck({
      kind: "includes",
      value,
      position: options?.position,
      ...errorUtil.errToObj(options?.message)
    });
  }
  startsWith(value, message) {
    return this._addCheck({
      kind: "startsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  endsWith(value, message) {
    return this._addCheck({
      kind: "endsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  min(minLength, message) {
    return this._addCheck({
      kind: "min",
      value: minLength,
      ...errorUtil.errToObj(message)
    });
  }
  max(maxLength, message) {
    return this._addCheck({
      kind: "max",
      value: maxLength,
      ...errorUtil.errToObj(message)
    });
  }
  length(len, message) {
    return this._addCheck({
      kind: "length",
      value: len,
      ...errorUtil.errToObj(message)
    });
  }
  /**
   * Equivalent to `.min(1)`
   */
  nonempty(message) {
    return this.min(1, errorUtil.errToObj(message));
  }
  trim() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "trim" }]
    });
  }
  toLowerCase() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toLowerCase" }]
    });
  }
  toUpperCase() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toUpperCase" }]
    });
  }
  get isDatetime() {
    return !!this._def.checks.find((ch) => ch.kind === "datetime");
  }
  get isDate() {
    return !!this._def.checks.find((ch) => ch.kind === "date");
  }
  get isTime() {
    return !!this._def.checks.find((ch) => ch.kind === "time");
  }
  get isDuration() {
    return !!this._def.checks.find((ch) => ch.kind === "duration");
  }
  get isEmail() {
    return !!this._def.checks.find((ch) => ch.kind === "email");
  }
  get isURL() {
    return !!this._def.checks.find((ch) => ch.kind === "url");
  }
  get isEmoji() {
    return !!this._def.checks.find((ch) => ch.kind === "emoji");
  }
  get isUUID() {
    return !!this._def.checks.find((ch) => ch.kind === "uuid");
  }
  get isNANOID() {
    return !!this._def.checks.find((ch) => ch.kind === "nanoid");
  }
  get isCUID() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid");
  }
  get isCUID2() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid2");
  }
  get isULID() {
    return !!this._def.checks.find((ch) => ch.kind === "ulid");
  }
  get isIP() {
    return !!this._def.checks.find((ch) => ch.kind === "ip");
  }
  get isCIDR() {
    return !!this._def.checks.find((ch) => ch.kind === "cidr");
  }
  get isBase64() {
    return !!this._def.checks.find((ch) => ch.kind === "base64");
  }
  get isBase64url() {
    return !!this._def.checks.find((ch) => ch.kind === "base64url");
  }
  get minLength() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxLength() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
};
ZodString.create = (params) => {
  return new ZodString({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodString,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};
function floatSafeRemainder(val, step) {
  const valDecCount = (val.toString().split(".")[1] || "").length;
  const stepDecCount = (step.toString().split(".")[1] || "").length;
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  const valInt = Number.parseInt(val.toFixed(decCount).replace(".", ""));
  const stepInt = Number.parseInt(step.toFixed(decCount).replace(".", ""));
  return valInt % stepInt / 10 ** decCount;
}
var ZodNumber = class _ZodNumber extends ZodType {
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
    this.step = this.multipleOf;
  }
  _parse(input) {
    if (this._def.coerce) {
      input.data = Number(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.number) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.number,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    let ctx = void 0;
    const status = new ParseStatus();
    for (const check of this._def.checks) {
      if (check.kind === "int") {
        if (!util.isInteger(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: "integer",
            received: "float",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (floatSafeRemainder(input.data, check.value) !== 0) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "finite") {
        if (!Number.isFinite(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_finite,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new _ZodNumber({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new _ZodNumber({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  int(message) {
    return this._addCheck({
      kind: "int",
      message: errorUtil.toString(message)
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  finite(message) {
    return this._addCheck({
      kind: "finite",
      message: errorUtil.toString(message)
    });
  }
  safe(message) {
    return this._addCheck({
      kind: "min",
      inclusive: true,
      value: Number.MIN_SAFE_INTEGER,
      message: errorUtil.toString(message)
    })._addCheck({
      kind: "max",
      inclusive: true,
      value: Number.MAX_SAFE_INTEGER,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
  get isInt() {
    return !!this._def.checks.find((ch) => ch.kind === "int" || ch.kind === "multipleOf" && util.isInteger(ch.value));
  }
  get isFinite() {
    let max = null;
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "finite" || ch.kind === "int" || ch.kind === "multipleOf") {
        return true;
      } else if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      } else if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return Number.isFinite(min) && Number.isFinite(max);
  }
};
ZodNumber.create = (params) => {
  return new ZodNumber({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodNumber,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};
var ZodBigInt = class _ZodBigInt extends ZodType {
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
  }
  _parse(input) {
    if (this._def.coerce) {
      try {
        input.data = BigInt(input.data);
      } catch {
        return this._getInvalidInput(input);
      }
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.bigint) {
      return this._getInvalidInput(input);
    }
    let ctx = void 0;
    const status = new ParseStatus();
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            type: "bigint",
            minimum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            type: "bigint",
            maximum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (input.data % check.value !== BigInt(0)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _getInvalidInput(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.bigint,
      received: ctx.parsedType
    });
    return INVALID;
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new _ZodBigInt({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new _ZodBigInt({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
};
ZodBigInt.create = (params) => {
  return new ZodBigInt({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodBigInt,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};
var ZodBoolean = class extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = Boolean(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.boolean) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.boolean,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodBoolean.create = (params) => {
  return new ZodBoolean({
    typeName: ZodFirstPartyTypeKind.ZodBoolean,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};
var ZodDate = class _ZodDate extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = new Date(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.date) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.date,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    if (Number.isNaN(input.data.getTime())) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_date
      });
      return INVALID;
    }
    const status = new ParseStatus();
    let ctx = void 0;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.getTime() < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            message: check.message,
            inclusive: true,
            exact: false,
            minimum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.getTime() > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            message: check.message,
            inclusive: true,
            exact: false,
            maximum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return {
      status: status.value,
      value: new Date(input.data.getTime())
    };
  }
  _addCheck(check) {
    return new _ZodDate({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  min(minDate, message) {
    return this._addCheck({
      kind: "min",
      value: minDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  max(maxDate, message) {
    return this._addCheck({
      kind: "max",
      value: maxDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  get minDate() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min != null ? new Date(min) : null;
  }
  get maxDate() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max != null ? new Date(max) : null;
  }
};
ZodDate.create = (params) => {
  return new ZodDate({
    checks: [],
    coerce: params?.coerce || false,
    typeName: ZodFirstPartyTypeKind.ZodDate,
    ...processCreateParams(params)
  });
};
var ZodSymbol = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.symbol) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.symbol,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodSymbol.create = (params) => {
  return new ZodSymbol({
    typeName: ZodFirstPartyTypeKind.ZodSymbol,
    ...processCreateParams(params)
  });
};
var ZodUndefined = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.undefined,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodUndefined.create = (params) => {
  return new ZodUndefined({
    typeName: ZodFirstPartyTypeKind.ZodUndefined,
    ...processCreateParams(params)
  });
};
var ZodNull = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.null) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.null,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodNull.create = (params) => {
  return new ZodNull({
    typeName: ZodFirstPartyTypeKind.ZodNull,
    ...processCreateParams(params)
  });
};
var ZodAny = class extends ZodType {
  constructor() {
    super(...arguments);
    this._any = true;
  }
  _parse(input) {
    return OK(input.data);
  }
};
ZodAny.create = (params) => {
  return new ZodAny({
    typeName: ZodFirstPartyTypeKind.ZodAny,
    ...processCreateParams(params)
  });
};
var ZodUnknown = class extends ZodType {
  constructor() {
    super(...arguments);
    this._unknown = true;
  }
  _parse(input) {
    return OK(input.data);
  }
};
ZodUnknown.create = (params) => {
  return new ZodUnknown({
    typeName: ZodFirstPartyTypeKind.ZodUnknown,
    ...processCreateParams(params)
  });
};
var ZodNever = class extends ZodType {
  _parse(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.never,
      received: ctx.parsedType
    });
    return INVALID;
  }
};
ZodNever.create = (params) => {
  return new ZodNever({
    typeName: ZodFirstPartyTypeKind.ZodNever,
    ...processCreateParams(params)
  });
};
var ZodVoid = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.void,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodVoid.create = (params) => {
  return new ZodVoid({
    typeName: ZodFirstPartyTypeKind.ZodVoid,
    ...processCreateParams(params)
  });
};
var ZodArray = class _ZodArray extends ZodType {
  _parse(input) {
    const { ctx, status } = this._processInputParams(input);
    const def = this._def;
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (def.exactLength !== null) {
      const tooBig = ctx.data.length > def.exactLength.value;
      const tooSmall = ctx.data.length < def.exactLength.value;
      if (tooBig || tooSmall) {
        addIssueToContext(ctx, {
          code: tooBig ? ZodIssueCode.too_big : ZodIssueCode.too_small,
          minimum: tooSmall ? def.exactLength.value : void 0,
          maximum: tooBig ? def.exactLength.value : void 0,
          type: "array",
          inclusive: true,
          exact: true,
          message: def.exactLength.message
        });
        status.dirty();
      }
    }
    if (def.minLength !== null) {
      if (ctx.data.length < def.minLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.minLength.message
        });
        status.dirty();
      }
    }
    if (def.maxLength !== null) {
      if (ctx.data.length > def.maxLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.maxLength.message
        });
        status.dirty();
      }
    }
    if (ctx.common.async) {
      return Promise.all([...ctx.data].map((item, i) => {
        return def.type._parseAsync(new ParseInputLazyPath(ctx, item, ctx.path, i));
      })).then((result2) => {
        return ParseStatus.mergeArray(status, result2);
      });
    }
    const result = [...ctx.data].map((item, i) => {
      return def.type._parseSync(new ParseInputLazyPath(ctx, item, ctx.path, i));
    });
    return ParseStatus.mergeArray(status, result);
  }
  get element() {
    return this._def.type;
  }
  min(minLength, message) {
    return new _ZodArray({
      ...this._def,
      minLength: { value: minLength, message: errorUtil.toString(message) }
    });
  }
  max(maxLength, message) {
    return new _ZodArray({
      ...this._def,
      maxLength: { value: maxLength, message: errorUtil.toString(message) }
    });
  }
  length(len, message) {
    return new _ZodArray({
      ...this._def,
      exactLength: { value: len, message: errorUtil.toString(message) }
    });
  }
  nonempty(message) {
    return this.min(1, message);
  }
};
ZodArray.create = (schema, params) => {
  return new ZodArray({
    type: schema,
    minLength: null,
    maxLength: null,
    exactLength: null,
    typeName: ZodFirstPartyTypeKind.ZodArray,
    ...processCreateParams(params)
  });
};
function deepPartialify(schema) {
  if (schema instanceof ZodObject) {
    const newShape = {};
    for (const key in schema.shape) {
      const fieldSchema = schema.shape[key];
      newShape[key] = ZodOptional.create(deepPartialify(fieldSchema));
    }
    return new ZodObject({
      ...schema._def,
      shape: () => newShape
    });
  } else if (schema instanceof ZodArray) {
    return new ZodArray({
      ...schema._def,
      type: deepPartialify(schema.element)
    });
  } else if (schema instanceof ZodOptional) {
    return ZodOptional.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodNullable) {
    return ZodNullable.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodTuple) {
    return ZodTuple.create(schema.items.map((item) => deepPartialify(item)));
  } else {
    return schema;
  }
}
var ZodObject = class _ZodObject extends ZodType {
  constructor() {
    super(...arguments);
    this._cached = null;
    this.nonstrict = this.passthrough;
    this.augment = this.extend;
  }
  _getCached() {
    if (this._cached !== null)
      return this._cached;
    const shape = this._def.shape();
    const keys = util.objectKeys(shape);
    this._cached = { shape, keys };
    return this._cached;
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.object) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    const { status, ctx } = this._processInputParams(input);
    const { shape, keys: shapeKeys } = this._getCached();
    const extraKeys = [];
    if (!(this._def.catchall instanceof ZodNever && this._def.unknownKeys === "strip")) {
      for (const key in ctx.data) {
        if (!shapeKeys.includes(key)) {
          extraKeys.push(key);
        }
      }
    }
    const pairs = [];
    for (const key of shapeKeys) {
      const keyValidator = shape[key];
      const value = ctx.data[key];
      pairs.push({
        key: { status: "valid", value: key },
        value: keyValidator._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (this._def.catchall instanceof ZodNever) {
      const unknownKeys = this._def.unknownKeys;
      if (unknownKeys === "passthrough") {
        for (const key of extraKeys) {
          pairs.push({
            key: { status: "valid", value: key },
            value: { status: "valid", value: ctx.data[key] }
          });
        }
      } else if (unknownKeys === "strict") {
        if (extraKeys.length > 0) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.unrecognized_keys,
            keys: extraKeys
          });
          status.dirty();
        }
      } else if (unknownKeys === "strip") {
      } else {
        throw new Error(`Internal ZodObject error: invalid unknownKeys value.`);
      }
    } else {
      const catchall = this._def.catchall;
      for (const key of extraKeys) {
        const value = ctx.data[key];
        pairs.push({
          key: { status: "valid", value: key },
          value: catchall._parse(
            new ParseInputLazyPath(ctx, value, ctx.path, key)
            //, ctx.child(key), value, getParsedType(value)
          ),
          alwaysSet: key in ctx.data
        });
      }
    }
    if (ctx.common.async) {
      return Promise.resolve().then(async () => {
        const syncPairs = [];
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          syncPairs.push({
            key,
            value,
            alwaysSet: pair.alwaysSet
          });
        }
        return syncPairs;
      }).then((syncPairs) => {
        return ParseStatus.mergeObjectSync(status, syncPairs);
      });
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get shape() {
    return this._def.shape();
  }
  strict(message) {
    errorUtil.errToObj;
    return new _ZodObject({
      ...this._def,
      unknownKeys: "strict",
      ...message !== void 0 ? {
        errorMap: (issue, ctx) => {
          const defaultError = this._def.errorMap?.(issue, ctx).message ?? ctx.defaultError;
          if (issue.code === "unrecognized_keys")
            return {
              message: errorUtil.errToObj(message).message ?? defaultError
            };
          return {
            message: defaultError
          };
        }
      } : {}
    });
  }
  strip() {
    return new _ZodObject({
      ...this._def,
      unknownKeys: "strip"
    });
  }
  passthrough() {
    return new _ZodObject({
      ...this._def,
      unknownKeys: "passthrough"
    });
  }
  // const AugmentFactory =
  //   <Def extends ZodObjectDef>(def: Def) =>
  //   <Augmentation extends ZodRawShape>(
  //     augmentation: Augmentation
  //   ): ZodObject<
  //     extendShape<ReturnType<Def["shape"]>, Augmentation>,
  //     Def["unknownKeys"],
  //     Def["catchall"]
  //   > => {
  //     return new ZodObject({
  //       ...def,
  //       shape: () => ({
  //         ...def.shape(),
  //         ...augmentation,
  //       }),
  //     }) as any;
  //   };
  extend(augmentation) {
    return new _ZodObject({
      ...this._def,
      shape: () => ({
        ...this._def.shape(),
        ...augmentation
      })
    });
  }
  /**
   * Prior to zod@1.0.12 there was a bug in the
   * inferred type of merged objects. Please
   * upgrade if you are experiencing issues.
   */
  merge(merging) {
    const merged = new _ZodObject({
      unknownKeys: merging._def.unknownKeys,
      catchall: merging._def.catchall,
      shape: () => ({
        ...this._def.shape(),
        ...merging._def.shape()
      }),
      typeName: ZodFirstPartyTypeKind.ZodObject
    });
    return merged;
  }
  // merge<
  //   Incoming extends AnyZodObject,
  //   Augmentation extends Incoming["shape"],
  //   NewOutput extends {
  //     [k in keyof Augmentation | keyof Output]: k extends keyof Augmentation
  //       ? Augmentation[k]["_output"]
  //       : k extends keyof Output
  //       ? Output[k]
  //       : never;
  //   },
  //   NewInput extends {
  //     [k in keyof Augmentation | keyof Input]: k extends keyof Augmentation
  //       ? Augmentation[k]["_input"]
  //       : k extends keyof Input
  //       ? Input[k]
  //       : never;
  //   }
  // >(
  //   merging: Incoming
  // ): ZodObject<
  //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
  //   Incoming["_def"]["unknownKeys"],
  //   Incoming["_def"]["catchall"],
  //   NewOutput,
  //   NewInput
  // > {
  //   const merged: any = new ZodObject({
  //     unknownKeys: merging._def.unknownKeys,
  //     catchall: merging._def.catchall,
  //     shape: () =>
  //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
  //     typeName: ZodFirstPartyTypeKind.ZodObject,
  //   }) as any;
  //   return merged;
  // }
  setKey(key, schema) {
    return this.augment({ [key]: schema });
  }
  // merge<Incoming extends AnyZodObject>(
  //   merging: Incoming
  // ): //ZodObject<T & Incoming["_shape"], UnknownKeys, Catchall> = (merging) => {
  // ZodObject<
  //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
  //   Incoming["_def"]["unknownKeys"],
  //   Incoming["_def"]["catchall"]
  // > {
  //   // const mergedShape = objectUtil.mergeShapes(
  //   //   this._def.shape(),
  //   //   merging._def.shape()
  //   // );
  //   const merged: any = new ZodObject({
  //     unknownKeys: merging._def.unknownKeys,
  //     catchall: merging._def.catchall,
  //     shape: () =>
  //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
  //     typeName: ZodFirstPartyTypeKind.ZodObject,
  //   }) as any;
  //   return merged;
  // }
  catchall(index) {
    return new _ZodObject({
      ...this._def,
      catchall: index
    });
  }
  pick(mask) {
    const shape = {};
    for (const key of util.objectKeys(mask)) {
      if (mask[key] && this.shape[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: () => shape
    });
  }
  omit(mask) {
    const shape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (!mask[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: () => shape
    });
  }
  /**
   * @deprecated
   */
  deepPartial() {
    return deepPartialify(this);
  }
  partial(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      const fieldSchema = this.shape[key];
      if (mask && !mask[key]) {
        newShape[key] = fieldSchema;
      } else {
        newShape[key] = fieldSchema.optional();
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: () => newShape
    });
  }
  required(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (mask && !mask[key]) {
        newShape[key] = this.shape[key];
      } else {
        const fieldSchema = this.shape[key];
        let newField = fieldSchema;
        while (newField instanceof ZodOptional) {
          newField = newField._def.innerType;
        }
        newShape[key] = newField;
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: () => newShape
    });
  }
  keyof() {
    return createZodEnum(util.objectKeys(this.shape));
  }
};
ZodObject.create = (shape, params) => {
  return new ZodObject({
    shape: () => shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.strictCreate = (shape, params) => {
  return new ZodObject({
    shape: () => shape,
    unknownKeys: "strict",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.lazycreate = (shape, params) => {
  return new ZodObject({
    shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
var ZodUnion = class extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const options = this._def.options;
    function handleResults(results) {
      for (const result of results) {
        if (result.result.status === "valid") {
          return result.result;
        }
      }
      for (const result of results) {
        if (result.result.status === "dirty") {
          ctx.common.issues.push(...result.ctx.common.issues);
          return result.result;
        }
      }
      const unionErrors = results.map((result) => new ZodError(result.ctx.common.issues));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return Promise.all(options.map(async (option) => {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        return {
          result: await option._parseAsync({
            data: ctx.data,
            path: ctx.path,
            parent: childCtx
          }),
          ctx: childCtx
        };
      })).then(handleResults);
    } else {
      let dirty = void 0;
      const issues = [];
      for (const option of options) {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        const result = option._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: childCtx
        });
        if (result.status === "valid") {
          return result;
        } else if (result.status === "dirty" && !dirty) {
          dirty = { result, ctx: childCtx };
        }
        if (childCtx.common.issues.length) {
          issues.push(childCtx.common.issues);
        }
      }
      if (dirty) {
        ctx.common.issues.push(...dirty.ctx.common.issues);
        return dirty.result;
      }
      const unionErrors = issues.map((issues2) => new ZodError(issues2));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
  }
  get options() {
    return this._def.options;
  }
};
ZodUnion.create = (types, params) => {
  return new ZodUnion({
    options: types,
    typeName: ZodFirstPartyTypeKind.ZodUnion,
    ...processCreateParams(params)
  });
};
var getDiscriminator = (type) => {
  if (type instanceof ZodLazy) {
    return getDiscriminator(type.schema);
  } else if (type instanceof ZodEffects) {
    return getDiscriminator(type.innerType());
  } else if (type instanceof ZodLiteral) {
    return [type.value];
  } else if (type instanceof ZodEnum) {
    return type.options;
  } else if (type instanceof ZodNativeEnum) {
    return util.objectValues(type.enum);
  } else if (type instanceof ZodDefault) {
    return getDiscriminator(type._def.innerType);
  } else if (type instanceof ZodUndefined) {
    return [void 0];
  } else if (type instanceof ZodNull) {
    return [null];
  } else if (type instanceof ZodOptional) {
    return [void 0, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodNullable) {
    return [null, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodBranded) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodReadonly) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodCatch) {
    return getDiscriminator(type._def.innerType);
  } else {
    return [];
  }
};
var ZodDiscriminatedUnion = class _ZodDiscriminatedUnion extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const discriminator = this.discriminator;
    const discriminatorValue = ctx.data[discriminator];
    const option = this.optionsMap.get(discriminatorValue);
    if (!option) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union_discriminator,
        options: Array.from(this.optionsMap.keys()),
        path: [discriminator]
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return option._parseAsync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    } else {
      return option._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    }
  }
  get discriminator() {
    return this._def.discriminator;
  }
  get options() {
    return this._def.options;
  }
  get optionsMap() {
    return this._def.optionsMap;
  }
  /**
   * The constructor of the discriminated union schema. Its behaviour is very similar to that of the normal z.union() constructor.
   * However, it only allows a union of objects, all of which need to share a discriminator property. This property must
   * have a different value for each object in the union.
   * @param discriminator the name of the discriminator property
   * @param types an array of object schemas
   * @param params
   */
  static create(discriminator, options, params) {
    const optionsMap = /* @__PURE__ */ new Map();
    for (const type of options) {
      const discriminatorValues = getDiscriminator(type.shape[discriminator]);
      if (!discriminatorValues.length) {
        throw new Error(`A discriminator value for key \`${discriminator}\` could not be extracted from all schema options`);
      }
      for (const value of discriminatorValues) {
        if (optionsMap.has(value)) {
          throw new Error(`Discriminator property ${String(discriminator)} has duplicate value ${String(value)}`);
        }
        optionsMap.set(value, type);
      }
    }
    return new _ZodDiscriminatedUnion({
      typeName: ZodFirstPartyTypeKind.ZodDiscriminatedUnion,
      discriminator,
      options,
      optionsMap,
      ...processCreateParams(params)
    });
  }
};
function mergeValues(a, b) {
  const aType = getParsedType(a);
  const bType = getParsedType(b);
  if (a === b) {
    return { valid: true, data: a };
  } else if (aType === ZodParsedType.object && bType === ZodParsedType.object) {
    const bKeys = util.objectKeys(b);
    const sharedKeys = util.objectKeys(a).filter((key) => bKeys.indexOf(key) !== -1);
    const newObj = { ...a, ...b };
    for (const key of sharedKeys) {
      const sharedValue = mergeValues(a[key], b[key]);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newObj[key] = sharedValue.data;
    }
    return { valid: true, data: newObj };
  } else if (aType === ZodParsedType.array && bType === ZodParsedType.array) {
    if (a.length !== b.length) {
      return { valid: false };
    }
    const newArray = [];
    for (let index = 0; index < a.length; index++) {
      const itemA = a[index];
      const itemB = b[index];
      const sharedValue = mergeValues(itemA, itemB);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newArray.push(sharedValue.data);
    }
    return { valid: true, data: newArray };
  } else if (aType === ZodParsedType.date && bType === ZodParsedType.date && +a === +b) {
    return { valid: true, data: a };
  } else {
    return { valid: false };
  }
}
var ZodIntersection = class extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const handleParsed = (parsedLeft, parsedRight) => {
      if (isAborted(parsedLeft) || isAborted(parsedRight)) {
        return INVALID;
      }
      const merged = mergeValues(parsedLeft.value, parsedRight.value);
      if (!merged.valid) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.invalid_intersection_types
        });
        return INVALID;
      }
      if (isDirty(parsedLeft) || isDirty(parsedRight)) {
        status.dirty();
      }
      return { status: status.value, value: merged.data };
    };
    if (ctx.common.async) {
      return Promise.all([
        this._def.left._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        }),
        this._def.right._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        })
      ]).then(([left, right]) => handleParsed(left, right));
    } else {
      return handleParsed(this._def.left._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }), this._def.right._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }));
    }
  }
};
ZodIntersection.create = (left, right, params) => {
  return new ZodIntersection({
    left,
    right,
    typeName: ZodFirstPartyTypeKind.ZodIntersection,
    ...processCreateParams(params)
  });
};
var ZodTuple = class _ZodTuple extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (ctx.data.length < this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_small,
        minimum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      return INVALID;
    }
    const rest = this._def.rest;
    if (!rest && ctx.data.length > this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_big,
        maximum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      status.dirty();
    }
    const items = [...ctx.data].map((item, itemIndex) => {
      const schema = this._def.items[itemIndex] || this._def.rest;
      if (!schema)
        return null;
      return schema._parse(new ParseInputLazyPath(ctx, item, ctx.path, itemIndex));
    }).filter((x) => !!x);
    if (ctx.common.async) {
      return Promise.all(items).then((results) => {
        return ParseStatus.mergeArray(status, results);
      });
    } else {
      return ParseStatus.mergeArray(status, items);
    }
  }
  get items() {
    return this._def.items;
  }
  rest(rest) {
    return new _ZodTuple({
      ...this._def,
      rest
    });
  }
};
ZodTuple.create = (schemas, params) => {
  if (!Array.isArray(schemas)) {
    throw new Error("You must pass an array of schemas to z.tuple([ ... ])");
  }
  return new ZodTuple({
    items: schemas,
    typeName: ZodFirstPartyTypeKind.ZodTuple,
    rest: null,
    ...processCreateParams(params)
  });
};
var ZodRecord = class _ZodRecord extends ZodType {
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const pairs = [];
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    for (const key in ctx.data) {
      pairs.push({
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, key)),
        value: valueType._parse(new ParseInputLazyPath(ctx, ctx.data[key], ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (ctx.common.async) {
      return ParseStatus.mergeObjectAsync(status, pairs);
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get element() {
    return this._def.valueType;
  }
  static create(first, second, third) {
    if (second instanceof ZodType) {
      return new _ZodRecord({
        keyType: first,
        valueType: second,
        typeName: ZodFirstPartyTypeKind.ZodRecord,
        ...processCreateParams(third)
      });
    }
    return new _ZodRecord({
      keyType: ZodString.create(),
      valueType: first,
      typeName: ZodFirstPartyTypeKind.ZodRecord,
      ...processCreateParams(second)
    });
  }
};
var ZodMap = class extends ZodType {
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.map) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.map,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    const pairs = [...ctx.data.entries()].map(([key, value], index) => {
      return {
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, [index, "key"])),
        value: valueType._parse(new ParseInputLazyPath(ctx, value, ctx.path, [index, "value"]))
      };
    });
    if (ctx.common.async) {
      const finalMap = /* @__PURE__ */ new Map();
      return Promise.resolve().then(async () => {
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          if (key.status === "aborted" || value.status === "aborted") {
            return INVALID;
          }
          if (key.status === "dirty" || value.status === "dirty") {
            status.dirty();
          }
          finalMap.set(key.value, value.value);
        }
        return { status: status.value, value: finalMap };
      });
    } else {
      const finalMap = /* @__PURE__ */ new Map();
      for (const pair of pairs) {
        const key = pair.key;
        const value = pair.value;
        if (key.status === "aborted" || value.status === "aborted") {
          return INVALID;
        }
        if (key.status === "dirty" || value.status === "dirty") {
          status.dirty();
        }
        finalMap.set(key.value, value.value);
      }
      return { status: status.value, value: finalMap };
    }
  }
};
ZodMap.create = (keyType, valueType, params) => {
  return new ZodMap({
    valueType,
    keyType,
    typeName: ZodFirstPartyTypeKind.ZodMap,
    ...processCreateParams(params)
  });
};
var ZodSet = class _ZodSet extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.set) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.set,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const def = this._def;
    if (def.minSize !== null) {
      if (ctx.data.size < def.minSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.minSize.message
        });
        status.dirty();
      }
    }
    if (def.maxSize !== null) {
      if (ctx.data.size > def.maxSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.maxSize.message
        });
        status.dirty();
      }
    }
    const valueType = this._def.valueType;
    function finalizeSet(elements2) {
      const parsedSet = /* @__PURE__ */ new Set();
      for (const element of elements2) {
        if (element.status === "aborted")
          return INVALID;
        if (element.status === "dirty")
          status.dirty();
        parsedSet.add(element.value);
      }
      return { status: status.value, value: parsedSet };
    }
    const elements = [...ctx.data.values()].map((item, i) => valueType._parse(new ParseInputLazyPath(ctx, item, ctx.path, i)));
    if (ctx.common.async) {
      return Promise.all(elements).then((elements2) => finalizeSet(elements2));
    } else {
      return finalizeSet(elements);
    }
  }
  min(minSize, message) {
    return new _ZodSet({
      ...this._def,
      minSize: { value: minSize, message: errorUtil.toString(message) }
    });
  }
  max(maxSize, message) {
    return new _ZodSet({
      ...this._def,
      maxSize: { value: maxSize, message: errorUtil.toString(message) }
    });
  }
  size(size, message) {
    return this.min(size, message).max(size, message);
  }
  nonempty(message) {
    return this.min(1, message);
  }
};
ZodSet.create = (valueType, params) => {
  return new ZodSet({
    valueType,
    minSize: null,
    maxSize: null,
    typeName: ZodFirstPartyTypeKind.ZodSet,
    ...processCreateParams(params)
  });
};
var ZodFunction = class _ZodFunction extends ZodType {
  constructor() {
    super(...arguments);
    this.validate = this.implement;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.function) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.function,
        received: ctx.parsedType
      });
      return INVALID;
    }
    function makeArgsIssue(args, error) {
      return makeIssue({
        data: args,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_arguments,
          argumentsError: error
        }
      });
    }
    function makeReturnsIssue(returns, error) {
      return makeIssue({
        data: returns,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_return_type,
          returnTypeError: error
        }
      });
    }
    const params = { errorMap: ctx.common.contextualErrorMap };
    const fn = ctx.data;
    if (this._def.returns instanceof ZodPromise) {
      const me = this;
      return OK(async function(...args) {
        const error = new ZodError([]);
        const parsedArgs = await me._def.args.parseAsync(args, params).catch((e) => {
          error.addIssue(makeArgsIssue(args, e));
          throw error;
        });
        const result = await Reflect.apply(fn, this, parsedArgs);
        const parsedReturns = await me._def.returns._def.type.parseAsync(result, params).catch((e) => {
          error.addIssue(makeReturnsIssue(result, e));
          throw error;
        });
        return parsedReturns;
      });
    } else {
      const me = this;
      return OK(function(...args) {
        const parsedArgs = me._def.args.safeParse(args, params);
        if (!parsedArgs.success) {
          throw new ZodError([makeArgsIssue(args, parsedArgs.error)]);
        }
        const result = Reflect.apply(fn, this, parsedArgs.data);
        const parsedReturns = me._def.returns.safeParse(result, params);
        if (!parsedReturns.success) {
          throw new ZodError([makeReturnsIssue(result, parsedReturns.error)]);
        }
        return parsedReturns.data;
      });
    }
  }
  parameters() {
    return this._def.args;
  }
  returnType() {
    return this._def.returns;
  }
  args(...items) {
    return new _ZodFunction({
      ...this._def,
      args: ZodTuple.create(items).rest(ZodUnknown.create())
    });
  }
  returns(returnType) {
    return new _ZodFunction({
      ...this._def,
      returns: returnType
    });
  }
  implement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  strictImplement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  static create(args, returns, params) {
    return new _ZodFunction({
      args: args ? args : ZodTuple.create([]).rest(ZodUnknown.create()),
      returns: returns || ZodUnknown.create(),
      typeName: ZodFirstPartyTypeKind.ZodFunction,
      ...processCreateParams(params)
    });
  }
};
var ZodLazy = class extends ZodType {
  get schema() {
    return this._def.getter();
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const lazySchema = this._def.getter();
    return lazySchema._parse({ data: ctx.data, path: ctx.path, parent: ctx });
  }
};
ZodLazy.create = (getter, params) => {
  return new ZodLazy({
    getter,
    typeName: ZodFirstPartyTypeKind.ZodLazy,
    ...processCreateParams(params)
  });
};
var ZodLiteral = class extends ZodType {
  _parse(input) {
    if (input.data !== this._def.value) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_literal,
        expected: this._def.value
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
  get value() {
    return this._def.value;
  }
};
ZodLiteral.create = (value, params) => {
  return new ZodLiteral({
    value,
    typeName: ZodFirstPartyTypeKind.ZodLiteral,
    ...processCreateParams(params)
  });
};
function createZodEnum(values, params) {
  return new ZodEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodEnum,
    ...processCreateParams(params)
  });
}
var ZodEnum = class _ZodEnum extends ZodType {
  _parse(input) {
    if (typeof input.data !== "string") {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(this._def.values);
    }
    if (!this._cache.has(input.data)) {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get options() {
    return this._def.values;
  }
  get enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Values() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  extract(values, newDef = this._def) {
    return _ZodEnum.create(values, {
      ...this._def,
      ...newDef
    });
  }
  exclude(values, newDef = this._def) {
    return _ZodEnum.create(this.options.filter((opt) => !values.includes(opt)), {
      ...this._def,
      ...newDef
    });
  }
};
ZodEnum.create = createZodEnum;
var ZodNativeEnum = class extends ZodType {
  _parse(input) {
    const nativeEnumValues = util.getValidEnumValues(this._def.values);
    const ctx = this._getOrReturnCtx(input);
    if (ctx.parsedType !== ZodParsedType.string && ctx.parsedType !== ZodParsedType.number) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(util.getValidEnumValues(this._def.values));
    }
    if (!this._cache.has(input.data)) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get enum() {
    return this._def.values;
  }
};
ZodNativeEnum.create = (values, params) => {
  return new ZodNativeEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodNativeEnum,
    ...processCreateParams(params)
  });
};
var ZodPromise = class extends ZodType {
  unwrap() {
    return this._def.type;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.promise && ctx.common.async === false) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.promise,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const promisified = ctx.parsedType === ZodParsedType.promise ? ctx.data : Promise.resolve(ctx.data);
    return OK(promisified.then((data) => {
      return this._def.type.parseAsync(data, {
        path: ctx.path,
        errorMap: ctx.common.contextualErrorMap
      });
    }));
  }
};
ZodPromise.create = (schema, params) => {
  return new ZodPromise({
    type: schema,
    typeName: ZodFirstPartyTypeKind.ZodPromise,
    ...processCreateParams(params)
  });
};
var ZodEffects = class extends ZodType {
  innerType() {
    return this._def.schema;
  }
  sourceType() {
    return this._def.schema._def.typeName === ZodFirstPartyTypeKind.ZodEffects ? this._def.schema.sourceType() : this._def.schema;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const effect = this._def.effect || null;
    const checkCtx = {
      addIssue: (arg) => {
        addIssueToContext(ctx, arg);
        if (arg.fatal) {
          status.abort();
        } else {
          status.dirty();
        }
      },
      get path() {
        return ctx.path;
      }
    };
    checkCtx.addIssue = checkCtx.addIssue.bind(checkCtx);
    if (effect.type === "preprocess") {
      const processed = effect.transform(ctx.data, checkCtx);
      if (ctx.common.async) {
        return Promise.resolve(processed).then(async (processed2) => {
          if (status.value === "aborted")
            return INVALID;
          const result = await this._def.schema._parseAsync({
            data: processed2,
            path: ctx.path,
            parent: ctx
          });
          if (result.status === "aborted")
            return INVALID;
          if (result.status === "dirty")
            return DIRTY(result.value);
          if (status.value === "dirty")
            return DIRTY(result.value);
          return result;
        });
      } else {
        if (status.value === "aborted")
          return INVALID;
        const result = this._def.schema._parseSync({
          data: processed,
          path: ctx.path,
          parent: ctx
        });
        if (result.status === "aborted")
          return INVALID;
        if (result.status === "dirty")
          return DIRTY(result.value);
        if (status.value === "dirty")
          return DIRTY(result.value);
        return result;
      }
    }
    if (effect.type === "refinement") {
      const executeRefinement = (acc) => {
        const result = effect.refinement(acc, checkCtx);
        if (ctx.common.async) {
          return Promise.resolve(result);
        }
        if (result instanceof Promise) {
          throw new Error("Async refinement encountered during synchronous parse operation. Use .parseAsync instead.");
        }
        return acc;
      };
      if (ctx.common.async === false) {
        const inner = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inner.status === "aborted")
          return INVALID;
        if (inner.status === "dirty")
          status.dirty();
        executeRefinement(inner.value);
        return { status: status.value, value: inner.value };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((inner) => {
          if (inner.status === "aborted")
            return INVALID;
          if (inner.status === "dirty")
            status.dirty();
          return executeRefinement(inner.value).then(() => {
            return { status: status.value, value: inner.value };
          });
        });
      }
    }
    if (effect.type === "transform") {
      if (ctx.common.async === false) {
        const base = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (!isValid(base))
          return INVALID;
        const result = effect.transform(base.value, checkCtx);
        if (result instanceof Promise) {
          throw new Error(`Asynchronous transform encountered during synchronous parse operation. Use .parseAsync instead.`);
        }
        return { status: status.value, value: result };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((base) => {
          if (!isValid(base))
            return INVALID;
          return Promise.resolve(effect.transform(base.value, checkCtx)).then((result) => ({
            status: status.value,
            value: result
          }));
        });
      }
    }
    util.assertNever(effect);
  }
};
ZodEffects.create = (schema, effect, params) => {
  return new ZodEffects({
    schema,
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    effect,
    ...processCreateParams(params)
  });
};
ZodEffects.createWithPreprocess = (preprocess, schema, params) => {
  return new ZodEffects({
    schema,
    effect: { type: "preprocess", transform: preprocess },
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    ...processCreateParams(params)
  });
};
var ZodOptional = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.undefined) {
      return OK(void 0);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodOptional.create = (type, params) => {
  return new ZodOptional({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodOptional,
    ...processCreateParams(params)
  });
};
var ZodNullable = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.null) {
      return OK(null);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodNullable.create = (type, params) => {
  return new ZodNullable({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodNullable,
    ...processCreateParams(params)
  });
};
var ZodDefault = class extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    let data = ctx.data;
    if (ctx.parsedType === ZodParsedType.undefined) {
      data = this._def.defaultValue();
    }
    return this._def.innerType._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  removeDefault() {
    return this._def.innerType;
  }
};
ZodDefault.create = (type, params) => {
  return new ZodDefault({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodDefault,
    defaultValue: typeof params.default === "function" ? params.default : () => params.default,
    ...processCreateParams(params)
  });
};
var ZodCatch = class extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const newCtx = {
      ...ctx,
      common: {
        ...ctx.common,
        issues: []
      }
    };
    const result = this._def.innerType._parse({
      data: newCtx.data,
      path: newCtx.path,
      parent: {
        ...newCtx
      }
    });
    if (isAsync(result)) {
      return result.then((result2) => {
        return {
          status: "valid",
          value: result2.status === "valid" ? result2.value : this._def.catchValue({
            get error() {
              return new ZodError(newCtx.common.issues);
            },
            input: newCtx.data
          })
        };
      });
    } else {
      return {
        status: "valid",
        value: result.status === "valid" ? result.value : this._def.catchValue({
          get error() {
            return new ZodError(newCtx.common.issues);
          },
          input: newCtx.data
        })
      };
    }
  }
  removeCatch() {
    return this._def.innerType;
  }
};
ZodCatch.create = (type, params) => {
  return new ZodCatch({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodCatch,
    catchValue: typeof params.catch === "function" ? params.catch : () => params.catch,
    ...processCreateParams(params)
  });
};
var ZodNaN = class extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.nan) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.nan,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
};
ZodNaN.create = (params) => {
  return new ZodNaN({
    typeName: ZodFirstPartyTypeKind.ZodNaN,
    ...processCreateParams(params)
  });
};
var BRAND = /* @__PURE__ */ Symbol("zod_brand");
var ZodBranded = class extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const data = ctx.data;
    return this._def.type._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  unwrap() {
    return this._def.type;
  }
};
var ZodPipeline = class _ZodPipeline extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.common.async) {
      const handleAsync = async () => {
        const inResult = await this._def.in._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inResult.status === "aborted")
          return INVALID;
        if (inResult.status === "dirty") {
          status.dirty();
          return DIRTY(inResult.value);
        } else {
          return this._def.out._parseAsync({
            data: inResult.value,
            path: ctx.path,
            parent: ctx
          });
        }
      };
      return handleAsync();
    } else {
      const inResult = this._def.in._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
      if (inResult.status === "aborted")
        return INVALID;
      if (inResult.status === "dirty") {
        status.dirty();
        return {
          status: "dirty",
          value: inResult.value
        };
      } else {
        return this._def.out._parseSync({
          data: inResult.value,
          path: ctx.path,
          parent: ctx
        });
      }
    }
  }
  static create(a, b) {
    return new _ZodPipeline({
      in: a,
      out: b,
      typeName: ZodFirstPartyTypeKind.ZodPipeline
    });
  }
};
var ZodReadonly = class extends ZodType {
  _parse(input) {
    const result = this._def.innerType._parse(input);
    const freeze = (data) => {
      if (isValid(data)) {
        data.value = Object.freeze(data.value);
      }
      return data;
    };
    return isAsync(result) ? result.then((data) => freeze(data)) : freeze(result);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodReadonly.create = (type, params) => {
  return new ZodReadonly({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodReadonly,
    ...processCreateParams(params)
  });
};
function cleanParams(params, data) {
  const p = typeof params === "function" ? params(data) : typeof params === "string" ? { message: params } : params;
  const p2 = typeof p === "string" ? { message: p } : p;
  return p2;
}
function custom(check, _params = {}, fatal) {
  if (check)
    return ZodAny.create().superRefine((data, ctx) => {
      const r = check(data);
      if (r instanceof Promise) {
        return r.then((r2) => {
          if (!r2) {
            const params = cleanParams(_params, data);
            const _fatal = params.fatal ?? fatal ?? true;
            ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
          }
        });
      }
      if (!r) {
        const params = cleanParams(_params, data);
        const _fatal = params.fatal ?? fatal ?? true;
        ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
      }
      return;
    });
  return ZodAny.create();
}
var late = {
  object: ZodObject.lazycreate
};
var ZodFirstPartyTypeKind;
(function(ZodFirstPartyTypeKind2) {
  ZodFirstPartyTypeKind2["ZodString"] = "ZodString";
  ZodFirstPartyTypeKind2["ZodNumber"] = "ZodNumber";
  ZodFirstPartyTypeKind2["ZodNaN"] = "ZodNaN";
  ZodFirstPartyTypeKind2["ZodBigInt"] = "ZodBigInt";
  ZodFirstPartyTypeKind2["ZodBoolean"] = "ZodBoolean";
  ZodFirstPartyTypeKind2["ZodDate"] = "ZodDate";
  ZodFirstPartyTypeKind2["ZodSymbol"] = "ZodSymbol";
  ZodFirstPartyTypeKind2["ZodUndefined"] = "ZodUndefined";
  ZodFirstPartyTypeKind2["ZodNull"] = "ZodNull";
  ZodFirstPartyTypeKind2["ZodAny"] = "ZodAny";
  ZodFirstPartyTypeKind2["ZodUnknown"] = "ZodUnknown";
  ZodFirstPartyTypeKind2["ZodNever"] = "ZodNever";
  ZodFirstPartyTypeKind2["ZodVoid"] = "ZodVoid";
  ZodFirstPartyTypeKind2["ZodArray"] = "ZodArray";
  ZodFirstPartyTypeKind2["ZodObject"] = "ZodObject";
  ZodFirstPartyTypeKind2["ZodUnion"] = "ZodUnion";
  ZodFirstPartyTypeKind2["ZodDiscriminatedUnion"] = "ZodDiscriminatedUnion";
  ZodFirstPartyTypeKind2["ZodIntersection"] = "ZodIntersection";
  ZodFirstPartyTypeKind2["ZodTuple"] = "ZodTuple";
  ZodFirstPartyTypeKind2["ZodRecord"] = "ZodRecord";
  ZodFirstPartyTypeKind2["ZodMap"] = "ZodMap";
  ZodFirstPartyTypeKind2["ZodSet"] = "ZodSet";
  ZodFirstPartyTypeKind2["ZodFunction"] = "ZodFunction";
  ZodFirstPartyTypeKind2["ZodLazy"] = "ZodLazy";
  ZodFirstPartyTypeKind2["ZodLiteral"] = "ZodLiteral";
  ZodFirstPartyTypeKind2["ZodEnum"] = "ZodEnum";
  ZodFirstPartyTypeKind2["ZodEffects"] = "ZodEffects";
  ZodFirstPartyTypeKind2["ZodNativeEnum"] = "ZodNativeEnum";
  ZodFirstPartyTypeKind2["ZodOptional"] = "ZodOptional";
  ZodFirstPartyTypeKind2["ZodNullable"] = "ZodNullable";
  ZodFirstPartyTypeKind2["ZodDefault"] = "ZodDefault";
  ZodFirstPartyTypeKind2["ZodCatch"] = "ZodCatch";
  ZodFirstPartyTypeKind2["ZodPromise"] = "ZodPromise";
  ZodFirstPartyTypeKind2["ZodBranded"] = "ZodBranded";
  ZodFirstPartyTypeKind2["ZodPipeline"] = "ZodPipeline";
  ZodFirstPartyTypeKind2["ZodReadonly"] = "ZodReadonly";
})(ZodFirstPartyTypeKind || (ZodFirstPartyTypeKind = {}));
var instanceOfType = (cls, params = {
  message: `Input not instance of ${cls.name}`
}) => custom((data) => data instanceof cls, params);
var stringType = ZodString.create;
var numberType = ZodNumber.create;
var nanType = ZodNaN.create;
var bigIntType = ZodBigInt.create;
var booleanType = ZodBoolean.create;
var dateType = ZodDate.create;
var symbolType = ZodSymbol.create;
var undefinedType = ZodUndefined.create;
var nullType = ZodNull.create;
var anyType = ZodAny.create;
var unknownType = ZodUnknown.create;
var neverType = ZodNever.create;
var voidType = ZodVoid.create;
var arrayType = ZodArray.create;
var objectType = ZodObject.create;
var strictObjectType = ZodObject.strictCreate;
var unionType = ZodUnion.create;
var discriminatedUnionType = ZodDiscriminatedUnion.create;
var intersectionType = ZodIntersection.create;
var tupleType = ZodTuple.create;
var recordType = ZodRecord.create;
var mapType = ZodMap.create;
var setType = ZodSet.create;
var functionType = ZodFunction.create;
var lazyType = ZodLazy.create;
var literalType = ZodLiteral.create;
var enumType = ZodEnum.create;
var nativeEnumType = ZodNativeEnum.create;
var promiseType = ZodPromise.create;
var effectsType = ZodEffects.create;
var optionalType = ZodOptional.create;
var nullableType = ZodNullable.create;
var preprocessType = ZodEffects.createWithPreprocess;
var pipelineType = ZodPipeline.create;
var ostring = () => stringType().optional();
var onumber = () => numberType().optional();
var oboolean = () => booleanType().optional();
var coerce = {
  string: ((arg) => ZodString.create({ ...arg, coerce: true })),
  number: ((arg) => ZodNumber.create({ ...arg, coerce: true })),
  boolean: ((arg) => ZodBoolean.create({
    ...arg,
    coerce: true
  })),
  bigint: ((arg) => ZodBigInt.create({ ...arg, coerce: true })),
  date: ((arg) => ZodDate.create({ ...arg, coerce: true }))
};
var NEVER = INVALID;

// ../../packages/axonwall_lib/dist/schemas/index.js
var InterfaceTypeSchema = external_exports.enum([
  "static",
  "dhcp",
  "pppoe",
  "track6",
  "vlan",
  "bridge",
  "wireguard",
  "loopback"
]);
var InterfaceSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1).max(32),
  // e.g. "wan", "lan", "opt1"
  device: external_exports.string().min(1).max(32).regex(/^[a-zA-Z0-9_.:-]+$/, "Invalid device identifier"),
  // e.g. "eth0", "enp1s0"
  type: InterfaceTypeSchema.default("static"),
  enabled: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default(""),
  ipv4Address: external_exports.string().refine((val) => val === "" || isValidCIDR(val) || isValidIPv4(val), {
    message: "Invalid IPv4 address or CIDR"
  }).optional(),
  ipv4Gateway: external_exports.string().optional(),
  ipv6Address: external_exports.string().refine((val) => val === "" || isValidCIDR(val) || isValidIPv6(val), {
    message: "Invalid IPv6 address or CIDR"
  }).optional(),
  ipv6Gateway: external_exports.string().optional(),
  mtu: external_exports.number().int().min(576).max(65535).default(1500),
  macAddress: external_exports.string().refine((val) => val === "" || isValidMAC(val), {
    message: "Invalid MAC address"
  }).optional()
});
var AliasTypeSchema = external_exports.enum(["host", "network", "port", "mac", "urltable", "geoip", "asn", "fqdn"]);
var AliasSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().regex(/^[a-zA-Z0-9_]+$/, "Alias name must be alphanumeric or underscore"),
  type: AliasTypeSchema,
  entries: external_exports.array(external_exports.string().min(1)),
  url: external_exports.string().optional(),
  refreshIntervalHours: external_exports.number().int().optional(),
  description: external_exports.string().max(255).default(""),
  enabled: external_exports.boolean().default(true)
});
var RuleActionSchema = external_exports.enum(["pass", "block", "reject"]);
var RuleDirectionSchema = external_exports.enum(["in", "out"]);
var RuleProtocolSchema = external_exports.enum(["any", "tcp", "udp", "tcp_udp", "icmp", "ipv6-icmp", "esp", "ah", "gre"]);
var FirewallRuleSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  action: RuleActionSchema.default("pass"),
  direction: RuleDirectionSchema.default("in"),
  interface: external_exports.string().min(1).default("lan"),
  // interface name or 'any' or 'floating'
  quick: external_exports.boolean().default(true),
  protocol: RuleProtocolSchema.default("any"),
  source: external_exports.string().default("any"),
  // 'any', IP, CIDR, or '$alias_name'
  sourcePort: external_exports.string().refine((val) => val === "" || val === "any" || isValidPortRange(val) || val.startsWith("$"), {
    message: "Invalid source port range or alias"
  }).default(""),
  destination: external_exports.string().default("any"),
  destinationPort: external_exports.string().refine((val) => val === "" || val === "any" || isValidPortRange(val) || val.startsWith("$"), {
    message: "Invalid destination port range or alias"
  }).default(""),
  gateway: external_exports.string().optional(),
  // for policy routing
  gatewayGroup: external_exports.string().optional(),
  // for multi-WAN policy routing
  log: external_exports.boolean().default(false),
  enabled: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default(""),
  sortOrder: external_exports.number().int().default(100)
});
var NatTypeSchema = external_exports.enum(["dnat", "snat", "masquerade", "nptv6"]);
var NatRuleSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  type: NatTypeSchema.default("dnat"),
  interface: external_exports.string().min(1).default("wan"),
  protocol: RuleProtocolSchema.default("tcp"),
  source: external_exports.string().default("any"),
  sourcePort: external_exports.string().default(""),
  destination: external_exports.string().default("wan_ip"),
  destinationPort: external_exports.string().default(""),
  targetIp: external_exports.string().optional(),
  // translated internal IP
  targetPort: external_exports.string().optional(),
  // translated internal port
  log: external_exports.boolean().default(false),
  enabled: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default(""),
  sortOrder: external_exports.number().int().default(100)
});
var GatewaySchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1).max(32),
  interface: external_exports.string().min(1),
  gatewayIp: external_exports.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), {
    message: "Invalid gateway IP"
  }),
  monitorIp: external_exports.string().optional(),
  weight: external_exports.number().int().min(1).max(30).default(1),
  isDefault: external_exports.boolean().default(false),
  enabled: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default("")
});
var WireGuardPeerSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  publicKey: external_exports.string().min(32),
  presharedKey: external_exports.string().optional(),
  allowedIps: external_exports.array(external_exports.string()),
  endpoint: external_exports.string().optional(),
  // host:port
  persistentKeepalive: external_exports.number().int().min(0).max(3600).default(25),
  enabled: external_exports.boolean().default(true)
});
var WireGuardConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  listenPort: external_exports.number().int().min(1).max(65535).default(51820),
  privateKey: external_exports.string().min(32).optional(),
  address: external_exports.string().default("10.10.0.1/24"),
  peers: external_exports.array(WireGuardPeerSchema).default([])
});
var AntiLockoutSchema = external_exports.object({
  enabled: external_exports.boolean().default(true),
  interface: external_exports.string().default("lan"),
  ports: external_exports.array(external_exports.number()).default([80, 443, 22, 3e3, 2966])
});
var SystemSettingsSchema = external_exports.object({
  hostname: external_exports.string().default("axonwall"),
  domain: external_exports.string().default("local"),
  dnsServers: external_exports.array(external_exports.string()).default(["1.1.1.1", "8.8.8.8"]),
  timezone: external_exports.string().default("UTC"),
  flowtableOffload: external_exports.boolean().default(true),
  sshEnabled: external_exports.boolean().optional(),
  sshPort: external_exports.number().int().min(1).max(65535).optional(),
  webGuiPort: external_exports.number().int().min(1).max(65535).optional(),
  antiLockout: AntiLockoutSchema.default({
    enabled: true,
    interface: "lan",
    ports: [80, 443, 22, 3e3, 2966]
  })
});
var DhcpStaticMappingSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  mac: external_exports.string().refine(isValidMAC, { message: "Invalid MAC address" }),
  ip: external_exports.string().refine(isValidIPv4, { message: "Invalid IPv4 address" }),
  hostname: external_exports.string().optional(),
  description: external_exports.string().max(255).default("")
});
var DhcpSubnetSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  interface: external_exports.string().min(1),
  subnet: external_exports.string().refine(isValidCIDR, { message: "Invalid subnet CIDR" }),
  poolStart: external_exports.string().refine(isValidIPv4, { message: "Invalid pool start IPv4" }),
  poolEnd: external_exports.string().refine(isValidIPv4, { message: "Invalid pool end IPv4" }),
  routers: external_exports.array(external_exports.string()).default([]),
  dnsServers: external_exports.array(external_exports.string()).default([]),
  staticMappings: external_exports.array(DhcpStaticMappingSchema).default([]),
  enabled: external_exports.boolean().default(true)
});
var DhcpConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(true),
  subnets: external_exports.array(DhcpSubnetSchema).default([])
});
var DnsHostOverrideSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  hostname: external_exports.string().min(1),
  domain: external_exports.string().min(1),
  ip: external_exports.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: "Invalid IP address" }),
  description: external_exports.string().max(255).default("")
});
var DnsBlocklistFeedSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  url: external_exports.string(),
  entriesCount: external_exports.number().int().default(0),
  enabled: external_exports.boolean().default(true)
});
var DnsBlocklistConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  feeds: external_exports.array(DnsBlocklistFeedSchema).default([]),
  whitelist: external_exports.array(external_exports.string()).default([]),
  blacklist: external_exports.array(external_exports.string()).default([]),
  action: external_exports.enum(["always_null", "always_nxdomain"]).default("always_null")
});
var DnsConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(true),
  listenPort: external_exports.number().int().min(1).max(65535).default(53),
  dnssec: external_exports.boolean().default(true),
  dotEnabled: external_exports.boolean().default(true),
  dotUpstreams: external_exports.array(external_exports.string()).default(["1.1.1.1@853#cloudflare-dns.com", "9.9.9.9@853#dns.quad9.net"]),
  hostOverrides: external_exports.array(DnsHostOverrideSchema).default([]),
  blocklist: DnsBlocklistConfigSchema.optional()
});
var StaticRouteSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  network: external_exports.string().refine(isValidCIDR, { message: "Invalid route network CIDR" }),
  gateway: external_exports.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: "Invalid route gateway IP" }),
  interface: external_exports.string().optional(),
  description: external_exports.string().max(255).default(""),
  enabled: external_exports.boolean().default(true)
});
var GatewayGroupMemberSchema = external_exports.object({
  gatewayName: external_exports.string().min(1),
  tier: external_exports.number().int().min(1).max(5).default(1),
  weight: external_exports.number().int().min(1).max(30).default(1)
});
var GatewayGroupSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  trigger: external_exports.enum(["down", "loss", "latency", "both"]).default("down"),
  members: external_exports.array(GatewayGroupMemberSchema).min(1),
  description: external_exports.string().max(255).default("")
});
var VlanSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  tag: external_exports.number().int().min(1).max(4094),
  parentInterface: external_exports.string().min(1),
  vlanInterface: external_exports.string().min(1),
  priority: external_exports.number().int().min(0).max(7).default(0),
  description: external_exports.string().max(255).default("")
});
var BridgeMemberSchema = external_exports.object({
  interface: external_exports.string().min(1),
  stp: external_exports.boolean().default(true),
  cost: external_exports.number().int().default(100),
  priority: external_exports.number().int().default(32)
});
var BridgeSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  members: external_exports.array(BridgeMemberSchema).default([]),
  vlanFiltering: external_exports.boolean().default(true),
  stp: external_exports.boolean().default(false),
  description: external_exports.string().max(255).default("")
});
var BondModeSchema = external_exports.enum([
  "802.3ad",
  "active-backup",
  "balance-rr",
  "balance-xor",
  "broadcast",
  "balance-tlb",
  "balance-alb"
]);
var BondSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  members: external_exports.array(external_exports.string()).min(1),
  mode: BondModeSchema.default("802.3ad"),
  lacpRate: external_exports.enum(["slow", "fast"]).default("fast"),
  xmitHashPolicy: external_exports.enum(["layer2", "layer2+3", "layer3+4"]).default("layer2+3"),
  miimon: external_exports.number().int().default(100),
  description: external_exports.string().max(255).default("")
});
var VirtualIpTypeSchema = external_exports.enum(["alias", "carp", "proxyarp"]);
var VirtualIpSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  interface: external_exports.string().min(1),
  ip: external_exports.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: "Invalid IP address" }),
  subnetBits: external_exports.number().int().min(1).max(128).default(32),
  type: VirtualIpTypeSchema.default("alias"),
  vhid: external_exports.number().int().min(1).max(255).optional(),
  password: external_exports.string().optional(),
  description: external_exports.string().max(255).default("")
});
var VrfSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  tableId: external_exports.number().int().min(1).max(65535),
  interfaces: external_exports.array(external_exports.string()).default([]),
  description: external_exports.string().max(255).default("")
});
var IpsecTunnelSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  enabled: external_exports.boolean().default(true),
  routeBased: external_exports.boolean().default(true),
  xfrmInterfaceId: external_exports.number().int().min(1).max(65535).default(1),
  localAddress: external_exports.string().default("%any"),
  remoteAddress: external_exports.string().min(1),
  authMethod: external_exports.enum(["psk", "pubkey"]).default("psk"),
  presharedKey: external_exports.string().optional(),
  ikeProposals: external_exports.array(external_exports.string()).default(["aes256-sha256-modp2048", "aes256gcm16-prfsha256-ecp256"]),
  espProposals: external_exports.array(external_exports.string()).default(["aes256gcm16-ecp256", "aes256-sha256"]),
  localTs: external_exports.array(external_exports.string()).default(["0.0.0.0/0"]),
  remoteTs: external_exports.array(external_exports.string()).default(["0.0.0.0/0"]),
  dpdDelay: external_exports.number().int().default(30),
  dpdAction: external_exports.enum(["restart", "clear", "hold"]).default("restart"),
  description: external_exports.string().max(255).default("")
});
var IpsecConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  tunnels: external_exports.array(IpsecTunnelSchema).default([])
});
var OpenVpnCsoSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  commonName: external_exports.string().min(1),
  assignedIp: external_exports.string().refine(isValidIPv4, { message: "Invalid IPv4" }).optional(),
  pushRoutes: external_exports.array(external_exports.string()).default([]),
  description: external_exports.string().max(255).default("")
});
var OpenVpnServerSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  enabled: external_exports.boolean().default(true),
  protocol: external_exports.enum(["udp", "tcp"]).default("udp"),
  port: external_exports.number().int().min(1).max(65535).default(1194),
  deviceType: external_exports.enum(["tun", "tap"]).default("tun"),
  devName: external_exports.string().default("ovpn-dco0"),
  dcoEnabled: external_exports.boolean().default(true),
  tunnelNetwork: external_exports.string().refine(isValidCIDR, { message: "Invalid tunnel CIDR" }).default("10.8.0.0/24"),
  localNetwork: external_exports.string().optional(),
  cipher: external_exports.string().default("AES-256-GCM"),
  authDigest: external_exports.string().default("SHA256"),
  caCert: external_exports.string().optional(),
  serverCert: external_exports.string().optional(),
  serverKey: external_exports.string().optional(),
  dhParams: external_exports.string().optional(),
  clientToClient: external_exports.boolean().default(false),
  duplicateCn: external_exports.boolean().default(false),
  cso: external_exports.array(OpenVpnCsoSchema).default([]),
  description: external_exports.string().max(255).default("")
});
var OpenVpnConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  servers: external_exports.array(OpenVpnServerSchema).default([])
});
var TrafficShaperQueueSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  priority: external_exports.number().int().min(1).max(7).default(3),
  bandwidthPercent: external_exports.number().min(1).max(100).default(20),
  burst: external_exports.string().default("15k"),
  codel: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default("")
});
var TrafficShaperInterfaceSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  interface: external_exports.string().min(1),
  downloadBandwidthMbps: external_exports.number().min(0).default(100),
  uploadBandwidthMbps: external_exports.number().min(0).default(50),
  scheduler: external_exports.enum(["cake", "fq_codel", "htb"]).default("cake"),
  cakeDiffserv: external_exports.enum(["diffserv3", "diffserv4", "besteffort"]).default("diffserv4"),
  cakeAckFilter: external_exports.boolean().default(true),
  enabled: external_exports.boolean().default(true),
  queues: external_exports.array(TrafficShaperQueueSchema).default([])
});
var TrafficShaperConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  interfaces: external_exports.array(TrafficShaperInterfaceSchema).default([])
});
var BgpNeighborSchema = external_exports.object({
  peerIp: external_exports.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: "Invalid peer IP" }),
  remoteAs: external_exports.number().int().min(1).max(4294967295),
  description: external_exports.string().max(255).default(""),
  password: external_exports.string().optional(),
  bfd: external_exports.boolean().default(true),
  nextHopSelf: external_exports.boolean().default(false),
  softReconfiguration: external_exports.boolean().default(true)
});
var BgpConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  asNumber: external_exports.number().int().min(1).max(4294967295).default(64512),
  routerId: external_exports.string().refine(isValidIPv4, { message: "Invalid router ID" }).default("1.1.1.1"),
  networks: external_exports.array(external_exports.string()).default([]),
  neighbors: external_exports.array(BgpNeighborSchema).default([])
});
var OspfAreaSchema = external_exports.object({
  areaId: external_exports.string().default("0.0.0.0"),
  interfaces: external_exports.array(external_exports.string()).default([]),
  networks: external_exports.array(external_exports.string()).default([])
});
var OspfConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  routerId: external_exports.string().refine(isValidIPv4, { message: "Invalid router ID" }).default("1.1.1.1"),
  redistributeConnected: external_exports.boolean().default(true),
  redistributeDefault: external_exports.boolean().default(false),
  areas: external_exports.array(OspfAreaSchema).default([])
});
var FrrConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  bgp: BgpConfigSchema.default({}),
  ospf: OspfConfigSchema.default({})
});
var PacketTracerQuerySchema = external_exports.object({
  inInterface: external_exports.string().min(1),
  srcIp: external_exports.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: "Invalid source IP" }),
  dstIp: external_exports.string().refine((val) => isValidIPv4(val) || isValidIPv6(val), { message: "Invalid destination IP" }),
  protocol: external_exports.enum(["tcp", "udp", "icmp"]).default("tcp"),
  srcPort: external_exports.number().int().min(1).max(65535).default(12345),
  dstPort: external_exports.number().int().min(1).max(65535).default(80)
});
var SuricataModeSchema = external_exports.enum(["ids", "ips"]);
var SuricataRuleSourceSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  url: external_exports.string(),
  enabled: external_exports.boolean().default(true)
});
var TlsDecryptionSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  caCertificateId: external_exports.string().uuid().optional(),
  transparentProxyPort: external_exports.number().int().default(3129),
  bypassedDomains: external_exports.array(external_exports.string()).default([])
  // Don't intercept banks, healthcare
});
var SuricataConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  mode: SuricataModeSchema.default("ips"),
  interfaces: external_exports.array(external_exports.string()).default(["wan"]),
  nfqueueFailOpen: external_exports.boolean().default(true),
  nfqueueBypass: external_exports.boolean().default(true),
  tlsDecryption: TlsDecryptionSchema.optional(),
  ruleSources: external_exports.array(SuricataRuleSourceSchema).default([
    {
      name: "ET Open Ruleset",
      url: "https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz",
      enabled: true
    }
  ]),
  homeNet: external_exports.array(external_exports.string()).default(["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])
});
var CaptivePortalZoneSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  interface: external_exports.string().min(1),
  listenPort: external_exports.number().int().default(8999),
  authServers: external_exports.array(external_exports.string()).default(["ldap_internal"]),
  sessionTimeoutMinutes: external_exports.number().int().min(1).default(720),
  idleTimeoutMinutes: external_exports.number().int().min(1).default(60),
  passThroughMacs: external_exports.array(external_exports.string()).default([]),
  passThroughIps: external_exports.array(external_exports.string()).default([]),
  enableBandwidthQuotas: external_exports.boolean().default(false),
  downloadLimitKbps: external_exports.number().int().default(1e4),
  uploadLimitKbps: external_exports.number().int().default(5e3),
  enabled: external_exports.boolean().default(true)
});
var CaptivePortalConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  zones: external_exports.array(CaptivePortalZoneSchema).default([])
});
var AcmeAccountSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  email: external_exports.string().email(),
  caDirectoryUrl: external_exports.string().default("https://acme-v02.api.letsencrypt.org/directory"),
  eabKid: external_exports.string().optional(),
  eabHmacKey: external_exports.string().optional(),
  enabled: external_exports.boolean().default(true)
});
var AcmeCertificateSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  domain: external_exports.string().min(1),
  altNames: external_exports.array(external_exports.string()).default([]),
  challengeType: external_exports.enum(["http-01", "dns-01"]).default("http-01"),
  dnsProvider: external_exports.string().optional(),
  autoRenew: external_exports.boolean().default(true),
  renewDaysBeforeExpiry: external_exports.number().int().default(30),
  deployServices: external_exports.array(external_exports.enum(["webgui", "openvpn", "ipsec", "haproxy"])).default(["webgui"]),
  status: external_exports.enum(["pending", "valid", "expired", "error"]).default("pending"),
  expiresAt: external_exports.string().optional()
});
var InternalCASchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  commonName: external_exports.string(),
  organization: external_exports.string().optional(),
  privateKeyBase64: external_exports.string().optional(),
  certificateBase64: external_exports.string().optional(),
  isDecryptionRoot: external_exports.boolean().default(false)
});
var AcmeConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  accounts: external_exports.array(AcmeAccountSchema).default([]),
  certificates: external_exports.array(AcmeCertificateSchema).default([]),
  internalCAs: external_exports.array(InternalCASchema).default([])
});
var CrowdSecConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  lapiUrl: external_exports.string().default("http://127.0.0.1:8080/"),
  apiKey: external_exports.string().optional(),
  remediationSetName: external_exports.string().default("set_crowdsec_blacklists"),
  action: external_exports.enum(["drop", "reject"]).default("drop"),
  logBanned: external_exports.boolean().default(true)
});
var VrrpInstanceSchema = external_exports.object({
  name: external_exports.string().min(1).default("VI_WAN"),
  vrid: external_exports.number().int().min(1).max(255).default(1),
  interface: external_exports.string().min(1).default("eth0"),
  priority: external_exports.number().int().min(1).max(255).default(100),
  virtualIps: external_exports.array(external_exports.string()).default([]),
  authPassword: external_exports.string().optional()
});
var ConntrackSyncSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  interface: external_exports.string().default("eth0"),
  protocol: external_exports.enum(["multicast", "unicast"]).default("unicast"),
  peerAddress: external_exports.string().optional(),
  port: external_exports.number().int().default(3780),
  multicastGroup: external_exports.string().optional(),
  bufferSize: external_exports.number().int().optional(),
  filterIgnoreIps: external_exports.array(external_exports.string()).optional(),
  mode: external_exports.enum(["FTFW", "NOTRACK", "ALARM"]).optional()
});
var HaSyncSectionsSchema = external_exports.object({
  interfaces: external_exports.boolean().default(false),
  firewall: external_exports.boolean().default(true),
  dhcp: external_exports.boolean().default(true),
  dns: external_exports.boolean().default(true),
  aliases: external_exports.boolean().default(true),
  vpn: external_exports.boolean().default(true),
  sqlite: external_exports.boolean().optional().default(true),
  nas: external_exports.boolean().optional(),
  zfs: external_exports.boolean().optional(),
  k3s: external_exports.boolean().optional()
});
var HaSqliteSyncConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  mode: external_exports.enum(["direct_stream", "litestream"]).default("direct_stream"),
  databases: external_exports.array(external_exports.string()).default([
    "/var/lib/axonwall/headscale/db.sqlite"
  ]),
  syncIntervalSeconds: external_exports.number().int().min(1).default(5),
  listenPort: external_exports.number().int().min(1).max(65535).default(9876),
  peerAddress: external_exports.string().optional(),
  peerPort: external_exports.number().int().min(1).max(65535).optional(),
  authToken: external_exports.string().optional(),
  litestreamBucket: external_exports.string().optional(),
  litestreamEndpoint: external_exports.string().optional(),
  litestreamAccessKeyId: external_exports.string().optional(),
  litestreamSecretAccessKey: external_exports.string().optional()
});
var HighAvailabilityConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  nodeRole: external_exports.enum(["master", "backup"]).default("master"),
  role: external_exports.enum(["master", "backup"]).optional(),
  peerAddress: external_exports.string().default(""),
  peerIp: external_exports.string().optional(),
  syncInterface: external_exports.string().optional(),
  peerPort: external_exports.number().int().default(2966),
  mtlsCert: external_exports.string().optional(),
  mtlsKey: external_exports.string().optional(),
  vrrpInstances: external_exports.array(VrrpInstanceSchema).default([]),
  conntrackSync: ConntrackSyncSchema.default({ enabled: false }),
  sqliteSync: HaSqliteSyncConfigSchema.optional().default({
    enabled: false,
    mode: "direct_stream",
    databases: ["/var/lib/axonwall/headscale/db.sqlite"],
    syncIntervalSeconds: 5,
    listenPort: 9876
  }),
  syncSections: HaSyncSectionsSchema.default({
    interfaces: false,
    firewall: true,
    dhcp: true,
    dns: true,
    aliases: true,
    vpn: true,
    sqlite: true
  }),
  maintenanceMode: external_exports.boolean().optional()
});
var ObservabilityConfigSchema = external_exports.object({
  metrics: external_exports.object({
    enabled: external_exports.boolean().default(true),
    port: external_exports.number().int().default(9090),
    retentionDays: external_exports.number().int().default(30),
    scrapeIntervalSeconds: external_exports.number().int().default(10)
  }).default({ enabled: true, port: 9090, retentionDays: 30, scrapeIntervalSeconds: 10 }),
  flowExport: external_exports.object({
    enabled: external_exports.boolean().default(false),
    version: external_exports.enum(["ipfix", "netflow9"]).default("ipfix"),
    collectorHost: external_exports.string().optional(),
    collectorPort: external_exports.number().int().default(2055),
    interfaces: external_exports.array(external_exports.string()).default([])
  }).default({ enabled: false, version: "ipfix", collectorPort: 2055, interfaces: [] }),
  alerting: external_exports.object({
    enabled: external_exports.boolean().default(false),
    webhookUrl: external_exports.string().optional(),
    emailRecipient: external_exports.string().optional(),
    notifyOnFailover: external_exports.boolean().default(true),
    notifyOnThreshold: external_exports.boolean().default(true)
  }).default({ enabled: false, notifyOnFailover: true, notifyOnThreshold: true }),
  clickhouse: external_exports.object({
    enabled: external_exports.boolean().default(false),
    url: external_exports.string().default("http://127.0.0.1:8123"),
    database: external_exports.string().default("axonwall"),
    username: external_exports.string().default("admin"),
    password: external_exports.string().optional()
  }).default({ enabled: false, url: "http://127.0.0.1:8123", database: "axonwall", username: "admin" })
});
var NutUpsConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  name: external_exports.string().default("axonups"),
  driver: external_exports.string().default("usbhid-ups"),
  port: external_exports.string().default("auto"),
  shutdownBatteryPct: external_exports.number().int().min(1).max(50).default(20),
  lowBatteryRuntimeSec: external_exports.number().int().default(300)
});
var HaProxyFrontendSchema = external_exports.object({
  name: external_exports.string().min(1),
  bindPort: external_exports.number().int().min(1).max(65535),
  ssl: external_exports.boolean().default(false),
  defaultBackend: external_exports.string().min(1),
  certName: external_exports.string().optional()
});
var HaProxyBackendServerSchema = external_exports.object({
  name: external_exports.string().min(1),
  address: external_exports.string().min(1),
  port: external_exports.number().int().min(1).max(65535),
  check: external_exports.boolean().default(true)
});
var HaProxyBackendSchema = external_exports.object({
  name: external_exports.string().min(1),
  mode: external_exports.enum(["http", "tcp"]).default("http"),
  balance: external_exports.enum(["roundrobin", "leastconn", "source"]).default("roundrobin"),
  servers: external_exports.array(HaProxyBackendServerSchema).default([])
});
var HaProxyPluginConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  mode: external_exports.enum(["http", "tcp"]).default("http"),
  frontends: external_exports.array(HaProxyFrontendSchema).default([]),
  backends: external_exports.array(HaProxyBackendSchema).default([])
});
var FreeRadiusClientSchema = external_exports.object({
  name: external_exports.string().min(1),
  ipAddress: external_exports.string().min(1),
  secret: external_exports.string().min(1)
});
var FreeRadiusPluginConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  authPort: external_exports.number().int().default(1812),
  acctPort: external_exports.number().int().default(1813),
  clients: external_exports.array(FreeRadiusClientSchema).default([]),
  ldapSync: external_exports.boolean().default(true)
});
var SnmpPluginConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  community: external_exports.string().default("public"),
  sysLocation: external_exports.string().default("Axonwall Gateway"),
  sysContact: external_exports.string().default("admin@local"),
  listenPort: external_exports.number().int().default(161)
});
var PluginCategorySchema = external_exports.enum(["core_role", "extension"]);
var PluginManifestSchema = external_exports.object({
  id: external_exports.string().min(1),
  name: external_exports.string().min(1),
  version: external_exports.string().min(1),
  category: PluginCategorySchema.default("extension").optional(),
  description: external_exports.string().default(""),
  author: external_exports.string().default("Axonwall Community"),
  systemdUnits: external_exports.array(external_exports.string()).default([]),
  privileges: external_exports.array(external_exports.string()).default([]),
  nftHooks: external_exports.array(external_exports.object({
    table: external_exports.string(),
    chain: external_exports.string(),
    priority: external_exports.number().int()
  })).optional(),
  menuEntry: external_exports.object({
    title: external_exports.string(),
    path: external_exports.string(),
    icon: external_exports.string().optional()
  }).optional()
});
var InstalledPluginRecordSchema = external_exports.object({
  id: external_exports.string(),
  enabled: external_exports.boolean().default(true),
  installedAt: external_exports.string().optional(),
  config: external_exports.record(external_exports.string(), external_exports.any()).optional()
});
var AiProviderTypeSchema = external_exports.enum([
  "antigravity",
  "ollama",
  "claude-code",
  "codex",
  "vllm"
]);
var AntigravitySettingsSchema = external_exports.object({
  endpoint: external_exports.string().default("https://generativelanguage.googleapis.com/v1beta"),
  apiKey: external_exports.string().optional(),
  model: external_exports.string().default("gemini-2.5-pro"),
  thinkingBudget: external_exports.number().int().default(1024)
});
var OllamaSettingsSchema = external_exports.object({
  endpoint: external_exports.string().default("http://127.0.0.1:11434"),
  model: external_exports.string().default("llama3.3:latest"),
  temperature: external_exports.number().min(0).max(2).default(0.2)
});
var ClaudeCodeSettingsSchema = external_exports.object({
  endpoint: external_exports.string().default("https://api.anthropic.com/v1"),
  apiKey: external_exports.string().optional(),
  model: external_exports.string().default("claude-3-7-sonnet-20250219"),
  extendedThinking: external_exports.boolean().default(true)
});
var CodexSettingsSchema = external_exports.object({
  endpoint: external_exports.string().default("https://api.openai.com/v1"),
  apiKey: external_exports.string().optional(),
  model: external_exports.string().default("gpt-4o"),
  temperature: external_exports.number().min(0).max(2).default(0.2)
});
var VllmSettingsSchema = external_exports.object({
  endpoint: external_exports.string().default("http://127.0.0.1:8000/v1"),
  apiKey: external_exports.string().optional(),
  model: external_exports.string().default("qwen2.5-coder-32b-instruct"),
  maxTokens: external_exports.number().int().default(4096)
});
var AiConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  activeProvider: AiProviderTypeSchema.default("antigravity"),
  systemContextInference: external_exports.boolean().default(true),
  autoAuditOnSave: external_exports.boolean().default(false),
  providers: external_exports.object({
    antigravity: AntigravitySettingsSchema.default({}),
    ollama: OllamaSettingsSchema.default({}),
    claudeCode: ClaudeCodeSettingsSchema.default({}),
    codex: CodexSettingsSchema.default({}),
    vllm: VllmSettingsSchema.default({})
  }).default({})
});
var SatelliteNodeSchema = external_exports.object({
  id: external_exports.string(),
  name: external_exports.string(),
  arch: external_exports.enum(["mipsle", "arm64", "amd64", "armv7", "unknown"]).default("unknown"),
  os: external_exports.string().default("Linux"),
  ip: external_exports.string().default("127.0.0.1"),
  lastSeen: external_exports.string().optional(),
  status: external_exports.enum(["online", "offline", "enrolling", "degraded"]).default("enrolling"),
  ztpToken: external_exports.string().optional(),
  wireguard: external_exports.object({
    tunnelIp: external_exports.string().default("10.99.0.2/24"),
    publicKey: external_exports.string().optional(),
    endpoint: external_exports.string().optional(),
    connected: external_exports.boolean().default(false)
  }).default({}),
  wifi: external_exports.array(external_exports.object({
    radio: external_exports.string(),
    ssid: external_exports.string(),
    channel: external_exports.number().int().optional(),
    security: external_exports.enum(["wpa2-psk", "wpa3-sae", "wpa3-enterprise", "open"]).default("wpa3-sae"),
    fastRoaming: external_exports.object({
      enabled: external_exports.boolean().default(false),
      mobilityDomain: external_exports.string().optional()
      // 4 hex digits, e.g. "a1b2"
    }).optional(),
    clientsCount: external_exports.number().int().default(0),
    enabled: external_exports.boolean().default(true)
  })).optional(),
  metrics: external_exports.object({
    cpuUsagePercent: external_exports.number().default(0),
    memUsagePercent: external_exports.number().default(0),
    uptimeSeconds: external_exports.number().int().default(0),
    activeConns: external_exports.number().int().default(0),
    rxBytesTotal: external_exports.number().int().default(0),
    txBytesTotal: external_exports.number().int().default(0)
  }).optional(),
  activePolicyVersion: external_exports.number().int().default(1)
});
var SatelliteFleetConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(true),
  listenPort: external_exports.number().int().default(2966),
  defaultHeartbeatIntervalSec: external_exports.number().int().default(30),
  watchdogTimeoutSec: external_exports.number().int().default(60),
  nodes: external_exports.array(SatelliteNodeSchema).default([])
});
var ZeroTrustAppSchema = external_exports.object({
  id: external_exports.string().uuid().optional(),
  name: external_exports.string().min(1),
  publicHostname: external_exports.string().min(1),
  internalUpstream: external_exports.string().min(1),
  // e.g. "http://10.0.0.5:8080"
  allowedRoles: external_exports.array(external_exports.string()).default(["admin", "user"]),
  enabled: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default("")
});
var ZeroTrustConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  apps: external_exports.array(ZeroTrustAppSchema).default([])
});
var HeadscaleConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  magicDnsDomain: external_exports.string().default("tailnet.axonwall.local")
});
var GeoIpModeSchema = external_exports.enum(["block", "allow"]);
var GeoIpDirectionSchema = external_exports.enum(["in", "out", "both"]);
var GeoIpConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  mode: GeoIpModeSchema.default("block"),
  direction: GeoIpDirectionSchema.default("in"),
  countries: external_exports.array(external_exports.string().length(2)).default([]),
  excludedSubnets: external_exports.array(external_exports.string()).default(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
  log: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default("")
});
var SsoProviderSchema = external_exports.enum(["oidc", "entra", "okta", "google"]);
var SsoRoleMappingSchema = external_exports.object({
  idpGroup: external_exports.string().min(1),
  role: external_exports.enum(["admin", "operator", "readonly"])
});
var SsoConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  provider: SsoProviderSchema.default("oidc"),
  displayName: external_exports.string().default("Enterprise SSO"),
  issuerUrl: external_exports.string().default(""),
  clientId: external_exports.string().default(""),
  clientSecret: external_exports.string().default(""),
  redirectUri: external_exports.string().default(""),
  scopes: external_exports.array(external_exports.string()).default(["openid", "profile", "email", "groups"]),
  groupClaim: external_exports.string().default("groups"),
  roleMappings: external_exports.array(SsoRoleMappingSchema).default([
    { idpGroup: "Axonwall-Admins", role: "admin" },
    { idpGroup: "Axonwall-Operators", role: "operator" },
    { idpGroup: "Axonwall-Auditors", role: "readonly" }
  ])
});
var CoreCapabilitiesSchema = external_exports.object({
  firewallEnabled: external_exports.boolean().default(true),
  nasEnabled: external_exports.boolean().default(false),
  k3sEnabled: external_exports.boolean().default(false)
});
var ZfsTopologySchema = external_exports.enum([
  "stripe",
  "mirror",
  "raidz1",
  "raidz2",
  "raidz3",
  "draid1",
  "draid2",
  "draid3"
]);
var ZfsCompressionSchema = external_exports.enum(["lz4", "zstd", "gzip", "off"]);
var ZfsPoolSchema = external_exports.object({
  name: external_exports.string().min(1).regex(/^[a-zA-Z][a-zA-Z0-9_-]*$/),
  topology: ZfsTopologySchema.default("mirror"),
  dataDisks: external_exports.array(external_exports.string()).min(1),
  cacheDisks: external_exports.array(external_exports.string()).default([]),
  logDisks: external_exports.array(external_exports.string()).default([]),
  spareDisks: external_exports.array(external_exports.string()).default([]),
  ashift: external_exports.number().int().min(9).max(16).default(12),
  autotrim: external_exports.boolean().default(true),
  compression: ZfsCompressionSchema.default("lz4"),
  scrubScheduleCron: external_exports.string().default("0 2 * * 0"),
  description: external_exports.string().max(255).default("")
});
var ZfsDatasetSchema = external_exports.object({
  id: external_exports.string().optional(),
  name: external_exports.string().min(1),
  pool: external_exports.string().min(1).default("tank"),
  type: external_exports.enum(["filesystem", "zvol"]).default("filesystem"),
  compression: ZfsCompressionSchema.default("lz4"),
  dedup: external_exports.enum(["off", "on"]).default("off"),
  quotaGb: external_exports.number().nonnegative().default(0),
  recordSize: external_exports.enum(["4K", "16K", "64K", "128K", "512K", "1M"]).default("128K"),
  volSizeGb: external_exports.number().nonnegative().default(10),
  encryption: external_exports.enum(["off", "aes-256-gcm"]).default("off"),
  aclMode: external_exports.enum(["passthrough", "restricted"]).default("passthrough"),
  replicateToHaPeer: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default("")
});
var ZfsSnapshotPolicySchema = external_exports.object({
  id: external_exports.string().optional(),
  dataset: external_exports.string().min(1),
  interval: external_exports.enum(["hourly", "daily", "weekly"]).default("hourly"),
  keepCount: external_exports.number().int().min(1).max(1e3).default(24),
  replicateToHaPeer: external_exports.boolean().default(true),
  enabled: external_exports.boolean().default(true)
});
var SmbShareSchema = external_exports.object({
  id: external_exports.string().optional(),
  name: external_exports.string().min(1),
  path: external_exports.string().min(1),
  comment: external_exports.string().max(255).default(""),
  readOnly: external_exports.boolean().default(false),
  guestOk: external_exports.boolean().default(false),
  browseable: external_exports.boolean().default(true),
  timeMachine: external_exports.boolean().default(false),
  shadowCopies: external_exports.boolean().default(true),
  validUsers: external_exports.array(external_exports.string()).default([]),
  hostsAllow: external_exports.array(external_exports.string()).default([]),
  enabled: external_exports.boolean().default(true)
});
var NfsExportSchema = external_exports.object({
  id: external_exports.string().optional(),
  path: external_exports.string().min(1),
  allowedNetworks: external_exports.array(external_exports.string()).default(["192.168.1.0/24"]),
  readOnly: external_exports.boolean().default(false),
  mapRootUser: external_exports.enum(["root", "nobody"]).default("root"),
  async: external_exports.boolean().default(false),
  enabled: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default("")
});
var IscsiLunSchema = external_exports.object({
  lunId: external_exports.number().int().min(0).default(0),
  zvolPath: external_exports.string().min(1),
  blockSize: external_exports.enum(["512", "4096"]).default("4096"),
  readOnly: external_exports.boolean().default(false)
});
var IscsiTargetSchema = external_exports.object({
  id: external_exports.string().optional(),
  iqn: external_exports.string().min(1).default("iqn.2026-10.io.axonwall:storage.target0"),
  portalIp: external_exports.string().default("0.0.0.0"),
  portalPort: external_exports.number().int().default(3260),
  allowedInitiators: external_exports.array(external_exports.string()).default([]),
  chapUser: external_exports.string().default(""),
  chapSecret: external_exports.string().default(""),
  luns: external_exports.array(IscsiLunSchema).default([]),
  enabled: external_exports.boolean().default(true),
  description: external_exports.string().max(255).default("")
});
var S3ServerConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  listenPort: external_exports.number().int().default(9e3),
  consolePort: external_exports.number().int().default(9001),
  rootDataset: external_exports.string().default("/mnt/tank/s3"),
  accessKey: external_exports.string().default("axonwall-admin"),
  secretKey: external_exports.string().default(""),
  buckets: external_exports.array(external_exports.string()).default([])
});
var NasConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  workgroup: external_exports.string().default("WORKGROUP"),
  serverString: external_exports.string().default("Axonwall Enterprise ZFS NAS"),
  pools: external_exports.array(ZfsPoolSchema).default([]),
  datasets: external_exports.array(ZfsDatasetSchema).default([]),
  snapshotPolicies: external_exports.array(ZfsSnapshotPolicySchema).default([]),
  smbShares: external_exports.array(SmbShareSchema).default([]),
  nfsExports: external_exports.array(NfsExportSchema).default([]),
  iscsiTargets: external_exports.array(IscsiTargetSchema).default([]),
  s3: S3ServerConfigSchema.optional()
});
var OpenEbsConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(true),
  zfsLocalPvEnabled: external_exports.boolean().default(true),
  zfsLocalPvPool: external_exports.string().default("tank"),
  replicatedStorageEnabled: external_exports.boolean().default(true),
  defaultReplicaCount: external_exports.number().int().min(1).max(5).default(2),
  replicatedBackingPool: external_exports.string().default("tank/openebs-replicated")
});
var K3sWorkloadSpecSchema = external_exports.object({
  id: external_exports.string().optional(),
  name: external_exports.string().min(1),
  namespace: external_exports.string().default("default"),
  image: external_exports.string().min(1),
  replicas: external_exports.number().int().min(1).max(32).default(1),
  port: external_exports.number().int().min(1).max(65535).default(80),
  storageClass: external_exports.enum(["axonwall-replicated-ha", "axonwall-zfs-local", "none"]).default("axonwall-replicated-ha"),
  storageSizeGb: external_exports.number().int().min(1).default(10),
  mountPath: external_exports.string().default("/data"),
  enabled: external_exports.boolean().default(true)
});
var K3sConfigSchema = external_exports.object({
  enabled: external_exports.boolean().default(false),
  clusterCidr: external_exports.string().default("10.42.0.0/16"),
  serviceCidr: external_exports.string().default("10.43.0.0/16"),
  nodeIpInterface: external_exports.string().default("lan"),
  flannelBackend: external_exports.enum(["wireguard-native", "vxlan", "host-gw"]).default("wireguard-native"),
  disableTraefik: external_exports.boolean().default(false),
  autoJoinHaPeer: external_exports.boolean().default(true),
  openEbs: OpenEbsConfigSchema.optional(),
  workloads: external_exports.array(K3sWorkloadSpecSchema).default([])
});
var DesiredStateSchema = external_exports.object({
  version: external_exports.number().int().default(1),
  capabilities: CoreCapabilitiesSchema.optional(),
  system: SystemSettingsSchema.default({}),
  interfaces: external_exports.array(InterfaceSchema).default([]),
  vlans: external_exports.array(VlanSchema).default([]),
  bridges: external_exports.array(BridgeSchema).default([]),
  bonds: external_exports.array(BondSchema).default([]),
  virtualIps: external_exports.array(VirtualIpSchema).default([]),
  vrfs: external_exports.array(VrfSchema).default([]),
  aliases: external_exports.array(AliasSchema).default([]),
  rules: external_exports.array(FirewallRuleSchema).default([]),
  nat: external_exports.array(NatRuleSchema).default([]),
  gateways: external_exports.array(GatewaySchema).default([]),
  gatewayGroups: external_exports.array(GatewayGroupSchema).default([]),
  dhcp: DhcpConfigSchema.default({ enabled: true, subnets: [] }),
  dns: DnsConfigSchema.default({ enabled: true, hostOverrides: [] }),
  routes: external_exports.array(StaticRouteSchema).default([]),
  trafficShaper: TrafficShaperConfigSchema.optional(),
  wireguard: WireGuardConfigSchema.optional(),
  ipsec: IpsecConfigSchema.optional(),
  openvpn: OpenVpnConfigSchema.optional(),
  headscale: HeadscaleConfigSchema.optional(),
  frr: FrrConfigSchema.optional(),
  suricata: SuricataConfigSchema.optional(),
  captivePortal: CaptivePortalConfigSchema.optional(),
  acme: AcmeConfigSchema.optional(),
  crowdsec: CrowdSecConfigSchema.optional(),
  geoip: GeoIpConfigSchema.optional(),
  sso: SsoConfigSchema.optional(),
  tlsDecryption: TlsDecryptionSchema.optional(),
  ha: HighAvailabilityConfigSchema.optional(),
  observability: ObservabilityConfigSchema.optional(),
  ups: NutUpsConfigSchema.optional(),
  haproxy: HaProxyPluginConfigSchema.optional(),
  freeradius: FreeRadiusPluginConfigSchema.optional(),
  snmp: SnmpPluginConfigSchema.optional(),
  plugins: external_exports.array(InstalledPluginRecordSchema).optional(),
  ai: AiConfigSchema.optional(),
  fleet: SatelliteFleetConfigSchema.optional(),
  zeroTrust: ZeroTrustConfigSchema.optional(),
  nas: NasConfigSchema.optional(),
  k3s: K3sConfigSchema.optional()
});

// ../../packages/axonwall_lib/dist/plugins/index.js
function resolveCapabilities(state) {
  const plugins = state?.plugins ?? [];
  const fwPlugin = plugins.find((p) => p.id === "core-firewall");
  const nasPlugin = plugins.find((p) => p.id === "core-nas");
  const k3sPlugin = plugins.find((p) => p.id === "core-k3s");
  const firewallEnabled = state?.capabilities?.firewallEnabled !== void 0 ? state.capabilities.firewallEnabled : fwPlugin !== void 0 ? fwPlugin.enabled : true;
  const nasEnabled = state?.capabilities?.nasEnabled !== void 0 ? state.capabilities.nasEnabled : nasPlugin !== void 0 ? nasPlugin.enabled : Boolean(state?.nas?.enabled);
  const k3sEnabled = state?.capabilities?.k3sEnabled !== void 0 ? state.capabilities.k3sEnabled : k3sPlugin !== void 0 ? k3sPlugin.enabled : Boolean(state?.k3s?.enabled);
  return {
    firewallEnabled,
    nasEnabled,
    k3sEnabled
  };
}

// ../../packages/axonwall_lib/dist/compile/suricata/index.js
function compileSuricata(config) {
  if (!config || !config.enabled) {
    return {
      suricataYaml: "# Suricata IDS/IPS is disabled\n",
      nftRules: []
    };
  }
  const homeNetList = config.homeNet.join(",");
  const isIps = config.mode === "ips";
  const suricataYaml = `# Axonwall Suricata 7.0 Configuration (Auto-Generated)
%YAML 1.1
---
suricata-version: "7.0"

vars:
  address-groups:
    HOME_NET: "[${homeNetList}]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,8080,8000,8888"
    SHELLCODE_PORTS: "!80"
    SSH_PORTS: "22"

default-log-dir: /var/log/suricata/

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer: yes
            http-body: yes
            metadata: yes
        - flow
        - dns:
            version: 2
        - http:
            extended: yes
        - tls:
            extended: yes

nfq:
  mode: ${isIps ? "accept" : "repeat"}
  repeat-mark: 1
  repeat-mask: 1
  bypass: ${config.nfqueueBypass ? "yes" : "no"}
  fail-open: ${config.nfqueueFailOpen ? "yes" : "no"}

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
    dns:
      tcp:
        enabled: yes
      udp:
        enabled: yes

default-rule-path: /var/lib/axonwall/suricata/rules
rule-files:
  - suricata.rules
  - local.rules
`;
  const nftRules = [];
  for (const iface of config.interfaces) {
    const queueAction = config.nfqueueBypass ? "queue num 0-3 bypass" : "queue num 0-3";
    nftRules.push(`iifname "${iface}" ${queueAction} comment "suricata-ips-inbound"`, `oifname "${iface}" ${queueAction} comment "suricata-ips-outbound"`);
  }
  return {
    suricataYaml,
    nftRules
  };
}

// ../../packages/axonwall_lib/dist/compile/crowdsec/index.js
function compileCrowdSec(config) {
  if (!config || !config.enabled) {
    return {
      bouncerYaml: "# CrowdSec integration is disabled\n",
      nftSetDefinition: "",
      nftRule: ""
    };
  }
  const setName = config.remediationSetName || "set_crowdsec_blacklists";
  const verdict = config.action === "reject" ? "reject" : "drop";
  const bouncerYaml = `# Axonwall CrowdSec Firewall Bouncer Configuration
mode: nftables
log_mode: file
log_dir: /var/log/
log_level: info
log_compression: true
log_max_size: 100
log_max_backups: 3
log_max_age: 30

api_url: ${config.lapiUrl || "http://127.0.0.1:8080/"}
api_key: ${config.apiKey || "CROWDSEC_API_KEY_HERE"}
insecure_skip_verify: false

disable_ipv6: false

# Native nftables binding into table inet axonwall
nftables:
  ipv4:
    enabled: true
    set-only: true
    table: axonwall
    chain: input
    family: inet
    set: ${setName}
    rule: "ip saddr @${setName} ${verdict}"
  ipv6:
    enabled: true
    set-only: true
    table: axonwall
    chain: input
    family: inet
    set: ${setName}_v6
    rule: "ip6 saddr @${setName}_v6 ${verdict}"
`;
  const nftSetDefinition = `set ${setName} {
  type ipv4_addr
  flags interval, timeout
}
set ${setName}_v6 {
  type ipv6_addr
  flags interval, timeout
}`;
  const nftRule = config.logBanned ? `ip saddr @${setName} log prefix "axonwall-crowdsec-${verdict}: " ${verdict}
    ip6 saddr @${setName}_v6 log prefix "axonwall-crowdsec-${verdict}: " ${verdict}` : `ip saddr @${setName} ${verdict}
    ip6 saddr @${setName}_v6 ${verdict}`;
  return {
    bouncerYaml,
    nftSetDefinition,
    nftRule
  };
}

// ../../packages/axonwall_lib/dist/compile/geoip/index.js
var COUNTRY_CIDR_TABLE = {
  CN: [
    "1.0.1.0/24",
    "1.0.2.0/23",
    "14.0.0.0/11",
    "27.8.0.0/13",
    "36.96.0.0/12",
    "42.0.0.0/11",
    "58.14.0.0/15",
    "59.32.0.0/11",
    "101.64.0.0/11",
    "110.16.0.0/12",
    "111.0.0.0/10",
    "112.0.0.0/10",
    "113.64.0.0/11",
    "114.216.0.0/13",
    "115.192.0.0/12",
    "116.128.0.0/10",
    "117.128.0.0/10",
    "118.112.0.0/13",
    "119.0.0.0/12",
    "120.0.0.0/11",
    "121.0.0.0/11",
    "122.0.0.0/11",
    "123.56.0.0/14",
    "124.64.0.0/11",
    "175.0.0.0/11",
    "180.96.0.0/11",
    "182.88.0.0/13",
    "183.0.0.0/10",
    "218.0.0.0/11",
    "220.160.0.0/11",
    "221.0.0.0/11",
    "222.128.0.0/11",
    "223.64.0.0/11"
  ],
  RU: [
    "2.60.0.0/14",
    "5.16.0.0/12",
    "31.13.0.0/16",
    "37.19.128.0/17",
    "46.17.40.0/21",
    "62.76.0.0/15",
    "77.37.128.0/17",
    "78.25.0.0/16",
    "79.132.0.0/14",
    "80.64.0.0/13",
    "81.16.128.0/17",
    "82.145.0.0/16",
    "83.149.0.0/16",
    "85.92.128.0/17",
    "87.224.0.0/12",
    "89.175.0.0/16",
    "91.122.0.0/15",
    "92.242.0.0/16",
    "93.158.128.0/17",
    "94.25.0.0/16",
    "95.24.0.0/14",
    "176.14.0.0/15",
    "178.64.0.0/13",
    "188.162.0.0/15",
    "194.85.0.0/16",
    "195.208.0.0/15",
    "212.164.0.0/14",
    "213.87.0.0/16",
    "217.118.64.0/18"
  ],
  KP: [
    "175.45.176.0/22",
    "210.52.109.0/24",
    "198.18.0.0/15"
  ],
  IR: [
    "2.176.0.0/12",
    "5.160.0.0/12",
    "31.56.0.0/14",
    "37.114.0.0/15",
    "78.38.0.0/15",
    "80.191.0.0/16",
    "82.99.192.0/18",
    "85.185.0.0/16",
    "89.165.0.0/16",
    "91.98.0.0/15",
    "92.42.48.0/20",
    "94.101.128.0/17",
    "188.158.0.0/15",
    "194.225.0.0/16"
  ],
  BY: [
    "37.212.0.0/14",
    "46.53.128.0/17",
    "82.209.192.0/18",
    "86.57.128.0/17",
    "93.84.0.0/15",
    "93.125.0.0/16",
    "178.120.0.0/14",
    "194.158.192.0/19"
  ],
  SY: [
    "82.137.200.0/21",
    "82.137.208.0/20",
    "82.137.224.0/19",
    "185.73.184.0/22",
    "185.87.12.0/22",
    "194.126.32.0/19"
  ],
  RO: [
    "79.112.0.0/13",
    "82.76.0.0/14",
    "86.120.0.0/13",
    "89.32.0.0/14",
    "92.80.0.0/13",
    "188.24.0.0/14"
  ],
  US: [
    "3.0.0.0/9",
    "8.0.0.0/9",
    "12.0.0.0/9",
    "13.0.0.0/8",
    "24.0.0.0/10",
    "52.0.0.0/11",
    "54.0.0.0/11",
    "64.0.0.0/10",
    "72.0.0.0/10",
    "104.0.0.0/10",
    "142.250.0.0/15",
    "172.217.0.0/16"
  ],
  DE: [
    "46.4.0.0/14",
    "85.10.192.0/18",
    "88.130.0.0/15",
    "91.0.0.0/10",
    "144.76.0.0/16",
    "178.63.0.0/16"
  ],
  GB: [
    "25.0.0.0/8",
    "51.0.0.0/10",
    "81.128.0.0/11",
    "86.0.0.0/11",
    "90.192.0.0/10"
  ],
  FR: [
    "51.68.0.0/14",
    "77.128.0.0/10",
    "82.64.0.0/11",
    "88.160.0.0/11",
    "90.0.0.0/10"
  ],
  BR: [
    "177.0.0.0/11",
    "179.96.0.0/11",
    "186.192.0.0/11",
    "187.0.0.0/11",
    "189.0.0.0/11",
    "201.0.0.0/11"
  ],
  IN: [
    "49.12.0.0/14",
    "103.0.0.0/10",
    "106.192.0.0/11",
    "115.96.0.0/11",
    "117.192.0.0/11",
    "182.64.0.0/11"
  ],
  AU: [
    "1.120.0.0/13",
    "101.160.0.0/11",
    "120.144.0.0/12",
    "139.130.0.0/16",
    "144.130.0.0/15",
    "203.0.112.0/20"
  ],
  JP: [
    "114.144.0.0/12",
    "124.32.0.0/11",
    "126.0.0.0/9",
    "133.0.0.0/8",
    "210.128.0.0/10"
  ]
};
function compileGeoIp(config) {
  if (!config || !config.enabled || config.countries.length === 0) {
    return {
      nftSetDefinitions: [],
      inputRules: [],
      forwardRules: []
    };
  }
  const countryCidrs = /* @__PURE__ */ new Set();
  for (const cc of config.countries) {
    const code = cc.toUpperCase();
    const cidrs = COUNTRY_CIDR_TABLE[code] || [];
    for (const c of cidrs) {
      countryCidrs.add(c);
    }
  }
  const setDefs = [];
  const inputRules = [];
  const forwardRules = [];
  const elements = Array.from(countryCidrs).join(", ");
  if (!elements) {
    return { nftSetDefinitions: [], inputRules: [], forwardRules: [] };
  }
  setDefs.push(`  set set_geoip_countries {`);
  setDefs.push(`    type ipv4_addr;`);
  setDefs.push(`    flags interval;`);
  setDefs.push(`    elements = { ${elements} };`);
  setDefs.push(`  }`);
  const excluded = config.excludedSubnets && config.excludedSubnets.length > 0 ? config.excludedSubnets : ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
  setDefs.push(`  set set_geoip_excluded {`);
  setDefs.push(`    type ipv4_addr;`);
  setDefs.push(`    flags interval;`);
  setDefs.push(`    elements = { ${excluded.join(", ")} };`);
  setDefs.push(`  }`);
  const logAction = config.log ? 'log prefix "axonwall-geoip: " ' : "";
  if (config.mode === "block") {
    if (config.direction === "in" || config.direction === "both") {
      const inRule = `ip saddr != @set_geoip_excluded ip saddr @set_geoip_countries ${logAction}drop comment "geoip-inbound-block"`;
      inputRules.push(inRule);
      forwardRules.push(inRule);
    }
    if (config.direction === "out" || config.direction === "both") {
      const outRule = `ip daddr != @set_geoip_excluded ip daddr @set_geoip_countries ${logAction}drop comment "geoip-outbound-block"`;
      forwardRules.push(outRule);
    }
  } else if (config.mode === "allow") {
    if (config.direction === "in" || config.direction === "both") {
      const inRule = `ip saddr != @set_geoip_excluded ip saddr != @set_geoip_countries ${logAction}drop comment "geoip-inbound-whitelist-drop"`;
      inputRules.push(inRule);
      forwardRules.push(inRule);
    }
    if (config.direction === "out" || config.direction === "both") {
      const outRule = `ip daddr != @set_geoip_excluded ip daddr != @set_geoip_countries ${logAction}drop comment "geoip-outbound-whitelist-drop"`;
      forwardRules.push(outRule);
    }
  }
  return {
    nftSetDefinitions: setDefs,
    inputRules,
    forwardRules
  };
}

// ../../packages/axonwall_lib/dist/compile/nas/index.js
function compileZfsPoolCommand(pool) {
  const args = [
    "zpool create -f",
    `-o ashift=${pool.ashift ?? 12}`,
    `-o autotrim=${pool.autotrim !== false ? "on" : "off"}`,
    `-O compression=${pool.compression ?? "lz4"}`,
    "-O acltype=posixacl",
    "-O xattr=sa",
    "-O dnodesize=auto",
    "-O normalization=formD",
    `-O mountpoint=/mnt/${pool.name}`,
    pool.name
  ];
  if (pool.topology && pool.topology !== "stripe") {
    args.push(pool.topology);
  }
  args.push(...pool.dataDisks);
  if (pool.logDisks && pool.logDisks.length > 0) {
    args.push("log");
    if (pool.logDisks.length >= 2) {
      args.push("mirror");
    }
    args.push(...pool.logDisks);
  }
  if (pool.cacheDisks && pool.cacheDisks.length > 0) {
    args.push("cache", ...pool.cacheDisks);
  }
  if (pool.spareDisks && pool.spareDisks.length > 0) {
    args.push("spare", ...pool.spareDisks);
  }
  return args.join(" ");
}
function compileZfsDatasetCommands(dataset) {
  const fullName = dataset.name.startsWith(`${dataset.pool}/`) ? dataset.name : `${dataset.pool}/${dataset.name}`;
  if (dataset.type === "zvol") {
    const volSize = dataset.volSizeGb && dataset.volSizeGb > 0 ? `${dataset.volSizeGb}G` : "10G";
    return [
      `zfs create -p -V ${volSize} -o compression=${dataset.compression ?? "lz4"} -o volblocksize=16K ${fullName}`
    ];
  }
  const cmds = [
    `zfs create -p -o compression=${dataset.compression ?? "lz4"} -o recordsize=${dataset.recordSize ?? "128K"} -o dedup=${dataset.dedup ?? "off"} -o aclmode=${dataset.aclMode ?? "passthrough"} ${fullName}`
  ];
  if (dataset.quotaGb && dataset.quotaGb > 0) {
    cmds.push(`zfs set quota=${dataset.quotaGb}G ${fullName}`);
  }
  return cmds;
}
function compileSmbConf(nas) {
  const lines = [
    "# Axonwall Auto-Generated Samba (SMB3) Configuration",
    "[global]",
    `  workgroup = ${nas?.workgroup || "WORKGROUP"}`,
    `  server string = ${nas?.serverString || "Axonwall Enterprise ZFS NAS"}`,
    "  security = user",
    "  map to guest = Bad User",
    "  server min protocol = SMB2_10",
    "  ea support = yes",
    "  vfs objects = acl_xattr",
    "  map acl inherit = yes",
    "  store dos attributes = yes",
    "  load printers = no",
    "  printing = bsd",
    "  printcap name = /dev/null",
    "  disable spoolss = yes",
    ""
  ];
  for (const share of nas?.smbShares ?? []) {
    if (!share.enabled)
      continue;
    lines.push(`[${share.name}]`);
    lines.push(`  path = ${share.path}`);
    if (share.comment) {
      lines.push(`  comment = ${share.comment}`);
    }
    lines.push(`  browseable = ${share.browseable !== false ? "yes" : "no"}`);
    lines.push(`  read only = ${share.readOnly ? "yes" : "no"}`);
    lines.push(`  guest ok = ${share.guestOk ? "yes" : "no"}`);
    const vfsObjects = ["acl_xattr"];
    if (share.shadowCopies) {
      vfsObjects.push("shadow_copy2");
    }
    if (share.timeMachine) {
      vfsObjects.push("catia", "fruit", "streams_xattr");
    }
    lines.push(`  vfs objects = ${vfsObjects.join(" ")}`);
    if (share.shadowCopies) {
      lines.push("  shadow:snapdir = .zfs/snapshot");
      lines.push("  shadow:sort = desc");
      lines.push("  shadow:format = @auto-%Y%m%d-%H%M");
      lines.push("  shadow:localtime = yes");
    }
    if (share.timeMachine) {
      lines.push("  fruit:aapl = yes");
      lines.push("  fruit:time machine = yes");
    }
    if (share.validUsers && share.validUsers.length > 0) {
      lines.push(`  valid users = ${share.validUsers.join(" ")}`);
    }
    if (share.hostsAllow && share.hostsAllow.length > 0) {
      lines.push(`  hosts allow = ${share.hostsAllow.join(" ")}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}
function compileNfsExports(nas) {
  const lines = [
    "# Axonwall Auto-Generated NFSv4 Exports"
  ];
  for (const exp of nas?.nfsExports ?? []) {
    if (!exp.enabled)
      continue;
    const mode = exp.readOnly ? "ro" : "rw";
    const syncMode = exp.async ? "async" : "sync";
    const squash = exp.mapRootUser === "root" ? "no_root_squash" : "root_squash";
    const nets = exp.allowedNetworks && exp.allowedNetworks.length > 0 ? exp.allowedNetworks : ["*"];
    const clientSpecs = nets.map((net) => `${net}(${mode},${syncMode},no_subtree_check,${squash})`).join(" ");
    lines.push(`${exp.path} ${clientSpecs}`);
  }
  lines.push("");
  return lines.join("\n");
}
function compileIscsiConfig(nas) {
  const targets = (nas?.iscsiTargets ?? []).filter((t) => t.enabled);
  return JSON.stringify({
    generatedBy: "axonwall-nas-compiler",
    targets: targets.map((t) => ({
      iqn: t.iqn,
      portal: `${t.portalIp}:${t.portalPort}`,
      allowedInitiators: t.allowedInitiators,
      chapEnabled: Boolean(t.chapUser && t.chapSecret),
      chapUser: t.chapUser || void 0,
      luns: t.luns.map((l) => ({
        lunId: l.lunId,
        zvolDevice: l.zvolPath.startsWith("/dev/") ? l.zvolPath : `/dev/zvol/${l.zvolPath.replace(/^\/+/, "")}`,
        blockSize: Number(l.blockSize),
        readOnly: l.readOnly
      }))
    }))
  }, null, 2);
}
function compileNas(nas) {
  const zfsCommands = [];
  for (const pool of nas?.pools ?? []) {
    zfsCommands.push(compileZfsPoolCommand(pool));
  }
  for (const ds of nas?.datasets ?? []) {
    zfsCommands.push(...compileZfsDatasetCommands(ds));
  }
  return {
    smbConf: compileSmbConf(nas),
    nfsExports: compileNfsExports(nas),
    iscsiConf: compileIscsiConfig(nas),
    zfsCommands
  };
}

// ../../packages/axonwall_lib/dist/compile/k3s/index.js
function compileK3s(state, joinToken) {
  const k3s = state.k3s ?? {
    enabled: false,
    clusterCidr: "10.42.0.0/16",
    serviceCidr: "10.43.0.0/16",
    nodeIpInterface: "lan",
    flannelBackend: "wireguard-native",
    disableTraefik: false,
    autoJoinHaPeer: true,
    openEbs: {
      enabled: true,
      zfsLocalPvEnabled: true,
      zfsLocalPvPool: "tank",
      replicatedStorageEnabled: true,
      defaultReplicaCount: 2,
      replicatedBackingPool: "tank/openebs-replicated"
    },
    workloads: []
  };
  const effectiveRole = state.ha?.role || state.ha?.nodeRole || "master";
  const effectivePeer = state.ha?.peerIp || state.ha?.peerAddress || "";
  const isSecondaryJoin = Boolean(state.ha?.enabled) && effectiveRole === "backup" && Boolean(effectivePeer) && k3s.autoJoinHaPeer !== false;
  const tlsSans = /* @__PURE__ */ new Set(["127.0.0.1", "localhost"]);
  if (effectivePeer) {
    tlsSans.add(effectivePeer);
  }
  for (const vip of state.virtualIps ?? []) {
    const cleanIp = vip.ip.split("/")[0];
    if (cleanIp)
      tlsSans.add(cleanIp);
  }
  const configLines = [
    "# Axonwall Auto-Generated K3s Control Plane Configuration",
    `write-kubeconfig-mode: "0640"`,
    `cluster-cidr: "${k3s.clusterCidr}"`,
    `service-cidr: "${k3s.serviceCidr}"`,
    `flannel-backend: "${k3s.flannelBackend}"`
  ];
  const ifaceObj = state.interfaces.find((i) => i.name === k3s.nodeIpInterface);
  if (ifaceObj?.device) {
    configLines.push(`flannel-iface: "${ifaceObj.device}"`);
  }
  if (isSecondaryJoin && effectivePeer) {
    configLines.push(`server: "https://${effectivePeer}:6443"`);
    if (joinToken) {
      configLines.push(`token: "${joinToken}"`);
    } else {
      configLines.push(`token-file: "/var/lib/axonwall/k3s-join.token"`);
    }
  } else {
    configLines.push("cluster-init: true");
  }
  if (k3s.disableTraefik) {
    configLines.push("disable:");
    configLines.push("  - traefik");
  }
  configLines.push("tls-san:");
  for (const san of tlsSans) {
    configLines.push(`  - "${san}"`);
  }
  configLines.push("");
  const zfsPool = k3s.openEbs?.zfsLocalPvPool || "tank";
  const replicaCount = state.ha?.enabled ? k3s.openEbs?.defaultReplicaCount ?? 2 : 1;
  const openEbsManifestYaml = [
    "# Axonwall Auto-Generated OpenEBS StorageClasses (ZFS-LocalPV + Replicated HA)",
    "apiVersion: v1",
    "kind: Namespace",
    "metadata:",
    "  name: openebs",
    "---",
    "apiVersion: storage.k8s.io/v1",
    "kind: StorageClass",
    "metadata:",
    "  name: axonwall-zfs-local",
    "  annotations:",
    `    storageclass.kubernetes.io/is-default-class: "${k3s.openEbs?.replicatedStorageEnabled ? "false" : "true"}"`,
    "provisioner: zfs.csi.openebs.io",
    "allowVolumeExpansion: true",
    "parameters:",
    '  fstype: "zfs"',
    '  compression: "lz4"',
    '  dedup: "off"',
    '  recordsize: "128k"',
    `  poolname: "${zfsPool}"`,
    "reclaimPolicy: Retain",
    "volumeBindingMode: WaitForFirstConsumer",
    "---",
    "apiVersion: storage.k8s.io/v1",
    "kind: StorageClass",
    "metadata:",
    "  name: axonwall-replicated-ha",
    "  annotations:",
    `    storageclass.kubernetes.io/is-default-class: "${k3s.openEbs?.replicatedStorageEnabled ? "true" : "false"}"`,
    "provisioner: io.openebs.csi-mayastor",
    "allowVolumeExpansion: true",
    "parameters:",
    '  protocol: "nvmf"',
    '  ioTimeout: "30"',
    `  repl: "${replicaCount}"`,
    `  backingZfsPool: "${k3s.openEbs?.replicatedBackingPool || `${zfsPool}/openebs-replicated`}"`,
    "reclaimPolicy: Retain",
    "volumeBindingMode: Immediate",
    ""
  ].join("\n");
  const workloadDocs = [];
  for (const wl of k3s.workloads ?? []) {
    if (!wl.enabled)
      continue;
    const ns = wl.namespace || "default";
    if (wl.storageClass !== "none") {
      workloadDocs.push([
        "apiVersion: v1",
        "kind: PersistentVolumeClaim",
        "metadata:",
        `  name: ${wl.name}-pvc`,
        `  namespace: ${ns}`,
        "spec:",
        "  accessModes:",
        "    - ReadWriteOnce",
        `  storageClassName: ${wl.storageClass}`,
        "  resources:",
        "    requests:",
        `      storage: ${wl.storageSizeGb}Gi`
      ].join("\n"));
    }
    const deployLines = [
      "apiVersion: apps/v1",
      "kind: Deployment",
      "metadata:",
      `  name: ${wl.name}`,
      `  namespace: ${ns}`,
      "spec:",
      `  replicas: ${wl.replicas}`,
      "  selector:",
      "    matchLabels:",
      `      app: ${wl.name}`,
      "  template:",
      "    metadata:",
      "      labels:",
      `        app: ${wl.name}`,
      "    spec:",
      "      containers:",
      `        - name: ${wl.name}`,
      `          image: ${wl.image}`,
      "          ports:",
      `            - containerPort: ${wl.port}`
    ];
    if (wl.storageClass !== "none") {
      deployLines.push("          volumeMounts:", `            - name: data`, `              mountPath: ${wl.mountPath}`, "      volumes:", "        - name: data", "          persistentVolumeClaim:", `            claimName: ${wl.name}-pvc`);
    }
    workloadDocs.push(deployLines.join("\n"));
  }
  return {
    k3sConfigYaml: configLines.join("\n"),
    openEbsManifestYaml,
    workloadsManifestYaml: workloadDocs.join("\n---\n")
  };
}

// ../../packages/axonwall_lib/dist/compile/nft/index.js
function buildNasAndK3sInputRules(state, ifDeviceMap, nasEnabled, k3sEnabled) {
  const hostRules = [];
  const trustedDevs = state.interfaces.filter((i) => i.enabled && i.name !== "wan" && i.device).map((i) => `"${i.device}"`);
  if (state.ha?.enabled && state.ha.syncInterface) {
    const syncDev = ifDeviceMap.get(state.ha.syncInterface) || state.ha.syncInterface;
    if (!trustedDevs.includes(`"${syncDev}"`)) {
      trustedDevs.push(`"${syncDev}"`);
    }
    hostRules.push(`    iifname "${syncDev}" tcp dport { 8443, 9443 } accept comment "ha-state-and-zfs-sync"`);
  }
  const devSet = trustedDevs.length > 0 ? `iifname { ${trustedDevs.join(", ")} } ` : "";
  if (nasEnabled) {
    hostRules.push("    # NAS Plugin (core-nas): SMB, NFSv4, iSCSI, and S3 Service Ports");
    hostRules.push(`    ${devSet}tcp dport { 139, 445 } accept comment "nas-smb"`);
    hostRules.push(`    ${devSet}meta l4proto { tcp, udp } th dport { 111, 2049 } accept comment "nas-nfsv4"`);
    hostRules.push(`    ${devSet}tcp dport 3260 accept comment "nas-iscsi"`);
    if (state.nas?.s3?.enabled) {
      const s3Port = state.nas.s3.listenPort || 9e3;
      const s3Console = state.nas.s3.consolePort || 9001;
      hostRules.push(`    ${devSet}tcp dport { ${s3Port}, ${s3Console} } accept comment "nas-s3-minio"`);
    }
  }
  if (k3sEnabled) {
    hostRules.push("    # Kubernetes Plugin (core-k3s): K3s Control Plane & OpenEBS Distributed Storage");
    hostRules.push(`    ${devSet}tcp dport { 6443, 10250, 2379, 2380, 10124, 9500 } accept comment "k3s-and-openebs-tcp"`);
    hostRules.push(`    ${devSet}udp dport { 8472, 51820, 51821 } accept comment "k3s-flannel-mesh"`);
    hostRules.push('    iifname "cni0" accept comment "k3s-cni0"');
    hostRules.push('    iifname "flannel*" accept comment "k3s-flannel"');
  }
  return hostRules;
}
function compileNftables(state) {
  const lines = [];
  const warnings = [];
  const files = [];
  const reloadServices = [];
  const capabilities = resolveCapabilities(state);
  if (state.nas || capabilities.nasEnabled) {
    const nasCompiled = compileNas(state.nas);
    files.push({
      path: "/etc/axonwall/managed/nas_config.json",
      content: JSON.stringify({
        enabled: capabilities.nasEnabled,
        pools: state.nas?.pools ?? [],
        datasets: state.nas?.datasets ?? [],
        snapshotPolicies: state.nas?.snapshotPolicies ?? [],
        smbConf: nasCompiled.smbConf,
        nfsExports: nasCompiled.nfsExports,
        iscsiConf: nasCompiled.iscsiConf
      }, null, 2),
      fileMode: 384
    });
  }
  if (state.k3s || capabilities.k3sEnabled) {
    const k3sCompiled = compileK3s(state);
    const effectiveRole = state.ha?.role || state.ha?.nodeRole || "master";
    const effectivePeer = state.ha?.peerIp || state.ha?.peerAddress || "";
    files.push({
      path: "/etc/axonwall/managed/k3s_config.json",
      content: JSON.stringify({
        enabled: capabilities.k3sEnabled,
        haEnabled: Boolean(state.ha?.enabled),
        haRole: effectiveRole,
        haPeerAddress: effectivePeer,
        haSharedSecret: state.ha?.sqliteSync?.authToken || state.ha?.vrrpInstances?.[0]?.authPassword || "",
        autoJoinHaPeer: state.k3s?.autoJoinHaPeer !== false,
        zfsLocalPvPool: state.k3s?.openEbs?.zfsLocalPvPool || "tank",
        replicatedPool: state.k3s?.openEbs?.replicatedBackingPool || "tank/openebs-replicated",
        k3sConfigYaml: k3sCompiled.k3sConfigYaml,
        openEbsManifestYaml: k3sCompiled.openEbsManifestYaml,
        workloadsManifestYaml: k3sCompiled.workloadsManifestYaml
      }, null, 2),
      fileMode: 384
    });
  }
  const ifDeviceMap = /* @__PURE__ */ new Map();
  for (const iface of state.interfaces) {
    ifDeviceMap.set(iface.name, iface.device);
  }
  if (!capabilities.firewallEnabled) {
    lines.push("#!/usr/sbin/nft -f");
    lines.push("# Axonwall Host-Mode Appliance Ruleset (core-firewall plugin disabled)");
    lines.push(`# Active Roles: NAS=${capabilities.nasEnabled} | K3s=${capabilities.k3sEnabled}`);
    lines.push(`# Version: ${state.version} | Generated: ${(/* @__PURE__ */ new Date()).toISOString()}`);
    lines.push("");
    lines.push("table inet axonwall {}");
    lines.push("flush table inet axonwall");
    lines.push("table inet axonwall {");
    lines.push("  chain input {");
    lines.push("    type filter hook input priority filter; policy drop;");
    lines.push("    ct state established,related accept");
    lines.push("    ct state invalid drop");
    lines.push('    iif "lo" accept');
    lines.push("    icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept");
    lines.push("    icmpv6 type { echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept");
    if (state.system.antiLockout?.enabled) {
      const lanIface = state.system.antiLockout.interface;
      const lanDev = ifDeviceMap.get(lanIface) || lanIface;
      const ports = state.system.antiLockout.ports.join(", ");
      lines.push(`    iifname "${lanDev}" tcp dport { ${ports} } accept comment "anti-lockout"`);
    }
    lines.push(...buildNasAndK3sInputRules(state, ifDeviceMap, capabilities.nasEnabled, capabilities.k3sEnabled));
    lines.push("  }");
    lines.push("");
    lines.push("  chain forward {");
    if (capabilities.k3sEnabled) {
      lines.push("    type filter hook forward priority filter; policy drop;");
      lines.push("    ct state established,related accept");
      lines.push('    iifname "cni0" accept comment "k3s-pod-forward"');
      lines.push('    oifname "cni0" accept comment "k3s-pod-forward"');
      lines.push('    iifname "flannel*" accept comment "k3s-flannel-forward"');
      lines.push('    oifname "flannel*" accept comment "k3s-flannel-forward"');
    } else {
      lines.push("    type filter hook forward priority filter; policy drop;");
    }
    lines.push("  }");
    lines.push("");
    lines.push("  chain output {");
    lines.push("    type filter hook output priority filter; policy accept;");
    lines.push("  }");
    lines.push("}");
    lines.push("");
    return {
      nftScript: lines.join("\n"),
      files,
      reloadServices,
      warnings
    };
  }
  const suricataConfig = state.suricata ? {
    ...state.suricata,
    interfaces: state.suricata.interfaces.map((i) => ifDeviceMap.get(i) || i)
  } : void 0;
  const suricataCompiled = compileSuricata(suricataConfig);
  const crowdsecCompiled = compileCrowdSec(state.crowdsec);
  const geoipCompiled = compileGeoIp(state.geoip);
  if (state.suricata?.enabled) {
    files.push({
      path: "/etc/suricata/suricata.yaml",
      content: suricataCompiled.suricataYaml,
      fileMode: 420
    });
    reloadServices.push("suricata");
  }
  if (state.crowdsec?.enabled) {
    files.push({
      path: "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml",
      content: crowdsecCompiled.bouncerYaml,
      fileMode: 420
    });
    reloadServices.push("crowdsec-firewall-bouncer");
  }
  lines.push("#!/usr/sbin/nft -f");
  lines.push("# Axonwall Auto-Generated nftables configuration");
  lines.push(`# Version: ${state.version} | Generated: ${(/* @__PURE__ */ new Date()).toISOString()}`);
  lines.push("");
  lines.push("table inet axonwall {}");
  lines.push("flush table inet axonwall");
  lines.push("table inet axonwall {");
  lines.push("  # Dynamic quarantine sets");
  lines.push("  set blocked_ips {");
  lines.push("    type ipv4_addr;");
  lines.push("    flags interval;");
  lines.push("  }");
  lines.push("  set blocked_ips6 {");
  lines.push("    type ipv6_addr;");
  lines.push("    flags interval;");
  lines.push("  }");
  lines.push("  set blocked_macs {");
  lines.push("    type ether_addr;");
  lines.push("  }");
  lines.push("");
  if (state.crowdsec?.enabled) {
    lines.push("  # CrowdSec integration");
    lines.push(crowdsecCompiled.nftSetDefinition.split("\n").map((l) => "  " + l).join("\n"));
    lines.push("");
  }
  if (state.geoip?.enabled && geoipCompiled.nftSetDefinitions.length > 0) {
    lines.push("  # GeoIP Location-based Sets");
    lines.push(...geoipCompiled.nftSetDefinitions);
    lines.push("");
  }
  if (state.aliases.length > 0) {
    lines.push("  # Aliases & Dynamic Sets");
    for (const alias of state.aliases) {
      if (!alias.enabled || alias.entries.length === 0)
        continue;
      const setName = `set_${sanitizeIdentifier(alias.name)}`;
      let setType2 = "ipv4_addr";
      if (alias.type === "port") {
        setType2 = "inet_service";
      } else if (alias.type === "mac") {
        setType2 = "ether_addr";
      } else if (alias.type === "network" || alias.type === "host") {
        setType2 = alias.entries.some((e) => e.includes(":")) ? "ipv6_addr" : "ipv4_addr";
      }
      const elements = alias.entries.join(", ");
      lines.push(`  set ${setName} {`);
      lines.push(`    type ${setType2};`);
      if (alias.type === "network" || alias.type === "host" || alias.type === "port") {
        lines.push("    flags interval;");
      }
      lines.push(`    elements = { ${elements} };`);
      lines.push("  }");
    }
    lines.push("");
  }
  const enabledDevices = state.interfaces.filter((i) => i.enabled && i.device).map((i) => `"${i.device}"`);
  if (state.system.flowtableOffload && enabledDevices.length > 0) {
    lines.push("  # Flowtable Fastpath");
    lines.push("  flowtable ft_fastpath {");
    lines.push("    hook ingress priority filter;");
    lines.push(`    devices = { ${enabledDevices.join(", ")} };`);
    lines.push("  }");
    lines.push("");
  }
  lines.push("  chain prerouting {");
  lines.push("    type nat hook prerouting priority dstnat - 10; policy accept;");
  if (state.suricata?.tlsDecryption?.enabled) {
    const tlsConfig = state.suricata.tlsDecryption;
    lines.push(`    # TLS Decryption Interception`);
    for (const iface of state.interfaces) {
      if (iface.enabled && iface.name !== "wan") {
        const dev = iface.device;
        lines.push(`    iifname "${dev}" tcp dport 443 redirect to :${tlsConfig.transparentProxyPort} comment "tls-decryption-intercept"`);
      }
    }
  }
  for (const nat of state.nat) {
    if (!nat.enabled || nat.type !== "dnat" || !nat.targetIp)
      continue;
    const ifaceDev = ifDeviceMap.get(nat.interface) || nat.interface;
    let protoMatch = "";
    if (nat.protocol === "any" || nat.protocol === "tcp_udp") {
      protoMatch = nat.destinationPort ? `meta l4proto { tcp, udp } th dport ${formatPort(nat.destinationPort)}` : "meta l4proto { tcp, udp }";
    } else if (nat.protocol === "tcp" || nat.protocol === "udp") {
      protoMatch = nat.destinationPort ? `${nat.protocol} dport ${formatPort(nat.destinationPort)}` : `meta l4proto ${nat.protocol}`;
    } else {
      protoMatch = `meta l4proto ${nat.protocol}`;
    }
    const isV6 = nat.targetIp.includes(":");
    const family = isV6 ? "ip6" : "ip";
    const formattedIp = isV6 && nat.targetPort ? `[${nat.targetIp}]` : nat.targetIp;
    const dnatTarget = nat.targetPort ? `${formattedIp}:${nat.targetPort}` : formattedIp;
    lines.push(`    iifname "${ifaceDev}" ${protoMatch} dnat ${family} to ${dnatTarget}`);
  }
  lines.push("  }");
  lines.push("");
  lines.push("  chain input {");
  lines.push("    type filter hook input priority filter; policy drop;");
  if (state.crowdsec?.enabled) {
    lines.push(`    ${crowdsecCompiled.nftRule} comment "crowdsec-drop"`);
  }
  if (state.geoip?.enabled && geoipCompiled.inputRules.length > 0) {
    for (const rule of geoipCompiled.inputRules) {
      lines.push(`    ${rule}`);
    }
  }
  lines.push('    ip saddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ether saddr @blocked_macs drop comment "ai-micro-segmentation"');
  lines.push("    ct state established,related accept");
  lines.push("    ct state invalid drop");
  lines.push('    iif "lo" accept');
  lines.push("    icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept");
  lines.push("    icmpv6 type { echo-request, echo-reply, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept");
  if (state.system.antiLockout?.enabled) {
    const lanIface = state.system.antiLockout.interface;
    if (lanIface !== "wan") {
      const lanDev = ifDeviceMap.get(lanIface) || lanIface;
      const ports = state.system.antiLockout.ports.join(", ");
      lines.push(`    # Anti-Lockout: Allow management access from ${lanIface}`);
      lines.push(`    iifname "${lanDev}" tcp dport { ${ports} } accept comment "anti-lockout"`);
    } else {
      warnings.push("Anti-Lockout interface was set to 'wan'; suppressed generation on WAN for appliance security.");
    }
  }
  lines.push(...buildNasAndK3sInputRules(state, ifDeviceMap, capabilities.nasEnabled, capabilities.k3sEnabled));
  if (state.wireguard?.enabled) {
    lines.push(`    udp dport ${state.wireguard.listenPort} accept comment "wireguard-service"`);
  }
  if (state.headscale?.enabled) {
    lines.push(`    udp dport 41641 accept comment "headscale-mesh"`);
  }
  for (const iface of state.interfaces) {
    if (!iface.enabled)
      continue;
    const dev = iface.device;
    lines.push(`    iifname "${dev}" jump input_${iface.name}`);
  }
  if (state.headscale?.enabled) {
    lines.push(`    iifname "tailscale0" jump input_tailscale`);
  }
  lines.push("  }");
  lines.push("");
  lines.push("  chain forward {");
  lines.push("    type filter hook forward priority filter; policy drop;");
  lines.push(...suricataCompiled.nftRules.map((r) => "    " + r));
  if (state.geoip?.enabled && geoipCompiled.forwardRules.length > 0) {
    for (const rule of geoipCompiled.forwardRules) {
      lines.push(`    ${rule}`);
    }
  }
  lines.push('    ip saddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip daddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ip6 daddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ether saddr @blocked_macs drop comment "ai-micro-segmentation"');
  if (state.system.flowtableOffload && enabledDevices.length > 0) {
    lines.push("    meta l4proto { tcp, udp } flow add @ft_fastpath");
  }
  lines.push("    ct state established,related accept");
  lines.push("    ct state invalid drop");
  for (const iface of state.interfaces) {
    if (!iface.enabled)
      continue;
    const dev = iface.device;
    lines.push(`    iifname "${dev}" jump forward_${iface.name}`);
  }
  if (state.headscale?.enabled) {
    lines.push(`    iifname "tailscale0" jump forward_tailscale`);
  }
  lines.push("  }");
  lines.push("");
  lines.push("  chain output {");
  lines.push("    type filter hook output priority filter; policy accept;");
  lines.push("  }");
  lines.push("");
  lines.push("  chain postrouting {");
  lines.push("    type nat hook postrouting priority srcnat; policy accept;");
  for (const nat of state.nat) {
    if (!nat.enabled)
      continue;
    const ifaceDev = ifDeviceMap.get(nat.interface) || nat.interface;
    if (nat.type === "masquerade") {
      lines.push(`    oifname "${ifaceDev}" masquerade comment "outbound-nat"`);
    } else if (nat.type === "snat" && nat.targetIp) {
      const family = nat.targetIp.includes(":") ? "ip6" : "ip";
      lines.push(`    oifname "${ifaceDev}" snat ${family} to ${nat.targetIp} comment "outbound-snat"`);
    }
  }
  if (!state.nat.some((n) => n.type === "masquerade" || n.type === "snat")) {
    const gatewayIfaces = new Set((state.gateways || []).filter((g) => g.enabled).map((g) => g.interface));
    if (gatewayIfaces.size === 0) {
      gatewayIfaces.add("wan");
    }
    for (const gwIfaceName of gatewayIfaces) {
      const iface = state.interfaces.find((i) => i.name === gwIfaceName);
      if (iface) {
        lines.push(`    oifname "${iface.device}" masquerade comment "default-gateway-masquerade"`);
      }
    }
  }
  lines.push("  }");
  lines.push("");
  const isFloating = (ifaceName) => ifaceName === "any" || ifaceName === "floating";
  for (const iface of state.interfaces) {
    if (!iface.enabled)
      continue;
    const inputRules = state.rules.filter((r) => r.enabled && (r.interface === iface.name || iface.name !== "wan" && isFloating(r.interface))).sort((a, b) => a.sortOrder - b.sortOrder);
    const forwardRules = state.rules.filter((r) => r.enabled && (r.interface === iface.name || isFloating(r.interface))).sort((a, b) => a.sortOrder - b.sortOrder);
    lines.push(`  chain input_${iface.name} {`);
    for (const rule of inputRules) {
      if (rule.direction === "in") {
        const stmt = formatRuleStatement(rule, state.aliases);
        if (stmt)
          lines.push(`    ${stmt}`);
      }
    }
    lines.push("  }");
    lines.push("");
    lines.push(`  chain forward_${iface.name} {`);
    for (const rule of forwardRules) {
      const stmt = formatRuleStatement(rule, state.aliases);
      if (stmt)
        lines.push(`    ${stmt}`);
    }
    lines.push("  }");
    lines.push("");
  }
  if (state.headscale?.enabled) {
    const tsRules = state.rules.filter((r) => r.enabled && (r.interface === "tailscale" || isFloating(r.interface))).sort((a, b) => a.sortOrder - b.sortOrder);
    lines.push(`  chain input_tailscale {`);
    for (const rule of tsRules) {
      if (rule.direction === "in") {
        const stmt = formatRuleStatement(rule, state.aliases);
        if (stmt)
          lines.push(`    ${stmt}`);
      }
    }
    lines.push("  }");
    lines.push("");
    lines.push(`  chain forward_tailscale {`);
    for (const rule of tsRules) {
      const stmt = formatRuleStatement(rule, state.aliases);
      if (stmt)
        lines.push(`    ${stmt}`);
    }
    lines.push("  }");
    lines.push("");
  }
  lines.push("}");
  lines.push("");
  return {
    nftScript: lines.join("\n"),
    files,
    reloadServices,
    warnings
  };
}
function compileSatelliteNftables(node) {
  const lines = [];
  const warnings = [];
  const files = [];
  const reloadServices = [];
  lines.push("#!/usr/sbin/nft -f");
  lines.push("# Axonwall Auto-Generated Satellite nftables configuration");
  lines.push(`# Node: ${node.id} | Generated: ${(/* @__PURE__ */ new Date()).toISOString()}`);
  lines.push("");
  lines.push("flush ruleset");
  lines.push("table inet axonwall {");
  lines.push("  set blocked_ips {");
  lines.push("    type ipv4_addr;");
  lines.push("    flags interval;");
  lines.push("  }");
  lines.push("  set blocked_ips6 {");
  lines.push("    type ipv6_addr;");
  lines.push("    flags interval;");
  lines.push("  }");
  lines.push("  set blocked_macs {");
  lines.push("    type ether_addr;");
  lines.push("  }");
  lines.push("");
  lines.push("  chain input {");
  lines.push("    type filter hook input priority filter; policy drop;");
  lines.push('    ip saddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip6 saddr @blocked_ips6 drop comment "ai-micro-segmentation"');
  lines.push('    ether saddr @blocked_macs drop comment "ai-micro-segmentation"');
  lines.push("    ct state established,related accept");
  lines.push("    ct state invalid drop");
  lines.push('    iif "lo" accept');
  lines.push("    # Allow management protocols");
  lines.push('    tcp dport 22 accept comment "allow-ssh"');
  const wgTunnelIp = node.wireguard?.tunnelIp || node.tunnelIp;
  if (wgTunnelIp) {
    lines.push('    udp dport 51820 accept comment "allow-wireguard"');
    lines.push('    iifname "wg-axon0" accept comment "allow-wg-mesh-traffic"');
  }
  lines.push('    udp dport 41641 accept comment "headscale-mesh"');
  lines.push('    iifname "tailscale0" accept comment "allow-tailscale-mesh-traffic"');
  lines.push("  }");
  lines.push("");
  lines.push("  chain forward {");
  lines.push("    type filter hook forward priority filter; policy drop;");
  lines.push('    ip saddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ip daddr @blocked_ips drop comment "ai-micro-segmentation"');
  lines.push('    ether saddr @blocked_macs drop comment "ai-micro-segmentation"');
  lines.push("    ct state established,related accept");
  lines.push("    ct state invalid drop");
  lines.push('    iifname "wg-axon0" accept');
  lines.push('    iifname "tailscale0" accept');
  lines.push("  }");
  lines.push("");
  lines.push("  chain output {");
  lines.push("    type filter hook output priority filter; policy accept;");
  lines.push("  }");
  lines.push("}");
  lines.push("");
  return {
    nftScript: lines.join("\n"),
    files,
    reloadServices,
    warnings
  };
}
function formatPort(val) {
  if (val.startsWith("$"))
    return `@set_${sanitizeIdentifier(val.slice(1))}`;
  if (val.includes(",") && !val.trim().startsWith("{"))
    return `{ ${val} }`;
  return val;
}
function formatRuleStatement(rule, aliases) {
  const parts = [];
  if (rule.source && rule.source !== "any") {
    if (rule.source.startsWith("$")) {
      const rawName = rule.source.slice(1);
      const aliasName = sanitizeIdentifier(rawName);
      const matchedAlias = aliases.find((a) => a.name.toLowerCase() === rawName.toLowerCase());
      const isV6 = matchedAlias?.entries.some((e) => e.includes(":"));
      parts.push(`${isV6 ? "ip6" : "ip"} saddr @set_${aliasName}`);
    } else if (rule.source.includes(":")) {
      parts.push(`ip6 saddr ${rule.source}`);
    } else {
      parts.push(`ip saddr ${rule.source}`);
    }
  }
  if (rule.destination && rule.destination !== "any") {
    if (rule.destination.startsWith("$")) {
      const rawName = rule.destination.slice(1);
      const aliasName = sanitizeIdentifier(rawName);
      const matchedAlias = aliases.find((a) => a.name.toLowerCase() === rawName.toLowerCase());
      const isV6 = matchedAlias?.entries.some((e) => e.includes(":"));
      parts.push(`${isV6 ? "ip6" : "ip"} daddr @set_${aliasName}`);
    } else if (rule.destination.includes(":")) {
      parts.push(`ip6 daddr ${rule.destination}`);
    } else {
      parts.push(`ip daddr ${rule.destination}`);
    }
  }
  const hasSport = Boolean(rule.sourcePort && rule.sourcePort !== "any");
  const hasDport = Boolean(rule.destinationPort && rule.destinationPort !== "any");
  if (rule.protocol === "tcp" || rule.protocol === "udp") {
    if (hasSport || hasDport) {
      if (hasSport)
        parts.push(`${rule.protocol} sport ${formatPort(rule.sourcePort)}`);
      if (hasDport)
        parts.push(`${rule.protocol} dport ${formatPort(rule.destinationPort)}`);
    } else {
      parts.push(`meta l4proto ${rule.protocol}`);
    }
  } else if (rule.protocol === "tcp_udp") {
    parts.push("meta l4proto { tcp, udp }");
    if (hasSport)
      parts.push(`th sport ${formatPort(rule.sourcePort)}`);
    if (hasDport)
      parts.push(`th dport ${formatPort(rule.destinationPort)}`);
  } else if (rule.protocol === "ipv6-icmp") {
    parts.push("meta l4proto ipv6-icmp");
  } else if (rule.protocol !== "any") {
    parts.push(`meta l4proto ${rule.protocol}`);
  }
  if (rule.log) {
    parts.push(`log prefix "axonwall-rule:${rule.id?.slice(0, 8) || "log"}: " group 0`);
  }
  if (rule.action === "pass") {
    if (rule.gatewayGroup) {
      const markHex = `0x${hashStringToInt(rule.gatewayGroup, 4096, 32767).toString(16)}`;
      parts.push(`meta mark set ${markHex}`);
    } else if (rule.gateway) {
      const markHex = `0x${hashStringToInt(rule.gateway, 256, 4095).toString(16)}`;
      parts.push(`meta mark set ${markHex}`);
    }
  }
  const actionMap = {
    pass: "accept",
    block: "drop",
    reject: "reject"
  };
  parts.push(actionMap[rule.action] || "accept");
  if (rule.description) {
    const safeDesc = rule.description.replace(/"/g, "'");
    parts.push(`comment "${safeDesc}"`);
  }
  return parts.join(" ");
}
function hashStringToInt(str, min, max) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  const span = max - min + 1;
  return min + Math.abs(hash) % span;
}

// ../../packages/axonwall_lib/dist/lint/index.js
function lintRuleset(state) {
  const issues = [];
  const validIfaces = new Set(state.interfaces.map((i) => i.name));
  validIfaces.add("any");
  validIfaces.add("floating");
  for (const rule of state.rules) {
    if (!validIfaces.has(rule.interface)) {
      issues.push({
        type: "missing_interface",
        severity: "error",
        message: `Rule references non-existent interface '${rule.interface}'`,
        ruleId: rule.id
      });
    }
  }
  const referencedAliases = /* @__PURE__ */ new Set();
  for (const rule of state.rules) {
    for (const val of [rule.source, rule.destination, rule.sourcePort, rule.destinationPort]) {
      if (val && val.startsWith("$")) {
        referencedAliases.add(val.slice(1).toLowerCase());
      }
    }
  }
  for (const alias of state.aliases) {
    if (!referencedAliases.has(alias.name.toLowerCase())) {
      issues.push({
        type: "unused_alias",
        severity: "info",
        message: `Alias '${alias.name}' is defined but not referenced in any firewall rule`,
        aliasName: alias.name
      });
    }
  }
  const rulesByIface = /* @__PURE__ */ new Map();
  for (const rule of state.rules) {
    if (!rule.enabled)
      continue;
    const iface = rule.interface;
    if (!rulesByIface.has(iface)) {
      rulesByIface.set(iface, []);
    }
    rulesByIface.get(iface).push(rule);
  }
  for (const [iface, rules] of rulesByIface.entries()) {
    const sorted = [...rules].sort((a, b) => a.sortOrder - b.sortOrder);
    const catchAllByDirection = /* @__PURE__ */ new Map();
    const normPort = (p) => !p || p === "any" ? "any" : p;
    for (let i = 0; i < sorted.length; i++) {
      const current = sorted[i];
      const dir = current.direction || "in";
      const catchAllRule = catchAllByDirection.get(dir);
      if (catchAllRule) {
        issues.push({
          type: "shadowed_rule",
          severity: "warning",
          message: `Rule '${current.description || current.id || "unnamed"}' is shadowed by catch-all rule '${catchAllRule.description || catchAllRule.id || "unnamed"}' above it on interface ${iface}`,
          ruleId: current.id
        });
      }
      if (current.quick !== false && current.protocol === "any" && (current.source === "any" || !current.source) && (current.destination === "any" || !current.destination) && (!current.sourcePort || current.sourcePort === "any") && (!current.destinationPort || current.destinationPort === "any")) {
        if (!catchAllByDirection.has(dir)) {
          catchAllByDirection.set(dir, current);
        }
      }
      for (let j = 0; j < i; j++) {
        const prev = sorted[j];
        if (prev.action === current.action && prev.protocol === current.protocol && prev.source === current.source && prev.destination === current.destination && normPort(prev.sourcePort) === normPort(current.sourcePort) && normPort(prev.destinationPort) === normPort(current.destinationPort) && prev.direction === current.direction) {
          issues.push({
            type: "duplicate_rule",
            severity: "warning",
            message: `Rule has identical match criteria and action to rule above it on interface ${iface}`,
            ruleId: current.id
          });
          break;
        }
      }
    }
  }
  if (state.system?.antiLockout?.enabled) {
    if (state.system.antiLockout.interface === "wan") {
      issues.push({
        type: "anti_lockout_on_wan",
        severity: "error",
        message: "Anti-Lockout rule cannot be bound to the 'wan' interface. Management services must be isolated to LAN/internal networks."
      });
    }
  }
  const mgmtPortNums = [22, 80, 443, 2966, 3e3];
  const mgmtPorts = new Set(mgmtPortNums.map(String));
  for (const rule of state.rules) {
    if (!rule.enabled || rule.action !== "pass" || rule.direction !== "in")
      continue;
    if (rule.interface !== "wan")
      continue;
    if (rule.protocol !== "tcp" && rule.protocol !== "tcp_udp" && rule.protocol !== "any")
      continue;
    const isWildcardSrc = !rule.source || rule.source === "any" || rule.source === "0.0.0.0/0" || rule.source === "::/0";
    if (isWildcardSrc) {
      const dport = (rule.destinationPort || "").trim().toLowerCase();
      let touchesMgmt = false;
      if (dport === "" || dport === "any") {
        touchesMgmt = true;
      } else {
        const ports = dport.split(/[\s,]+/).map((p) => p.trim()).filter(Boolean);
        for (const p of ports) {
          if (mgmtPorts.has(p) || p === "any") {
            touchesMgmt = true;
            break;
          }
          if (p.includes("-")) {
            const [startStr, endStr] = p.split("-").map((s) => s.trim());
            const start = Number.parseInt(startStr, 10);
            const end = Number.parseInt(endStr, 10);
            if (!Number.isNaN(start) && !Number.isNaN(end) && mgmtPortNums.some((mp) => mp >= start && mp <= end)) {
              touchesMgmt = true;
              break;
            }
          }
        }
      }
      if (touchesMgmt) {
        issues.push({
          type: "wan_management_exposed",
          severity: "warning",
          message: `Rule '${rule.description || rule.id || "unnamed"}' exposes Web Console / SSH management port(s) on ${rule.interface} to the public internet (source: any).`,
          ruleId: rule.id
        });
      }
    }
  }
  return issues;
}

// src/index.ts
import * as crypto from "node:crypto";

// ../../node_modules/.pnpm/ws@8.22.0/node_modules/ws/wrapper.mjs
var import_stream = __toESM(require_stream(), 1);
var import_extension = __toESM(require_extension(), 1);
var import_permessage_deflate = __toESM(require_permessage_deflate(), 1);
var import_receiver = __toESM(require_receiver(), 1);
var import_sender = __toESM(require_sender(), 1);
var import_subprotocol = __toESM(require_subprotocol(), 1);
var import_websocket = __toESM(require_websocket(), 1);
var import_websocket_server = __toESM(require_websocket_server(), 1);

// src/index.ts
import * as http2 from "node:http";
import * as https from "node:https";
import * as fs from "node:fs";

// src/headscale.ts
import http from "http";
var HEADSCALE_SOCKET_PATH = process.env.HEADSCALE_SOCKET_PATH || "/run/headscale/headscale.sock";
function headscaleRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const options = {
      socketPath: HEADSCALE_SOCKET_PATH,
      path,
      method,
      timeout: 5e3,
      headers: {
        "Content-Type": "application/json"
      }
    };
    const req = http.request(options, (res) => {
      let data = "";
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve(data);
          }
        } else {
          reject(new Error(`Headscale API error ${res.statusCode}: ${data}`));
        }
      });
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Headscale request timed out after 5000ms: ${path}`));
    });
    req.on("error", (e) => {
      reject(new Error(`Failed to connect to Headscale: ${e.message}`));
    });
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}
async function listUsers() {
  const data = await headscaleRequest("GET", "/api/v1/user");
  return data.users || [];
}
async function createUser(name) {
  const data = await headscaleRequest("POST", "/api/v1/user", { name });
  return data.user;
}
async function createPreAuthKey(user, reusable, ephemeral, expiration) {
  const data = await headscaleRequest("POST", "/api/v1/preauthkey", {
    user,
    reusable,
    ephemeral,
    expiration
    // e.g., '2023-12-31T23:59:59Z'
  });
  return data.preAuthKey;
}

// src/index.ts
function buildArtifactBundle(jobId, state) {
  const issues = lintRuleset(state);
  const warnings = issues.map((i) => `[${i.severity.toUpperCase()}] ${i.message}`);
  const { nftScript, files, reloadServices } = compileNftables(state);
  const hash = crypto.createHash("sha256").update(nftScript).digest("hex");
  return {
    jobId,
    bundleHash: hash,
    nftScript,
    files,
    reloadServices,
    warnings,
    generatedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
async function main() {
  console.log("[Axonwall Controller] Starting Axonwall Control Plane Worker...");
  console.log("[Axonwall Controller] Monitoring config changes and apply pipeline.");
  const activeSatellites = /* @__PURE__ */ new Map();
  const prometheusRegistry = new import_prom_client.default.Registry();
  import_prom_client.default.collectDefaultMetrics({ register: prometheusRegistry });
  const satUptimeGauge = new import_prom_client.default.Gauge({
    name: "axonwall_satellite_uptime_seconds",
    help: "Uptime of the satellite node in seconds",
    labelNames: ["satellite_id"],
    registers: [prometheusRegistry]
  });
  const satCpuGauge = new import_prom_client.default.Gauge({
    name: "axonwall_satellite_cpu_usage_percent",
    help: "CPU usage of the satellite node",
    labelNames: ["satellite_id"],
    registers: [prometheusRegistry]
  });
  const satMemGauge = new import_prom_client.default.Gauge({
    name: "axonwall_satellite_memory_usage_percent",
    help: "Memory usage of the satellite node",
    labelNames: ["satellite_id"],
    registers: [prometheusRegistry]
  });
  const satConnsGauge = new import_prom_client.default.Gauge({
    name: "axonwall_satellite_active_connections",
    help: "Number of active netfilter tracked connections",
    labelNames: ["satellite_id"],
    registers: [prometheusRegistry]
  });
  const satRxBytesGauge = new import_prom_client.default.Counter({
    name: "axonwall_satellite_rx_bytes_total",
    help: "Total received bytes on the satellite",
    labelNames: ["satellite_id"],
    registers: [prometheusRegistry]
  });
  const satTxBytesGauge = new import_prom_client.default.Counter({
    name: "axonwall_satellite_tx_bytes_total",
    help: "Total transmitted bytes on the satellite",
    labelNames: ["satellite_id"],
    registers: [prometheusRegistry]
  });
  const lastRxTxBytes = /* @__PURE__ */ new Map();
  const certPath = "/etc/axonwall/certs/hub.crt";
  const keyPath = "/etc/axonwall/certs/hub.key";
  const caPath = "/etc/axonwall/certs/ca.crt";
  const uiPort = parseInt(process.env.UI_PORT || "3000", 10);
  let server;
  const requestHandler = (req, res) => {
    let pathname;
    try {
      pathname = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`).pathname;
    } catch {
      res.writeHead(400);
      res.end("Bad Request");
      return;
    }
    if (pathname === "/metrics" && req.method === "GET") {
      prometheusRegistry.metrics().then((metricsStr) => {
        res.writeHead(200, { "Content-Type": prometheusRegistry.contentType });
        res.end(metricsStr);
      }).catch(() => {
        if (!res.headersSent) {
          res.writeHead(500);
          res.end("Internal Server Error");
        }
      });
      return;
    }
    const verifyFleetAuth = (req2, res2) => {
      const token = req2.headers["x-axonwall-ztp-token"] || req2.headers["authorization"]?.replace(/^Bearer\s+/i, "");
      const expectedToken = process.env.AXONWALL_ZTP_TOKEN;
      if (!expectedToken && process.env.NODE_ENV === "production") {
        res2.writeHead(503, { "Content-Type": "application/json" });
        res2.end(JSON.stringify({ error: "Fleet management authentication unconfigured" }));
        return false;
      }
      const tokenToMatch = expectedToken || "dev-ztp-token";
      const isValid2 = token && token.length === tokenToMatch.length && crypto.timingSafeEqual(Buffer.from(token), Buffer.from(tokenToMatch));
      if (!isValid2) {
        res2.writeHead(401, { "Content-Type": "application/json" });
        res2.end(JSON.stringify({ error: "Unauthorized: Valid X-Axonwall-ZTP-Token required" }));
        return false;
      }
      return true;
    };
    if (pathname === "/api/v1/fleet/block" && req.method === "POST") {
      if (!verifyFleetAuth(req, res)) return;
      let body = "";
      req.on("data", (chunk) => {
        body += chunk.toString();
        if (body.length > 65536) {
          req.destroy();
          return;
        }
      });
      req.on("end", () => {
        try {
          const payload = JSON.parse(body);
          const target = payload.target;
          const isMac = payload.isMac || false;
          if (!target) {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: "Missing target" }));
          }
          console.log(`[Fleet Manager] AI Copilot requested global block for: ${target} (isMac: ${isMac})`);
          let count = 0;
          for (const sat of activeSatellites.values()) {
            if (sat.ws && sat.ws.readyState === import_websocket.default.OPEN) {
              sat.ws.send(JSON.stringify({
                type: "BLOCK_TARGET",
                payload: { target, isMac }
              }));
              count++;
            }
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, notifiedSatellites: count }));
        } catch (err) {
          res.writeHead(400);
          res.end(JSON.stringify({ error: "Invalid JSON" }));
        }
      });
      return;
    }
    if (pathname === "/api/v1/fleet/satellites" && req.method === "GET") {
      if (!verifyFleetAuth(req, res)) return;
      res.writeHead(200, { "Content-Type": "application/json" });
      const satellitesData = Array.from(activeSatellites.values()).map((s) => {
        const { ws, wgPrivateKey, ...rest } = s;
        return rest;
      });
      res.end(JSON.stringify({
        totalConnected: Array.from(activeSatellites.values()).filter((s) => s.ws && s.ws.readyState === import_websocket.default.OPEN).length,
        totalEnrolled: activeSatellites.size,
        satellites: satellitesData
      }));
      return;
    }
    let forwardedHost = req.headers["x-forwarded-host"] || req.headers.host || "localhost";
    if (typeof req.headers.origin === "string") {
      try {
        const originHost = new URL(req.headers.origin).host;
        if (originHost) forwardedHost = originHost;
      } catch {
      }
    }
    const uiReq = http2.request({
      hostname: "127.0.0.1",
      port: uiPort,
      path: req.url,
      method: req.method,
      headers: {
        ...req.headers,
        "x-forwarded-proto": req.headers["x-forwarded-proto"] || (req.socket?.encrypted ? "https" : "http"),
        "x-forwarded-host": forwardedHost,
        "x-forwarded-for": req.socket?.remoteAddress || "127.0.0.1"
      }
    }, (uiRes) => {
      res.writeHead(uiRes.statusCode || 200, uiRes.headers);
      uiRes.pipe(res);
    });
    req.on("aborted", () => uiReq.destroy());
    uiReq.on("error", () => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
      res.end(`<!DOCTYPE html>
<html>
<head><title>Axonwall Appliance - Initializing</title>
<meta http-equiv="refresh" content="3">
<style>
body { font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
.card { background: #1e293b; padding: 2.5rem; border-radius: 12px; border: 1px solid #334155; text-align: center; max-width: 480px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); }
h1 { color: #38bdf8; margin: 0 0 1rem 0; font-size: 1.5rem; }
p { color: #94a3b8; font-size: 0.95rem; line-height: 1.5; margin: 0 0 1.5rem 0; }
.spinner { border: 3px solid #334155; border-top: 3px solid #38bdf8; border-radius: 50%; width: 28px; height: 28px; animation: spin 1s linear infinite; margin: 0 auto; }
@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="card">
  <h1>Axonwall Web Console</h1>
  <p>The web management console is initializing. This page will refresh automatically...</p>
  <div class="spinner"></div>
</div>
</body>
</html>`);
    });
    req.pipe(uiReq);
  };
  if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
    console.log("[Axonwall Controller] Starting in SECURE mTLS mode");
    server = https.createServer({
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
      ca: fs.existsSync(caPath) ? fs.readFileSync(caPath) : void 0,
      requestCert: fs.existsSync(caPath),
      rejectUnauthorized: false
    }, requestHandler);
  } else {
    console.log("[Axonwall Controller] Starting in INSECURE HTTP mode");
    server = http2.createServer(requestHandler);
  }
  const wss = new import_websocket_server.default({ noServer: true, maxPayload: 1048576 });
  server.on("upgrade", (request2, socket, head) => {
    let pathname;
    try {
      pathname = new URL(request2.url || "/", `http://${request2.headers.host || "localhost"}`).pathname;
    } catch {
      socket.write("HTTP/1.1 400 Bad Request\r\n\r\n");
      socket.destroy();
      return;
    }
    if (pathname === "/ws/satellite") {
      const satId = request2.headers["x-axonwall-satellite-id"];
      const token = request2.headers["x-axonwall-ztp-token"];
      if (!satId || !token) {
        console.log(`[Fleet Manager] Rejected connection: missing ZTP headers`);
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }
      const expectedToken = process.env.AXONWALL_ZTP_TOKEN;
      if (!expectedToken && process.env.NODE_ENV === "production") {
        console.log(`[Fleet Manager] Rejected connection: AXONWALL_ZTP_TOKEN not configured`);
        socket.write("HTTP/1.1 503 Service Unavailable\r\n\r\n");
        socket.destroy();
        return;
      }
      const tokenToMatch = expectedToken || "dev-ztp-token";
      const isTokenValid = token.length === tokenToMatch.length && crypto.timingSafeEqual(Buffer.from(token), Buffer.from(tokenToMatch));
      if (!isTokenValid) {
        console.log(`[Fleet Manager] Rejected connection: invalid ZTP token for ${satId}`);
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }
      if (fs.existsSync(caPath)) {
        const tlsSocket = socket;
        if (!tlsSocket.authorized) {
          console.log(`[Fleet Manager] Rejected connection: unauthorized client TLS certificate for ${satId}`);
          socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
          socket.destroy();
          return;
        }
      }
      console.log(`[Fleet Manager] Satellite authenticated successfully: ${satId}`);
      wss.handleUpgrade(request2, socket, head, (ws) => {
        wss.emit("connection", ws, request2, satId);
      });
    } else {
      const uiWsReq = http2.request({
        hostname: "127.0.0.1",
        port: uiPort,
        path: request2.url,
        method: request2.method,
        headers: request2.headers
      });
      uiWsReq.on("upgrade", (uiRes, uiSocket, uiHead) => {
        const headerLines = [];
        for (let i = 0; i < uiRes.rawHeaders.length; i += 2) {
          headerLines.push(`${uiRes.rawHeaders[i]}: ${uiRes.rawHeaders[i + 1]}`);
        }
        socket.write(`HTTP/1.1 101 Switching Protocols\r
${headerLines.join("\r\n")}\r
\r
`);
        if (uiHead && uiHead.length) socket.write(uiHead);
        if (head && head.length) uiSocket.write(head);
        uiSocket.on("error", () => socket.destroy());
        socket.on("error", () => uiSocket.destroy());
        uiSocket.pipe(socket);
        socket.pipe(uiSocket);
      });
      uiWsReq.on("response", (uiRes) => {
        socket.end(`HTTP/1.1 ${uiRes.statusCode || 502} ${uiRes.statusMessage || "Bad Gateway"}\r
\r
`);
        uiRes.resume();
      });
      uiWsReq.on("error", () => {
        socket.destroy();
      });
      uiWsReq.end();
    }
  });
  let ipCounter = 2;
  function broadcastMeshTopology() {
    console.log("[Fleet Manager] Computing and broadcasting full-mesh SD-WAN topology...");
    const allSats = Array.from(activeSatellites.values());
    for (const sat of allSats) {
      if (!sat.ws || sat.ws.readyState !== import_websocket.default.OPEN) continue;
      const peers = allSats.filter((p) => p.id !== sat.id).map((p) => ({
        publicKey: p.wgPublicKey,
        endpoint: `${p.ip}:51820`,
        // Assuming they are reachable on their public IP on 51820
        allowedIps: `${p.tunnelIp.split("/")[0]}/32`,
        // Only route their tunnel IP for the mesh
        keepAliveSec: 25
      }));
      sat.ws.send(JSON.stringify({
        type: "SYNC_WIREGUARD",
        payload: {
          interfaceName: "wg-axon0",
          tunnelIp: sat.tunnelIp,
          listenPort: 51820,
          privateKey: sat.wgPrivateKey,
          peers
        }
      }));
    }
  }
  wss.on("connection", async (ws, request2, satId) => {
    const remoteIp = request2.socket.remoteAddress || "127.0.0.1";
    console.log(`[Fleet Manager] Satellite Enrolled & Connected: ${satId} from ${remoteIp}`);
    const existing = activeSatellites.get(satId);
    if (existing?.ws && existing.ws !== ws) {
      try {
        existing.ws.terminate();
      } catch {
      }
    }
    let wgPrivateKey = existing?.wgPrivateKey;
    let wgPublicKey = existing?.wgPublicKey;
    if (!wgPrivateKey || !wgPublicKey) {
      const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
      const rawPriv = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
      const rawPub = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
      wgPrivateKey = rawPriv.toString("base64");
      wgPublicKey = rawPub.toString("base64");
    }
    let tunnelIp = existing?.tunnelIp;
    if (!tunnelIp) {
      const usedIps = new Set(Array.from(activeSatellites.values()).map((s) => s.tunnelIp?.split("/")[0]).filter(Boolean));
      for (let i = 2; i <= 254; i++) {
        const candidate = `10.99.0.${i}`;
        if (!usedIps.has(candidate)) {
          tunnelIp = `${candidate}/24`;
          break;
        }
      }
      if (!tunnelIp) {
        tunnelIp = `10.99.0.${ipCounter++ % 250 + 2}/24`;
      }
    }
    const state = {
      id: satId,
      connectedAt: (/* @__PURE__ */ new Date()).toISOString(),
      lastSeen: (/* @__PURE__ */ new Date()).toISOString(),
      ip: remoteIp.replace(/^::ffff:/, ""),
      arch: request2.headers["user-agent"]?.includes("arm") ? "arm64" : "amd64",
      wgPrivateKey,
      wgPublicKey,
      tunnelIp,
      wireguard: { tunnelIp },
      ws
    };
    activeSatellites.set(satId, state);
    try {
      console.log(`[Fleet Manager] Provisioning Headscale PreAuthKey for ${satId}...`);
      let users = await listUsers();
      let satelliteUser = users.find((u) => u.name === "satellites");
      if (!satelliteUser) {
        satelliteUser = await createUser("satellites");
      }
      const expiration = new Date(Date.now() + 60 * 60 * 1e3).toISOString();
      const preAuthKey = await createPreAuthKey("satellites", false, true, expiration);
      ws.send(JSON.stringify({
        type: "SYNC_HEADSCALE",
        payload: {
          serverUrl: process.env.HEADSCALE_EXTERNAL_URL || "https://hub.axonwall.local",
          authKey: preAuthKey.key
        }
      }));
      console.log(`[Fleet Manager] Dispatched Headscale ZTP credentials to ${satId}`);
    } catch (err) {
      console.error(`[Fleet Manager] Failed to provision Headscale key for ${satId}: ${err.message}`);
    }
    const { nftScript } = compileSatelliteNftables(state);
    ws.send(JSON.stringify({
      type: "SYNC_NFTABLES",
      payload: {
        script: nftScript
      }
    }));
    broadcastMeshTopology();
    ws.on("message", (message) => {
      state.lastSeen = (/* @__PURE__ */ new Date()).toISOString();
      try {
        const text = message.toString();
        const parsed = JSON.parse(text);
        if (parsed.type === "TELEMETRY_REPORT") {
          let report;
          if (typeof parsed.payload === "string") {
            report = JSON.parse(parsed.payload);
          } else {
            report = parsed.payload;
          }
          state.metrics = report.metrics;
          console.log(`[Fleet Manager] Telemetry from ${satId}: CPU ${report.metrics.cpuUsagePercent?.toFixed(1)}% | RAM ${report.metrics.memUsagePercent?.toFixed(1)}% | Active Conns: ${report.metrics.activeConns}`);
          satUptimeGauge.set({ satellite_id: satId }, report.metrics.uptimeSeconds || 0);
          satCpuGauge.set({ satellite_id: satId }, report.metrics.cpuUsagePercent || 0);
          satMemGauge.set({ satellite_id: satId }, report.metrics.memUsagePercent || 0);
          satConnsGauge.set({ satellite_id: satId }, report.metrics.activeConns || 0);
          const currentRx = report.metrics.rxBytesTotal || 0;
          const currentTx = report.metrics.txBytesTotal || 0;
          const last = lastRxTxBytes.get(satId) || { rx: 0, tx: 0 };
          if (currentRx >= last.rx) satRxBytesGauge.inc({ satellite_id: satId }, currentRx - last.rx);
          if (currentTx >= last.tx) satTxBytesGauge.inc({ satellite_id: satId }, currentTx - last.tx);
          lastRxTxBytes.set(satId, { rx: currentRx, tx: currentTx });
          if (ws.readyState === import_websocket.default.OPEN) {
            ws.send(JSON.stringify({ type: "PING", payload: {} }));
          }
        }
      } catch {
      }
    });
    ws.on("close", () => {
      console.log(`[Fleet Manager] Satellite Disconnected: ${satId}`);
      const current = activeSatellites.get(satId);
      if (current?.ws === ws) {
        satUptimeGauge.remove({ satellite_id: satId });
        satCpuGauge.remove({ satellite_id: satId });
        satMemGauge.remove({ satellite_id: satId });
        satConnsGauge.remove({ satellite_id: satId });
        lastRxTxBytes.delete(satId);
        current.ws = void 0;
        broadcastMeshTopology();
      }
    });
  });
  const port = parseInt(process.env.CONTROLLER_PORT || "2966", 10);
  server.listen(port, "0.0.0.0", () => {
    console.log(`[Axonwall Controller] Fleet Manager listening on 0.0.0.0:${port}`);
  });
}
if (process.env.NODE_ENV !== "test") {
  main().catch((err) => {
    console.error("[Axonwall Controller] Fatal error:", err);
    process.exit(1);
  });
}
export {
  buildArtifactBundle
};
