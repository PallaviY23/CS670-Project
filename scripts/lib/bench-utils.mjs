import { cpus, platform, release } from "node:os";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { parseArgs } from "node:util";

export function parseOptions(options) {
  return parseArgs({ options, allowPositionals: false }).values;
}

const round = (value) => Number(value.toFixed(2));

export function summarize(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mean = sorted.reduce((total, value) => total + value, 0) / sorted.length;
  const quantile = (q) => sorted[Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1)];
  const variance = sorted.reduce((total, value) => total + (value - mean) ** 2, 0) / Math.max(1, sorted.length - 1);
  return {
    n: sorted.length,
    mean: round(mean),
    median: round(sorted.length % 2 ? sorted[(sorted.length - 1) / 2] : (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2),
    p95: round(quantile(0.95)),
    min: round(sorted[0]),
    max: round(sorted[sorted.length - 1]),
    stdDev: round(Math.sqrt(variance)),
  };
}

export function summarizeSamples(samples, fields) {
  return Object.fromEntries(fields.map((field) => [field, summarize(samples.map((sample) => sample[field]))]));
}

export function hostInfo() {
  const processors = cpus();
  return {
    node: process.version,
    platform: `${platform()} ${release()}`,
    cpu: processors[0]?.model?.trim(),
    cores: processors.length,
  };
}

function csvCell(value) {
  const text = value === undefined || value === null ? "" : String(value);
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export async function writeCsv(path, rows) {
  if (!rows.length) return;
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(","), ...rows.map((row) => headers.map((header) => csvCell(row[header])).join(","))];
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${lines.join("\n")}\n`);
}

export async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export const timestamp = () => new Date().toISOString().replace(/[:.]/g, "-");
