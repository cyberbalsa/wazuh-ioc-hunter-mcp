import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

const SPILL_DIR = join(tmpdir(), "wazuh-ioc-hunter");
const SPILL_THRESHOLD = 10;

/**
 * If resultCount > threshold, write full text to disk and return a summary + file path.
 * Otherwise return the full text inline.
 */
export function maybeSpill(fullText: string, resultCount: number, toolLabel: string): string {
  if (resultCount <= SPILL_THRESHOLD) {
    return fullText;
  }

  // Write full results to disk
  mkdirSync(SPILL_DIR, { recursive: true });
  const filename = `${toolLabel}-${Date.now()}.txt`;
  const filepath = join(SPILL_DIR, filename);
  writeFileSync(filepath, fullText, "utf-8");

  // Build summary: header lines + first ~10 result blocks, then pointer
  const lines = fullText.split("\n");

  // Find a reasonable cut point — after the header and ~10 result entries
  // Results are separated by blank lines in most formatters
  let blankCount = 0;
  let cutLine = lines.length;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() === "") {
      blankCount++;
      // Each result block ends with a blank line; cut after 10 blocks
      if (blankCount >= SPILL_THRESHOLD + 1) {
        cutLine = i + 1;
        break;
      }
    }
  }

  const summaryLines = lines.slice(0, cutLine);
  return [
    ...summaryLines,
    "",
    `--- ${resultCount} total results (showing first ${SPILL_THRESHOLD}) ---`,
    `Full output: ${filepath}`,
    `Use the Read tool on that file to see all results.`,
  ].join("\n");
}
