import test from "node:test";
import assert from "node:assert";

import { chatWithThreatReport } from "./reportChat.js";

test("chatWithThreatReport rejects empty report", async () => {
  await assert.rejects(
    () =>
      chatWithThreatReport({
        reportText: "   ",
        messages: [{ role: "user", content: "Hi" }],
      }),
    /report text is empty/,
  );
});

test("chatWithThreatReport rejects non-user last message", async () => {
  await assert.rejects(
    () =>
      chatWithThreatReport({
        reportText: "# Report",
        messages: [
          { role: "user", content: "Hi" },
          { role: "assistant", content: "Hello" },
        ],
      }),
    /last message must be from the user/,
  );
});
